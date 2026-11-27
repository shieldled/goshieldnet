// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pierrec/lz4/v4"
	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

// The post-admission app-message layer over the Client (RFC out-of-scope,
// line 5): the same 20-byte-header + XChaCha20-Poly1305 framing the message layer
// (framing.go / protocol.c), now keyed by the transport's k_c2s/k_s2c. The 20-byte header IS
// the AEAD AAD (protocol_marshal_aad). MessageNum starts at 1 (0 is reserved).
// This makes the Client a full controller: TakeControlApp frames the first app
// message as the promoting PUSH (§8.5(c)), SendApp/RecvApp carry the rest.

const appHeaderSize = 20

// SendQueueMaxDefault is §2's SEND_QUEUE_MAX: the byte cap on the total of
// snd_queue and snd_buf, i.e. what a session may commit against a peer that has
// stopped acknowledging. §9.5 makes bounding this mandatory and independent of
// peer liveness — a session is never destroyed for inactivity, so the send path
// is the only thing standing between a vanished peer and unbounded growth.
const SendQueueMaxDefault = 32 * 1024

// MaxMsgPayloadDefault is §13's MAX_MSG_PAYLOAD. It is per architecture — an
// ESP32-WROOM cannot buffer what a controller can — and §13 requires it MUST NOT
// exceed SEND_QUEUE_MAX, since a message padded past the send-queue cap could
// never be written. It bounds the §13 pad-class ladder.
const MaxMsgPayloadDefault = SendQueueMaxDefault

// MaxAppPayload bounds an application message in either direction. It is this
// implementation's tighter bound under message-layer §7.1, not the spec's 16 MiB
// ceiling: a sender must not exceed it and a receiver rejects anything above it.
const MaxAppPayload = 1 << 20

// Sentinel errors. Message-layer §1.2 requires a receiver to distinguish three
// read outcomes and MUST NOT collapse them: no progress (reusable), a rejected
// frame (the session MUST survive, keep reading), and a partial frame (the stream
// is desynchronised and the session MUST be closed).
var (
	// ErrRejected is a frame that was read in full and then refused — a failed
	// AEAD open or a §7 length-rule violation. The stream is still frame-aligned:
	// callers MUST continue reading rather than tear the session down.
	ErrRejected = errors.New("shieldnet: frame rejected")

	// ErrDesync means some but not all of a frame was consumed. Every later read
	// would parse payload bytes as a header, so the session MUST be closed
	// (message layer 8). Client.RecvApp and RecvAppNum end it themselves: the
	// Client is IDLE afterwards (SessionDead stays false) and the caller admits
	// again. Server.RecvAppNumGen drops the primary it came from.
	ErrDesync = errors.New("shieldnet: stream desynchronised")

	// ErrReplay is a MessageNum at or below the high-water mark.
	ErrReplay = errors.New("shieldnet: app MessageNum replay")

	// ErrPayloadTooLarge is a send-side payload exceeding MaxAppPayload.
	ErrPayloadTooLarge = errors.New("shieldnet: payload exceeds MaxAppPayload")

	// ErrNotEstablished is a send or receive on a session that is not established
	// (or whose keys have been wiped by teardown).
	ErrNotEstablished = errors.New("shieldnet: not established")

	// ErrSessionClosed is a read or write on a session that was closed or
	// replaced (a newer promotion, DropPrimary, Close) while the call waited. It
	// is not a desync: the stream did not lose alignment, it ended. Do not end
	// the current session in response (Server.DropPrimaryIf).
	ErrSessionClosed = errors.New("shieldnet: session closed or replaced")

	// ErrSendQueueFull is §9.5: the session's send queue is at SEND_QUEUE_MAX, so
	// the write is refused rather than queued. §9.5 requires an error to the
	// caller and never a silent drop, and requires writes to resume once the
	// total falls back below the cap.
	ErrSendQueueFull = errors.New("shieldnet: send queue full")

	// ErrNotIdle is returned when TakeControl is called while an admission or a session is
	// in progress. After ErrSessionDead the teardown that returns the client
	// to IDLE runs asynchronously; wait for SessionDead() before re-admitting.
	ErrNotIdle = errors.New("shieldnet: client not IDLE")

	// ErrEmptyFirstMessage is returned by TakeControl for an empty first
	// message: admission carries a first message (transport 10.2), and nothing
	// is sent.
	ErrEmptyFirstMessage = errors.New("shieldnet: empty first message")

	// ErrSessionDead is §7.2: SESSION_DEAD_MS elapsed with no accepted s2c
	// envelope, so the peer is presumed gone. It is distinct from
	// ErrNotEstablished because the causes differ and the remedies differ — this
	// one says the session existed and the peer stopped answering. Recovery is an
	// explicit TakeControl; the library never re-admits on its own (§7.2).
	ErrSessionDead = errors.New("shieldnet: session dead")
)

func joinErr(sentinel, cause error) error { return fmt.Errorf("%w: %v", sentinel, cause) }

// notEstablishedErr distinguishes "never established / locally closed" from
// §9.3's "the peer stopped answering", which is the distinction a caller needs
// to decide whether to retry.
func (c *Client) notEstablishedErr() error {
	if c.deadFlag.Load() && !c.closedByUser.Load() {
		return ErrSessionDead
	}
	return ErrNotEstablished
}

// FlagCompressed is the high bit of MessageType: the sealed payload is a raw LZ4
// block and OriginalSize is its decompressed length (message layer §5).
const FlagCompressed = 0x80000000

// padFloor is the smallest padding class (transport §13). Classes are powers of
// two from here up; a message pads to the smallest class that holds it.
const padFloor = 64

// padClassTo returns the §13 size class for a payload of n octets against a
// ceiling, or n itself when the ladder would exceed it. §13 runs the ladder to
// MAX_MSG_PAYLOAD, which is per architecture, so the ceiling is a parameter
// rather than a constant — pinning it to this implementation's own receive bound
// is what left a controller padding to classes an ESP32 could not receive.
func padClassTo(n, ceiling int) int {
	c := padFloor
	for c < n {
		c <<= 1
	}
	// A class that does not fit under the ceiling once the AEAD tag is added is
	// not usable: padding to it would make the frame unsendable. Fall back to the
	// true length rather than rejecting the message — §13 makes padding a SHOULD,
	// so an unpaddable payload is sent unpadded, not refused. Without this, every
	// payload between 16385 and 32752 octets was rejected outright when padded
	// while the same payload sent unpadded went through.
	if c+chacha20poly1305.Overhead > ceiling {
		return n
	}
	return c
}

// padClass is the receive-side ladder. A receiver does not know the sender's
// MAX_MSG_PAYLOAD, so it validates against the absolute ceiling and is liberal
// in what it accepts.
func padClass(n int) int { return padClassTo(n, MaxAppPayload) }

func appHeader(encSize, origSize, msgType uint32, num uint64) []byte {
	h := make([]byte, appHeaderSize)
	binary.BigEndian.PutUint32(h[0:], encSize)
	binary.BigEndian.PutUint32(h[4:], origSize)
	binary.BigEndian.PutUint32(h[8:], msgType)
	binary.BigEndian.PutUint64(h[12:], num)
	return h
}

func appNonce(num uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	binary.BigEndian.PutUint64(n[8:], num) // protocol_nonce_from_msgnum
	return n
}

// compressBlock returns the raw LZ4 block for payload, or nil if compressing it
// did not make it smaller. The device decompresses with LZ4_decompress_safe
// against OriginalSize, so the block must be the bare LZ4 block with no framing.
func compressBlock(payload []byte) []byte {
	buf := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock(payload, buf, nil)
	if err != nil || n == 0 || n >= len(payload) {
		return nil // incompressible, or not worth it — send it plain
	}
	return buf[:n]
}

// frameApp builds one wire app message (header || XChaCha ciphertext) under k_c2s.
//
// compress and pad are the CALLER's decisions, not this layer's: transport §13
// draws its categories by message kind, which this layer deliberately does not
// know. Compression is applied only if it actually shrinks the payload.
//
// The two are mutually exclusive, and compression wins. Padding a compressed
// message would need three lengths on the wire — padded, compressed and true —
// and the header carries two, so a receiver could not find the end of the LZ4
// block. §13 excludes the combination for that reason.
func (c *Client) frameApp(msgType uint32, payload []byte, compress, pad bool) ([]byte, error) {
	c.mu.Lock()
	key := append([]byte(nil), c.kC2S...) // copy: teardown wipes the original
	c.mu.Unlock()
	defer zero(key)
	ceiling := c.maxMsgPayload()
	if n := int(c.peerBound.Load()); n > 0 && n < ceiling {
		ceiling = n
	}
	return frameAppWith(key, c.nextTx(), msgType, payload, compress, pad, ceiling)
}

// minPaddedSize is the Size of a message padded to the smallest class: the
// floor of any receive bound a peer can have.
const minPaddedSize = padFloor + chacha20poly1305.Overhead

// SetPeerReceiveBound tells the client the largest Size the peer accepts
// (message layer 7.3: a sender MUST respect the receiver's bound as well as its
// own). From then on, until the session ends, a message whose Size would exceed
// it is refused with ErrPayloadTooLarge, and padding uses only a class that
// fits it. 0 means unknown (only the client's own MaxMsgPayload applies); a
// bound below 80, the Size of the smallest padded message, is refused. The
// bound is reset at every admission, so set it again after each one, once the
// application protocol has told it (for sled, DEVICE_INFO's envelope). The
// receive side keeps the client's own bound.
func (c *Client) SetPeerReceiveBound(n int) error {
	if n < 0 || (n > 0 && n < minPaddedSize) {
		return fmt.Errorf("shieldnet: peer receive bound %d is below %d", n, minPaddedSize)
	}
	c.peerBound.Store(int64(n))
	return nil
}

// Transport §13 sorts messages into three categories, and only the caller knows
// which one a message kind is in. Two of the three share a wire treatment:
//
//   - SendAppPadded     — control and configuration: padded, never compressed.
//   - SendAppCompressed — bulk content AND pixel frames: compressed if that
//     shrinks the payload, never padded.
//   - SendApp           — verbatim. An escape hatch, not a default.
//
// Compression is opt-in rather than automatic because the failure modes are not
// symmetric: forgetting to compress a pixel frame costs bandwidth, while
// compressing a control message by accident is the leak §13 forbids.

// SendApp frames a message verbatim — no compression, no padding.
//
// This is rarely the right call. A control or configuration message wants
// SendAppPadded; a pixel frame or a bulk upload wants SendAppCompressed. Use this
// only for a payload whose framing the caller is managing itself.
func (c *Client) SendApp(msgType uint32, payload []byte) error {
	return c.sendApp(msgType, payload, false, false)
}

// SendAppPadded pads the message up to the smallest §13 size class (powers of two
// from 64 B) and sends it uncompressed. This is the call for control and
// configuration messages: forbidding compression stops content-dependent ratio
// leakage, and padding stops the message's own length identifying which command it
// was. Both are needed; either alone leaves the other route open.
func (c *Client) SendAppPadded(msgType uint32, payload []byte) error {
	return c.sendApp(msgType, payload, false, true)
}

// SendAppCompressed requests LZ4. Use it for the two categories transport §13
// permits to compress — pixel frames and bulk content (a blob uploaded whole) —
// and never for a control or configuration message.
//
// This is the normal path for a pixel stream. Frames are the highest-volume
// traffic on the link and compress well, since LED content is full of uniform and
// repeating regions; §13 permits it and the device decompresses before dispatch.
// Compression is applied only if it shrinks the payload, so a noisy frame that
// does not compress is sent plain and this is never worse on the wire than
// SendApp.
//
// The residual differs by category and §13 accepts both: for a pixel frame,
// roughly how uniform the scene is — already visible to anyone who can see the
// lights; for bulk content, a size fingerprint of which artifact was uploaded,
// which padding does not blunt because §13 makes the two mutually exclusive.
func (c *Client) SendAppCompressed(msgType uint32, payload []byte) error {
	return c.sendApp(msgType, payload, true, false)
}

// SendAppBulk frames bulk content (message layer 6.3): compressed if that
// shrinks the payload, else padded to a class that fits the bound, since a bulk
// message that is not compressed SHOULD be padded.
func (c *Client) SendAppBulk(msgType uint32, payload []byte) error {
	return c.sendApp(msgType, payload, true, true)
}

func (c *Client) sendApp(msgType uint32, payload []byte, compress, pad bool) error {
	sess, err := c.sendSess()
	if err != nil {
		return err
	}
	// F3: txMu is taken BEFORE framing, not just around the write. MessageNum is
	// allocated inside frameApp, and the peer enforces strictly-increasing
	// (§6.2), so numbering outside the lock lets two senders take 5 and 6 and
	// then write 6 before 5 — the peer rejects 5 as a replay and the message is
	// silently lost, which is precisely what §9.5 forbids. Numbering and writing
	// must be one critical section.
	c.txMu.Lock()
	defer c.txMu.Unlock()

	frame, err := c.frameApp(msgType, payload, compress, pad)
	if err != nil {
		return err
	}
	// §9.5: "the device MUST refuse further application writes — returning an
	// error to the caller, never silently dropping — and MUST resume accepting
	// them once the total falls below the cap." kcp-go signals a full window by
	// blocking, so a deadline converts that into the required error. It is a
	// deadline and not a permanent refusal, so writes resume by construction once
	// the window drains.
	//
	// The deadline is session state, not call state, so set-write-clear must also
	// be inside txMu: otherwise the first sender to finish clears it out from
	// under a second that is still blocked in Write, leaving it with no deadline.
	if testHookBeforeSendWrite != nil {
		testHookBeforeSendWrite()
	}
	sess.SetWriteDeadline(time.Now().Add(msDur(SendBlockedMS)))
	c.markOutstanding() // §7.2 outstanding-data gate
	_, err = sess.Write(frame)
	sess.SetWriteDeadline(time.Time{})
	// kcp-go returns its write-deadline timeout as errors.WithStack(timeoutError{})
	// (pkg/errors). *withStack does NOT implement net.Error, so a direct type
	// assertion is always false and §9.5's refusal never reaches the caller.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrSendQueueFull
	}
	return c.afterRead(sess, err)
}

// RecvApp reads one framed app message, verifies+decrypts it under k_s2c, and
// returns the message type and plaintext.
func (c *Client) RecvApp() (uint32, []byte, error) {
	c.mu.Lock()
	sess := c.kcp
	c.mu.Unlock()
	if sess == nil {
		return 0, nil, c.notEstablishedErr()
	}
	t, p, err := c.recvAppFrom(sess)
	return t, p, c.endIfDesync(sess, c.afterRead(sess, err))
}

// endIfDesync ends sess when a read on it found the stream desynchronised
// (message layer 8: the session MUST be ended), and returns err. When §7.2's
// clock has also run for SESSION_DEAD_MS the session is dead, not
// desynchronised (transport 10.3), and the read returns ErrSessionDead. The
// test is inclusive because one accepted envelope can start both 10 s clocks:
// lastRx is stamped just before the frame's budget starts, so when the
// watchdog fires the liveness clock reads at least SESSION_DEAD_MS, often
// exactly, and livenessExpired's strict test would then still say alive. A
// read that comes back after the read loop's own dead teardown is reported
// dead too.
func (c *Client) endIfDesync(sess *kcp.UDPSession, err error) error {
	if !errors.Is(err, ErrDesync) {
		return err
	}
	c.teardownIf(sess, c.silentFor(SessionDeadMS))
	if c.SessionDead() {
		return ErrSessionDead
	}
	return err
}

// recvAppFrom is RecvApp's parse, split out from the session lookup so the
// receive path — every §7 length rule and the §1.2 outcome classes — can be
// driven directly from a byte stream in tests rather than only through a live
// session.
func (c *Client) recvAppFrom(sess io.Reader) (uint32, []byte, error) {
	t, _, p, err := c.recvAppNumFrom(sess)
	return t, p, err
}

func (c *Client) recvAppNumFrom(sess io.Reader) (uint32, uint64, []byte, error) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	c.mu.Lock()
	key := append([]byte(nil), c.kS2C...) // copy: teardown wipes the original
	c.mu.Unlock()
	defer zero(key)
	// A compressed message may decompress to MaxAppPayload whatever this
	// client's MaxMsgPayload: OriginalSize is not bounded by the Size bound.
	return recvAppWith(sess, key, &c.rxNum, &c.rxStage, c.maxMsgPayload(), msDur(c.MidFrameBudgetMS), MaxAppPayload)
}

// RecvAppNum is RecvApp, additionally returning the message's MessageNum. A
// responder needs it to echo as ACK's orig_message_num.
func (c *Client) RecvAppNum() (uint32, uint64, []byte, error) {
	c.mu.Lock()
	sess := c.kcp
	c.mu.Unlock()
	if sess == nil {
		return 0, 0, nil, c.notEstablishedErr()
	}
	t, n, p, err := c.recvAppNumFrom(sess)
	return t, n, p, c.endIfDesync(sess, c.afterRead(sess, err))
}

// isValidPaddedLen reports whether a sealed plaintext of n octets is a legal
// carrier for a true length of origSize: either exactly origSize (unpadded, or
// padded to a class the sender's ceiling could not hold), or origSize padded up
// to the SMALLEST §13 class that holds it.
//
// Only the smallest class is accepted. §13 says a message "is padded up to the
// smallest class that holds it", so a larger one is not a conforming encoding —
// and accepting any class would let a peer attach up to MaxAppPayload of
// attacker-chosen padding to a 1-byte message, which is both a per-message
// covert channel and an amplification lever a conforming receiver refuses.
func isValidPaddedLen(n, origSize int) bool {
	if n == origSize {
		return true
	}
	if n < origSize || n > MaxAppPayload {
		return false
	}
	return n == padClass(origSize)
}

// LastTxNum returns the MessageNum of the most recent application message this
// client sent. The sled layer correlates a response to its command by
// orig_message_num and never by message order, so a controller issuing more than
// one command needs this to match answers to requests.
func (c *Client) LastTxNum() uint64 { return c.txNum.Load() }

// SetReadDeadline bounds subsequent RecvApp/RecvAppNum/Recv calls, so a caller
// can implement shieldnet-protocol/spec/application.md 7.1's "read timeout" outcome. Without
// it a peer that promotes the session and then never answers at the application
// layer blocks a reader forever: §7.2's liveness timer fires only while the
// client has unacknowledged data OUTSTANDING, and a promoted session that has
// been fully acknowledged has none, so nothing else ends the wait.
//
// A deadline that expires mid-frame is "no progress": the receive path stages
// the fragment and resumes on the next call (see rxStage), so a timeout here is
// §1.2's first row. That holds until MidFrameBudgetMS has passed since the
// frame's first octet; from then on the read returns ErrDesync (message layer
// 8, "partial message"). The zero time clears it.
func (c *Client) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	sess := c.kcp
	c.mu.Unlock()
	if sess == nil {
		return c.notEstablishedErr()
	}
	return sess.SetReadDeadline(t)
}

// TakeControlApp admits and sends the first app message (msgType, payload) as the
// promoting PUSH (§8.5(c)), framed under k_c2s once admission derives the keys.
func (c *Client) TakeControlApp(msgType uint32, payload []byte) error {
	return c.takeControl(payload, true, msgType, false)
}

// TakeControlAppPadded is TakeControlApp with the promoting message padded to
// §13's class ladder, which is what §13 asks for when that message is control or
// configuration — as it is for the usual CmdPing probe. It is a separate entry
// point rather than the default because §13 assigns the category by message kind
// and forbids padding pixel frames and compressed bulk content outright, so this
// layer must be told rather than guess.
func (c *Client) TakeControlAppPadded(msgType uint32, payload []byte) error {
	return c.takeControl(payload, true, msgType, true)
}
