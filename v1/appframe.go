// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// The application message layer, factored so both roles can use it.
//
// shieldnet-protocol/shieldnet-message-layer.md specifies one wire format used in both
// directions: client→device under k_c2s, device→client under k_s2c. The framing
// is therefore role-agnostic — only which key seals and which opens differs — so
// it lives here as functions over an explicit key rather than as methods on
// Client. Server.SendApp/RecvApp use the same code with the keys swapped, which
// is what makes the four keys §8.5(a)4 installs actually reachable.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// appPeer is one end of the message layer: the key it seals with, the key it
// opens with, and the two per-direction MessageNum counters (§6.2).
type appPeer struct {
	txMu  sync.Mutex // numbering and writing are one critical section
	txNum atomic.Uint64

	rxMu    sync.Mutex
	rxNum   uint64
	rxStage rxStage
}

// rxStage holds a frame that has arrived only in part, so the next call can
// resume it.
//
// A caller may set a read deadline — the example device does, to stay responsive
// to its session being replaced — and both a 20-octet header and a body can
// legitimately span two KCP segments. A read that times out between them has
// consumed bytes without completing a frame. That is NOT §1.2's third row: the
// stream is intact and the rest of the frame is still on its way. With nowhere
// to keep the fragment the only honest report would be ErrDesync, which turns
// the caller's own liveness timer into a session kill and makes the one error
// that means "this session cannot be recovered" untrustworthy.
//
// Staging is bounded: message layer 8 item 2 requires a receiver to limit how
// long a message may remain partly read, and to treat expiry as "partial
// message". start is when the frame's first octet arrived; see recvAppWith.
type rxStage struct {
	hdr   [appHeaderSize]byte
	hdrN  int
	body  []byte // allocated once the header is complete and bounds-checked
	bodyN int
	start time.Time // arrival of the frame's first octet; zero while nothing is staged
}

// errPartialTooLong is the cause joined to ErrDesync when a frame stayed partly
// read for longer than the mid-frame budget.
var errPartialTooLong = errors.New("message partly read for longer than MidFrameBudgetMS")

// watchedRead runs read. While a frame is staged and r is an io.Closer (the
// *kcp.UDPSession of both roles), a timer closes r once budget has passed since
// the frame's first octet. It closes rather than setting a read deadline
// because a kcp-go Read that began without a deadline ignores one set later;
// Close wakes it. fired reports that the timer closed r, and is decided under
// the same lock the timer takes, so a read that returned data in the same
// instant still reports fired: the caller must then return ErrDesync and
// nothing else. Invariant: the watchdog closes the session if and only if
// recvAppWith returns ErrDesync for it.
func watchedRead(r io.Reader, stage *rxStage, budget time.Duration, read func() (int, error)) (int, bool, error) {
	closer, ok := r.(io.Closer)
	if !ok || stage.start.IsZero() {
		n, err := read()
		return n, false, err
	}
	var mu sync.Mutex
	var fired, done bool
	t := time.AfterFunc(time.Until(stage.start.Add(budget)), func() {
		mu.Lock()
		if !done {
			fired = true
			_ = closer.Close()
		}
		mu.Unlock()
	})
	n, err := read()
	t.Stop()
	mu.Lock()
	done = true
	f := fired
	mu.Unlock()
	return n, f, err
}

func (s *rxStage) reset() { *s = rxStage{} }

// isTimeoutErr reports whether err is a read/write deadline expiring. kcp-go
// wraps its timeouts in pkg/errors, whose *withStack does NOT implement
// net.Error, so this must use errors.As and not a type assertion.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// nextTx allocates the next MessageNum, or 0 once the space is exhausted.
//
// §6.4 requires a sender that has used 2^64-1 to "refuse to send again on that
// key rather than advance": a bare Add(1) refuses exactly one message and then
// hands out 1 again, repeating the nonce of the session's FIRST message under a
// key that has already used it. The CAS loop makes the refusal permanent.
func (p *appPeer) nextTx() uint64 {
	for {
		cur := p.txNum.Load()
		if cur == ^uint64(0) {
			return 0 // exhausted, and stays exhausted
		}
		if p.txNum.CompareAndSwap(cur, cur+1) {
			return cur + 1
		}
	}
}

// frameAppWith builds one wire message: header || AEAD(body) sealed under key.
//
// compress and pad are the caller's decision, not this layer's: transport §13
// draws its categories by message kind, which this layer deliberately does not
// know. They are mutually exclusive and compression wins — a padded compressed
// message would need three lengths on the wire and the header carries two.
func frameAppWith(key []byte, num uint64, msgType uint32, payload []byte, compress, pad bool, ceiling int) ([]byte, error) {
	if msgType&FlagCompressed != 0 {
		return nil, errors.New("shieldnet: MessageType must not set FlagCompressed; use the compress argument")
	}
	// A sender must not emit a frame a conforming receiver has to reject. Size is
	// the body plus the tag, and padding rounds the body up, so the bound is on
	// the largest body this payload can produce.
	maxBody := len(payload)
	if pad && !compress {
		maxBody = padClassTo(len(payload), ceiling)
	}
	if maxBody+chacha20poly1305.Overhead > ceiling {
		return nil, ErrPayloadTooLarge
	}
	if len(key) == 0 { // wiped by teardown, or never derived
		return nil, ErrNotEstablished
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if num == 0 { // §6.2: 0 is reserved, and reaching it means the space wrapped
		return nil, errors.New("shieldnet: MessageNum space exhausted")
	}
	origSize := uint32(len(payload))
	body := payload
	compressed := false
	if compress {
		if z := compressBlock(payload); z != nil {
			body = z
			msgType |= FlagCompressed
			compressed = true
		}
	}
	if pad && !compressed {
		if cls := padClassTo(len(payload), ceiling); cls > len(payload) {
			padded := make([]byte, cls)
			copy(padded, payload)
			body = padded
		}
	}
	hdr := appHeader(uint32(len(body))+uint32(aead.Overhead()), origSize, msgType, num)
	return append(hdr, aead.Seal(nil, appNonce(num), body, hdr)...), nil
}

// MaxOriginalSize is the protocol's ceiling on OriginalSize, 64 MiB (message
// layer 7.1).
const MaxOriginalSize = 64 << 20

// recvAppWith reads one framed message from r and opens it under key, returning
// the message type, its MessageNum and the plaintext. The number is returned
// because a device must echo it as ACK's orig_message_num — the sled layer
// correlates a response to its command by that field and never by message order
// (shieldnet-protocol/spec/application.md 3.3), so a responder that cannot see
// it cannot answer conformantly. rxNum is
// the caller's receive high-water mark; it is advanced ONLY once the frame has
// authenticated and satisfied §7, so a rejected frame cannot wedge the session
// (§1.2).
//
// budget is the mid-frame budget (<= 0 means MidFrameBudgetMSDefault): once
// that long has passed since the frame's first octet arrived, the frame is
// message layer 8's "partial message" and the call returns ErrDesync. It is
// checked at entry, at each timeout that leaves the frame staged, and — for a
// reader that is an io.Closer — by a watchdog that closes r (see watchedRead).
//
// maxOriginal bounds the decompressed size of a compressed message: the
// receiver's own memory bound, which message layer 7 leaves to it and which is
// distinct from the bound on Size (ceiling). An uncompressed body is bounded by
// its own length. OriginalSize above MaxOriginalSize is rejected whatever
// maxOriginal says (message layer 7.1).
func recvAppWith(r io.Reader, key []byte, rxNum *uint64, stage *rxStage, ceiling int, budget time.Duration, maxOriginal int) (uint32, uint64, []byte, error) {
	if budget <= 0 {
		budget = msDur(MidFrameBudgetMSDefault)
	}
	expired := func() bool { return !stage.start.IsZero() && time.Since(stage.start) >= budget }
	// Time spent outside this call counts: the frame has stayed partly read.
	if expired() {
		stage.reset()
		return 0, 0, nil, joinErr(ErrDesync, errPartialTooLong)
	}
	// Resume, or start, the header. See rxStage: a partial header is only §1.2's
	// third row when the bytes are LOST, and staging them is what stops a
	// caller's read deadline from manufacturing a desynchronisation. Read rather
	// than io.ReadFull, so the first octet's arrival is seen when it happens.
	for stage.hdrN < appHeaderSize {
		n, fired, err := watchedRead(r, stage, budget, func() (int, error) { return r.Read(stage.hdr[stage.hdrN:]) })
		if fired {
			stage.reset()
			return 0, 0, nil, joinErr(ErrDesync, errPartialTooLong)
		}
		if n > 0 && stage.start.IsZero() {
			stage.start = time.Now() // the first octet only: the bound runs from here
		}
		stage.hdrN += n
		if stage.hdrN == appHeaderSize {
			break // as io.ReadFull, an error arriving with the last octet is dropped
		}
		if err != nil {
			if stage.hdrN == 0 {
				return 0, 0, nil, err // §1.2 first row: no progress, session survives
			}
			if isTimeoutErr(err) {
				if expired() {
					stage.reset()
					return 0, 0, nil, joinErr(ErrDesync, errPartialTooLong)
				}
				// Part of the header is held; the next call continues it. Report the
				// bare timeout, which §1.2 and §9.5 both treat as "idle".
				return 0, 0, nil, err
			}
			// A real short read: the rest of the frame is on the wire and the
			// staged bytes can never be completed. KCP is a stream, so a 20-octet
			// header can span two segments legitimately; before this was
			// distinguished, losing one and timing out returned the bare timeout,
			// callers classified it as idle, and the next read parsed the header's
			// tail as a fresh header — permanent desync, no diagnosis.
			stage.reset()
			return 0, 0, nil, joinErr(ErrDesync, err)
		}
	}
	hdr := stage.hdr
	size := binary.BigEndian.Uint32(hdr[0:])
	msgType := binary.BigEndian.Uint32(hdr[8:])
	num := binary.BigEndian.Uint64(hdr[12:])
	// Both pre-read bounds first. These are the ONLY checks allowed to run before
	// the body is consumed, and both correctly report ErrDesync: the header is
	// gone and the body is still on the wire, so the stream is misaligned (§7.1).
	// §7.1: a receiver bounds what it will allocate on the strength of a 20-byte
	// header. That bound is the CONFIGURED ceiling, not the package maximum —
	// a device with MaxMsgPayload = 2 KiB must not be made to allocate 1 MiB.
	if ceiling <= 0 || ceiling > MaxAppPayload {
		ceiling = MaxAppPayload
	}
	if size > uint32(ceiling) { // bound before allocating on a desynced size
		stage.reset()
		return 0, 0, nil, ErrDesync
	}
	if size < chacha20poly1305.Overhead { // §7: the minimum is the tag alone
		stage.reset()
		return 0, 0, nil, ErrDesync
	}
	if stage.body == nil {
		stage.body = make([]byte, size)
		stage.bodyN = 0
	}
	for stage.bodyN < len(stage.body) {
		n, fired, err := watchedRead(r, stage, budget, func() (int, error) { return io.ReadFull(r, stage.body[stage.bodyN:]) })
		if fired {
			stage.reset()
			return 0, 0, nil, joinErr(ErrDesync, errPartialTooLong)
		}
		stage.bodyN += n
		if err != nil {
			if isTimeoutErr(err) {
				if expired() {
					stage.reset()
					return 0, 0, nil, joinErr(ErrDesync, errPartialTooLong)
				}
				return 0, 0, nil, err // staged; the next call continues this frame
			}
			stage.reset()
			return 0, 0, nil, joinErr(ErrDesync, err)
		}
	}
	enc := stage.body
	// The frame is consumed WHOLE from here on, so the stream is frame-aligned
	// again whatever verdict follows. Release the staging before those verdicts,
	// not after: ErrReplay and ErrRejected are both "keep reading", and leaving a
	// completed frame staged would make the next call re-read this one.
	stage.reset()

	// The frame is now consumed WHOLE, so everything below leaves the stream
	// frame-aligned and is survivable (§1.2's middle row). The replay check has
	// to be here and not above the body read: ErrReplay is documented as "ignore
	// it and continue", so rejecting before the body was consumed would leave
	// Size bytes on the wire and silently desynchronise the very caller that
	// followed the documentation.
	if num == 0 || num <= *rxNum { // §6.2: >= 1 and strictly increasing
		return 0, 0, nil, ErrReplay
	}
	if len(key) == 0 {
		return 0, 0, nil, ErrNotEstablished
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, 0, nil, err
	}
	pt, err := aead.Open(nil, appNonce(num), enc, hdr[:]) // AAD = the header
	if err != nil {
		// §1.2: the frame was consumed whole, so the stream is still aligned and
		// the session MUST survive. The high-water mark is NOT advanced.
		return 0, 0, nil, ErrRejected
	}

	origSize := binary.BigEndian.Uint32(hdr[4:])
	if origSize > MaxOriginalSize {
		return 0, 0, nil, ErrRejected
	}
	var out []byte
	if msgType&FlagCompressed != 0 {
		if origSize == 0 { // §7: compressed with OriginalSize 0 is invalid
			return 0, 0, nil, ErrRejected
		}
		if int64(origSize) > int64(maxOriginal) { // this receiver's memory bound, not the Size bound
			return 0, 0, nil, ErrRejected
		}
		buf, derr := lz4DecodeBlock(pt, int(origSize))
		if derr != nil {
			return 0, 0, nil, ErrRejected
		}
		out = buf
		msgType &^= FlagCompressed
	} else {
		if !isValidPaddedLen(len(pt), int(origSize)) {
			return 0, 0, nil, ErrRejected
		}
		out = pt[:origSize]
	}
	*rxNum = num
	return msgType, num, out, nil
}
