// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// This file is the §7 client — the controller. It runs exactly one admission
// attempt per TakeControl invocation (no backoff, no automatic retry — §7.2), and
// on success holds one kcp-go session over a per-session shim (c2s seal). §7.5
// requires socket input, timers and app requests be serialised: the handshake
// runs synchronously in the caller's goroutine (nothing else reads the socket
// then), and after commit a single readLoop goroutine owns the socket while the
// state byte is guarded by mu.

var errAttemptFailed = errors.New("shieldnet: admission attempt failed")

// closing reports whether Close has run. §7.2's phase timers are wall-clock, so
// an attempt that keeps looping after Close shut the socket makes no progress
// and cannot stop: Read returns net.ErrClosed instantly, which is not a timeout,
// so the "ignore ICMP" continue below spins on the CPU until the deadline.
func (c *Client) closing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// One drain (drainQueued) is bounded by both, so a socket fed faster than it
// is drained — a chatty device, or a sender spoofing its address — cannot keep
// an admission phase past its deadline; what is left is read by the phase's
// ordinary blocking read. phaseDrainMS is the drain the client had before it
// read without blocking. maxDrainDatagrams covers every legitimate reply with
// a wide margin: a phase draws at most one RETRY or ADMIT per INIT or FINISH
// it has sent (three INITs; FINISH every 500 ms within a phase below
// COOKIE_EPOCH_MS, so at most eight), and it is the floor of the session
// shim's inbound buffer.
const (
	phaseDrainMS      = 2
	maxDrainDatagrams = 64
)

// testHookPhaseExpired, when set by a test, runs when an admission timer
// expires, just before the drain and the resend/fail decision: phase is
// "retry" (AWAIT_RETRY) or "admit" (AWAIT_ADMIT), and final is true at the
// phase's end.
var testHookPhaseExpired func(phase string, final bool)

func phaseExpired(phase string, final bool) {
	if testHookPhaseExpired != nil {
		testHookPhaseExpired(phase, final)
	}
}

// jitter applies §2's "retry jitter: ±20 %, uniform" to a retransmission
// interval, so that two controllers told to take control at the same moment do
// not retransmit in lockstep and present the device with a synthetic flood. The
// FINISH phase cap is a hard clamp jitter MUST NOT exceed (§7.4); the caller
// applies it, since only the caller knows the phase budget.
func jitter(d time.Duration) time.Duration {
	var b [8]byte
	rand.Read(b[:])
	pct := 80 + binary.BigEndian.Uint64(b[:])%41 // uniform over 80..120
	return d * time.Duration(pct) / 100
}

type clientState int

const (
	stIdle clientState = iota
	stAwaitRetry
	stAwaitAdmit
	stAwaitPushAck
	stEstablished
)

// connectedConn adapts a connected *net.UDPConn to net.PacketConn so the shim can
// drive it: WriteTo ignores the address (the socket is connected) and uses Write.
type connectedConn struct{ c *net.UDPConn }

func (cc connectedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := cc.c.Read(p)
	return n, cc.c.RemoteAddr(), err
}
func (cc connectedConn) WriteTo(p []byte, _ net.Addr) (int, error) { return cc.c.Write(p) }
func (cc connectedConn) Close() error                              { return cc.c.Close() }
func (cc connectedConn) LocalAddr() net.Addr                       { return cc.c.LocalAddr() }
func (cc connectedConn) SetDeadline(t time.Time) error             { return cc.c.SetDeadline(t) }
func (cc connectedConn) SetReadDeadline(t time.Time) error         { return cc.c.SetReadDeadline(t) }
func (cc connectedConn) SetWriteDeadline(t time.Time) error        { return cc.c.SetWriteDeadline(t) }

// Client is a controller for one device.
type Client struct {
	conn       *net.UDPConn // connected to the device (§7.2: connect for getsockname + ICMP)
	deviceAddr net.Addr
	deviceID   []byte
	local      []netip.Prefix
	ownCS      []byte // the client's own canonical_source (§7.3 step 2)
	kDev       []byte
	kReq       []byte
	kResp      []byte

	mu           sync.Mutex
	state        clientState
	kcp          *kcp.UDPSession
	shim         *sessionConn
	convID       uint32
	firstAck     chan struct{}
	done         chan struct{}
	rlStop       chan struct{} // closed to stop this attempt's readLoop
	rlDone       chan struct{} // closed by readLoop on exit
	rlLive       atomic.Int32  // readLoops currently running; must be 0 once idle
	rlStuck      atomic.Bool   // readLoop missed its stop deadline (should never happen)
	Tuning       KCPTuning
	skipSrcCheck bool // test-only: bypass §4.3 on loopback
	kC2S, kS2C   []byte
	txNum        atomic.Uint64
	closeOnce    sync.Once // Close is idempotent (M5)
	// attempts counts TakeControl calls in flight. Their handshake reads the
	// static keys without mu, so Close waits for them before wiping. Add runs
	// under mu after the closing() check, and Close closes done under mu, so
	// every attempt that got past the check is counted before Close's Wait.
	attempts sync.WaitGroup
	tdMu     sync.Mutex // serialises teardown; see teardown
	// §9.5/§13 send-path bounds. Zero means the default. SendQueueMax caps what
	// this session may commit against a peer that has stopped acknowledging;
	// MaxMsgPayload bounds the §13 pad-class ladder and MUST NOT exceed it.
	SendQueueMax  int
	MaxMsgPayload int
	// FinishPhaseMS is FINISH_PHASE_MS (transport 4.2, 4.3), the deployment's
	// cap on the FINISH phase of an admission. Zero means the package constant
	// FinishPhaseMS (1 500). It must exceed the round-trip time plus the
	// device's FINISH processing (transport 4.3, "The FINISH-phase budget") and
	// stay below COOKIE_EPOCH_MS (transport 4.2). A negative value or one at or
	// above CookieEpochMS is reported by TakeControl*, ahead of ErrNotIdle and
	// before anything is sent.
	FinishPhaseMS int
	// MidFrameBudgetMS bounds how long a message may stay partly read (message
	// layer 8 item 2), measured from the arrival of its first octet. Once it has
	// passed, the read returns ErrDesync ("partial message") instead of waiting
	// or reporting a timeout. Zero or negative means MidFrameBudgetMSDefault
	// (10 000). It must exceed the time to receive a MaxMsgPayload-sized message
	// on the slowest link the deployment supports. Time the caller spends not
	// reading counts against it: a frame left staged by a read deadline and
	// resumed after the budget has passed is ErrDesync. Like every ErrDesync
	// from RecvApp, it ends the session: the Client is IDLE afterwards and
	// TakeControl* admits again.
	MidFrameBudgetMS int

	// §7.2 liveness (SESSION_DEAD_MS; §9.3 is the device's silence rule). lastRx is the arrival of the most recent ACCEPTED s2c
	// envelope (an envelope that failed to open proves nothing about the peer);
	// deadFlag records that SESSION_DEAD_MS elapsed without one, so a caller
	// learns WHY the session went away rather than only that it is gone.
	lastRx atomic.Int64
	base   time.Time // monotonic origin for lastRx/outstandingSince; see monoMS
	// outstanding is §7.2's "unacknowledged data outstanding" gate: set when the
	// application writes and whenever a KCP PUSH goes out, cleared when an
	// accepted s2c envelope carries a una past every PUSH sent (see
	// inboundAccepted). A millisecond-timestamp comparison was tried first and is
	// wrong: a write landing in the same millisecond as the last inbound leaves
	// lastTx == lastRx and the gate never opens.
	outstanding atomic.Bool
	// outstandingSince is when outstanding last went false→true (monoMS).
	// §7.2's clock starts there, not at lastRx: after an idle spell lastRx is
	// already older than SESSION_DEAD_MS, and measuring from it declared a
	// healthy session dead on the first tick after its first write.
	outstandingSince atomic.Int64
	// dying is set by markDead, before the watcher's teardown runs: sends in
	// that window fail with ErrSessionDead instead of writing into the dead
	// session. deadFlag (SessionDead) is set only once teardown has returned
	// the client to IDLE, so a caller that sees it can TakeControl at once.
	dying        atomic.Bool
	deadFlag     atomic.Bool
	closedByUser atomic.Bool   // Close() was called; outranks deadFlag in reporting
	deadCh       chan struct{} // per-session; guarded by mu, nil once closed
	sessGone     chan struct{} // closed by teardown; reaps the liveness watcher
	txMu         sync.Mutex    // serialises app writes and their write deadline
	rxMu         sync.Mutex    // guards rxNum and rxStage (M10)
	rxNum        uint64
	rxStage      rxStage
	// peerBound is the peer's receive bound on Size (message layer 7.3), set by
	// SetPeerReceiveBound for one session; 0 means unknown.
	peerBound    atomic.Int64
	appMode      bool
	appFirstType uint32
	appFirstPad  bool
}

// NewClient dials (connects) the device and derives the client's static keys.
// local is the interface prefix set for §4.3 (only used to validate the client's
// own source is well-formed); psk and deviceID are the shared inputs.
func NewClient(deviceAddr string, psk, deviceID []byte, local []netip.Prefix) (*Client, error) {
	// A nil or short PSK would derive k_req/k_resp anyone can compute; a short
	// device_id would panic later inside EncodeINIT. Fail closed up front.
	if err := checkLen("psk", psk, 32); err != nil {
		return nil, err
	}
	if allZero(psk) {
		return nil, fmt.Errorf("%w: psk is all zero", ErrBadKeyMaterial)
	}
	if err := checkLen("device_id", deviceID, 8); err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", deviceAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	la := conn.LocalAddr().(*net.UDPAddr)
	a, _ := netip.AddrFromSlice(la.IP)
	ownCS := Canonicalize(a.Unmap(), uint16(la.Port))
	setPMTUProbe(conn)
	kDev := DeriveKDev(psk, deviceID)
	static := DeriveStatic(kDev)
	return &Client{
		conn:       conn,
		deviceAddr: raddr,
		deviceID:   append([]byte(nil), deviceID...),
		local:      local,
		ownCS:      ownCS,
		kDev:       kDev,
		kReq:       static.KReq,
		kResp:      static.KResp,
		base:       time.Now(),
		done:       make(chan struct{}),
		Tuning:     DefaultKCPTuning,
	}, nil
}

func randConv() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// monoMS is milliseconds since c.base on the monotonic clock, plus one so a
// stamp is never the zero that means "unset". A wall-clock stamp
// (Unix milliseconds) carries no monotonic reading, so a clock step —
// NTP's first sync, a long device-side pause — moved the §7.2 timer with it.
func (c *Client) monoMS() int64 { return time.Since(c.base).Milliseconds() + 1 }

// afterRead maps a read or write error on a session that was torn down while the read
// was blocked to the sentinel for why it ended (§7.2 / README "Errors"), not to
// the stream classification recvAppWith gives a byte stream that ended. The
// server does the same with ErrSessionClosed (server.go RecvAppNumGen).
func (c *Client) afterRead(sess *kcp.UDPSession, err error) error {
	if err == nil || errors.Is(err, ErrRejected) || errors.Is(err, ErrReplay) || isTimeoutErr(err) {
		return err
	}
	c.mu.Lock()
	gone := c.kcp != sess
	c.mu.Unlock()
	if gone {
		return c.notEstablishedErr()
	}
	return err
}

func msDur(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

// TakeControl runs one admission attempt (§7.2). On success the client is
// ESTABLISHED and firstMsg has been sent as the promoting first PUSH; use Recv and
// Send. A failed admission attempt returns to IDLE, wiping every derived value,
// and returns errAttemptFailed; a first message that cannot be sent is refused
// with its own error (for example ErrPayloadTooLarge). A call while not IDLE
// changes nothing and returns ErrNotIdle. One attempt per call: it never retries.
// TakeControl admits with a RAW first payload. It clears app mode, so a Client
// that previously used TakeControlApp does not silently frame this payload as an
// application message of the earlier call's type. An empty firstMsg is refused
// with ErrEmptyFirstMessage before anything is sent.
//
// Deprecated: a first message is a sealed message of the message layer
// (transport 10.2, 12.2), and a raw one is not; use TakeControlApp or
// TakeControlAppPadded.
func (c *Client) TakeControl(firstMsg []byte) error {
	return c.takeControl(firstMsg, false, 0, false)
}

// takeControl publishes the app mode UNDER THE SAME LOCK that passes the IDLE
// guard. Setting it in the exported wrappers instead let a call that is about to
// be rejected as not-IDLE still mutate a concurrent attempt's mode: a
// TakeControlApp already past admission would then read appMode == false, skip
// framing, and send its raw payload as the promoting PUSH, which the peer parses
// as a 20-octet header — ErrDesync on a session that otherwise came up fine.
func (c *Client) takeControl(firstMsg []byte, appMode bool, appFirstType uint32, appFirstPad bool) error {
	finishPhase, err := c.finishPhaseMS()
	if err != nil {
		return err
	}
	if !appMode && len(firstMsg) == 0 {
		return ErrEmptyFirstMessage // transport 10.2: there is no empty first message
	}
	c.mu.Lock()
	if c.state != stIdle {
		c.mu.Unlock()
		return ErrNotIdle
	}
	// teardown returns the client to IDLE, so the guard above no longer excludes
	// an attempt started after Close: it would run both phases against a closed
	// socket before failing.
	if c.closing() {
		c.mu.Unlock()
		return errAttemptFailed
	}
	c.attempts.Add(1)
	defer c.attempts.Done()
	c.state = stAwaitRetry
	c.appMode = appMode
	c.appFirstType = appFirstType
	c.appFirstPad = appFirstPad
	c.mu.Unlock()

	// fresh per-attempt client_nonce and X25519 keypair (§7.2)
	nonce := make([]byte, 24)
	rand.Read(nonce)
	ecPriv := make([]byte, 32)
	rand.Read(ecPriv)
	ecPub, err := curve25519.X25519(ecPriv, curve25519.Basepoint)
	if err != nil {
		zero(ecPriv)
		c.toIdle()
		return errAttemptFailed
	}

	buf := make([]byte, 2048)

	// ── AWAIT_RETRY: send INIT, up to 3 transmissions at INIT_RETRY_MS ──
	initMsg := EncodeINIT(nonce, c.deviceID, InitMAC(c.kReq, nonce, c.deviceID))
	var rf RETRYFields
	gotRetry := false
	// handleRetry is the drain's handler; it also ends the drain after Close.
	handleRetry := func(b []byte) bool {
		if c.closing() {
			return true
		}
		if f, ok := c.checkRETRY(b, nonce); ok {
			rf, gotRetry = f, true
			return true
		}
		return false
	}
	for i := 0; i < InitTransmissions && !gotRetry && !c.closing(); i++ {
		if i > 0 {
			// transport 10.3 rule 4: the retransmit timer expired. A RETRY
			// already queued is read before the retransmission goes out.
			phaseExpired("retry", false)
			if drainQueued(c.conn, handleRetry) {
				break
			}
		}
		c.conn.Write(initMsg) // resend the SAME INIT
		deadline := time.Now().Add(jitter(msDur(InitRetryMS)))
		for time.Now().Before(deadline) && !gotRetry && !c.closing() {
			c.conn.SetReadDeadline(deadline)
			n, rerr := c.conn.Read(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					break // resend
				}
				continue // ignore ICMP etc. (§7.6)
			}
			if f, ok := c.checkRETRY(buf[:n], nonce); ok {
				rf = f
				gotRetry = true
			}
		}
	}
	if !gotRetry && !c.closing() {
		// transport 10.3 rule 4: at the phase's end, a RETRY already queued
		// still counts; one that arrives after it does not.
		phaseExpired("retry", true)
		drainQueued(c.conn, handleRetry)
	}
	if !gotRetry {
		zero(ecPriv)
		c.toIdle()
		return errAttemptFailed
	}

	// Retain the (epoch_tag, cookie, admission_epoch) set (§7.2) by COPYING it out
	// of the read buffer — DecodeRETRY returns slices into buf, which the FINISH
	// read loop below overwrites.
	epochTag := append([]byte(nil), rf.EpochTag...)
	cookie := append([]byte(nil), rf.Cookie...)
	admissionEpoch := append([]byte(nil), rf.AdmissionEpoch...)

	// ── AWAIT_ADMIT: send FINISH, resend at FINISH_RETRY_MS across ≤1500ms ──
	context := Context(nonce, epochTag, cookie, admissionEpoch, c.deviceID)
	finMsg := EncodeFINISH(nonce, epochTag, cookie, admissionEpoch, ecPub,
		ClientTag(c.kReq, context, ecPub))
	c.mu.Lock()
	c.state = stAwaitAdmit
	c.mu.Unlock()

	dhCache := map[string][]byte{}
	var keys SessionKeys
	admitted := false
	handleAdmit := func(b []byte) bool {
		if c.closing() {
			return true
		}
		if k, ok := c.checkADMIT(b, context, ecPriv, ecPub, admissionEpoch, dhCache); ok {
			keys, admitted = k, true
			return true
		}
		return false
	}
	phaseDeadline := time.Now().Add(msDur(finishPhase))
	for first := true; time.Now().Before(phaseDeadline) && !admitted && !c.closing(); first = false {
		if !first {
			// transport 10.3 rule 4: an ADMIT already queued when the
			// retransmit timer expires is read before FINISH goes out again.
			phaseExpired("admit", false)
			if drainQueued(c.conn, handleAdmit) {
				break
			}
		}
		c.conn.Write(finMsg) // byte-identical resend (§7.4)
		rd := time.Now().Add(jitter(msDur(FinishRetryMS)))
		if rd.After(phaseDeadline) {
			rd = phaseDeadline
		}
		for time.Now().Before(rd) && !admitted && !c.closing() {
			c.conn.SetReadDeadline(rd)
			n, rerr := c.conn.Read(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					break
				}
				continue // ignore ICMP (§7.6)
			}
			if k, ok := c.checkADMIT(buf[:n], context, ecPriv, ecPub, admissionEpoch, dhCache); ok {
				keys = k
				admitted = true
			}
		}
	}
	if !admitted && !c.closing() {
		phaseExpired("admit", true) // as for RETRY above
		drainQueued(c.conn, handleAdmit)
	}
	// leaving AWAIT_ADMIT: wipe the ephemeral private key and the cached dh (§7.2/§7.4)
	zero(ecPriv)
	for _, v := range dhCache {
		zero(v)
	}
	if !admitted {
		c.toIdle()
		return errAttemptFailed
	}

	// ── commit (§7.4 step 5): kcp session, first PUSH, AWAIT_PUSH_ACK ──
	return c.commit(keys, firstMsg)
}

// checkRETRY runs §7.3 on a datagram; returns the fields and true if it is a valid
// RETRY for this attempt.
func (c *Client) classify(datagram []byte) Class {
	if c.skipSrcCheck {
		return classifyDatagram(RoleClient, datagram)
	}
	return Classify(RoleClient, addrOf(c.deviceAddr), c.local, datagram)
}

func (c *Client) checkRETRY(datagram, nonce []byte) (RETRYFields, bool) {
	if c.classify(datagram) != ClassRETRY {
		return RETRYFields{}, false
	}
	f, err := DecodeRETRY(datagram) // step 1: length before field access
	if err != nil {
		return RETRYFields{}, false
	}
	if !hmac.Equal(f.ObservedSource, c.ownCS) { // step 2: our socket address
		return RETRYFields{}, false
	}
	want := RetryMAC(c.kResp, nonce, f.EpochTag, f.Cookie, f.AdmissionEpoch, c.deviceID, f.ObservedSource)
	if !hmac.Equal(want, f.RetryMAC) { // step 3
		return RETRYFields{}, false
	}
	if !hmac.Equal(f.DeviceID, c.deviceID) { // step 4: device we addressed
		return RETRYFields{}, false
	}
	return f, true // step 5: caller retains the (epoch_tag, cookie, admission_epoch) set
}

// checkADMIT runs §7.4 steps 1–4 on a datagram; returns the session keys and true
// on a valid ADMIT. dhCache is per-e_s (§7.4 step 4, required not optional).
func (c *Client) checkADMIT(datagram, context, ecPriv, ecPub, admissionEpoch []byte, dhCache map[string][]byte) (SessionKeys, bool) {
	if c.classify(datagram) != ClassADMIT {
		return SessionKeys{}, false
	}
	af, err := DecodeADMIT(datagram) // step 1: length, no timer touched
	if err != nil {
		return SessionKeys{}, false
	}
	if !hmac.Equal(af.AdmissionEpoch, admissionEpoch) { // step 2
		return SessionKeys{}, false
	}
	context2 := Context2(context, ecPub, af.ES)
	if !hmac.Equal(AdmitPre(c.kResp, context2), af.AdmitPre) { // step 3: before X25519
		return SessionKeys{}, false
	}
	// step 4: dh (cache per e_s), derive, verify admit_tag. dh is computed at
	// most once per distinct e_s: an all-zero result is cached too, as nil, so
	// a repeated ADMIT with that e_s is discarded with no second X25519.
	esKey := string(af.ES)
	dh, seen := dhCache[esKey]
	if !seen {
		d, derr := DH(ecPriv, af.ES)
		if derr != nil {
			d = nil
		}
		dh = d
		dhCache[esKey] = d
	}
	if dh == nil { // all-zero X25519 → discard
		return SessionKeys{}, false
	}
	master := Master(context2, c.kDev, dh)
	if !hmac.Equal(AdmitTag(master), af.AdmitTag) {
		zero(master) // fail after derivation: wipe (§6.2 step 7 mirror)
		return SessionKeys{}, false
	}
	keys := DeriveSession(master)
	zero(master)
	return keys, true
}

func (c *Client) commit(keys SessionKeys, firstMsg []byte) error {
	// H5: MessageNum is per-session. TakeControl is retryable, so a second
	// attempt derives fresh directional keys and MUST restart both counters —
	// otherwise the peer's message 1 is rejected against a stale high-water mark
	// and the session is unusable for its whole life.
	c.txNum.Store(0)
	c.rxMu.Lock()
	c.rxNum = 0
	c.rxStage.reset() // a new session starts on a frame boundary
	c.rxMu.Unlock()
	c.peerBound.Store(0) // a bound belongs to one session's peer

	// §7.2: arm the liveness timer for this session. lastRx starts at admission
	// rather than zero, so a device that promotes and then goes silent is
	// detected; deadFlag/deadCh are per-session, so a retry starts clean.
	c.lastRx.Store(c.monoMS())
	c.outstanding.Store(false)
	c.dying.Store(false)
	c.deadFlag.Store(false)
	c.mu.Lock()
	c.deadCh = make(chan struct{})
	dead := c.deadCh
	// gone is closed by teardown, so a session that ends any other way — the
	// PUSH_ACK timeout, commit's identity bail-out, an abandoned attempt — reaps
	// its watcher too. Without it one goroutine leaked per failed TakeControl.
	gone := make(chan struct{})
	c.sessGone = gone
	c.mu.Unlock()
	// watched is the session this watcher belongs to, stored before its
	// readLoop starts (markDead runs only from that readLoop). Tearing down
	// only that session keeps a late watcher from marking a session that was
	// ended on purpose dead, or from setting IDLE under a new attempt.
	var watched atomic.Pointer[kcp.UDPSession]
	go func() {
		select {
		case <-dead:
			c.teardownIf(watched.Load(), true) // safe: the readLoop has already returned
		case <-gone:
		case <-c.done:
		}
	}()

	// C1: frame the promoting message BEFORE any session state is built, so a
	// framing failure costs nothing and can never fall through to sending the
	// raw payload unsealed.
	c.mu.Lock()
	appMode, appFirstType, appFirstPad := c.appMode, c.appFirstType, c.appFirstPad
	c.mu.Unlock()

	first := firstMsg
	if appMode {
		// A COPY, not keys.KC2S itself: mu is released for the whole of frameApp,
		// and a teardown landing in that window runs zero(c.kC2S). Publishing the
		// caller's slice by reference would zero keys.KC2S too, and the copy taken
		// below would install an all-zero application key on a live session.
		c.mu.Lock()
		c.kC2S = append([]byte(nil), keys.KC2S...)
		c.mu.Unlock()
		// §13: never compressed — the promoting message is control or configuration
		// in every use this API has — and padded only when the caller says its kind
		// is one §13 pads. TakeControlApp cannot infer the category itself: the
		// message layer does not name messages, so the layer above assigns it.
		f, err := c.frameApp(appFirstType, firstMsg, false, appFirstPad)
		if err != nil {
			keys.wipe()
			c.toIdle()
			return err
		}
		first = f
	} else if len(first) > c.maxMsgPayload() {
		// §9.5: the raw first message is bounded like every other write.
		// kcp-go would otherwise queue all of it against SEND_QUEUE_MAX.
		keys.wipe()
		c.toIdle()
		return ErrPayloadTooLarge
	}

	c.mu.Lock()
	// Close may have run while this attempt was in admission. Installing a kcp
	// session now would leave c.kcp non-nil after Close returned — so Send/Recv
	// stop reporting ErrNotEstablished and write onto a closed socket — and would
	// leak the session's goroutines until PushAckTimeoutMS expired. The M7 guard
	// further down only protects the promotion to ESTABLISHED, not the install.
	select {
	case <-c.done:
		c.mu.Unlock()
		keys.wipe()
		c.toIdle()
		return errAttemptFailed
	default:
	}
	c.state = stAwaitPushAck
	c.convID = randConv()
	c.firstAck = make(chan struct{})
	c.shim = newSessionConn(connectedConn{c.conn}, c.deviceAddr, keys.KKcpC2S, true, c.Tuning.RcvWnd)
	c.shim.onPush = c.markOutstanding
	sess, err := kcp.NewConn3(c.convID, c.deviceAddr, nil, 0, 0, c.shim)
	if err != nil {
		// The shim was installed above and now belongs to no session. Left in
		// place it hands the next attempt this attempt's deliver channel and a
		// firstAck nobody will ever close.
		orphan := c.shim
		c.shim, c.firstAck, c.convID = nil, nil, 0
		c.mu.Unlock()
		orphan.Close()
		keys.wipe()
		c.toIdle()
		return errAttemptFailed
	}
	// §9.5: the send window is the byte cap. Clamp SndWnd so snd_queue+snd_buf
	// cannot exceed SEND_QUEUE_MAX, which is how the bound is enforced in Go.
	tuning := c.Tuning
	if w := c.sendWindowSegments(); tuning.SndWnd > w {
		tuning.SndWnd = w
	}
	applyTuning(sess, tuning)
	c.kcp = sess
	watched.Store(sess)
	zero(c.kC2S) // app mode installed a copy before framing; wipe it, don't drop it
	c.kC2S = append([]byte(nil), keys.KC2S...)
	c.kS2C = append([]byte(nil), keys.KS2C...)
	kc2sS2C := append([]byte(nil), keys.KKcpS2C...)
	// §4.6: the three keys copied above are wiped here rather than abandoned to
	// the GC. KKcpC2S is deliberately NOT wiped: newSessionConn holds it BY
	// REFERENCE for the life of the session, so zeroing it here seals every
	// envelope under an all-zero key and admission fails outright.
	zero(keys.KC2S)
	zero(keys.KS2C)
	zero(keys.KKcpS2C)
	shim := c.shim
	ack := c.firstAck
	rlStop := make(chan struct{})
	rlDone := make(chan struct{})
	c.rlStop, c.rlDone = rlStop, rlDone
	c.mu.Unlock()

	go c.readLoop(shim, kc2sS2C, rlStop, rlDone)

	// send the first PUSH (sn=0) — kcp-go emits it via the shim. In app mode the
	// first PUSH IS the first app message (§8.5(c)), framed above under k_c2s.
	// Senders cannot overtake this PUSH: sendSess refuses until ESTABLISHED.
	if testHookBeforeFirstWrite != nil {
		testHookBeforeFirstWrite()
	}
	c.markOutstanding()
	sess.SetWriteDeadline(time.Now().Add(msDur(PushAckTimeoutMS)))
	if _, err := sess.Write(first); err != nil {
		// The promoting message was never queued, so no ACK can promote this
		// session; failing now beats waiting out PUSH_ACK_TIMEOUT. Only this
		// attempt's session: one admitted after it must survive.
		c.teardownIf(sess, false)
		return errAttemptFailed
	}

	// AWAIT_PUSH_ACK: the first valid s2c envelope proves the device promoted
	select {
	case <-ack:
		// Clear the deadline set for the promoting PUSH above. It is an absolute
		// time, so leaving it in place makes every later Write fail with a
		// timeout once it passes -- about PushAckTimeoutMS after admission --
		// for any application that does not set its own deadline per write.
		sess.SetWriteDeadline(time.Time{})
		c.mu.Lock()
		// M7: a concurrent Close may already have torn this attempt down and
		// returned the client to IDLE. Promoting to ESTABLISHED on top of that
		// leaves the state byte saying ESTABLISHED with c.kcp nil — every Send
		// and Recv then fails "not established" forever, and TakeControl is
		// refused by its own IDLE guard, so the client is wedged with no way
		// back. Only this attempt's own session may declare itself established.
		if c.state != stAwaitPushAck || c.kcp != sess {
			c.mu.Unlock()
			return errAttemptFailed
		}
		c.state = stEstablished
		c.mu.Unlock()
		return nil
	case <-c.done:
		// Close joins the readLoop, so ack can never fire now; without this the
		// attempt sits here for the whole PUSH_ACK_TIMEOUT. Close runs teardown
		// itself after closing done, so this path must not run a second one.
		return errAttemptFailed
	case <-time.After(msDur(PushAckTimeoutMS)):
		// §7.2: "A timer that fires in the same tick as a message arrives loses."
		// Go's select chooses at random when both are ready, so re-poll before
		// declaring a timeout: discarding an ACK for a PUSH the device HAS
		// promoted leaves it holding a primary it may not reclaim for inactivity
		// (§9.5), and costs the controller a whole re-admission.
		select {
		case <-ack:
			sess.SetWriteDeadline(time.Time{})
			c.mu.Lock()
			if c.state != stAwaitPushAck || c.kcp != sess {
				c.mu.Unlock()
				return errAttemptFailed
			}
			c.state = stEstablished
			c.mu.Unlock()
			return nil
		default:
		}
		c.teardownIf(sess, false)
		return errAttemptFailed
	}
}

// readLoop owns the socket from commit onward: it opens s2c envelopes, feeds them
// to the shim (kcp-go), and drops anything else (a late ADMIT in AWAIT_PUSH_ACK /
// ESTABLISHED is dropped per §7.1). ks2c is k_kcp_s2c.
func (c *Client) readLoop(shim *sessionConn, ks2c []byte, stop, done chan struct{}) {
	defer close(done)
	// ks2c is this goroutine's own copy and nothing reads it once we return, so
	// unlike the shim's k_kcp_c2s it can be wiped (§4.6). teardown waits on done,
	// so the wipe has happened by the time it returns.
	defer zero(ks2c)
	c.rlLive.Add(1)
	defer c.rlLive.Add(-1)
	var s2cWin replayWindow
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.done:
			return
		case <-stop:
			return
		default:
		}
		// §9.3: the client distinguishes failure modes by its OWN timers, because
		// the device is silent by rule. Checked every iteration, so the 500ms read
		// deadline below doubles as the liveness tick and no extra goroutine is
		// needed. Deliberately NOT followed by re-admission: §7.2 removed retry
		// and its damping together, the damping having been the cheapest attack
		// in the protocol. Detection makes the state observable; acting on it is
		// the caller's explicit TakeControl.
		// §7.2: ESTABLISHED leaves for IDLE on "no authenticated datagram received
		// for SESSION_DEAD_MS **while the client has unacknowledged data
		// outstanding**". The outstanding-data gate is not optional: without it a
		// healthy but idle controller is torn down every SESSION_DEAD_MS, and
		// because §9.5 forbids the device reclaiming its primary for inactivity,
		// the device is left holding an orphan while the client pays a full
		// re-admission. §7.2 is explicit that a quiet controller "learns nothing
		// until it next sends".
		//
		// lastTx > lastRx is the outstanding-data test: if nothing has been
		// written since the last accepted inbound datagram, there is nothing
		// outstanding to be unacknowledged.
		// The clock runs from the later of the last accepted envelope and the
		// moment data went outstanding: §7.2 says a write after an idle spell
		// "then waits the full" SESSION_DEAD_MS.
		if c.livenessExpired() {
			c.markDead()
			return
		}
		c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, rerr := c.conn.Read(buf)
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue // ignore ICMP (§7.6)
		}
		datagram := buf[:n]
		if c.classify(datagram) != ClassEnvelope {
			continue // §7.1: RETRY/ADMIT/etc. dropped in AWAIT_PUSH_ACK/ESTABLISHED
		}
		if !envelopeLenOK(len(datagram)) {
			continue
		}
		pt, _, ok := s2cWin.open(ks2c, false, datagram) // s2c, marks after verify
		if !ok {
			continue
		}
		c.lastRx.Store(c.monoMS()) // §7.2: an ACCEPTED envelope only
		c.inboundAccepted(shim, pt)
		shim.deliver(pt)
		// first successful s2c → promotion confirmed (§7.2 AWAIT_PUSH_ACK done)
		c.mu.Lock()
		if c.state == stAwaitPushAck && c.firstAck != nil {
			close(c.firstAck)
			c.firstAck = nil
		}
		c.mu.Unlock()
	}
}

// Recv reads one application message from the established session.
//
// Deprecated: the stream carries sealed messages of the message layer
// (transport 12.2); use RecvApp or RecvAppNum.
func (c *Client) Recv(p []byte) (int, error) {
	c.mu.Lock()
	sess := c.kcp
	c.mu.Unlock()
	if sess == nil {
		return 0, c.notEstablishedErr()
	}
	n, err := sess.Read(p)
	return n, c.afterRead(sess, err)
}

// Send writes an application message on the established session.
//
// Deprecated: the stream carries sealed messages of the message layer
// (transport 12.2); use SendApp, SendAppPadded, SendAppCompressed or
// SendAppBulk.
func (c *Client) Send(p []byte) (int, error) {
	sess, err := c.sendSess()
	if err != nil {
		return 0, err
	}
	// §9.5: kcp-go accepts a whole buffer whenever its window has room, so an
	// unbounded raw write would queue far past SEND_QUEUE_MAX.
	if len(p) > c.maxMsgPayload() {
		return 0, ErrPayloadTooLarge
	}
	// Same bound and the same liveness arming as the *App path: without these,
	// a caller using the raw stream gets neither §9.5's ErrSendQueueFull nor
	// §7.2's dead-session detection, both of which README presents as properties
	// of the session rather than of the framed API.
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if testHookBeforeSendWrite != nil {
		testHookBeforeSendWrite()
	}
	c.markOutstanding()
	sess.SetWriteDeadline(time.Now().Add(msDur(SendBlockedMS)))
	n, err := sess.Write(p)
	sess.SetWriteDeadline(time.Time{})
	// kcp-go wraps its timeout in pkg/errors; see sendApp. errors.As, not a
	// type assertion, or §9.5's refusal is unreachable.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return n, ErrSendQueueFull
	}
	return n, c.afterRead(sess, err)
}

func (c *Client) toIdle() {
	c.mu.Lock()
	// An attempt that ends here rather than in teardown must still reap its
	// liveness watcher, or commit's framing-failure and NewConn3-failure paths
	// leak one goroutine per failed attempt, each holding the whole Client.
	if c.sessGone != nil {
		close(c.sessGone)
		c.sessGone = nil
	}
	// §7.2: every transition to IDLE wipes what the attempt derived. commit
	// installs c.kC2S before framing the promoting message, so the framing,
	// closed-client and NewConn3 failure paths all arrive here holding a live
	// application key that only teardown used to clear. nil, not merely zeroed:
	// appframe's len(key) == 0 guard is what makes a later send report
	// ErrNotEstablished instead of sealing under an all-zero key.
	zero(c.kC2S)
	c.kC2S = nil
	zero(c.kS2C)
	c.kS2C = nil
	c.state = stIdle
	c.mu.Unlock()
}

// readLoopStopTimeout bounds how long teardown waits for a readLoop to notice
// its stop signal. readLoop polls with a 500ms read deadline, so this is four
// times the worst expected case.
const readLoopStopTimeout = 2 * time.Second

// markDead records that §7.2's liveness timer expired. It is called FROM the
// readLoop, so it must not tear the session down itself: teardown joins the
// readLoop and would deadlock on its own caller. A watcher started in commit
// does the teardown once this goroutine has returned.
// maxMsgPayload is §13's MAX_MSG_PAYLOAD for this client, clamped to
// SEND_QUEUE_MAX because §13 forbids a message the send queue could never hold.
// finishPhaseMS resolves the FinishPhaseMS field: zero is the package default;
// a negative value or one at or above COOKIE_EPOCH_MS is a configuration error,
// not something to clamp.
func (c *Client) finishPhaseMS() (int, error) {
	ms := c.FinishPhaseMS
	if ms == 0 {
		return FinishPhaseMS, nil
	}
	if ms < 0 || ms >= CookieEpochMS {
		return 0, fmt.Errorf("shieldnet: FinishPhaseMS %d out of range: must be positive and below COOKIE_EPOCH_MS %d", ms, CookieEpochMS)
	}
	return ms, nil
}

func (c *Client) maxMsgPayload() int {
	q := c.SendQueueMax
	if q <= 0 {
		q = SendQueueMaxDefault
	}
	m := c.MaxMsgPayload
	if m <= 0 {
		m = MaxMsgPayloadDefault
	}
	if m > q {
		m = q // §13: MUST NOT exceed SEND_QUEUE_MAX
	}
	if m > MaxAppPayload {
		m = MaxAppPayload
	}
	// Floor: a ceiling below one pad class plus the tag makes EVERY send fail,
	// including the promoting app PUSH, so a misconfigured cap would brick the
	// client rather than bound it.
	if min := padFloor + chacha20poly1305.Overhead; m < min {
		m = min
	}
	return m
}

// sendWindowSegments derives kcp-go's send window from SEND_QUEUE_MAX. Go cannot
// read snd_queue+snd_buf back — kcp-go exposes WaitSnd on *KCP but not on
// UDPSession — so the byte cap is enforced by SIZING the window rather than by
// polling it: kcp-go blocks a Write once the window is full, and a write deadline
// turns that block into §9.5's required error. The C device, which owns its
// ikcp.c, checks the byte total directly and is the one §11's budget binds. See
// clampSendWindow for why the window-sizing bound is approximate by one write.
func (c *Client) sendWindowSegments() int {
	q := c.SendQueueMax
	if q <= 0 {
		q = SendQueueMaxDefault
	}
	n := q / WireMTU
	if n < 1 {
		n = 1
	}
	return n
}

// nextTx allocates the next MessageNum, or 0 once exhausted. §6.4: a sender that
// has used 2^64-1 must refuse to send AGAIN on that key, not merely refuse once —
// Add(1) would hand out 1 next, repeating the first message's nonce.
func (c *Client) nextTx() uint64 {
	for {
		cur := c.txNum.Load()
		if cur == ^uint64(0) {
			return 0
		}
		if c.txNum.CompareAndSwap(cur, cur+1) {
			return cur + 1
		}
	}
}

// markOutstanding opens §7.2's outstanding-data gate, starting its clock only
// on the false→true edge so a second write does not push the deadline out.
// The timestamp is published before the gate opens so a concurrent liveness
// check never pairs an open gate with a stale timestamp; two writers racing
// here store near-identical timestamps, which is harmless, so no CAS is needed.
func (c *Client) markOutstanding() {
	if c.outstanding.Load() {
		return
	}
	c.outstandingSince.Store(c.monoMS())
	if testHookMidMarkOutstanding != nil {
		testHookMidMarkOutstanding()
	}
	c.outstanding.Store(true)
}

// inboundAccepted is the read loop's outstanding-data rule for one accepted
// inbound KCP datagram (transport 10.3): the gate closes only once the peer's
// una has passed every PUSH sent, not on any envelope — a device that
// acknowledges part of the data and goes silent must still time out.
func (c *Client) inboundAccepted(shim *sessionConn, pt []byte) {
	shim.ackSeen(pt, func() { c.outstanding.Store(false) })
}

// livenessExpired is §7.2's test: data outstanding and nothing accepted for
// more than SESSION_DEAD_MS.
func (c *Client) livenessExpired() bool { return c.silentFor(SessionDeadMS + 1) }

// silentFor reports §7.2's gate open and nothing accepted for at least ms
// milliseconds. It reads the gate before the timestamp; see markOutstanding.
func (c *Client) silentFor(ms int64) bool {
	if !c.outstanding.Load() {
		return false
	}
	last := c.lastRx.Load()
	if since := c.outstandingSince.Load(); since > last {
		last = since
	}
	return last != 0 && c.monoMS()-last >= ms
}

// sendSess returns the session application writes may use. Only an ESTABLISHED
// session qualifies: during AWAIT_PUSH_ACK a concurrent sender could otherwise
// get its frame in ahead of the promoting PUSH (§8.5(a)3), and the device would
// then drop that PUSH's MessageNum as a replay. A session liveness has declared
// dead is refused too, even before its teardown has run.
func (c *Client) sendSess() (*kcp.UDPSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dying.Load() && !c.closedByUser.Load() {
		return nil, ErrSessionDead
	}
	if c.kcp == nil || c.state != stEstablished {
		return nil, c.notEstablishedErr()
	}
	return c.kcp, nil
}

func (c *Client) markDead() {
	c.dying.Store(true)
	// deadCh is written by commit and read here from the readLoop goroutine, so
	// it needs the mutex: a second concurrent teardown detaches rlStop/rlDone and
	// skips the join, so a later commit CAN overlap a still-running readLoop.
	// Nil-ing it under the lock also makes the close exactly-once without
	// reassigning a sync.Once, which would itself be a racy copy of a lock.
	c.mu.Lock()
	if c.deadCh != nil {
		close(c.deadCh)
		c.deadCh = nil
	}
	c.mu.Unlock()
}

// SessionDead reports whether the session ended because SESSION_DEAD_MS elapsed
// with no accepted s2c envelope (§7.2), as opposed to a local Close or a failed
// admission. Recovery is an explicit TakeControl; the library never re-admits on
// its own (§7.2).
func (c *Client) SessionDead() bool { return c.deadFlag.Load() && !c.closedByUser.Load() }

func (c *Client) teardown() { c.teardownAs(false) }

// teardownAs is teardown; dead records that liveness ended the session, which
// SessionDead reports once the client is back in IDLE.
func (c *Client) teardownAs(dead bool) {
	// Serialise the whole body. Without this a second concurrent teardown reads
	// the already-detached rlStop/rlDone as nil, skips the readLoop join
	// entirely, and returns having set stIdle while the reader is still on the
	// socket — after which a successor TakeControl passes its IDLE guard and runs
	// against a live foreign readLoop that steals its RETRY/ADMIT and closes its
	// firstAck and deadCh. Serialising makes the second call a no-op instead.
	c.tdMu.Lock()
	defer c.tdMu.Unlock()
	c.teardownLocked(dead)
}

// teardownIf tears down only if sess is still the client's session when it
// holds the locks teardownAs takes, and does nothing otherwise: by the time a
// reader reacts to its session's end, a new session may have been admitted,
// and a plain teardown would end that one.
func (c *Client) teardownIf(sess *kcp.UDPSession, dead bool) {
	c.tdMu.Lock()
	defer c.tdMu.Unlock()
	c.mu.Lock()
	same := sess != nil && c.kcp == sess
	c.mu.Unlock()
	if !same {
		return
	}
	// c.kcp cannot change before teardownLocked: only teardown (held off by
	// tdMu) clears it, and only an admission from IDLE sets it.
	c.teardownLocked(dead)
}

// teardownLocked is teardownAs's body; the caller holds tdMu.
func (c *Client) teardownLocked(dead bool) {

	// Stop this attempt's readLoop before releasing the session. It reads the same
	// socket as TakeControl, so leaving it running wedges every later admission
	// attempt: it starves the FD read lock and swallows RETRY/ADMIT as non-envelope
	// (§7.1). Signal and wait outside c.mu — readLoop takes c.mu on the first-ack
	// path, so waiting under the lock would deadlock instead.
	c.mu.Lock()
	stop, rdone := c.rlStop, c.rlDone
	c.rlStop, c.rlDone = nil, nil
	c.mu.Unlock()
	if stop != nil {
		close(stop)
		select {
		case <-rdone:
		case <-time.After(readLoopStopTimeout):
			// readLoop did not exit. Falling through leaves a reader on c.conn
			// with nothing able to stop it (rlStop is already detached), which
			// is the starvation this whole path exists to prevent. It should be
			// unreachable — readLoop's read deadline is 500ms — so record it
			// rather than continuing silently, and close the socket to force
			// the reader out of any blocking read.
			c.rlStuck.Store(true)
			if cc := c.conn; cc != nil {
				cc.SetReadDeadline(time.Now())
			}
			<-rdone // now guaranteed to return: the read cannot block
		}
	}

	c.mu.Lock()
	if c.kcp != nil {
		c.kcp.Close()
		c.kcp = nil
	}
	if c.shim != nil {
		// kcp-go's Close above has flushed under k_kcp_c2s; wipe takes the
		// shim's key lock, so a late write from kcp-go's update goroutine
		// fails instead of racing the wipe.
		c.shim.Close()
		c.shim.wipe()
		c.shim = nil
	}
	// nil, not just zeroed: appframe's `len(key) == 0` guard is how a send after
	// teardown reports ErrNotEstablished instead of sealing under an all-zero key.
	// zero() leaves len == 32, so zeroing alone left that guard dead code.
	zero(c.kC2S)
	c.kC2S = nil
	zero(c.kS2C)
	c.kS2C = nil
	if c.sessGone != nil {
		close(c.sessGone)
		c.sessGone = nil
	}
	c.state = stIdle
	if dead {
		c.deadFlag.Store(true)
	}
	c.mu.Unlock()
	// transport 10.3 rule 6: back in IDLE, nothing of the session is kept. A
	// partly staged message goes now, not at the next commit. rxMu after c.mu,
	// never under it (recvAppNumFrom takes rxMu, then c.mu); a reader holding
	// it is reading the session closed above and returns. kcp-go's own buffers
	// cannot be zeroed from outside; the shim's inbound channel is left to the
	// garbage collector (it holds only message-layer ciphertext).
	c.rxMu.Lock()
	c.rxStage.reset()
	c.rxMu.Unlock()
}

// EndSession ends the established session and returns the client to IDLE
// (transport 10.3): the session's keys and KCP state are wiped, and the static
// keys and the socket are kept, so TakeControl* can admit again. In IDLE it
// does nothing. During an admission (AWAIT_RETRY, AWAIT_ADMIT, AWAIT_PUSH_ACK)
// it changes nothing and returns ErrNotIdle; after Close it returns
// net.ErrClosed. Use EndSession to stop and later take control again, and
// Close to be done with the Client.
func (c *Client) EndSession() error {
	if c.closing() {
		return net.ErrClosed
	}
	c.mu.Lock()
	st, sess := c.state, c.kcp
	c.mu.Unlock()
	switch st {
	case stIdle:
		return nil
	case stEstablished:
		c.teardownIf(sess, false)
		return nil
	}
	return ErrNotIdle
}

// Close ends the client and its socket and wipes its static keys. The Client
// cannot be reused; to end only the session, use EndSession.
func (c *Client) Close() error {
	c.closedByUser.Store(true)
	c.mu.Lock() // see attempts
	c.closeOnce.Do(func() { close(c.done) })
	c.mu.Unlock()
	c.teardown()
	err := c.conn.Close()
	c.attempts.Wait() // the closed socket ends them within one read
	c.mu.Lock()
	zero(c.kDev)
	zero(c.kReq)
	zero(c.kResp)
	c.mu.Unlock()
	return err
}

func addrOf(a net.Addr) netip.Addr {
	if ua, ok := a.(*net.UDPAddr); ok {
		ad, _ := netip.AddrFromSlice(ua.IP)
		return ad.Unmap()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap.Addr()
}

// testHookBeforeFirstWrite, when set by a test, runs in commit just before the
// promoting PUSH is written: the window a concurrent sender used to race into.
var testHookBeforeFirstWrite func()

// testHookBeforeSendWrite, when set by a test, runs in sendApp and Send just
// before the session write, inside txMu: the window in which a teardown
// leaves a sender holding a closed session.
var testHookBeforeSendWrite func()

// testHookMidMarkOutstanding, when set by a test, runs in markOutstanding
// between storing outstandingSince and opening the gate.
var testHookMidMarkOutstanding func()
