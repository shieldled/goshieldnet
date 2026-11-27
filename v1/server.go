// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// This file is the device/server (§6, §8.5): a
// device-owned master read loop that owns the real UDP socket and does all §5
// demux, plus §8.5 promotion as a kcp-go session swap. Promotion internals differ
// from the C device's raw-ikcp model (kcp-go owns its own flush/goroutine/mutex),
// but the protocol invariants are the same and interoperate with the C side.
//
// All promotion and demux runs in the master loop goroutine, serialised by mu
// (the kcp_lock role). kcp-go's own per-session goroutines only call the shim's
// WriteTo, which touches immutable per-session state.

const internalMTU = WireMTU - EnvelopeLen // 1380 (§8.4)

// KCPTuning is the KCP transport tuning (§8.4/§11). DefaultKCPTuning is the spec's
// §11 recommendation (rcv_wnd 8), sized so two worst-case sessions fit an ESP32.
// Raise RcvWnd for a streaming data plane; both ends must match. See tuning.md.
type KCPTuning struct {
	SndWnd, RcvWnd                int
	NoDelay, Interval, Resend, NC int
}

// DefaultKCPTuning is the Tuning that NewClient and NewServer start with.
var DefaultKCPTuning = KCPTuning{SndWnd: 32, RcvWnd: 8, NoDelay: 1, Interval: 20, Resend: 2, NC: 1}

// clampSendWindow applies §9.5's byte cap by SIZING the send window from it.
// kcp-go exposes no queue-depth accessor on a session, so the bound cannot be
// enforced by polling; deriving snd_wnd is how it is enforced. Both roles use
// this — an earlier version clamped on the client only, leaving the Go device
// unbounded while the documentation said otherwise.
//
// The bound this achieves is approximate, and deliberately so. kcp-go admits a
// Write whenever WaitSnd < snd_wnd and then queues the WHOLE buffer, so the
// total after an admitted write is up to (snd_wnd - 1) segments plus that
// write — i.e. SEND_QUEUE_MAX + MAX_MSG_PAYLOAD - MSS, not SEND_QUEUE_MAX.
// Closing that gap exactly would mean sizing snd_wnd at
// SEND_QUEUE_MAX - MAX_MSG_PAYLOAD, which at the equal defaults leaves a
// one-segment window, or shrinking MAX_MSG_PAYLOAD, which is a wire constant
// the C device shares and cannot be changed on one side. §11's budget is the
// DEVICE's, and the device enforces the cap directly on its own ikcp.c queues
// where it can read them; these two roles are the controller and the emulator,
// so the residual is bounded and paid out of a host's heap.
func clampSendWindow(t KCPTuning, sendQueueMax int) KCPTuning {
	q := sendQueueMax
	if q <= 0 {
		q = SendQueueMaxDefault
	}
	w := q / WireMTU
	if w < 1 {
		w = 1
	}
	if t.SndWnd > w {
		t.SndWnd = w
	}
	return t
}

func applyTuning(s *kcp.UDPSession, t KCPTuning) {
	// Message-layer §1.1: "KCP MUST run in stream mode (stream = 1) on both
	// peers." A message of that layer is length-prefixed and may span many
	// MTU-sized KCP items, and a message-mode sender is not interoperable with a
	// bounded firmware receive buffer that reads exact byte counts. The C device
	// sets kcp->stream = 1; without this, Go and C disagree the moment a message
	// exceeds one segment — and only then, which is why every single-segment
	// test passed while an 8 KiB message to the C device vanished.
	//
	// kcp-go marks SetStreamMode deprecated but offers no replacement; it is the
	// only way to set stream = 1.
	s.SetStreamMode(true) //lint:ignore SA1019 no replacement exists; stream mode is mandatory (§1.1)
	s.SetMtu(internalMTU)
	s.SetNoDelay(t.NoDelay, t.Interval, t.Resend, t.NC)
	s.SetWindowSize(t.SndWnd, t.RcvWnd)
}

// WireMTU is WIRE_MTU (§2, default).
const WireMTU = 1400

// envelopeLenOK is transport 5.7's length rule for an envelope datagram:
// KCP_OVERHEAD + ENVELOPE_LEN <= n <= WIRE_MTU.
func envelopeLenOK(n int) bool { return n >= KcpOverhead+EnvelopeLen && n <= WireMTU }

type serverSession struct {
	conn *kcp.UDPSession
	shim *sessionConn

	// §8.5(a)4 names four keys, and all four are installed here. kc2s/ks2c seal
	// and open the envelope; kC2S/kS2C key the application message layer inside
	// the KCP stream (§13, shieldnet-message-layer.md). An earlier version copied
	// only the envelope pair, so a promoted session could never open an app-layer
	// frame — the transport came up into a session whose application keys had
	// already been wiped with the pending record.
	kc2s   []byte // k_kcp_c2s — inbound envelope open key
	kC2S   []byte // k_c2s — inbound app-layer key
	kS2C   []byte // k_s2c — outbound app-layer key
	tuple  []byte
	gen    uint32
	convID uint32
	app    appPeer // §6.2 MessageNum counters for the message layer
	window replayWindow
}

// Server is a responder over kcp-go. It admits clients (§6) and promotes the
// first PUSH into a primary session (§8.5).
//
// It does NOT implement §9.4's quiesce-and-resume: clearing ikcp's latched
// dead-link state in place requires reaching dead_link, ts_flush, rx_rto and
// every segment's xmit/rto/resendts, and kcp-go surfaces none of them from
// UDPSession. That gap is deliberate and is recorded, with its consequences, in
// shieldnet-protocol/README.md — the C device library owns its ikcp.c and does it properly.
// This type is an emulator, so the gap costs test fidelity, not correctness.
type Server struct {
	dev  *Device
	real net.PacketConn
	base time.Time

	// The primary and the promotion generation are record state, so they are
	// guarded by §10.1's rec_lock, which lives on Device (see device.go). Server
	// has no mutex of its own: two mutexes over one invariant is how the pending
	// table and the primary came to be mutated from different critical sections.
	primary   *serverSession
	promoGen  uint32
	closed    chan struct{}
	closeOnce sync.Once
	v6Socket  bool // see addrPort: decides the §4.3 mapped-address rule
	// serving is set (under rec) when Serve starts. The Serve goroutine is the
	// only caller of the handlers, and they read the device keys unlocked, so
	// it wipes the device itself once its loop has ended; Close wipes only if
	// Serve never ran.
	serving bool

	// §9.5/§13 send-path bounds; zero means the default.
	SendQueueMax  int
	MaxMsgPayload int
	Tuning        KCPTuning
	skipSrcCheck  bool // test-only: bypass §4.3 so loopback works

	// MidFrameBudgetMS bounds how long a message may stay partly read (message
	// layer 8 item 2), measured from the arrival of its first octet. Once it has
	// passed, the read returns ErrDesync ("partial message") instead of waiting
	// or reporting a timeout. Zero or negative means MidFrameBudgetMSDefault
	// (10 000). It must exceed the time to receive a MaxMsgPayload-sized message
	// on the slowest link the deployment supports. Time the caller spends not
	// reading counts against it: a frame left staged by a read deadline and
	// resumed after the budget has passed is ErrDesync. Like every ErrDesync
	// from RecvAppNumGen, it ends the session: the primary is dropped.
	MidFrameBudgetMS int
}

// NewServer wraps a Device and a bound UDP socket. The caller supplies the socket
// (so tests can use loopback) and the Device (with its keys and pending table).
//
// The socket must be bound to a single interface (transport 7.3); NewServer
// does not check it. The Device must have been built with that interface's
// prefixes and with fresh start-up secrets (see NewDeviceFromKDev).
func NewServer(dev *Device, conn net.PacketConn) *Server {
	s := &Server{
		dev: dev, real: conn, base: time.Now(),
		closed:   make(chan struct{}),
		v6Socket: isV6Socket(conn),
		Tuning:   DefaultKCPTuning,
	}
	// §4.4's cookie epoch is only meaningful against the clock that advances it,
	// and Serve advances it from s.base (see nowMS), not from the wall clock. A
	// device seeded with time.Now().UnixMilli() — the natural thing for an
	// embedder to pass, and what examples/server does — therefore starts thousands
	// of epochs ahead of the first tick, so rollEpochLocked takes neither its
	// "same epoch" nor its "+1" branch and discards the boot tag with
	// prevEpochTag = nil. Every FINISH whose RETRY was minted before that tick
	// then fails step 3a. Re-seed here so the boot tag is the one the first tick
	// shifts, whatever clock the caller used to build the Device.
	dev.RollEpoch(s.nowMS())
	setPMTUProbe(conn)
	return s
}

func (s *Server) nowMS() uint64 { return uint64(time.Since(s.base).Milliseconds()) }

// Primary returns the current established kcp session, or nil.
func (s *Server) Primary() *kcp.UDPSession {
	s.dev.rec.Lock()
	defer s.dev.rec.Unlock()
	if s.primary == nil {
		return nil
	}
	return s.primary.conn
}

// TickIntervalMS is how often Serve runs the §9.2 maintenance pass. It must be
// well below COOKIE_EPOCH_MS so the epoch actually rolls, and below
// PENDING_TTL_MS so expired records are reaped rather than merely detected.
const TickIntervalMS = 500

// Serve runs the master read loop until the socket closes or Close is called,
// and starts the §9.2 maintenance tick. It blocks; run it in its own goroutine.
func (s *Server) Serve() {
	s.dev.rec.Lock()
	s.serving = true
	s.dev.rec.Unlock()
	// Runs last: no handler can be in flight once the read loop has returned.
	defer s.dev.Wipe()
	go s.tickLoop() // §9.2 maintenance (M1)
	// tickLoop exits only on s.closed, so a Serve that returns on a socket error
	// without it would leave the tick firing every 500 ms for the life of the
	// process, pinning the Server, the Device and its keys. Close is idempotent
	// (closeOnce), so an embedder calling it as well is fine.
	defer s.Close()
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.real.ReadFrom(buf)
		if err != nil {
			return
		}
		s.handlePacket(append([]byte(nil), buf[:n]...), addr)
	}
}

// isV6Socket reports whether the listening socket can deliver GENUINE IPv6
// sources — the only case in which §4.3's ::ffff:0:0/96 rejection should fire.
//
// LocalAddr cannot answer this. Go's wildcard bind returns an AF_INET6
// dual-stack socket whose LocalAddr is "::" even for ListenPacket("udp",
// "0.0.0.0:0"), and on such a socket an ordinary IPv4 peer arrives as
// ::ffff:a.b.c.d. Treating that as a genuine v6 source rejects every IPv4
// controller, permanently and silently (§9.3 forbids a signal) — the exact
// failure §4.3's rationale warns about. Only IPV6_V6ONLY separates the two.
//
// Anything indeterminate returns false, i.e. v4 semantics: unmap and accept.
// That direction fails OPEN by design. Over-rejecting costs every controller;
// under-rejecting costs only the mapped-source case, which needs an attacker
// able to emit a genuine v6 datagram carrying a v4-mapped source address.
func isV6Socket(c net.PacketConn) bool {
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return false
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok || !a.Is6() || a.Is4In6() {
		return false // not AF_INET6 at all
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	v6only := false
	if err := raw.Control(func(fd uintptr) {
		if v, gerr := getsockoptV6Only(fd); gerr == nil {
			v6only = v != 0
		}
	}); err != nil {
		return false
	}
	return v6only
}

// tickLoop runs the device's §9.2 maintenance pass until Close.
func (s *Server) tickLoop() {
	t := time.NewTicker(TickIntervalMS * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.dev.Tick(s.nowMS()) // takes rec itself (§10.1)
		}
	}
}

// DropPrimary retires the current primary, leaving the server listening. It
// reports whether there was one to retire.
//
// A stream that has desynchronised MUST be closed (message layer 8), because
// every later read parses payload bytes as a frame header and the misalignment
// is permanent; RecvAppNumGen now does that itself with DropPrimaryIf. Unlike
// Close, dropping the primary keeps the socket, so the re-admission that is
// supposed to follow can happen.
//
// The device is left with no session; the next §8.5(a)-conforming first PUSH
// promotes a new one.
func (s *Server) DropPrimary() bool {
	return s.dropPrimary(func(*serverSession) bool { return true })
}

// PrimaryGen reports the current primary's promotion generation, and whether
// there is a primary. Generations are never reused (§8.5).
func (s *Server) PrimaryGen() (uint32, bool) {
	s.dev.rec.Lock()
	defer s.dev.rec.Unlock()
	if s.primary == nil {
		return 0, false
	}
	return s.primary.gen, true
}

// DropPrimaryIf retires the primary only if it is still generation gen, and
// reports whether it did (C: sn_device_end_primary(d, gen)). Use it to end the
// session a read or write failed on: by the time the caller reacts, a
// re-admission may have promoted a new session, and DropPrimary would kill
// that one instead. RecvAppNumGen returns the generation a message came from.
func (s *Server) DropPrimaryIf(gen uint32) bool {
	return s.dropPrimary(func(p *serverSession) bool { return p.gen == gen })
}

func (s *Server) dropPrimary(match func(*serverSession) bool) bool {
	s.dev.rec.Lock()
	p := s.primary
	if p != nil && !match(p) {
		p = nil
	}
	if p != nil {
		zero(p.kc2s)
		zero(p.kC2S)
		zero(p.kS2C)
		s.primary = nil
	}
	s.dev.rec.Unlock()
	if p == nil {
		return false
	}
	// §10.1/§10.3: kcp-go's Close takes the session mutex and runs a full flush.
	// It must not run under rec_lock, so it happens here, after the release.
	retireSession(p)
	return true
}

// retireSession closes a session that is no longer the primary: kcp-go's Close
// flushes under the session's own seal key, then the shim wipes that key and
// refuses any later seal from kcp-go's update goroutine.
func retireSession(p *serverSession) {
	p.conn.Close()
	p.shim.Close()
	p.shim.wipe()
}

// retired reports whether p is no longer the primary.
func (s *Server) retired(p *serverSession) bool {
	s.dev.rec.Lock()
	defer s.dev.rec.Unlock()
	return s.primary != p
}

// Close stops the server and retires the primary. The device's keys are wiped
// when Serve's loop exits, or here if Serve never ran; the Device must not be
// reused afterwards.
func (s *Server) Close() error {
	s.closeOnce.Do(func() { close(s.closed) }) // H3: Close is idempotent
	s.DropPrimary()
	err := s.real.Close()
	s.dev.rec.Lock()
	serving := s.serving
	s.dev.rec.Unlock()
	if !serving {
		s.dev.Wipe()
	}
	return err
}

func addrPort(addr net.Addr, v6Socket bool) netip.AddrPort {
	if ua, ok := addr.(*net.UDPAddr); ok {
		a, _ := netip.AddrFromSlice(ua.IP)
		// §4.3: "the test is applied to the received source address in its own
		// family, before canonicalisation." Whether a v4-mapped address is a
		// genuine IPv6 source (which §4.3 rejects, because it would canonicalise
		// onto the same tuple as a real IPv4 peer) or merely Go's 16-octet
		// representation of an IPv4 peer is NOT visible from the address — Go's
		// own net.IPv4() produces the mapped form. Only the socket family
		// distinguishes them, so unmap on a v4 socket and preserve the mapping on
		// a v6 one, where source.go's ::ffff:0:0/96 rule then applies.
		if !v6Socket {
			return netip.AddrPortFrom(a.Unmap(), uint16(ua.Port))
		}
		return netip.AddrPortFrom(a, uint16(ua.Port))
	}
	ap, _ := netip.ParseAddrPort(addr.String())
	return ap
}

// handlePacket runs §5 demux and dispatches. Exposed (unexported) for direct test
// drive as well as the Serve loop.
func (s *Server) handlePacket(datagram []byte, addr net.Addr) {
	ap := addrPort(addr, s.v6Socket)
	class := Classify(RoleDevice, ap.Addr(), s.dev.local, datagram)
	if s.skipSrcCheck {
		class = classifyDatagram(RoleDevice, datagram)
	}
	switch class {
	case ClassINIT:
		// Classify above applied §4.3 (or the test bypassed it on purpose).
		if retry := s.dev.handleINIT(datagram, ap, s.nowMS()); retry != nil {
			s.real.WriteTo(retry, addr)
		}
	case ClassFINISH:
		if admit := s.dev.handleFINISH(datagram, ap, s.nowMS()); admit != nil {
			s.real.WriteTo(admit, addr)
		}
	case ClassEnvelope:
		s.handleEnvelope(datagram, addr, ap)
	default:
		// dropped
	}
}

// tryOpen attempts one §8.1 candidate without marking: reconstruct against hwm,
// range-check, AEAD open. Returns (plaintext, seqFull, ok).
func tryOpen(key []byte, datagram []byte, hwm uint64) ([]byte, uint64, bool) {
	if len(datagram) < KcpOverhead+EnvelopeLen { // §3.6/§7.5; see replayWindow.open
		return nil, 0, false
	}
	seqWire := binary.BigEndian.Uint32(datagram[len(datagram)-EnvelopeLen : len(datagram)-16])
	cand := Reconstruct(seqWire, hwm)
	if !inRange(cand, hwm) {
		return nil, 0, false
	}
	pt, err := Open(key, true, uint64(cand), datagram) // c2s
	if err != nil {
		return nil, 0, false
	}
	return pt, uint64(cand), true
}

func convOf(kcpBytes []byte) uint32 {
	if len(kcpBytes) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(kcpBytes[:4])
}

// envCandidate is one §8.1 open candidate: the primary, or a pending record.
type envCandidate struct {
	primary bool
	idx     int // pending slot when !primary
	key     []byte
	hwm     uint64
	gen     uint32
}

func (s *Server) handleEnvelope(datagram []byte, addr net.Addr, ap netip.AddrPort) {
	if !envelopeLenOK(len(datagram)) {
		return
	}
	tuple := Canonicalize(ap.Addr(), ap.Port())
	now32 := uint32(s.nowMS())

	// §10.3: no verification of an UNAUTHENTICATED datagram — its AEAD open
	// included — may run under either lock; that is what stops a flood from
	// holding one. The lock is taken only to look the tuple up and copy each
	// candidate's key and high-water mark out, released for the opens, then
	// re-acquired to commit against a re-checked generation (§8.1 step 3, §8.6).
	//
	// BOTH candidates are collected here, in §8.1 step 2's order — primary before
	// pending — because step 3 requires falling through on failure: "a datagram
	// from a client re-admitting on the tuple its old session still holds fails
	// under the primary's keys and must still reach the pending record, or
	// promotion becomes impossible." §9.5 never destroys a session for
	// inactivity, so the stale primary is removed only BY a promotion; stopping
	// at the primary poisons that tuple until the client changes source port or
	// the device reboots.
	var cands []envCandidate
	s.dev.rec.Lock()
	select {
	case <-s.closed:
		s.dev.rec.Unlock()
		return
	default:
	}
	if s.primary != nil && bytes.Equal(s.primary.tuple, tuple) {
		cands = append(cands, envCandidate{
			primary: true,
			key:     append([]byte(nil), s.primary.kc2s...),
			hwm:     s.primary.window.hwm,
			gen:     s.primary.gen,
		})
	}
	if pi := s.dev.findPending(tuple); pi >= 0 && int32(s.dev.pending[pi].expiry-now32) > 0 {
		cands = append(cands, envCandidate{
			idx: pi,
			key: append([]byte(nil), s.dev.pending[pi].keys.KKcpC2S...),
			hwm: s.dev.pending[pi].c2sWindow.hwm,
			gen: s.dev.pending[pi].generation,
		})
	}
	s.dev.rec.Unlock()

	// §10.1: every copied key is wiped on EVERY exit. A deferred sweep rather
	// than a per-iteration wipe, because a successful open returns early and
	// would otherwise leave the untried candidate's key copy live on the heap —
	// one leaked copy per datagram whenever a pending record shares the tuple
	// with the primary, which is exactly the re-admission case.
	defer func() {
		for _, cand := range cands {
			zero(cand.key)
		}
	}()
	for _, cand := range cands {
		pt, seq, ok := tryOpen(cand.key, datagram, cand.hwm) // UNLOCKED (§10.3)
		if !ok {
			continue // §8.1 step 3: try the next candidate
		}
		s.commitEnvelope(cand, tuple, seq, pt, addr)
		return
	}
}

// commitEnvelope re-acquires rec and applies a datagram that opened under cand,
// re-validating that the candidate is still the one that was snapshotted.
func (s *Server) commitEnvelope(cand envCandidate, tuple []byte, seq uint64, pt []byte, addr net.Addr) {
	// §10.1: rec_lock permits "nothing that can block, ever", and §10.3 forbids
	// holding it across kcp_lock. Retiring a primary means kcp-go's Close, which
	// takes that session's mutex and runs a full ikcp_flush — so it is registered
	// here and run once rec is released. Defers are LIFO: this one is registered
	// first, so it runs LAST, after the Unlock below.
	var after []func()
	defer func() {
		for _, f := range after {
			f()
		}
	}()
	s.dev.rec.Lock()
	defer s.dev.rec.Unlock()
	select {
	case <-s.closed:
		return
	default:
	}
	if cand.primary {
		// The primary may have been replaced or torn down while the open ran; the
		// generation is what makes that detectable.
		if s.primary == nil || s.primary.gen != cand.gen || !bytes.Equal(s.primary.tuple, tuple) {
			return
		}
		if s.primary.window.testAndMark(seq) && convOf(pt) == s.primary.convID {
			s.primary.shim.deliver(pt) // kcp-go feeds its Input (§8.6)
		}
		return
	}
	// Pending → §8.5 promotion. Re-validate the slot against a freshly read
	// clock: it may have expired, been reaped, or been replaced by another
	// admission while the open ran.
	if cand.idx < 0 || cand.idx >= len(s.dev.pending) {
		return
	}
	r := &s.dev.pending[cand.idx]
	if !r.used || !bytes.Equal(r.tuple, tuple) || r.generation != cand.gen ||
		int32(r.expiry-uint32(s.nowMS())) <= 0 {
		return
	}
	s.promote(cand.idx, tuple, seq, pt, addr, &after)
}

// isPromotingSegment reports whether pt, an opened envelope's plaintext,
// is a KCP PUSH with sn 0: the only first segment that may promote (§8.5 (a)3).
func isPromotingSegment(pt []byte) bool {
	return len(pt) >= KcpOverhead && pt[4] == kcpCmdPush && binary.LittleEndian.Uint32(pt[12:16]) == 0
}

// promote is §8.5 as a kcp-go session swap, under mu (the kcp_lock role).
func (s *Server) promote(pi int, tuple []byte, seq uint64, pt []byte, addr net.Addr, after *[]func()) {
	r := &s.dev.pending[pi]
	// (a)1 re-check (expiry already checked by caller under the same lock)
	// (a)2 accept-test without marking
	if !r.c2sWindow.wouldAccept(seq) {
		return
	}
	// (a)3 require KCP PUSH sn==0 on the first segment; drop without marking
	if !isPromotingSegment(pt) {
		return
	}
	// H3: Close may have run while this datagram was waiting on rec. Installing a
	// primary now would leak a kcp-go session and three goroutines past shutdown,
	// and leave s.primary non-nil after Close returned. Checked BEFORE (a)4 marks
	// the window and takes the four key snapshots: bailing out after them burned a
	// generation and returned with all four still live, which is exactly the
	// promotion buffer §8.5 requires be wiped.
	select {
	case <-s.closed:
		return
	default:
	}

	// (a)4 mark, claim (increment pending_generation), snapshot everything (c) installs
	r.c2sWindow.testAndMark(seq)
	r.generation = s.dev.genCtr
	s.dev.genCtr++
	myClaim := r.generation
	snapKC2S := append([]byte(nil), r.keys.KKcpC2S...)
	snapKS2C := append([]byte(nil), r.keys.KKcpS2C...)
	snapAppC2S := append([]byte(nil), r.keys.KC2S...)
	snapAppS2C := append([]byte(nil), r.keys.KS2C...)
	snapTuple := append([]byte(nil), r.tuple...)
	snapWindow := r.c2sWindow // marked (hwm AND bitmap)

	// (a)5 retire the outgoing primary. Its seal key is wiped now, inside the
	// claim's critical section, so nothing can be sealed on the retired session
	// from the claim on (transport 12.2 item 6): kcp-go's update goroutine and
	// Close flush, which run later, fail closed. wipe takes the shim's key lock,
	// so this does not race them.
	retired := s.primary
	s.primary = nil
	if retired != nil {
		retired.shim.wipe()
		if testHookRetiredClaimed != nil {
			testHookRetiredClaimed(retired.conn)
		}
	}
	newGen := s.promoGen + 1

	// (b) create the new kcp-go session over a fresh shim, bound to the client conv
	conv := convOf(pt)
	shim := newSessionConn(s.real, addr, snapKS2C, false, s.Tuning.RcvWnd)
	sess, err := kcp.NewConn3(conv, addr, nil, 0, 0, shim)
	if err != nil {
		// allocation-failure branch: discard the claimed record only if unchanged;
		// close the already-retired primary; device ends with no session.
		if r.used && r.generation == myClaim {
			r.wipeKeys()
			r.used = false
		}
		// The Go analog of §8.5's promotion buffer, on the one exit path that
		// reaches neither (c) nor a reaper. All four, not just the envelope pair:
		// (a)4 snapshots the app-layer keys too, and nothing else will free them.
		zero(snapKC2S)
		zero(snapKS2C)
		zero(snapAppC2S)
		zero(snapAppS2C)
		if retired != nil {
			zero(retired.kc2s) // inbound key; no goroutine reads it post-retirement
			zero(retired.kC2S) // app-layer keys: nothing reads them post-retirement
			zero(retired.kS2C)
			// retired.shim.key (k_kcp_s2c) was wiped at (a)5, under the shim's key
			// lock; kcp-go's Close below runs on a shim that refuses to seal.
			ret := retired
			*after = append(*after, func() { retireSession(ret) })
		}
		return
	}
	applyTuning(sess, clampSendWindow(s.Tuning, s.SendQueueMax))

	// (c) install the new primary from the snapshot with the already-marked window
	s.promoGen = newGen
	s.primary = &serverSession{
		conn:   sess,
		shim:   shim,
		kc2s:   snapKC2S,
		kC2S:   snapAppC2S,
		kS2C:   snapAppS2C,
		tuple:  snapTuple,
		gen:    newGen,
		convID: conv,
		window: snapWindow,
	}
	// §8.5 (c): clear the pending record and wipe its key copies, only if its
	// generation still equals the claim. No reaper visits a cleared slot, so
	// unwiped copies would outlive the primary. The generation guard leaves a slot
	// re-claimed by a concurrent FINISH untouched.
	if r.used && r.generation == myClaim {
		r.wipeKeys()
		r.used = false
	}
	// close the retired session (its Close flush seals under its own shim key) and
	// best-effort wipe its keys (§8.5 wipe-before-free; Go cannot guarantee it)
	if retired != nil {
		zero(retired.kc2s) // inbound key; no goroutine reads it post-retirement
		zero(retired.kC2S) // app-layer keys: sendApp/RecvAppNum copy them out under
		zero(retired.kS2C) // rec before use, so nothing reads either post-retirement
		// retired.shim.key was wiped at (a)5; kcp-go's Close flush fails closed
		ret := retired
		*after = append(*after, func() { retireSession(ret) })
	}
	// feed the first PUSH to the new session's read loop
	shim.deliver(pt)
}

const kcpCmdPush = 81 // IKCP_CMD_PUSH

// testHookRetiredClaimed, when set by a test, runs in promote once the
// outgoing primary is retired, inside the claim's critical section, with that
// primary's kcp-go session.
var testHookRetiredClaimed func(retired *kcp.UDPSession)

// --- application message layer (device side) -------------------------------
//
// The device half of shieldnet-protocol/shieldnet-message-layer.md, mirroring Client's:
// device→client seals under k_s2c and client→device opens under k_c2s. These
// exist so the four keys §8.5(a)4 installs are actually usable from Go — without
// them the app-layer pair was installed on every promotion and unreachable.
//
// The sled responses, PIXEL_FRAME and NTP_SERVER payloads are in the sled package;
// these methods carry an opaque MessageType and payload.

// SendApp frames a message verbatim and writes it to the established primary.
func (s *Server) SendApp(msgType uint32, payload []byte) error {
	return s.sendApp(msgType, payload, false, false)
}

// SendAppPadded pads to a §13 size class. The device side of the sled protocol
// answers with control and configuration messages, which §13 forbids compressing
// and expects to be padded, so this is the usual call for a response.
func (s *Server) SendAppPadded(msgType uint32, payload []byte) error {
	return s.sendApp(msgType, payload, false, true)
}

// SendAppCompressed requests LZ4, for the two categories §13 permits to compress.
// A conforming sled device never needs it — every device→client message in that
// protocol is control — but the message layer allows it and a non-sled
// application may.
func (s *Server) SendAppCompressed(msgType uint32, payload []byte) error {
	return s.sendApp(msgType, payload, true, false)
}

func (s *Server) sendApp(msgType uint32, payload []byte, compress, pad bool) error {
	s.dev.rec.Lock()
	p := s.primary
	var key []byte
	if p != nil {
		key = append([]byte(nil), p.kS2C...) // copy: retirement wipes the original
	}
	s.dev.rec.Unlock()
	if p == nil || len(key) == 0 {
		return ErrNotEstablished
	}
	defer zero(key)

	p.app.txMu.Lock()
	defer p.app.txMu.Unlock()
	frame, err := frameAppWith(key, p.app.nextTx(), msgType, payload, compress, pad, s.maxMsgPayload())
	if err != nil {
		return err
	}
	// §9.5: refuse rather than block indefinitely, and never drop silently.
	p.conn.SetWriteDeadline(time.Now().Add(msDur(SendBlockedMS)))
	_, err = p.conn.Write(frame)
	p.conn.SetWriteDeadline(time.Time{})
	// kcp-go wraps its timeout in pkg/errors; a type assertion never matches.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrSendQueueFull
	}
	if err != nil && s.retired(p) {
		return ErrSessionClosed
	}
	return err
}

// RecvApp reads one framed message from the established primary and opens it
// under k_c2s. It returns ErrRejected for a frame that failed to authenticate or
// violated §7 — the session survives and the caller should keep reading — and
// ErrDesync when the stream is no longer frame-aligned, which is fatal (§1.2):
// the primary has then been dropped (see RecvAppNumGen).
func (s *Server) RecvApp() (uint32, []byte, error) {
	t, _, p, err := s.RecvAppNum()
	return t, p, err
}

// RecvAppNum is RecvApp, additionally returning the message's MessageNum. A
// device needs it to echo as ACK's orig_message_num: the sled layer correlates a
// response to its command by that field, never by message order.
func (s *Server) RecvAppNum() (uint32, uint64, []byte, error) {
	t, n, b, _, err := s.RecvAppNumGen()
	return t, n, b, err
}

// RecvAppNumGen is RecvAppNum, additionally returning the generation of the
// session the message (or error) came from. On ErrDesync it has already ended
// that session with DropPrimaryIf(gen) (message layer 8): the server is left
// listening, and a newer session that replaced it is untouched. A read on a
// session that was closed or replaced while it waited returns
// ErrSessionClosed, not ErrDesync.
func (s *Server) RecvAppNumGen() (uint32, uint64, []byte, uint32, error) {
	t, n, b, gen, err := s.recvAppNumGen()
	if errors.Is(err, ErrDesync) {
		// After recvAppNumGen has released p.app.rxMu.
		s.DropPrimaryIf(gen)
	}
	return t, n, b, gen, err
}

func (s *Server) recvAppNumGen() (uint32, uint64, []byte, uint32, error) {
	s.dev.rec.Lock()
	p := s.primary
	var key []byte
	if p != nil {
		key = append([]byte(nil), p.kC2S...)
	}
	s.dev.rec.Unlock()
	if p == nil || len(key) == 0 {
		return 0, 0, nil, 0, ErrNotEstablished
	}
	defer zero(key)

	p.app.rxMu.Lock()
	defer p.app.rxMu.Unlock()
	// The device's memory bound: a compressed message decompresses to at most
	// its own MaxMsgPayload, which is what sled's envelope promises it.
	t, n, b, err := recvAppWith(p.conn, key, &p.app.rxNum, &p.app.rxStage, s.maxMsgPayload(), msDur(s.MidFrameBudgetMS), s.maxMsgPayload())
	if err != nil && !errors.Is(err, ErrRejected) && s.retired(p) {
		return 0, 0, nil, p.gen, ErrSessionClosed
	}
	return t, n, b, p.gen, err
}

// maxMsgPayload is §13's MAX_MSG_PAYLOAD for this server, clamped to
// SEND_QUEUE_MAX (§13 forbids a message the send queue could never hold) and
// floored so a misconfiguration bounds the device rather than muting it.
func (s *Server) maxMsgPayload() int {
	q := s.SendQueueMax
	if q <= 0 {
		q = SendQueueMaxDefault
	}
	m := s.MaxMsgPayload
	if m <= 0 {
		m = MaxMsgPayloadDefault
	}
	if m > q {
		m = q
	}
	if m > MaxAppPayload {
		m = MaxAppPayload
	}
	if min := padFloor + 16; m < min {
		m = min
	}
	return m
}
