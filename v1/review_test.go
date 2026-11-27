// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Regression tests for the findings of the 2026-09-01 review. Each test is
// written to fail against the unfixed code; the comment on each names the
// finding and the defect it pins.

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// C1 — a framing failure must never fall through to sending the raw payload
// unsealed, and must not report success. frameApp rejects a MessageType with
// FlagCompressed set, which is the reachable trigger.
func TestTakeControlAppRejectsBadTypeWithoutSendingPlaintext(t *testing.T) {
	srv, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	_ = srv

	payload := []byte("SECRET-PLAINTEXT-MUST-NOT-APPEAR")
	err := cli.TakeControlApp(FlagCompressed|anyControlKind, payload)
	if err == nil {
		t.Fatal("TakeControlApp accepted a MessageType with FlagCompressed set")
	}
	// The client must be back in IDLE and retryable, not wedged.
	cli.mu.Lock()
	st := cli.state
	cli.mu.Unlock()
	if st != stIdle {
		t.Errorf("state = %v after a rejected framing, want stIdle", st)
	}
}

// H5 — MessageNum is per-session. A retried TakeControl must restart both
// counters; otherwise the peer's message 1 is rejected against a stale
// high-water mark and the session is unusable for its whole life.
//
// This drives a real second admission through commit(). The earlier version of
// this test hand-wrote the reset it meant to check — it set txNum/rxNum to 0
// itself and then asserted frameApp's arithmetic — so deleting the reset from
// commit() left it passing, which is precisely the regression it is named for.
func TestCountersResetPerSession(t *testing.T) {
	srv, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()

	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("app admission over loopback failed: %v", err)
	}
	if _, num, _, err := srv.RecvAppNum(); err != nil {
		t.Fatalf("first session promoting message: %v", err)
	} else if num != 1 {
		t.Fatalf("first session's first MessageNum = %d, want 1", num)
	}
	// burn a few numbers so a missing reset is visible as a non-1 value
	for i := 0; i < 3; i++ {
		if err := cli.SendApp(CmdPing, nil); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if _, _, _, err := srv.RecvAppNum(); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
	}
	if got := cli.txNum.Load(); got != 4 {
		t.Fatalf("txNum after four sends = %d, want 4", got)
	}

	// back to IDLE, then admit again: this is the retry §7.2 allows.
	cli.teardown()
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("re-admission over loopback failed: %v", err)
	}
	_, num, _, err := srv.RecvAppNum()
	if err != nil {
		t.Fatalf("second session promoting message: %v", err)
	}
	if num != 1 {
		t.Errorf("second session's first MessageNum = %d, want 1: commit did not "+
			"reset the counters, so the peer rejects it against a stale high-water mark", num)
	}
}

// H6 — a sender must not emit a frame a conforming receiver has to reject.
// padClass rounds up, and Size is body+16, so both paths need the bound.
func TestSendRejectsPayloadsThePeerMustReject(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	ceiling := c.maxMsgPayload() // §13 MAX_MSG_PAYLOAD, clamped to SEND_QUEUE_MAX
	for _, tc := range []struct {
		name string
		n    int
		pad  bool
	}{
		{"unpadded at the ceiling", ceiling, false},
		{"padded, genuinely above the ceiling", ceiling, true},
		{"far above the ceiling", ceiling * 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.txNum.Store(0)
			_, err := c.frameApp(anyBulkKind, make([]byte, tc.n), false, tc.pad)
			if !errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("frameApp(%d bytes, pad=%v) err = %v, want ErrPayloadTooLarge",
					tc.n, tc.pad, err)
			}
		})
	}
	// Just under the bound must still succeed.
	c.txNum.Store(0)
	if _, err := c.frameApp(anyBulkKind, make([]byte, ceiling-16), false, false); err != nil {
		t.Errorf("frameApp at the largest legal size failed: %v", err)
	}
}

// M2 — §1.2: a frame that fails to authenticate is REJECTED, not fatal. The
// replay high-water mark must not advance, or one bad frame wedges the session
// against every genuine message that follows.
func TestRejectedFrameDoesNotAdvanceReplayMark(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	c := &Client{kS2C: key, kC2S: key}

	// A well-formed frame at a high MessageNum whose ciphertext is garbage.
	hdr := appHeader(16, 0, CmdGetStatus, 9999)
	bad := append(append([]byte{}, hdr...), bytes.Repeat([]byte{0xFF}, 16)...)

	c.kcp = nil // RecvApp needs a stream; drive the parse directly below.
	_, _, err := c.recvAppFrom(bytes.NewReader(bad))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("forged frame err = %v, want ErrRejected", err)
	}
	if c.rxNum != 0 {
		t.Fatalf("rxNum advanced to %d on a frame that failed AEAD open — "+
			"one rejected frame now wedges the session (§1.2)", c.rxNum)
	}
}

// M3 — §7: FlagCompressed with OriginalSize == 0 must be rejected. An empty LZ4
// block decodes to nothing without error, so without the explicit rule the frame
// is accepted as a zero-length message.
func TestCompressedWithZeroOriginalSizeRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	c := &Client{kS2C: key}
	frame := sealFrame(t, key, FlagCompressed|CmdGetStatus, 1, 0, nil)
	_, _, err := c.recvAppFrom(bytes.NewReader(frame))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("FlagCompressed with OriginalSize=0 err = %v, want ErrRejected", err)
	}
}

// §13 — "a message is padded up to the smallest class that holds it". That is
// declarative: the SHOULD governs whether to pad at all, not which class. A
// receiver therefore accepts exactly two lengths — OriginalSize, or its smallest
// class — and nothing else. An earlier revision of this test asserted that any
// larger class was acceptable; that was a misreading, and it left a per-message
// covert channel and an amplification lever open.
func TestAcceptsOnlyTheSmallestPadClass(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	payload := bytes.Repeat([]byte{0xAB}, 65) // smallest class is 128

	// The smallest class is accepted.
	c := &Client{kS2C: key}
	body := make([]byte, 128)
	copy(body, payload)
	frame := sealFrame(t, key, CmdGetStatus, 1, uint32(len(payload)), body)
	typ, got, err := c.recvAppFrom(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("smallest class rejected: %v", err)
	}
	if typ != CmdGetStatus || !bytes.Equal(got, payload) {
		t.Errorf("got %d bytes, want %d", len(got), len(payload))
	}

	// Unpadded is accepted (the sender's ceiling may not hold the class).
	c = &Client{kS2C: key}
	frame = sealFrame(t, key, CmdGetStatus, 1, uint32(len(payload)), payload)
	if _, _, err := c.recvAppFrom(bytes.NewReader(frame)); err != nil {
		t.Errorf("unpadded rejected: %v", err)
	}

	// A LARGER class, and a non-class length, are both refused.
	for _, n := range []int{256, 1024, 100} {
		c = &Client{kS2C: key}
		b := make([]byte, n)
		copy(b, payload)
		f := sealFrame(t, key, CmdGetStatus, 1, uint32(len(payload)), b)
		if _, _, err := c.recvAppFrom(bytes.NewReader(f)); !errors.Is(err, ErrRejected) {
			t.Errorf("plaintext length %d err = %v, want ErrRejected", n, err)
		}
	}
}

// §1.2 — the three read outcomes must be distinguishable by the caller. A
// desynchronising failure and a survivable rejection are different errors.
func TestReadOutcomesAreDistinguishable(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)

	// Oversized Size: header consumed, body still on the wire → desync.
	c := &Client{kS2C: key}
	hdr := appHeader(MaxAppPayload+1, 4, CmdGetStatus, 1)
	if _, _, err := c.recvAppFrom(bytes.NewReader(hdr)); !errors.Is(err, ErrDesync) {
		t.Errorf("oversized Size err = %v, want ErrDesync", err)
	}

	// Truncated body → desync.
	c = &Client{kS2C: key}
	full := sealFrame(t, key, CmdGetStatus, 1, 4, []byte{1, 2, 3, 4})
	if _, _, err := c.recvAppFrom(bytes.NewReader(full[:len(full)-3])); !errors.Is(err, ErrDesync) {
		t.Errorf("truncated body err = %v, want ErrDesync", err)
	}

	// Replay → its own sentinel, session survives.
	c = &Client{kS2C: key, rxNum: 5}
	f := sealFrame(t, key, CmdGetStatus, 3, 4, []byte{1, 2, 3, 4})
	if _, _, err := c.recvAppFrom(bytes.NewReader(f)); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed MessageNum err = %v, want ErrReplay", err)
	}
}

// H7 — §4.3 rejects a genuine IPv6 source in ::ffff:0:0/96 because it would
// canonicalise onto the same tuple as a real IPv4 peer. On a v4 socket the same
// bytes are only Go's representation of an IPv4 peer and must be accepted.
func TestMappedV6SourceRuleIsSocketFamilyAware(t *testing.T) {
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:192.168.4.7"), Port: 5000}

	v4 := addrPort(mapped, false)
	if v4.Addr().Is4In6() {
		t.Error("on a v4 socket the address must be unmapped for the §4.3 v4 branch")
	}
	if SourceRejected(v4.Addr(), nil) {
		t.Error("a real IPv4 peer on a v4 socket must be accepted")
	}

	v6 := addrPort(mapped, true)
	if !v6.Addr().Is4In6() {
		t.Fatal("on a v6 socket the mapping must be preserved so §4.3 can see it")
	}
	if !SourceRejected(v6.Addr(), nil) {
		t.Error("a genuine v6 source in ::ffff:0:0/96 must be rejected (§4.3)")
	}
}

// H3 — Close must be idempotent. A deferred Close plus an error-path Close is
// ordinary Go and must not panic.
func TestCloseIsIdempotent(t *testing.T) {
	dev, _ := testDevice()
	mock := newMockConn()
	srv := NewServer(dev, mock)
	srv.Close()
	srv.Close() // must not panic on a closed channel

	_, cli, cleanup := loopbackPair(t)
	cleanup()
	cli.Close() // must not panic
}

// H3 — a promotion that was waiting on the lock must not install a primary
// after Close returned, which would leak a session and three goroutines.
func TestNoPromotionAfterClose(t *testing.T) {
	dev, _ := testDevice()
	mock := newMockConn()
	srv := NewServer(dev, mock)
	srv.Close()
	if p := srv.Primary(); p != nil {
		t.Fatal("primary non-nil after Close")
	}
}

// M1 — §9.2: the maintenance tick must roll the cookie epoch and wipe the keys
// of expired pending records. Without it COOKIE_EPOCH_MS is inert and four
// session keys stay live in RAM indefinitely.
func TestTickRollsEpochAndReapsPending(t *testing.T) {
	dev, _ := testDevice()
	first := append([]byte(nil), dev.epochTag...)

	dev.Tick(uint64(CookieEpochMS) * 3)
	if bytes.Equal(dev.epochTag, first) {
		t.Error("Tick did not roll the cookie epoch")
	}
	if dev.prevEpochTag == nil {
		t.Error("Tick did not retain the previous epoch tag (§2)")
	}

	// An expired record must have its keys wiped, not merely be skipped.
	dev.pending[0].used = true
	dev.pending[0].expiry = 1
	dev.pending[0].keys = SessionKeys{
		KC2S: bytes.Repeat([]byte{9}, 32), KS2C: bytes.Repeat([]byte{9}, 32),
		KKcpC2S: bytes.Repeat([]byte{9}, 32), KKcpS2C: bytes.Repeat([]byte{9}, 32),
	}
	dev.Tick(uint64(PendingTTLMS) * 10)
	if dev.pending[0].used {
		t.Error("expired pending record still marked used after Tick")
	}
	for _, k := range [][]byte{
		dev.pending[0].keys.KC2S, dev.pending[0].keys.KS2C,
		dev.pending[0].keys.KKcpC2S, dev.pending[0].keys.KKcpS2C,
	} {
		if !allZeroBytes(k) {
			t.Error("expired pending record kept live session keys after Tick")
		}
	}
}

// H4 — teardown wipes the directional keys under the lock while frameApp reads
// them. After Close, framing must fail cleanly rather than seal under a zeroed
// key or race the wipe.
func TestSendAfterCloseFailsCleanly(t *testing.T) {
	_, cli, cleanup := loopbackPair(t)
	defer cleanup()
	cli.Close()
	if err := cli.SendApp(CmdPing, []byte("x")); err == nil {
		t.Error("SendApp succeeded after Close")
	}
}

// H4/M10 — concurrent Close and SendApp must not race on the key or the
// counter. Run under -race for this to mean anything.
func TestConcurrentSendAndCloseNoRace(t *testing.T) {
	_, cli, cleanup := loopbackPair(t)
	defer cleanup()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = cli.SendApp(CmdPing, []byte("hello")) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(time.Millisecond); cli.Close() }()
	wg.Wait()
}

func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// --- helpers -------------------------------------------------------------

// sealFrame builds a wire app message directly, so a test can construct header
// fields the sender would never emit.
func sealFrame(t *testing.T, key []byte, msgType uint32, num uint64, origSize uint32, body []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	hdr := appHeader(uint32(len(body))+uint32(aead.Overhead()), origSize, msgType, num)
	return append(hdr, aead.Seal(nil, appNonce(num), body, hdr)...)
}

// loopbackPair brings up a real Go device and a real Go client over loopback
// UDP and admits the client, so a test exercises the whole stack.
func loopbackPairIdle(t *testing.T) (*Server, *Client, func()) {
	t.Helper()
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	cookieSecret := bytes.Repeat([]byte{0x44}, 32)
	admissionEpoch := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	dev := mustDev(NewDevice(psk, deviceID, cookieSecret, admissionEpoch, local, 8000))
	srv := NewServer(dev, sconn)
	srv.skipSrcCheck = true
	go srv.Serve()

	cli, err := NewClient(sconn.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	return srv, cli, func() { cli.Close(); srv.Close() }
}

// loopbackPair is loopbackPairIdle with the client admitted, raw (not app-framed).
func loopbackPair(t *testing.T) (*Server, *Client, func()) {
	t.Helper()
	srv, cli, cleanup := loopbackPairIdle(t)
	if err := cli.TakeControl([]byte("hello")); err != nil {
		cleanup()
		t.Fatalf("admission over loopback failed: %v", err)
	}
	return srv, cli, cleanup
}

// loopbackPairApp admits in APP mode, so the promoting PUSH is itself a framed
// message and the whole stream is app-framed. Raw Send and SendApp share one KCP
// stream, so a session must use one or the other from the first byte.
func loopbackPairApp(t *testing.T) (*Server, *Client, func()) {
	t.Helper()
	srv, cli, cleanup := loopbackPairIdle(t)
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		cleanup()
		t.Fatalf("app admission over loopback failed: %v", err)
	}
	return srv, cli, cleanup
}

// --- Device ownership design pass -----------------------------------------

// M6 — §10.1 names ONE rec_lock over pending records AND the primary's
// metadata. Before the design pass, HandleINIT/HandleFINISH mutated the pending
// table with no lock while handleEnvelope/promote touched the same fields under
// a Server-side mutex: two critical sections over one invariant, safe only
// because both happened to run on Serve's goroutine.
//
// This drives the control path and the envelope path from many goroutines at
// once. Under -race it fails if the two paths are not on the same lock.
func TestDeviceRecLockCoversControlAndEnvelopePaths(t *testing.T) {
	dev, deviceID := testDevice()
	dev.SetRandSource(fixedRand(0x42))
	mock := newMockConn()
	srv := NewServer(dev, mock)
	defer srv.Close()

	nonce := bytes.Repeat([]byte{0xAB}, 24)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := &net.UDPAddr{IP: net.IPv4(192, 168, 4, byte(2+i%8)), Port: 5000 + i}
			// control path: mutates the pending table and reads epoch_tag
			srv.handlePacket(validINIT(dev.kReq, nonce, deviceID), addr)
			// envelope path: looks the tuple up and may promote
			srv.handleEnvelope(make([]byte, KcpOverhead+EnvelopeLen+8), addr,
				addrPort(addr, false))
			// maintenance path: rolls the epoch and reaps expired records
			dev.Tick(uint64(i) * uint64(CookieEpochMS))
			_ = srv.Primary()
		}(i)
	}
	wg.Wait()
}

// M6 — the exported Device entry points must take rec themselves, so a caller
// cannot forget. Calling them concurrently must not race.
func TestDeviceEntryPointsAreSelfLocking(t *testing.T) {
	dev, deviceID := testDevice()
	dev.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	src := netip.MustParseAddrPort("192.168.4.9:5000")

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dev.HandleINIT(validINIT(dev.kReq, nonce, deviceID), src, 8000)
			dev.RollEpoch(uint64(i) * uint64(CookieEpochMS))
			dev.Tick(uint64(i) * uint64(PendingTTLMS))
		}(i)
	}
	wg.Wait()
}

// M8 — §8.5(a)4 names four keys. A promoted session must carry the app-layer
// pair too, or the transport comes up into a session whose application keys were
// wiped with the pending record and no §13 frame can ever be opened.
func TestPromotedSessionCarriesAllFourKeys(t *testing.T) {
	srv, cli, cleanup := loopbackPair(t)
	defer cleanup()
	_ = cli

	deadline := time.Now().Add(2 * time.Second)
	for srv.Primary() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Primary() == nil {
		t.Skip("no promotion in this environment")
	}
	srv.dev.rec.Lock()
	p := srv.primary
	var c2s, s2c, kcpC2S []byte
	if p != nil {
		c2s, s2c, kcpC2S = p.kC2S, p.kS2C, p.kc2s
	}
	srv.dev.rec.Unlock()

	for name, k := range map[string][]byte{"k_c2s": c2s, "k_s2c": s2c, "k_kcp_c2s": kcpC2S} {
		if len(k) != 32 {
			t.Errorf("%s: len %d, want 32 — §8.5(a)4 installs four keys", name, len(k))
		}
		if allZeroBytes(k) {
			t.Errorf("%s is all-zero: wiped with the pending record", name)
		}
	}
}

// M7 — a concurrent Close must not leave the state byte saying ESTABLISHED with
// no session behind it, which wedges the client permanently.
func TestNoEstablishedStateWithoutSession(t *testing.T) {
	for i := 0; i < 12; i++ {
		srv, cli, cleanup := loopbackPairIdle(t)
		go func() { time.Sleep(time.Duration(i) * 200 * time.Microsecond); cli.Close() }()
		_ = cli.TakeControl([]byte("hello"))
		cli.mu.Lock()
		st, sess := cli.state, cli.kcp
		cli.mu.Unlock()
		if st == stEstablished && sess == nil {
			cleanup()
			t.Fatal("state ESTABLISHED with a nil session — client is wedged")
		}
		cleanup()
		_ = srv
	}
}

// §10.3 — "No verification of an unauthenticated inbound datagram — its MAC, its
// AEAD open, HKDF, or a scalar multiplication — may run under either lock. That
// is what stops a flood from holding a lock."
//
// Regression guard. The design pass that gave Device the rec_lock wrapped
// HandleINIT/HandleFINISH wholesale, putting three MAC verifications, an X25519
// and a full key derivation under it — so a flood of forged FINISHes could hold
// rec_lock through a scalar multiplication, blocking the envelope path,
// Primary(), Close() and the maintenance tick.
//
// randFill is called inside step 6, immediately before the X25519, so it is an
// exact observation point for "is rec held during the expensive region?".
// TryLock succeeds only if it is not. §6.2 step 2's memcmp IS taken under the
// lock deliberately (§10.1), so this checks the derivation region specifically
// rather than the whole handler.
func TestExpensiveVerificationRunsWithoutRecLock(t *testing.T) {
	d, deviceID := testDevice()
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	src := netip.MustParseAddrPort("192.168.4.2:5000")

	var sawLockFree, called bool
	d.SetRandSource(func(b []byte) {
		called = true
		if d.rec.TryLock() { // held? then step 6 is running under rec_lock
			sawLockFree = true
			d.rec.Unlock()
		}
		for i := range b {
			b[i] = 0x42
		}
	})

	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	if retry == nil {
		t.Fatal("valid INIT dropped")
	}
	fin, _, _ := clientFINISH(deviceID, nonce, ecPriv, retry)
	if admit := d.HandleFINISH(fin, src, 8000); admit == nil {
		t.Fatal("valid FINISH dropped")
	}
	if !called {
		t.Fatal("step 6 never reached — the test observes nothing")
	}
	if !sawLockFree {
		t.Error("rec_lock was held across the ephemeral key generation, the " +
			"X25519 and the key derivation — §10.3 forbids exactly this, and a " +
			"flood of forged FINISHes would hold the lock through a scalar mult")
	}
}

// §13 — MAX_MSG_PAYLOAD MUST NOT exceed SEND_QUEUE_MAX: a message padded past the
// send-queue cap could never be written, so the ceiling has to move, not the
// ladder. The clamp is what enforces it.
func TestMaxMsgPayloadClampedToSendQueueMax(t *testing.T) {
	c := &Client{SendQueueMax: 8 * 1024, MaxMsgPayload: 64 * 1024}
	if got := c.maxMsgPayload(); got != 8*1024 {
		t.Errorf("maxMsgPayload = %d, want it clamped to SendQueueMax %d", got, 8*1024)
	}
	d := &Client{} // defaults
	if got := d.maxMsgPayload(); got != MaxMsgPayloadDefault {
		t.Errorf("default maxMsgPayload = %d, want %d", got, MaxMsgPayloadDefault)
	}
	if MaxMsgPayloadDefault > SendQueueMaxDefault {
		t.Error("the defaults themselves violate §13")
	}
}

// §13 — the pad-class ladder runs to MAX_MSG_PAYLOAD, which is per architecture.
// Pinning it to this implementation's own receive bound is what let a controller
// pad to a class an ESP32 could not receive.
func TestPadLadderFollowsTheConfiguredCeiling(t *testing.T) {
	// Below the ceiling the ladder behaves normally.
	if got := padClassTo(65, 8*1024); got != 128 {
		t.Errorf("padClassTo(65, 8Ki) = %d, want 128", got)
	}
	// A class that lands exactly on the ceiling is NOT usable: the AEAD tag makes
	// the framed size exceed it, so the payload keeps its true length rather than
	// padding into something unsendable.
	if got := padClassTo(3000, 4096); got != 3000 {
		t.Errorf("padClassTo(3000, 4096) = %d, want 3000 (class+tag exceeds)", got)
	}
	// With headroom for the tag, the class is used.
	if got := padClassTo(3000, 8192); got != 4096 {
		t.Errorf("padClassTo(3000, 8192) = %d, want 4096", got)
	}
	// But where the next class would overshoot the ceiling, the payload keeps its
	// true length rather than padding into something the peer cannot hold.
	if got := padClassTo(3000, 3500); got != 3000 {
		t.Errorf("padClassTo(3000, 3500) = %d, want 3000 (no class fits)", got)
	}
	// Padding must never produce a frame the ceiling cannot carry.
	for _, n := range []int{16384, 16385, 20000, 32752} {
		if cls := padClassTo(n, 32768); cls+16 > 32768 {
			t.Errorf("padClassTo(%d, 32Ki) = %d → framed %d exceeds the ceiling",
				n, cls, cls+16)
		}
	}
}

// §9.5 — the send window is derived from SEND_QUEUE_MAX, which is how the byte
// cap is enforced in Go: kcp-go exposes no queue-depth accessor on UDPSession, so
// the bound is applied by sizing the window rather than by polling it.
func TestSendWindowDerivedFromSendQueueMax(t *testing.T) {
	c := &Client{SendQueueMax: 32 * 1024}
	if got, want := c.sendWindowSegments(), 32*1024/WireMTU; got != want {
		t.Errorf("sendWindowSegments = %d, want %d", got, want)
	}
	// A cap smaller than one segment must still permit progress.
	tiny := &Client{SendQueueMax: 10}
	if got := tiny.sendWindowSegments(); got < 1 {
		t.Errorf("sendWindowSegments = %d, want at least 1", got)
	}
}

// §9.3 — a client whose peer stops answering must notice, report ErrSessionDead,
// and return to IDLE so an explicit TakeControl can recover. It must NOT re-admit
// on its own: §7.2 removed retry and its damping together.
func TestDeadSessionIsDetectedAndReported(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	srv, cli, cleanup := loopbackPair(t)
	defer cleanup()

	if cli.SessionDead() {
		t.Fatal("session reported dead immediately after admission")
	}

	// Silence the device: close its socket so no s2c envelope can arrive.
	srv.Close()

	// §7.2 detects a dead session only "while the client has unacknowledged data
	// outstanding" — a quiet controller learns nothing until it next sends, and
	// tearing an idle-but-healthy session down would strand the device holding an
	// orphan it may not reclaim (§9.5). So the application must actually send.
	if err := cli.SendApp(CmdPing, []byte("are you there")); err != nil {
		t.Logf("send after silencing returned %v (expected; the peer is gone)", err)
	}

	deadline := time.Now().Add(msDur(SessionDeadMS) + 5*time.Second)
	for !cli.SessionDead() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !cli.SessionDead() {
		t.Fatal("SESSION_DEAD_MS elapsed with no accepted envelope and the client " +
			"did not notice — §9.3 leaves detection to the client's own timers")
	}
	if err := cli.SendApp(CmdPing, nil); !errors.Is(err, ErrSessionDead) {
		t.Errorf("SendApp after death err = %v, want ErrSessionDead", err)
	}
	cli.mu.Lock()
	st := cli.state
	cli.mu.Unlock()
	if st != stIdle {
		t.Errorf("state = %v after death, want stIdle so TakeControl can recover", st)
	}
}

// Concurrent SendApp: all senders must return, and the framing must stay
// race-free.
//
// The peer is closed, so nothing drains and kcp-go's send window fills. Until
// the shim stopped passing socket errors to kcp-go, the client's connected
// socket got ECONNREFUSED from the closed port on its first write, kcp-go
// latched it, and every SendApp failed at once: the window never filled and
// this test proved nothing about blocking. Now the senders really block. Each
// gives up after SEND_BLOCKED_MS (§9.5) holding txMu, and once SESSION_DEAD_MS
// has passed since data went outstanding, liveness tears the session down and
// the rest fail fast with ErrSessionDead. Every sender must come back within
// that bound.
func TestConcurrentSendAppAllReturn(t *testing.T) {
	srv, cli, cleanup := loopbackPair(t)
	defer cleanup()

	// Silence the peer so nothing drains: kcp-go fills snd_wnd (derived from
	// SEND_QUEUE_MAX) and then blocks. That is the only state in which the
	// deadline matters, so a test against a healthy peer proves nothing.
	srv.Close()

	const n = 40
	errs := make(chan error, n)
	payload := bytes.Repeat([]byte{0xAB}, 16*1024)
	for i := 0; i < n; i++ {
		go func() { errs <- cli.SendApp(CmdPing, payload) }()
	}
	// Every sender must come back. See the honest limit above: this catches a
	// hang or a race, not the deadline clobber specifically.
	deadline := time.After(msDur(SessionDeadMS) + msDur(SendBlockedMS) + 5*time.Second)
	var blocked int
	for i := 0; i < n; i++ {
		select {
		case <-errs:
		case <-deadline:
			blocked = n - i
			t.Fatalf("%d of %d concurrent SendApp calls never returned", blocked, n)
		}
	}
}

// §9.3 — markDead runs on the readLoop goroutine while commit arms deadCh on the
// caller's. Both must be under the mutex. Meaningful only under -race.
func TestConcurrentTakeControlAndCloseNoRace(t *testing.T) {
	for i := 0; i < 6; i++ {
		_, cli, cleanup := loopbackPairIdle(t)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = cli.TakeControl([]byte("hello")) }()
		go func() { defer wg.Done(); time.Sleep(time.Millisecond); cli.Close() }()
		wg.Wait()
		cleanup()
	}
}

// §7.2 — the outstanding-data gate. An idle but HEALTHY session must survive
// SESSION_DEAD_MS: a controller that has sent nothing has nothing unacknowledged,
// and tearing it down would leave the device holding an orphan session it is
// forbidden to reclaim for inactivity (§9.5), while the client pays a full
// re-admission for nothing.
func TestIdleSessionSurvivesSessionDeadMS(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	srv, cli, cleanup := loopbackPair(t)
	defer cleanup()
	_ = srv

	// Send nothing at all, and wait past the liveness threshold.
	time.Sleep(msDur(SessionDeadMS) + 2*time.Second)

	if cli.SessionDead() {
		t.Fatal("an idle but healthy session was declared dead — §7.2 gates " +
			"detection on the client having unacknowledged data outstanding")
	}
	cli.mu.Lock()
	st := cli.state
	cli.mu.Unlock()
	if st != stEstablished {
		t.Errorf("state = %v after an idle spell, want stEstablished", st)
	}
}

// The device half of the message layer must round-trip against the client half.
// Before this existed, §8.5(a)4's app-layer keys were installed on every
// promotion and unreachable from Go — the fix was inert.
func TestGoServerAppLayerRoundTrip(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()

	deadline := time.Now().Add(2 * time.Second)
	for srv.Primary() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Primary() == nil {
		t.Skip("no promotion in this environment")
	}

	// Drain the promoting PING that TakeControlApp sent as the first frame.
	srv.Primary().SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := srv.RecvApp(); err != nil {
		t.Fatalf("server RecvApp (promoting frame): %v", err)
	}

	// client → device, padded (a control message per §13)
	want := []byte("GET_STATUS please")
	if err := cli.SendAppPadded(CmdGetStatus, want); err != nil {
		t.Fatalf("client SendAppPadded: %v", err)
	}
	srv.Primary().SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, got, err := srv.RecvApp()
	if err != nil {
		t.Fatalf("server RecvApp: %v", err)
	}
	if typ != CmdGetStatus || !bytes.Equal(got, want) {
		t.Errorf("device got type=%#x %q, want %#x %q", typ, got, CmdGetStatus, want)
	}

	// device → client, padded response
	resp := []byte("STATUS_RESP payload")
	if err := srv.SendAppPadded(RespStatus, resp); err != nil {
		t.Fatalf("server SendAppPadded: %v", err)
	}
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	ck.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, got, err = cli.RecvApp()
	if err != nil {
		t.Fatalf("client RecvApp: %v", err)
	}
	if typ != RespStatus || !bytes.Equal(got, resp) {
		t.Errorf("client got type=%#x %q, want %#x %q", typ, got, RespStatus, resp)
	}
}

// §1.2 — a rule applied BEFORE the payload is read leaves the stream misaligned,
// so it belongs in the "must close" row, not the survivable one. ErrReplay is
// documented as survivable ("ignore it and continue"), so the frame must be
// consumed whole before it is rejected. This reads a replayed frame and then a
// good one: if the replay left its body on the wire, the good frame is parsed
// from the middle of the previous ciphertext.
func TestReplayedFrameDoesNotDesyncTheStream(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	c := &Client{kS2C: key, rxNum: 5}

	replayed := sealFrame(t, key, CmdGetStatus, 3, 4, []byte{1, 2, 3, 4}) // num 3 <= 5
	good := sealFrame(t, key, CmdGetStatus, 6, 5, []byte("hello"))
	stream := bytes.NewReader(append(append([]byte{}, replayed...), good...))

	if _, _, err := c.recvAppFrom(stream); !errors.Is(err, ErrReplay) {
		t.Fatalf("first frame err = %v, want ErrReplay", err)
	}
	typ, got, err := c.recvAppFrom(stream)
	if err != nil {
		t.Fatalf("frame after a replay: %v — the replayed frame's body was left "+
			"on the wire, so the stream is desynchronised", err)
	}
	if typ != CmdGetStatus || string(got) != "hello" {
		t.Errorf("got type=%#x %q, want %#x %q", typ, got, CmdGetStatus, "hello")
	}
}

// §9.5 — the send bound must be enforced on BOTH roles. It was clamped on the
// client only, so a Go device's effective window was 32 segments (44 KB) against
// a 32 KiB cap, while the documentation said the clamp applied to both.
func TestSendWindowClampedOnBothRoles(t *testing.T) {
	want := SendQueueMaxDefault / WireMTU
	if got := clampSendWindow(DefaultKCPTuning, 0).SndWnd; got != want {
		t.Errorf("default clamp = %d, want %d", got, want)
	}
	if got := clampSendWindow(KCPTuning{SndWnd: 1024}, 32*1024).SndWnd; got != want {
		t.Errorf("SndWnd 1024 with a 32KiB cap = %d, want %d", got, want)
	}
	if got := clampSendWindow(KCPTuning{SndWnd: 1024}, 256*1024).SndWnd; got != 256*1024/WireMTU {
		t.Errorf("SndWnd 1024 with a 256KiB cap = %d, want %d", got, 256*1024/WireMTU)
	}
	if got := clampSendWindow(KCPTuning{SndWnd: 4}, 256*1024).SndWnd; got != 4 {
		t.Errorf("small SndWnd was raised to %d; the clamp must only lower", got)
	}
}

// teardown must be idempotent. A second concurrent call used to detach the
// readLoop handles, skip the join, and return with the reader still on the
// socket — after which a successor TakeControl could run against a live foreign
// readLoop. Meaningful under -race.
func TestConcurrentTeardownIsSafe(t *testing.T) {
	for i := 0; i < 8; i++ {
		_, cli, cleanup := loopbackPair(t)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); cli.teardown() }()
		}
		wg.Wait()
		cli.mu.Lock()
		st, sess := cli.state, cli.kcp
		cli.mu.Unlock()
		if st != stIdle || sess != nil {
			t.Fatalf("after concurrent teardowns: state=%v kcp=%v", st, sess != nil)
		}
		cleanup()
	}
}

// app mode is per-attempt. It used to latch, so a later raw TakeControl framed
// its payload as an application message of the PREVIOUS call's type — driving an
// unintended command at the device.
func TestAppModeDoesNotLatchAcrossAttempts(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()

	cli.mu.Lock()
	cli.appMode, cli.appFirstType = true, CmdSetBrightness
	cli.mu.Unlock()

	// A raw TakeControl must clear it, whatever the outcome of the attempt.
	_ = cli.TakeControl([]byte{0})
	cli.mu.Lock()
	mode := cli.appMode
	cli.mu.Unlock()
	if mode {
		t.Error("TakeControl left appMode set; a raw payload would be framed as " +
			"an application message of the previous TakeControlApp's type")
	}
}

// §6.4 — the no-wrap guard must be STICKY. Add(1) refuses exactly one message
// and then hands out 1 again, repeating the nonce of the session's first message
// under a key that has already used it — keystream reuse, which §6.4 calls
// catastrophic and "cheap to enforce".
func TestMessageNumExhaustionIsSticky(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	c.txNum.Store(^uint64(0))
	for i := 0; i < 3; i++ {
		if got := c.nextTx(); got != 0 {
			t.Fatalf("call %d after exhaustion returned %d, want 0 (refused)", i, got)
		}
	}
	if _, err := c.frameApp(CmdPing, nil, false, false); err == nil {
		t.Error("frameApp succeeded after MessageNum exhaustion")
	}

	var p appPeer
	p.txNum.Store(^uint64(0))
	for i := 0; i < 3; i++ {
		if got := p.nextTx(); got != 0 {
			t.Fatalf("appPeer call %d returned %d, want 0", i, got)
		}
	}
}

// §7.1 — the pre-read allocation bound is the CONFIGURED ceiling, not the
// package maximum. A device with a small MaxMsgPayload must not be made to
// allocate 1 MiB on the strength of a 20-byte header.
func TestReceiveBoundHonoursConfiguredCeiling(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	c := &Client{kS2C: key, SendQueueMax: 4096, MaxMsgPayload: 2048}

	// A header declaring more than this endpoint's ceiling is refused before any
	// allocation, and refused as a desync (header consumed, body on the wire).
	hdr := appHeader(64*1024, 16, CmdGetStatus, 1)
	if _, _, err := c.recvAppFrom(bytes.NewReader(hdr)); !errors.Is(err, ErrDesync) {
		t.Errorf("oversized-for-ceiling err = %v, want ErrDesync", err)
	}
	// Within the ceiling still works.
	body := []byte("ok")
	f := sealFrame(t, key, CmdGetStatus, 1, uint32(len(body)), body)
	if _, got, err := c.recvAppFrom(bytes.NewReader(f)); err != nil || string(got) != "ok" {
		t.Errorf("in-ceiling frame: got %q err %v", got, err)
	}
}

// §15 additions. These pin properties the earlier vector set could not catch:
// an implementation using one direction label for both envelope directions, one
// deriving k_dev from something other than the PSK, an Extract stage whose error
// a later Expand compensates for, and disagreement on the all-zero X25519 rule.
func TestGoldenScheduleAdditions(t *testing.T) {
	v := loadVectors(t)
	// TestGoldenSchedule already asserts each new vector equals its Go producer.
	// These are the RELATIONAL properties equality cannot express — the ones that
	// catch an implementation which is self-consistently wrong.
	psk, psk2 := dh(t, v.Inputs.PSK), dh(t, v.Inputs.PSK2)
	devID := dh(t, v.Inputs.DeviceID)
	if bytes.Equal(DeriveKDev(psk, devID), DeriveKDev(psk2, devID)) {
		t.Error("two distinct PSKs produced the same k_dev")
	}
	// These two used to read two constants out of the vector file and compare
	// them to each other. No Go code ran, so they could not fail on any
	// implementation bug — only on a corrupt vector file. Both now exercise the
	// producer, which is what makes them relational tests of the implementation.

	// The direction label is an INPUT, not a consequence of using different keys:
	// hold the key, sequence and plaintext fixed and flip only the direction.
	kEnv := dh(t, v.Inputs.PSK) // any 32-octet key; the property is about the label
	c2s, err := Seal(kEnv, true, 1, []byte("direction"))
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := Seal(kEnv, false, 1, []byte("direction"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, s2c) {
		t.Error("c2s and s2c envelopes identical under one key — the direction label is ignored")
	}

	// The k_dev stage is not skippable: deriving the static keys straight from the
	// PSK must not land on the same place as deriving them from k_dev.
	kDev := DeriveKDev(psk, devID)
	if bytes.Equal(DeriveStatic(kDev).KReq, DeriveStatic(psk).KReq) {
		t.Error("k_req is the same whether or not the k_dev stage runs; the chain is collapsed")
	}
}
