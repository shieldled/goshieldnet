// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Regression tests for the second goshieldnet review. Each test was first
// written against the unfixed code and failed there; see CHANGELOG.md.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A cookie is bounded by the caller's clock, not by how often Tick runs: one
// minted at t=8 s is refused an hour later even though no tick ran, and a FINISH
// within the epoch window is still admitted.
func TestCookieBoundedByClockNotTick(t *testing.T) {
	d, deviceID := testDevice() // nowMS 8000 -> epoch 2
	d.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	fin, _, _ := clientFINISH(deviceID, nonce, bytes.Repeat([]byte{7}, 32), retry)
	if admit := d.HandleFINISH(fin, src, 8000+3600*1000); admit != nil {
		t.Fatal("FINISH with a cookie from an hour ago was admitted (no tick ran)")
	}
	if admit := d.HandleFINISH(fin, src, 8000+CookieEpochMS); admit == nil {
		t.Fatal("FINISH one epoch later was refused; the previous epoch must stay valid")
	}
}

// INIT minted after a stalled tick uses the caller's epoch, so its FINISH is
// admitted even though the cached tags are many epochs old.
func TestCookieMintedFromClockAfterStalledTick(t *testing.T) {
	d, deviceID := testDevice() // cache holds epoch 2
	d.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAC}, 24)
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	now := uint64(8000 + 100*CookieEpochMS)
	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, now)
	f, err := DecodeRETRY(retry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.EpochTag, EpochTag(d.cookieSecret, be4(uint32(now/CookieEpochMS)))) {
		t.Fatal("RETRY was not minted under the clock's epoch")
	}
	fin, _, _ := clientFINISH(deviceID, nonce, bytes.Repeat([]byte{7}, 32), retry)
	if d.HandleFINISH(fin, src, now+10) == nil {
		t.Fatal("FINISH for a cookie minted from the clock was refused")
	}
}

// §4.3 is applied by the Device handlers themselves, as C does; SetSourceCheck
// turns it off for a loopback harness.
func TestDeviceHandlersRejectSources(t *testing.T) {
	d, deviceID := testDevice()
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	for _, s := range []string{"255.255.255.255:5000", "192.168.4.255:5000", "224.0.0.1:5000", "192.168.4.1:5000", "0.0.0.0:5000"} {
		if r := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), netip.MustParseAddrPort(s), 8000); r != nil {
			t.Errorf("RETRY minted for rejected source %s", s)
		}
		if a := d.HandleFINISH(make([]byte, 256), netip.MustParseAddrPort(s), 8000); a != nil {
			t.Errorf("FINISH answered for rejected source %s", s)
		}
	}
	if d.HandleINIT(validINIT(d.kReq, nonce, deviceID), netip.MustParseAddrPort("192.168.4.2:5000"), 8000) == nil {
		t.Error("an ordinary source was refused")
	}
	d.SetSourceCheck(false)
	if d.HandleINIT(validINIT(d.kReq, nonce, deviceID), netip.MustParseAddrPort("192.168.4.1:5000"), 8000) == nil {
		t.Error("SetSourceCheck(false) did not turn the check off")
	}
}

// Key material of the wrong width or value is refused instead of deriving keys
// anyone can compute or panicking later.
func TestConstructorsRejectBadKeyMaterial(t *testing.T) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cs := bytes.Repeat([]byte{0x22}, 32)
	ae := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	bad := []struct {
		name            string
		psk, id, cs, ae []byte
	}{
		{"nil psk", nil, id, cs, ae},
		{"short psk", psk[:16], id, cs, ae},
		{"zero psk", make([]byte, 32), id, cs, ae},
		{"short device_id", psk, id[:7], cs, ae},
		{"nil cookie_secret", psk, id, nil, ae},
		{"zero cookie_secret", psk, id, make([]byte, 32), ae},
		{"short admission_epoch", psk, id, cs, ae[:4]},
		{"zero admission_epoch", psk, id, cs, make([]byte, 8)},
		{"admission_epoch top bits", psk, id, cs, []byte{1, 0, 0, 0, 0, 0, 0, 1}},
	}
	for _, b := range bad {
		if _, err := NewDevice(b.psk, b.id, b.cs, b.ae, nil, 0); !errors.Is(err, ErrBadKeyMaterial) {
			t.Errorf("NewDevice(%s): err = %v, want ErrBadKeyMaterial", b.name, err)
		}
	}
	if _, err := NewDeviceFromKDev(make([]byte, 31), id, cs, ae, nil, 0); !errors.Is(err, ErrBadKeyMaterial) {
		t.Errorf("NewDeviceFromKDev(short k_dev): err = %v", err)
	}
	for _, c := range []struct{ psk, id []byte }{{nil, id}, {psk[:31], id}, {make([]byte, 32), id}, {psk, id[:7]}} {
		if _, err := NewClient("127.0.0.1:9", c.psk, c.id, nil); !errors.Is(err, ErrBadKeyMaterial) {
			t.Errorf("NewClient(len psk %d, len id %d): err = %v", len(c.psk), len(c.id), err)
		}
	}
	// A device built from k_dev admits exactly like one built from the PSK.
	kd := DeriveKDev(psk, id)
	a, err := NewDeviceFromKDev(kd, id, cs, ae, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := mustDev(NewDevice(psk, id, cs, ae, nil, 0))
	if !bytes.Equal(a.kReq, b.kReq) || !bytes.Equal(a.kResp, b.kResp) || !bytes.Equal(a.kDev, b.kDev) {
		t.Error("NewDeviceFromKDev derives different keys from NewDevice")
	}
}

// Wipe zeroes the static keys, the cookie secret and pending session keys.
func TestDeviceWipe(t *testing.T) {
	d, _ := testDevice()
	d.pending[0] = pendingRecord{used: true, keys: SessionKeys{
		KC2S: bytes.Repeat([]byte{1}, 32), KS2C: bytes.Repeat([]byte{1}, 32),
		KKcpC2S: bytes.Repeat([]byte{1}, 32), KKcpS2C: bytes.Repeat([]byte{1}, 32)}}
	k := d.pending[0].keys
	d.Wipe()
	for _, b := range [][]byte{d.kDev, d.kReq, d.kResp, d.cookieSecret, k.KC2S, k.KS2C, k.KKcpC2S, k.KKcpS2C} {
		if !allZero(b) {
			t.Fatal("Wipe left key material in place")
		}
	}
	if d.pending[0].used {
		t.Error("Wipe left a pending record in use")
	}
}

// A stream-mode PUSH with frg != 0 must not wedge the device's receive stream
// (kcp-go keeps frg; PeekSize then waits for segments rcv_wnd never admits).
func TestPeerFrgDoesNotWedgeDeviceStream(t *testing.T) {
	for _, frg := range []byte{0, 200} {
		srv, _, keys, addr := admitted(t)
		conv := uint32(0x11223344)
		first := kcpPush(conv, []byte("a"))
		first[5] = frg // the promoting PUSH too
		env, _ := Seal(keys.KKcpC2S, true, 1, first)
		srv.handlePacket(env, addr)
		p := srv.Primary()
		if p == nil {
			t.Fatal("no primary")
		}
		seg := kcpSeg(conv, kcpCmdPush, 1, []byte("b"))
		seg[5] = frg
		env, _ = Seal(keys.KKcpC2S, true, 2, seg)
		srv.handlePacket(env, addr)
		env, _ = Seal(keys.KKcpC2S, true, 3, kcpSeg(conv, kcpCmdPush, 2, []byte("c")))
		srv.handlePacket(env, addr)

		got := []byte{}
		buf := make([]byte, 64)
		deadline := time.Now().Add(time.Second)
		for len(got) < 3 && time.Now().Before(deadline) {
			p.SetReadDeadline(deadline)
			n, err := p.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		if string(got) != "abc" {
			t.Errorf("frg=%d: stream wedged, read %q of \"abc\"", frg, got)
		}
		srv.Close()
	}
}

func TestClearFrgWalksSegments(t *testing.T) {
	a := kcpSeg(1, kcpCmdPush, 0, []byte("xy"))
	b := kcpSeg(1, kcpCmdPush, 1, []byte("z"))
	a[5], b[5] = 9, 200
	dg := append(append([]byte(nil), a...), b...)
	clearFrg(dg)
	if dg[5] != 0 || dg[len(a)+5] != 0 {
		t.Fatalf("frg not cleared in every segment: %d %d", dg[5], dg[len(a)+5])
	}
	short := append([]byte(nil), a[:KcpOverhead]...)
	binary.LittleEndian.PutUint32(short[kcpLenOff:], 1000) // claims more than present
	short[5] = 7
	clearFrg(short) // must not panic on a truncated segment
}

// readmit runs INIT/FINISH from addr against srv and returns the session keys.
func readmit(t *testing.T, srv *Server, mock *mockConn, addr *net.UDPAddr, nb byte) SessionKeys {
	deviceID := srv.dev.DeviceID
	nonce := bytes.Repeat([]byte{nb}, 24)
	ecPriv := bytes.Repeat([]byte{nb ^ 0x55}, 32)
	srv.handlePacket(validINIT(srv.dev.kReq, nonce, deviceID), addr)
	retry := mock.lastSent()
	fin, ecPub, context := clientFINISH(deviceID, nonce, ecPriv, retry)
	srv.handlePacket(fin, addr)
	af, err := DecodeADMIT(mock.lastSent())
	if err != nil {
		t.Fatal(err)
	}
	dh, _ := DH(ecPriv, af.ES)
	master := Master(Context2(context, ecPub, af.ES), DeriveKDev(testPSK, deviceID), dh)
	return DeriveSession(master)
}

// A read on a session that a re-admission retired reports ErrSessionClosed, not
// ErrDesync, and DropPrimaryIf with that session's generation leaves the new
// session alone.
func TestRetiredSessionReadAndGenerationBoundDrop(t *testing.T) {
	srv, mock, keys, addr := admitted(t)
	defer srv.Close()
	// A: the first PUSH carries 10 of the 20 header octets, so a read stages.
	env, _ := Seal(keys.KKcpC2S, true, 1, kcpPush(0x11223344, make([]byte, 10)))
	srv.handlePacket(env, addr)
	a := srv.Primary()
	genA, ok := srv.PrimaryGen()
	if !ok {
		t.Fatal("no primary A")
	}
	a.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, _, err := srv.RecvAppNum(); !isTimeoutErr(err) {
		t.Fatalf("want staged timeout, got %v", err)
	}
	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	type res struct {
		gen uint32
		err error
	}
	ch := make(chan res, 1)
	go func() { _, _, _, g, err := srv.RecvAppNumGen(); ch <- res{g, err} }()
	time.Sleep(50 * time.Millisecond)

	// The client re-admits from a new port: B.
	addr2 := &net.UDPAddr{IP: addr.IP, Port: 5001}
	k2 := readmit(t, srv, mock, addr2, 0xCD)
	env, _ = Seal(k2.KKcpC2S, true, 1, kcpPush(0x55667788, []byte("x")))
	srv.handlePacket(env, addr2)
	b := srv.Primary()
	if b == nil || b == a {
		t.Fatal("B not promoted")
	}
	r := <-ch
	if !errors.Is(r.err, ErrSessionClosed) || errors.Is(r.err, ErrDesync) {
		t.Fatalf("read on retired A: err = %v, want ErrSessionClosed", r.err)
	}
	if r.gen != genA {
		t.Fatalf("RecvAppNumGen reported gen %d, want A's %d", r.gen, genA)
	}
	if srv.DropPrimaryIf(r.gen) {
		t.Fatal("DropPrimaryIf(A's generation) dropped something")
	}
	if srv.Primary() != b {
		t.Fatal("the new session B did not survive")
	}
	genB, _ := srv.PrimaryGen()
	if genB == genA || !srv.DropPrimaryIf(genB) || srv.Primary() != nil {
		t.Fatal("DropPrimaryIf(B's generation) did not drop B")
	}
}

type flakyConn struct {
	*mockConn
	fail chan struct{}
}

func (f *flakyConn) WriteTo(p []byte, a net.Addr) (int, error) {
	select {
	case <-f.fail:
		return 0, syscall.ENOBUFS
	default:
	}
	return f.mockConn.WriteTo(p, a)
}

// One transient sendto error must not latch the session's writes dead: kcp-go
// keeps the first write error for good, so the shim reports it as a lost
// datagram instead.
func TestTransientSendErrorDoesNotKillWrites(t *testing.T) {
	mock := newMockConn()
	fc := &flakyConn{mockConn: mock, fail: make(chan struct{}, 1)}
	dev, _ := testDevice()
	dev.SetRandSource(fixedRand(0x42))
	srv := NewServer(dev, fc)
	defer srv.Close()
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 4, 2), Port: 5000}
	keys := readmit(t, srv, mock, addr, 0xAB)
	env, _ := Seal(keys.KKcpC2S, true, 1, kcpPush(0x11223344, []byte("x")))
	srv.handlePacket(env, addr)
	if srv.Primary() == nil {
		t.Fatal("no primary")
	}
	fc.fail <- struct{}{} // exactly one failed sendto
	_ = srv.SendApp(0x10, []byte("hello"))
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if err := srv.SendApp(0x10, []byte("again")); err != nil {
			t.Fatalf("SendApp #%d after one transient sendto error: %v", i, err)
		}
	}
}

// After the shim is wiped, its key is zero and kcp-go's late writes fail
// instead of sealing.
func TestShimWipeRefusesLaterWrites(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	c := newSessionConn(newMockConn(), &net.UDPAddr{}, key, false, 0)
	if _, err := c.WriteTo(make([]byte, KcpOverhead), nil); err != nil {
		t.Fatal(err)
	}
	c.wipe()
	if !allZero(key) {
		t.Fatal("wipe left the seal key in place")
	}
	if _, err := c.WriteTo(make([]byte, KcpOverhead), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after wipe: %v, want net.ErrClosed", err)
	}
}

// The receive path's LZ4 decoder agrees with reference LZ4_decompress_safe on
// the blocks pierrec/lz4 disagreed on (verdicts taken from the C library).
func TestLZ4DecoderMatchesReference(t *testing.T) {
	for _, c := range []struct {
		hex    string
		size   int
		accept bool
	}{
		{"40616263640400", 8, false},     // match ends inside the last 5 bytes
		{"404142434404001041", 9, false}, // match starts inside the last 12
		{"40616263640400407778797a", 12, false},
		// Only the last-5-literals rule rejects this one: a 19-byte match
		// (extension byte) ends 4 bytes before the end, then 4 literals.
		{"4f61626364040000407778797a", 27, false},
		{"4f6162636404000050767778797a", 28, true}, // the same, ending 5 before
		{"1163", 1, true},                          // last sequence: match nibble is never read
		{"1862", 1, true},
		{"7461616461626263", 7, true},
		{"", 1, false},
		{"00", 1, false}, // decodes to 0 bytes, not the declared 1
	} {
		b, _ := hex.DecodeString(c.hex)
		_, err := lz4DecodeBlock(b, c.size)
		if (err == nil) != c.accept {
			t.Errorf("%s (size %d): accepted=%v, reference accepts=%v", c.hex, c.size, err == nil, c.accept)
		}
	}
}

// delayProxy forwards client<->server datagrams, delaying s2c by s2cDelay.
type delayProxy struct {
	front    *net.UDPConn // the client talks to this
	back     *net.UDPConn // connected to the server
	s2cDelay atomic.Int64 // ns
	cliAddr  atomic.Pointer[net.UDPAddr]
}

func newDelayProxy(t *testing.T, server net.Addr) *delayProxy {
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.DialUDP("udp", nil, server.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	p := &delayProxy{front: f, back: b}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, err := f.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.cliAddr.Store(a)
			b.Write(append([]byte(nil), buf[:n]...))
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			d := append([]byte(nil), buf[:n]...)
			delay := time.Duration(p.s2cDelay.Load())
			go func() {
				time.Sleep(delay)
				if a := p.cliAddr.Load(); a != nil {
					f.WriteToUDP(d, a)
				}
			}()
		}
	}()
	return p
}

// drainDevice reads application frames on the server until stop closes.
func drainDevice(srv *Server, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		p := srv.Primary()
		if p == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _, _ = srv.RecvApp()
	}
}

// §7.2: after an idle spell longer than SESSION_DEAD_MS, a write "then waits
// the full" SESSION_DEAD_MS. Measuring from the stale lastRx declared a healthy
// session dead on the next 500 ms tick whenever the reply was slower than that.
func TestNoFalseDeadAfterIdle(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test: waits out SESSION_DEAD_MS")
	}
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
	sconn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32), []byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))
	srv := NewServer(dev, sconn)
	srv.skipSrcCheck = true
	go srv.Serve()
	defer srv.Close()
	px := newDelayProxy(t, sconn.LocalAddr())
	defer px.front.Close()
	defer px.back.Close()

	cli, err := NewClient(px.front.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.skipSrcCheck = true
	la := px.back.LocalAddr().(*net.UDPAddr)
	a, _ := netip.AddrFromSlice(la.IP)
	cli.ownCS = Canonicalize(a.Unmap(), uint16(la.Port)) // what the server observes
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("admit: %v", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go drainDevice(srv, stop)
	time.Sleep(msDur(SessionDeadMS) + 300*time.Millisecond) // idle, healthy
	if cli.SessionDead() {
		t.Fatal("dead while idle")
	}
	px.s2cDelay.Store(int64(600 * time.Millisecond)) // a slow but live link
	if err := cli.SendAppPadded(CmdPing, []byte("hi")); err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	if cli.SessionDead() {
		t.Fatal("healthy session declared dead after its first post-idle send")
	}
}

// A sender racing commit is refused until ESTABLISHED, so it can never take the
// promoting PUSH's place; the promoting message is the first the device reads.
func TestSendCannotOvertakePromotingPush(t *testing.T) {
	srv, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	var sendErr error
	testHookBeforeFirstWrite = func() {
		sendErr = cli.SendAppPadded(CmdGetStatus, []byte("racing sender"))
	}
	defer func() { testHookBeforeFirstWrite = nil }()
	if err := cli.TakeControlApp(CmdPing, []byte("promote")); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !errors.Is(sendErr, ErrNotEstablished) {
		t.Fatalf("SendApp during AWAIT_PUSH_ACK: err = %v, want ErrNotEstablished", sendErr)
	}
	srv.Primary().SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, num, p, err := srv.RecvAppNum()
	if err != nil || typ != CmdPing || num != 1 || string(p) != "promote" {
		t.Fatalf("first device frame: type=%#x num=%d %q err=%v, want the promoting PING", typ, num, p, err)
	}
}

// A device-sent PUSH with frg >= the client's rcv_wnd must not wedge the
// client's receive stream.
func TestPeerFrgDoesNotWedgeClientStream(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	srv.Primary().SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := srv.RecvApp(); err != nil {
		t.Fatal(err)
	}
	srv.dev.rec.Lock()
	shim := srv.primary.shim
	srv.dev.rec.Unlock()
	cli.mu.Lock()
	conv := cli.convID
	cli.mu.Unlock()
	// A real response first, then one with frg = the client's RcvWnd.
	if err := srv.SendAppPadded(RespStatus, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := cli.RecvApp(); err != nil {
		t.Fatal(err)
	}
	seg := kcpSeg(conv, kcpCmdPush, 99, []byte("evil"))
	seg[5] = 8
	if _, err := shim.WriteTo(seg, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := srv.SendAppPadded(RespStatus, []byte("ok")); err != nil {
			t.Fatal(err)
		}
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := cli.RecvApp(); err != nil {
		t.Fatalf("client receive stream wedged by a peer frg: %v", err)
	}
}

// §9.5: raw Send and a raw first message are bounded like the *App path.
func TestRawSendBounded(t *testing.T) {
	srv, cli, cleanup := loopbackPair(t)
	defer cleanup()
	_ = srv
	if n, err := cli.Send(make([]byte, 8<<20)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("raw Send of 8 MiB: n=%d err=%v, want ErrPayloadTooLarge", n, err)
	}
	_, idle, cleanup2 := loopbackPairIdle(t)
	defer cleanup2()
	if err := idle.TakeControl(make([]byte, 8<<20)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("TakeControl with an 8 MiB first message: %v, want ErrPayloadTooLarge", err)
	}
}

// SessionDead turns true only once the client is back in IDLE, so the
// documented recovery — TakeControl as soon as it reports dead — is not refused.
// Between liveness declaring death and teardown finishing, sends fail with
// ErrSessionDead rather than writing into the dead session. Teardown is held on
// tdMu so that window is observed deterministically.
func TestSessionDeadImpliesIdle(t *testing.T) {
	_, cli, cleanup := loopbackPair(t)
	defer cleanup()
	cli.tdMu.Lock()
	cli.markDead() // what the readLoop does when SESSION_DEAD_MS elapses
	if cli.SessionDead() {
		cli.tdMu.Unlock()
		t.Fatal("SessionDead() true before teardown returned the client to IDLE")
	}
	if _, err := cli.Send([]byte("y")); !errors.Is(err, ErrSessionDead) {
		cli.tdMu.Unlock()
		t.Fatalf("Send while the dead session awaits teardown: %v, want ErrSessionDead", err)
	}
	cli.tdMu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for !cli.SessionDead() {
		if time.Now().After(deadline) {
			t.Fatal("session never reported dead")
		}
		time.Sleep(time.Millisecond)
	}
	cli.mu.Lock()
	st := cli.state
	cli.mu.Unlock()
	if st != stIdle {
		t.Fatalf("SessionDead() true while state = %v, want IDLE", st)
	}
}

// §7.6: ICMP MUST be ignored. Spoofed port-unreachables and frag-needed for the
// client's 4-tuple must not break its write path.
func TestSpoofedICMPDoesNotBreakClientWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		code byte
		mtu  uint16
	}{{"port-unreachable", 3, 0}, {"frag-needed", 4, 576}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli, cleanup := loopbackPairApp(t)
			defer cleanup()
			stop := make(chan struct{})
			defer close(stop)
			go drainDevice(srv, stop)
			cport := cli.conn.LocalAddr().(*net.UDPAddr).Port
			sport := cli.conn.RemoteAddr().(*net.UDPAddr).Port
			for i := 0; i < 50; i++ {
				sendSpoofedICMP(t, cport, sport, tc.code, tc.mtu)
				time.Sleep(2 * time.Millisecond)
				if err := cli.SendAppPadded(CmdPing, []byte("x")); err != nil {
					t.Fatalf("send %d after spoofed ICMP: %v", i, err)
				}
			}
		})
	}
}
