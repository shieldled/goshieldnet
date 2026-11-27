// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// holdProxy forwards client<->server datagrams, holding back every datagram of
// type holdType while hold is set, and counts the datagrams of type countType
// the client sends after mark is set.
type holdProxy struct {
	mu         sync.Mutex
	front      *net.UDPConn // the client talks to this
	back       *net.UDPConn // connected to the server
	cliAddr    atomic.Pointer[net.UDPAddr]
	hold       atomic.Bool
	held       chan []byte
	mark       atomic.Bool
	countAfter atomic.Int32
	holdType   byte
	countType  byte
}

func isWire(d []byte, typ byte) bool {
	return len(d) >= HeaderLen && bytes.Equal(d[:8], Magic) && d[8] == typ
}

func (p *holdProxy) frontConn() *net.UDPConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.front
}

// serveFront forwards what the client sends on f to the server.
func (p *holdProxy) serveFront(f *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, a, err := f.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.cliAddr.Store(a)
		d := append([]byte(nil), buf[:n]...)
		if isWire(d, p.countType) && p.mark.Load() {
			p.countAfter.Add(1)
		}
		p.back.Write(d)
	}
}

// rebindFront closes the client-facing socket and binds a new one on the same
// address.
func (p *holdProxy) rebindFront(t *testing.T, between func()) {
	p.mu.Lock()
	old := p.front
	addr := old.LocalAddr().(*net.UDPAddr)
	old.Close()
	p.mu.Unlock()
	between()
	f, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Errorf("rebind %s: %v", addr, err)
		return
	}
	t.Cleanup(func() { f.Close() })
	p.mu.Lock()
	p.front = f
	p.mu.Unlock()
	go p.serveFront(f)
}

func newHoldProxy(t *testing.T, server net.Addr, holdType, countType byte) *holdProxy {
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.DialUDP("udp", nil, server.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	p := &holdProxy{front: f, back: b, held: make(chan []byte, 16), holdType: holdType, countType: countType}
	p.hold.Store(true)
	t.Cleanup(func() { p.frontConn().Close(); b.Close() })
	go p.serveFront(f)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			d := append([]byte(nil), buf[:n]...)
			if isWire(d, p.holdType) && p.hold.Load() {
				select {
				case p.held <- d:
				default:
				}
				continue
			}
			if a := p.cliAddr.Load(); a != nil {
				p.frontConn().WriteToUDP(d, a)
			}
		}
	}()
	return p
}

// release sends the first held datagram to the client from the current front
// socket and stops holding.
func (p *holdProxy) release(t *testing.T) {
	select {
	case d := <-p.held:
		p.hold.Store(false)
		if _, err := p.frontConn().WriteToUDP(d, p.cliAddr.Load()); err != nil {
			t.Errorf("send held datagram: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("no held datagram from the device")
	}
}

// proxiedPair is a server behind a holdProxy and a client dialled to the
// proxy, set up as TestFinishPhaseRaisedAdmitsSlowDevice does.
func proxiedPair(t *testing.T, holdType, countType byte) (*Server, *holdProxy, *Client) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32), []byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))
	srv := NewServer(dev, sconn)
	srv.skipSrcCheck = true
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	px := newHoldProxy(t, sconn.LocalAddr(), holdType, countType)
	cli, err := NewClient(px.front.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	cli.skipSrcCheck = true
	la := px.back.LocalAddr().(*net.UDPAddr)
	a, _ := netip.AddrFromSlice(la.IP)
	cli.ownCS = Canonicalize(a.Unmap(), uint16(la.Port)) // what the server observes
	return srv, px, cli
}

func setPhaseHook(t *testing.T, f func(phase string, final bool)) {
	testHookPhaseExpired = f
	t.Cleanup(func() { testHookPhaseExpired = nil })
}

// transport 10.3 rule 4: an ADMIT queued when the FINISH retransmit timer
// expires is read before FINISH is sent again.
func TestTransport10QueuedAdmitBeforeResend(t *testing.T) {
	_, px, cli := proxiedPair(t, TypeADMIT, TypeFIN)
	var once sync.Once
	setPhaseHook(t, func(phase string, final bool) {
		if phase != "admit" || final {
			return
		}
		once.Do(func() {
			px.release(t)
			px.mark.Store(true)
		})
	})
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp: %v", err)
	}
	if n := px.countAfter.Load(); n != 0 {
		t.Fatalf("%d FINISH sent after the ADMIT was queued, want 0", n)
	}
}

// transport 10.6, 10.3 rule 4: a queued ICMP error does not hide a valid ADMIT
// behind it at the phase's end.
func TestTransport10DrainSkipsICMP(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the non-blocking drain is linux only")
	}
	_, px, cli := proxiedPair(t, TypeADMIT, TypeFIN)
	cli.FinishPhaseMS = 600
	setPhaseHook(t, func(phase string, final bool) {
		if phase != "admit" || !final {
			return
		}
		px.rebindFront(t, func() {
			// The client's connected socket now queues ECONNREFUSED from the
			// ICMP port unreachable.
			cli.conn.Write([]byte{0})
			time.Sleep(50 * time.Millisecond)
		})
		px.release(t)
	})
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp: %v", err)
	}
}

func TestTransport10DrainEndsOnClose(t *testing.T) {
	_, _, cli := proxiedPair(t, TypeADMIT, TypeFIN)
	cli.FinishPhaseMS = 600
	closed := make(chan time.Duration, 1)
	setPhaseHook(t, func(phase string, final bool) {
		if phase != "admit" || !final {
			return
		}
		go func() {
			start := time.Now()
			cli.Close()
			closed <- time.Since(start)
		}()
		time.Sleep(100 * time.Millisecond) // let Close shut the socket
	})
	cli.TakeControlApp(CmdPing, nil)
	select {
	case d := <-closed:
		if d >= time.Second {
			t.Fatalf("Close took %s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return: the drain did not end")
	}
}

// transport 10.5 step 4: dh is computed at most once per distinct e_s, even
// when it is all-zero.
func TestTransport105ZeroDHCached(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	var calls atomic.Int32
	es := make([]byte, 32) // a low-order point: X25519 gives all zeros
	// Only this test's own point counts: a DH from another goroutine does not.
	testHookDH = func(peerPublic []byte) {
		if bytes.Equal(peerPublic, es) {
			calls.Add(1)
		}
	}
	defer func() { testHookDH = nil }()

	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	ecPub := bytes.Repeat([]byte{0x09}, 32)
	context := bytes.Repeat([]byte{0x21}, 32)
	epoch := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	admit := EncodeADMIT(epoch, es, AdmitPre(cli.kResp, Context2(context, ecPub, es)), make([]byte, 16))
	dhCache := map[string][]byte{}
	for i := 0; i < 2; i++ {
		if _, ok := cli.checkADMIT(admit, context, ecPriv, ecPub, epoch, dhCache); ok {
			t.Fatal("an ADMIT with a low-order e_s was accepted")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("DH ran %d times for one e_s, want 1", n)
	}
}
