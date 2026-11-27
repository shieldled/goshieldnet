// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A FinishPhaseMS outside (0, COOKIE_EPOCH_MS) is a configuration error that
// TakeControl reports before anything is sent: no INIT reaches the device.
func TestFinishPhaseRejectedBeforeINIT(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
	for _, ms := range []int{CookieEpochMS, -1} {
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		cli, err := NewClient(sock.LocalAddr().String(), psk, deviceID, local)
		if err != nil {
			t.Fatal(err)
		}
		cli.FinishPhaseMS = ms
		err = cli.TakeControl([]byte{1})
		if err == nil || errors.Is(err, errAttemptFailed) {
			t.Errorf("FinishPhaseMS %d: TakeControl = %v, want a configuration error", ms, err)
		}
		sock.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 2048)
		if n, _, rerr := sock.ReadFromUDP(buf); rerr == nil {
			t.Errorf("FinishPhaseMS %d: the device received %d octets; nothing may be sent", ms, n)
		} else if !isTimeoutErr(rerr) {
			t.Errorf("FinishPhaseMS %d: read: %v", ms, rerr)
		}
		cli.Close()
		sock.Close()
	}
}

// admitDelayProxy forwards client<->server datagrams, delaying only the
// device's ADMIT by admitDelay; everything else passes undelayed.
type admitDelayProxy struct {
	front   *net.UDPConn // the client talks to this
	back    *net.UDPConn // connected to the server
	cliAddr atomic.Pointer[net.UDPAddr]
}

func newAdmitDelayProxy(t *testing.T, server net.Addr, admitDelay time.Duration) *admitDelayProxy {
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.DialUDP("udp", nil, server.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	p := &admitDelayProxy{front: f, back: b}
	t.Cleanup(func() { f.Close(); b.Close() })
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
			var delay time.Duration
			if len(d) == AdmitLen && bytes.HasPrefix(d, Magic) && d[8] == TypeADMIT {
				delay = admitDelay
			}
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

// transport 4.3: a device whose ADMIT takes longer than the default 1 500 ms
// FINISH phase is admitted once the deployment raises FinishPhaseMS, and is not
// admitted at the default (which proves the delay exceeds it).
func TestFinishPhaseRaisedAdmitsSlowDevice(t *testing.T) {
	for _, c := range []struct {
		ms    int
		admit bool
	}{{3500, true}, {0, false}} {
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
		px := newAdmitDelayProxy(t, sconn.LocalAddr(), 2000*time.Millisecond)

		cli, err := NewClient(px.front.LocalAddr().String(), psk, deviceID, local)
		if err != nil {
			t.Fatal(err)
		}
		cli.skipSrcCheck = true
		la := px.back.LocalAddr().(*net.UDPAddr)
		a, _ := netip.AddrFromSlice(la.IP)
		cli.ownCS = Canonicalize(a.Unmap(), uint16(la.Port)) // what the server observes
		cli.FinishPhaseMS = c.ms
		err = cli.TakeControlApp(CmdPing, nil)
		if c.admit && err != nil {
			t.Errorf("FinishPhaseMS %d: admit: %v", c.ms, err)
		}
		if !c.admit && err == nil {
			t.Errorf("FinishPhaseMS %d: admitted although every ADMIT arrives after the phase", c.ms)
		}
		cli.Close()
		srv.Close()
	}
}
