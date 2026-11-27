// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A commit-phase failure must not poison the client for later attempts.
//
// Regression: commit() spawns readLoop, which reads the same socket as
// TakeControl. teardown() used to leave it running (it exited only on c.done,
// closed just by Close), so after a push-ACK timeout the leaked readLoop
// starved the next TakeControl on the FD read lock and swallowed its
// RETRY/ADMIT as non-envelope (§7.1). The second attempt then blocked forever.
//
// The half-device below admits normally but never promotes: it drops every
// envelope, so the client always times out in AWAIT_PUSH_ACK. Two attempts in a
// row must each return errAttemptFailed rather than hanging — retry after a
// failed attempt is the application's call (§7).
func TestClientRetryAfterCommitFailure(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()

	dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32),
		[]byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))

	// Half-device: INIT->RETRY and FINISH->ADMIT, but envelopes are dropped, so
	// the client never sees the s2c that would confirm promotion.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			sconn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, ap, rerr := sconn.ReadFromUDPAddrPort(buf)
			if rerr != nil {
				continue
			}
			d := buf[:n]
			switch classifyDatagram(RoleDevice, d) {
			case ClassINIT:
				if r := dev.HandleINIT(d, ap, 8000); r != nil {
					sconn.WriteToUDPAddrPort(r, ap)
				}
			case ClassFINISH:
				if a := dev.HandleFINISH(d, ap, uint64(time.Now().UnixMilli())); a != nil {
					sconn.WriteToUDPAddrPort(a, ap)
				}
			}
		}
	}()

	cli, err := NewClient(sconn.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		done := make(chan error, 1)
		go func() { done <- cli.TakeControl([]byte("probe")) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("attempt %d: unexpectedly succeeded against a device that never promotes", attempt)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("attempt %d hung: readLoop from the previous attempt still owns the socket", attempt)
		}
	}
}

// The invariant behind the hang above, asserted directly: a failed attempt must
// leave no readLoop running on the socket. A leaked one competes with
// TakeControl for the FD read lock and eats its RETRY/ADMIT.
func TestNoReadLoopSurvivesFailedAttempt(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()

	dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32),
		[]byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			sconn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, ap, rerr := sconn.ReadFromUDPAddrPort(buf)
			if rerr != nil {
				continue
			}
			d := buf[:n]
			switch classifyDatagram(RoleDevice, d) {
			case ClassINIT:
				if r := dev.HandleINIT(d, ap, 8000); r != nil {
					sconn.WriteToUDPAddrPort(r, ap)
				}
			case ClassFINISH:
				if a := dev.HandleFINISH(d, ap, uint64(time.Now().UnixMilli())); a != nil {
					sconn.WriteToUDPAddrPort(a, ap)
				}
			}
		}
	}()

	cli, err := NewClient(sconn.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()

	if err := cli.TakeControl([]byte("probe")); err == nil {
		t.Fatal("expected the attempt to fail against a device that never promotes")
	}
	if cli.rlStuck.Load() {
		t.Error("teardown had to force the socket deadline to stop readLoop; " +
			"the 500ms read deadline should make that unreachable")
	}
	if n := cli.rlLive.Load(); n != 0 {
		t.Fatalf("%d readLoop(s) still running after a failed attempt; they own the socket "+
			"and will starve/steal from the next TakeControl", n)
	}
}

// A session must stay writable past the promoting PUSH's deadline. commit sets
// an absolute write deadline for that first PUSH; leaving it in place makes a
// later blocking Write fail instantly with a timeout once it passes, for any
// caller that does not set its own deadline per write. Found by a hardware test
// that simply sent frames and got "send: timeout".
//
// The write has to actually block for the deadline to matter -- kcp-go only
// consults it when it must wait for send-window space, so a plain loopback
// write returns before ever looking. Stop the server first so nothing is
// acknowledged, then write past the window.
func TestWritesSurvivePushAckDeadline(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32),
		[]byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))
	srv := NewServer(dev, sconn)
	srv.skipSrcCheck = true
	go srv.Serve()

	cli, err := NewClient(sconn.LocalAddr().String(), psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()
	if err := cli.TakeControl([]byte("hello")); err != nil {
		t.Fatalf("TakeControl: %v", err)
	}

	srv.Close() // nothing drains or ACKs from here on
	sconn.Close()
	time.Sleep(msDur(PushAckTimeoutMS) + 500*time.Millisecond) // past the stale deadline

	// Fill the send window, then keep writing. With the deadline cleared this
	// blocks; with it stale every write returns errTimeout immediately.
	done := make(chan error, 1)
	go func() {
		payload := bytes.Repeat([]byte{0x5A}, 1024)
		for i := 0; i < 4096; i++ {
			if _, err := cli.Send(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	// Blocking is the expected outcome. A non-timeout error (the socket is shut)
	// is also fine — what must not happen is errTimeout, which is the stale
	// deadline firing.
	select {
	case err := <-done:
		// kcp-go wraps errTimeout (pkg/errors), so a direct net.Error assertion
		// misses it; match the error itself.
		var ne net.Error
		if (errors.As(err, &ne) && ne.Timeout()) ||
			(err != nil && strings.Contains(err.Error(), "timeout")) {
			t.Fatalf("write failed with a timeout on a session with no write deadline: %v "+
				"(the commit write deadline was not cleared)", err)
		}
	case <-time.After(3 * time.Second):
		// Blocked on window space with no deadline — correct.
	}
}
