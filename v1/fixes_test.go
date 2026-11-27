// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// §7.2's admission phases are wall-clock loops, and a read on a socket Close has
// shut fails instantly with net.ErrClosed — which is not a timeout, so the "ignore
// ICMP" continue used to spin on it. The attempt still ended only at its own
// deadline: measured at 3.0 s of wall time for 3.7 s of CPU on a silent device.
func TestCloseEndsAnInFlightTakeControlPromptly(t *testing.T) {
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close() // bound so the client is not ICMP-refused; never answers

	psk := bytes.Repeat([]byte{0x33}, 32)
	cli, err := NewClient(silent.LocalAddr().String(), psk, []byte{9, 8, 7, 6, 5, 4, 3, 2},
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")})
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true

	done := make(chan error, 1)
	go func() { done <- cli.TakeControl([]byte("hello")) }()
	time.Sleep(150 * time.Millisecond) // let it reach the AWAIT_RETRY read loop

	start := time.Now()
	cli.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("TakeControl succeeded against a silent device")
		}
		// The full AWAIT_RETRY budget is InitTransmissions × INIT_RETRY_MS = 3 s.
		// Anything approaching that means the loop ran to its deadline rather than
		// noticing the close.
		if el := time.Since(start); el > time.Second {
			t.Errorf("TakeControl ran %s past Close; it must abandon the phase, "+
				"not spin on net.ErrClosed until the deadline", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TakeControl never returned after Close")
	}

	// And a fresh attempt on a closed client is refused rather than run: teardown
	// returns the state to IDLE, so the IDLE guard alone no longer excludes it.
	if err := cli.TakeControl([]byte("hello")); err == nil {
		t.Error("TakeControl after Close was accepted")
	}
}

// §4.4's epoch is only meaningful against the clock that advances it. NewServer
// ticks from its own base, so a Device seeded from the wall clock — the natural
// thing to pass, and what examples/server does — used to start thousands of
// epochs ahead: the first tick then matched neither cookieEpoch nor its
// successor, and rollEpochLocked discarded the boot tag with prevEpochTag = nil.
// Every FINISH whose RETRY was minted before that tick failed step 3a.
func TestNewServerSeedsTheEpochOnTheClockItTicks(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	dev := mustDev(NewDevice(bytes.Repeat([]byte{0x33}, 32), []byte{9, 8, 7, 6, 5, 4, 3, 2},
		bytes.Repeat([]byte{0x44}, 32), []byte{0, 1, 2, 3, 4, 5, 6, 7}, nil,
		uint64(time.Now().UnixMilli())))
	srv := NewServer(dev, conn)
	defer srv.Close()

	dev.rec.Lock()
	boot := dev.cookieEpoch
	bootTag := append([]byte(nil), dev.epochTag...)
	dev.rec.Unlock()

	if got := uint32(srv.nowMS() / CookieEpochMS); got != boot && got != boot+1 {
		t.Fatalf("the first tick's epoch %d is neither the boot epoch %d nor its "+
			"successor: rollEpochLocked will discard the boot tag", got, boot)
	}
	// Cross one boundary on the server's clock: §4.4 keeps the previous tag.
	dev.RollEpoch(uint64(CookieEpochMS))
	dev.rec.Lock()
	defer dev.rec.Unlock()
	if !bytes.Equal(dev.prevEpochTag, bootTag) {
		t.Error("the boot epoch_tag was discarded by the first boundary crossing, " +
			"so a FINISH answering a RETRY minted before it fails step 3a")
	}
}

// Message-layer §1.2's third row requires a desynchronised session be closed, and
// closing it must be an action a responder can actually take. Before DropPrimary
// the only way to end a session was Close, which takes the socket down too and so
// refuses the re-admission that is supposed to follow.
func TestDropPrimaryRetiresTheSessionAndKeepsListening(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()

	if srv.Primary() == nil {
		t.Fatal("no primary after admission")
	}
	if _, _, _, err := srv.RecvAppNum(); err != nil {
		t.Fatalf("promoting message: %v", err)
	}

	if !srv.DropPrimary() {
		t.Fatal("DropPrimary reported nothing to retire")
	}
	if srv.Primary() != nil {
		t.Error("the primary survived DropPrimary")
	}
	if srv.DropPrimary() {
		t.Error("a second DropPrimary reported a retirement")
	}
	// §8.5's wipe-before-free: the keys go with the session, so both app-layer
	// entry points report ErrNotEstablished rather than working on a dead one.
	if _, _, _, err := srv.RecvAppNum(); !errors.Is(err, ErrNotEstablished) {
		t.Errorf("RecvAppNum after DropPrimary: %v, want ErrNotEstablished", err)
	}
	if err := srv.SendApp(RespAck, nil); !errors.Is(err, ErrNotEstablished) {
		t.Errorf("SendApp after DropPrimary: %v, want ErrNotEstablished", err)
	}

	// The socket is still up, which is the whole point: the controller re-admits.
	cli.teardown()
	if err := cli.TakeControlAppPadded(CmdPing, nil); err != nil {
		t.Fatalf("re-admission after DropPrimary: %v", err)
	}
	if _, num, _, err := srv.RecvAppNum(); err != nil {
		t.Fatalf("promoting message of the new session: %v", err)
	} else if num != 1 {
		t.Errorf("new session's first MessageNum = %d, want 1", num)
	}
}
