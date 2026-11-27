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

// transport 10.2: a first message is a sealed message; there is no empty one.
func TestTransport102EmptyFirstMessageRefused(t *testing.T) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
	cli, err := NewClient(sock.LocalAddr().String(), bytes.Repeat([]byte{0x33}, 32), []byte{9, 8, 7, 6, 5, 4, 3, 2}, local)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := cli.TakeControl(nil); !errors.Is(err, ErrEmptyFirstMessage) {
		t.Fatalf("TakeControl(nil): err = %v, want ErrEmptyFirstMessage", err)
	}
	if st := stateOf(cli); st != stIdle {
		t.Fatalf("state %d, want IDLE", st)
	}
	_ = sock.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, rerr := sock.ReadFromUDP(buf); rerr == nil {
		t.Fatalf("the device received %d octets; nothing may be sent", n)
	}
}

// transport 10.3 rule 6: back in IDLE, a partly staged message is gone.
func TestTransport103IdleResetsRxStage(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	if _, err := primaryOf(t, srv).Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := cli.RecvApp(); err == nil || !isTimeoutErr(err) {
		t.Fatalf("precondition: want a timeout, got %v", err)
	}
	cli.rxMu.Lock()
	n := cli.rxStage.hdrN
	cli.rxMu.Unlock()
	if n != 10 {
		t.Fatalf("precondition: hdrN = %d, want 10", n)
	}
	cli.teardown()
	cli.rxMu.Lock()
	n = cli.rxStage.hdrN
	cli.rxMu.Unlock()
	if n != 0 {
		t.Fatalf("hdrN = %d after teardown, want 0", n)
	}
}

// transport 13 item 5: the inbound buffer holds the receive window.
func TestTransport13InboundHoldsWindow(t *testing.T) {
	c := newSessionConn(newMockConn(), &net.UDPAddr{}, bytes.Repeat([]byte{0x11}, 32), true, 256)
	for i := 0; i < 256; i++ {
		c.deliver([]byte{byte(i)})
	}
	if n := len(c.inbound); n != 256 {
		t.Fatalf("inbound holds %d datagrams, want 256", n)
	}
}
