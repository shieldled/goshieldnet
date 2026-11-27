// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// End-to-end: a real Go client admits to a real Go server over loopback UDP,
// promotes, and exchanges application data both ways. Loopback 127.0.0.1 is on
// §4.3's rejection list, so both ends set skipSrcCheck (the source predicate is
// covered by source_test.go/demux_test.go); everything else is exercised for real.
func TestGoClientGoServerInterop(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	cookieSecret := bytes.Repeat([]byte{0x44}, 32)
	admissionEpoch := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	// server socket
	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	dev := mustDev(NewDevice(psk, deviceID, cookieSecret, admissionEpoch, local, 8000))
	srv := NewServer(dev, sconn)
	srv.skipSrcCheck = true
	go srv.Serve()
	defer srv.Close()

	serverAddr := sconn.LocalAddr().String()

	cli, err := NewClient(serverAddr, psk, deviceID, local)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()

	// take control, sending the first application message as the promoting PUSH
	if err := cli.TakeControl([]byte("hello-from-controller")); err != nil {
		t.Fatalf("TakeControl: %v", err)
	}

	// the server should now have a primary; read the client's first message off it
	deadline := time.Now().Add(2 * time.Second)
	var prim *net.UDPAddr
	_ = prim
	var sess = srv.Primary()
	for sess == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		sess = srv.Primary()
	}
	if sess == nil {
		t.Fatal("server never promoted")
	}
	sess.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != "hello-from-controller" {
		t.Errorf("server got %q", buf[:n])
	}

	// server → client application data
	if _, err := sess.Write([]byte("ack-from-device")); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 128)
	// Recv blocks on the client's kcp session; give it a deadline via the session
	cli.mu.Lock()
	ckcp := cli.kcp
	cli.mu.Unlock()
	ckcp.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, err := cli.Recv(rbuf)
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(rbuf[:rn]) != "ack-from-device" {
		t.Errorf("client got %q", rbuf[:rn])
	}

	// client → server again over the established session
	if _, err := cli.Send([]byte("second-command")); err != nil {
		t.Fatal(err)
	}
	sess.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("server read 2: %v", err)
	}
	if string(buf[:n2]) != "second-command" {
		t.Errorf("server got 2 %q", buf[:n2])
	}
}
