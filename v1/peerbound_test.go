// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

// primaryOf waits for the server's primary session.
func primaryOf(t *testing.T, srv *Server) *kcp.UDPSession {
	t.Helper()
	for i := 0; i < 200 && srv.Primary() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	p := srv.Primary()
	if p == nil {
		t.Fatal("no primary")
	}
	return p
}

// readRawFrame reads one framed message off the device's stream without
// opening it, and returns its 20-octet header.
func readRawFrame(t *testing.T, sess *kcp.UDPSession) []byte {
	t.Helper()
	_ = sess.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer sess.SetReadDeadline(time.Time{})
	hdr := make([]byte, appHeaderSize)
	if _, err := io.ReadFull(sess, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[0:4]))
	if _, err := io.ReadFull(sess, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return hdr
}

// message layer 7.3: a sender respects the receiver's bound as well as its own.
func TestMsg73PeerBoundRefusesOversize(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	if err := cli.SetPeerReceiveBound(1200); err != nil {
		t.Fatal(err)
	}
	f, err := cli.frameApp(CmdPing, make([]byte, 1184), false, true)
	if err != nil {
		t.Fatalf("1184 bytes under bound 1200: %v", err)
	}
	if size := binary.BigEndian.Uint32(f[0:4]); size != 1200 {
		t.Fatalf("Size = %d, want 1200", size)
	}
	if _, err := cli.frameApp(CmdPing, make([]byte, 1185), false, true); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("1185 bytes under bound 1200: err = %v, want ErrPayloadTooLarge", err)
	}
	if err := cli.SetPeerReceiveBound(79); err == nil {
		t.Fatal("a bound of 79 was accepted")
	}
}

func TestMsg73PeerBoundCapsPadding(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	if err := cli.SetPeerReceiveBound(1024); err != nil {
		t.Fatal(err)
	}
	f, err := cli.frameApp(CmdPing, make([]byte, 1000), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if size := binary.BigEndian.Uint32(f[0:4]); size != 1016 {
		t.Fatalf("Size = %d, want 1016 (class 1024 would be Size 1040, over the bound)", size)
	}
}

// message layer 6.3: bulk content is padded when it is not compressed.
func TestMsg73BulkPadsWhenIncompressible(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	p := primaryOf(t, srv)
	readRawFrame(t, p) // the admitting message
	payload := make([]byte, 100)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := cli.SendAppBulk(anyBulkKind, payload); err != nil {
		t.Fatal(err)
	}
	hdr := readRawFrame(t, p)
	if size := binary.BigEndian.Uint32(hdr[0:4]); size != 144 {
		t.Fatalf("Size = %d, want 144 (class 128)", size)
	}
	if binary.BigEndian.Uint32(hdr[8:12])&FlagCompressed != 0 {
		t.Fatal("FlagCompressed set on incompressible bulk content")
	}
}

func TestMsg73BulkCompresses(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	p := primaryOf(t, srv)
	readRawFrame(t, p)
	if err := cli.SendAppBulk(anyBulkKind, make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	hdr := readRawFrame(t, p)
	if binary.BigEndian.Uint32(hdr[8:12])&FlagCompressed == 0 {
		t.Fatal("1000 zero bytes sent uncompressed")
	}
}
