// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// message layer 7.3: a compressed message whose OriginalSize exceeds this
// receiver's own bound is refused, and the bound is inclusive.
func TestMsg71ReceiverBoundRejects(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	payload := make([]byte, 40*1024)
	frame, err := frameAppWith(key, 1, anyBulkKind, payload, true, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	var rx uint64
	if _, _, _, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, 32*1024, 0, 32*1024); !errors.Is(err, ErrRejected) {
		t.Fatalf("OriginalSize 40 KiB over a 32 KiB bound: err = %v, want ErrRejected", err)
	}
	rx = 0
	typ, _, got, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, 32*1024, 0, 40*1024)
	if err != nil {
		t.Fatalf("OriginalSize 40 KiB at a 40 KiB bound: %v", err)
	}
	if typ != anyBulkKind || !bytes.Equal(got, payload) {
		t.Fatalf("got type %#x, %d bytes; want the 40 KiB payload", typ, len(got))
	}
}

// The server passes its own MaxMsgPayload as the decompressed bound.
func TestMsg71ServerDecompressedBound(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	srv.MaxMsgPayload = 4096
	p := primaryOf(t, srv)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); err != nil { // the admitting PING
		t.Fatal(err)
	}
	if err := cli.SendAppCompressed(anyBulkKind, make([]byte, 30*1024)); err != nil {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); !errors.Is(err, ErrRejected) {
		t.Fatalf("RecvAppNumGen: err = %v, want ErrRejected", err)
	}
	if err := cli.SendAppPadded(CmdPing, nil); err != nil {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, _, _, _, err := srv.RecvAppNumGen()
	if err != nil || typ != CmdPing {
		t.Fatalf("after the rejection: type %#x, err %v; want PING, nil", typ, err)
	}
}
