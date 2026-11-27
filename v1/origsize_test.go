// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// message layer 7.1, 7.3: OriginalSize is bounded by MaxOriginalSize and by
// the receiver's own memory bound, not by the bound on Size.
func TestMsg71CompressedOriginalAboveSizeBound(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	payload := make([]byte, 40*1024)
	frame, err := frameAppWith(key, 1, anyBulkKind, payload, true, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	var rx uint64
	typ, _, got, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, 32*1024, 0, MaxAppPayload)
	if err != nil {
		t.Fatalf("40 KiB compressed under a 32 KiB Size bound: %v", err)
	}
	if typ != anyBulkKind || !bytes.Equal(got, payload) {
		t.Fatalf("got type %#x, %d bytes; want the 40 KiB payload", typ, len(got))
	}
}

func TestMsg71OriginalAboveMaxRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	// A real LZ4 block that decodes to exactly MaxOriginalSize+1 octets, so
	// only the MaxOriginalSize check can refuse it. No block under a 32 KiB
	// Size bound can decode that far (LZ4's ratio is at most about 255:1), so
	// the Size bound here is MaxAppPayload.
	block := compressBlock(make([]byte, MaxOriginalSize+1))
	if block == nil || len(block)+chacha20poly1305.Overhead > MaxAppPayload {
		t.Fatalf("precondition: block of %d bytes", len(block))
	}
	hdr := appHeader(uint32(len(block)+chacha20poly1305.Overhead), MaxOriginalSize+1, anyBulkKind|FlagCompressed, 1)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	frame := append(hdr, aead.Seal(nil, appNonce(1), block, hdr)...)
	var rx uint64
	_, _, got, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, MaxAppPayload, 0, MaxOriginalSize*2)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("OriginalSize %d: err = %v (%d bytes), want ErrRejected", MaxOriginalSize+1, err, len(got))
	}
}
