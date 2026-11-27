// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// A compressible payload the shape of a bulk blob: repeated structure,
// which is what makes LZ4 worth the carve-out in transport §13.
func artifactLike(n int) []byte {
	b := make([]byte, 0, n)
	for len(b) < n {
		b = append(b, []byte("BLOB\x00\x01\x00\x00key:alpha,beta,gamma,delta;val:0000")...)
	}
	return b[:n]
}

func TestFrameAppCompressesBulkPayload(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	payload := artifactLike(4096)

	plain, err := c.frameApp(anyBulkKind, payload, false, false)
	if err != nil {
		t.Fatal(err)
	}
	c.txNum.Store(0)
	comp, err := c.frameApp(anyBulkKind, payload, true, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(comp) >= len(plain) {
		t.Fatalf("compressed frame %d not smaller than plain %d", len(comp), len(plain))
	}
	if mt := binary.BigEndian.Uint32(comp[8:]); mt&FlagCompressed == 0 {
		t.Fatalf("FlagCompressed not set: msgType=%#x", mt)
	}
	if os := binary.BigEndian.Uint32(comp[4:]); os != uint32(len(payload)) {
		t.Fatalf("OriginalSize = %d, want %d", os, len(payload))
	}
	// Size counts the on-wire body: compressed bytes + the 16-byte tag.
	if sz := binary.BigEndian.Uint32(comp[0:]); sz != uint32(len(comp))-appHeaderSize {
		t.Fatalf("Size = %d, want %d", sz, len(comp)-appHeaderSize)
	}
	if mt := binary.BigEndian.Uint32(plain[8:]); mt&FlagCompressed != 0 {
		t.Fatal("FlagCompressed set on an uncompressed frame")
	}
}

// An incompressible payload must fall back to plain rather than grow.
func TestFrameAppSkipsUselessCompression(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	payload := make([]byte, 512)
	if _, err := rand.Read(payload); err != nil { // random: genuinely incompressible
		t.Fatal(err)
	}
	f, err := c.frameApp(anyBulkKind, payload, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if mt := binary.BigEndian.Uint32(f[8:]); mt&FlagCompressed != 0 {
		t.Fatal("compressed an incompressible payload")
	}
	if sz := binary.BigEndian.Uint32(f[0:]); sz != uint32(len(payload))+16 {
		t.Fatalf("Size = %d, want %d", sz, len(payload)+16)
	}
}

// FlagCompressed is owned by the framing, not the caller's message kind.
func TestFrameAppRejectsCallerSetFlag(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	if _, err := c.frameApp(FlagCompressed|anyBulkKind, []byte("x"), false, false); err == nil {
		t.Fatal("accepted a MessageType with FlagCompressed set")
	}
}

// The §7 length rules for a compressed frame, exercised through the function
// that implements them. This test used to round-trip the lz4 library and t.Log a
// branch it never asserted: it never called recvAppWith at all, so the receive
// path it is named for was unexecuted by it.
func TestRecvAppLengthRules(t *testing.T) {
	key := bytes.Repeat([]byte{0x3D}, 32)
	payload := artifactLike(2048)
	block := compressBlock(payload)
	if block == nil {
		t.Fatal("artifactLike payload did not compress")
	}
	seal := func(body []byte, origSize uint32) []byte {
		t.Helper()
		hdr := appHeader(uint32(len(body))+chacha20poly1305.Overhead, origSize,
			anyBulkKind|FlagCompressed, 1)
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			t.Fatal(err)
		}
		return append(hdr, aead.Seal(nil, appNonce(1), body, hdr)...)
	}
	recv := func(frame []byte) error {
		var rx uint64
		_, _, _, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, MaxAppPayload, 0, MaxAppPayload)
		return err
	}

	if err := recv(seal(block, uint32(len(payload)))); err != nil {
		t.Fatalf("a well-formed compressed frame was rejected: %v", err)
	}
	// A truncated block. LZ4's block decoder may or may not report an error on
	// one; what makes the frame unacceptable either way is that it cannot inflate
	// to exactly OriginalSize, which is the check the receive path must be making
	// rather than trusting the decoder to fail.
	if err := recv(seal(block[:len(block)/2], uint32(len(payload)))); !errors.Is(err, ErrRejected) {
		t.Errorf("truncated block: err = %v, want ErrRejected", err)
	}
	// §7: compressed with OriginalSize 0 is invalid on its face.
	if err := recv(seal(block, 0)); !errors.Is(err, ErrRejected) {
		t.Errorf("OriginalSize 0: err = %v, want ErrRejected", err)
	}
	// §7.1: an OriginalSize above the ceiling is refused before the allocation it
	// would otherwise size.
	if err := recv(seal(block, MaxAppPayload+1)); !errors.Is(err, ErrRejected) {
		t.Errorf("OriginalSize above the ceiling: err = %v, want ErrRejected", err)
	}
}

func TestPadClassLadder(t *testing.T) {
	for _, tc := range []struct{ n, want int }{
		{0, 64}, {1, 64}, {8, 64}, {64, 64}, {65, 128}, {128, 128},
		{129, 256}, {1000, 1024}, {1024, 1024}, {1025, 2048},
	} {
		if got := padClass(tc.n); got != tc.want {
			t.Errorf("padClass(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
	// Above the ladder a message keeps its true length rather than doubling into
	// a class this layer would refuse to read back.
	if got := padClass(MaxAppPayload); got != MaxAppPayload {
		t.Errorf("padClass(max) = %d, want %d", got, MaxAppPayload)
	}
}

func TestFrameAppPadsControlMessage(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} // an 8-octet write

	f, err := c.frameApp(anyControlKind, payload, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Sealed body is the 64 B class plus the Poly1305 tag; OriginalSize stays true.
	if sz := binary.BigEndian.Uint32(f[0:]); sz != 64+16 {
		t.Errorf("Size = %d, want %d", sz, 64+16)
	}
	if os := binary.BigEndian.Uint32(f[4:]); os != uint32(len(payload)) {
		t.Errorf("OriginalSize = %d, want %d", os, len(payload))
	}
	if mt := binary.BigEndian.Uint32(f[8:]); mt&FlagCompressed != 0 {
		t.Error("padded message must not be compressed")
	}

	c.txNum.Store(0)
	plain, err := c.frameApp(anyControlKind, payload, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) >= len(f) {
		t.Errorf("unpadded frame %d not smaller than padded %d", len(plain), len(f))
	}
}

// Compression wins over padding: the combination is undefined on the wire (three
// lengths, two header fields), so frameApp must never emit both.
func TestFrameAppNeverPadsCompressed(t *testing.T) {
	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	payload := artifactLike(4096)
	f, err := c.frameApp(anyBulkKind, payload, true, true)
	if err != nil {
		t.Fatal(err)
	}
	mt := binary.BigEndian.Uint32(f[8:])
	if mt&FlagCompressed == 0 {
		t.Fatal("expected compression to be applied")
	}
	body := int(binary.BigEndian.Uint32(f[0:])) - 16
	if body == padClass(body) && body != len(payload) {
		t.Errorf("compressed body %d looks padded to a class", body)
	}
}

// A pixel frame is the highest-volume message this protocol carries, and §13
// permits compressing it. This pins that the compressed path actually pays on
// frame-shaped data — a 28-byte header plus RGBW pixels with the uniform and
// repeating regions LED content is full of.
func TestPixelFrameCompresses(t *testing.T) {
	const strips, leds = 8, 256
	frame := make([]byte, 28+strips*leds*4)
	binary.BigEndian.PutUint64(frame[0:], 1)  // frame number
	binary.BigEndian.PutUint64(frame[8:], 0)  // not_before
	binary.BigEndian.PutUint64(frame[16:], 0) // not_after
	binary.BigEndian.PutUint32(frame[24:], uint32(strips*leds*4))
	px := frame[28:]
	for i := 0; i < len(px); i += 4 { // a gradient with large flat runs
		v := byte((i / 4) / leds * 8)
		px[i], px[i+1], px[i+2], px[i+3] = v, 0x00, 0xff-v, 0x00
	}

	c := &Client{kC2S: bytes.Repeat([]byte{0x11}, 32)}
	plain, err := c.frameApp(CmdPixelFrame, frame, false, false)
	if err != nil {
		t.Fatal(err)
	}
	c.txNum.Store(0)
	comp, err := c.frameApp(CmdPixelFrame, frame, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(comp) >= len(plain) {
		t.Fatalf("frame did not compress: %d vs %d", len(comp), len(plain))
	}
	if mt := binary.BigEndian.Uint32(comp[8:]); mt&FlagCompressed == 0 {
		t.Fatal("FlagCompressed not set on a compressed frame")
	}
	t.Logf("frame %d B -> %d B on the wire (%.1f%%)",
		len(plain), len(comp), 100*float64(len(comp))/float64(len(plain)))
}
