// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"bytes"
	"testing"
	"time"
)

// The wire stride is 4 whatever the strip is, so both strip types produce the
// same frame size for the same pixel count. Sizing from DEVICE_INFO's bpp is
// the mistake this asserts against.
func TestFrameSizeIgnoresStripBPP(t *testing.T) {
	if got, err := FrameBytes(2, 1024); got != 8192 || err != nil {
		t.Fatalf("2x1024 frame is %d bytes (%v), want 8192", got, err)
	}
	// An RGB device and an RGBW device of the same geometry agree.
	if got, _ := FrameBytes(1, 64); got != 256 {
		t.Fatalf("1x64 frame must be 256 bytes at the 4-byte wire stride")
	}
}

func TestPixelFrameRoundTrip(t *testing.T) {
	pixels := make([]byte, 256)
	for i := range pixels {
		pixels[i] = byte(i)
	}
	b, err := PixelFrame(-1, 1234567890, 9876543210, pixels)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := ParsePixelFrame(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// frame_number is signed on the wire; -1 must survive rather than becoming
	// a very large unsigned value.
	if got.FrameNumber != -1 || got.NotBefore != 1234567890 || got.NotAfter != 9876543210 {
		t.Fatalf("header round-trip: %+v", got)
	}
	if len(got.Pixels) != len(pixels) {
		t.Fatalf("pixels %d bytes, want %d", len(got.Pixels), len(pixels))
	}
}

func TestPixelFrameVector(t *testing.T) {
	want := vector(t, "000000000000000117979cfe3d85cd15", 32)
	got, err := PixelFrame(1, 1700000000123456789, 1700000000133456789, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PIXEL_FRAME\n got %x\nwant %x", got, want)
	}
	p, err := ParsePixelFrame(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.FrameNumber != 1 || p.NotBefore != 1700000000123456789 ||
		p.NotAfter != 1700000000133456789 || !bytes.Equal(p.Pixels, []byte{1, 2, 3, 4}) {
		t.Fatalf("decoded %+v", p)
	}
}

func TestFrameTimes(t *testing.T) {
	now := time.Unix(1700000000, 0)
	nb, na := FrameTimes(now, 33*time.Millisecond, 10*time.Millisecond)
	if nb != 1700000000033000000 || na != 1700000000043000000 {
		t.Errorf("lead 33 ms window 10 ms: (%d, %d)", nb, na)
	}
	for _, w := range []time.Duration{0, -time.Millisecond} {
		if _, na := FrameTimes(now, 33*time.Millisecond, w); na != 0 {
			t.Errorf("window %v: notAfter %d, want 0", w, na)
		}
	}
	if nb, _ := FrameTimes(now, -time.Second, 10*time.Millisecond); nb != 1700000000000000000 {
		t.Errorf("negative lead: notBefore %d", nb)
	}
}

func TestFrameTimesClampsLead(t *testing.T) {
	nb, na := FrameTimes(time.Unix(1700000000, 0), 5*time.Second, 10*time.Millisecond)
	if nb != 1700000001000000000 || na != 1700000001010000000 {
		t.Errorf("lead 5 s: (%d, %d)", nb, na)
	}
}

func TestFrameTimesZeroNowIsOff(t *testing.T) {
	nb, na := FrameTimes(time.Time{}, 33*time.Millisecond, 10*time.Millisecond)
	if nb != 0 || na != 0 {
		t.Errorf("zero now: (%d, %d), want (0, 0)", nb, na)
	}
}

func TestPixelFrameRejectsOversize(t *testing.T) {
	if _, err := PixelFrame(0, 0, 0, make([]byte, MaxFrameBytes+PixelWireBPP)); err == nil {
		t.Error("a frame over MaxFrameBytes must be refused")
	}
}

func TestPixelFrameRejectsPartialPixels(t *testing.T) {
	if _, err := PixelFrame(0, 0, 0, make([]byte, 255)); err == nil {
		t.Error("255 bytes is not a whole number of 4-byte pixels")
	}
}

func TestPixelFrameHeaderTooShort(t *testing.T) {
	if _, err := ParsePixelFrame(make([]byte, 27)); err != ErrShort {
		t.Errorf("27 bytes: %v, want ErrShort", err)
	}
}

// A length disagreement means the stream is misframed, not that the peer is
// newer — the one payload where trailing bytes are NOT ignored.
func TestPixelFrameRequiresExactLength(t *testing.T) {
	b, _ := PixelFrame(0, 0, 0, make([]byte, 16))
	if _, err := ParsePixelFrame(append(b, 0xAA, 0xBB, 0xCC, 0xDD)); err == nil {
		t.Error("a declared length shorter than the payload must be refused")
	}
	if _, err := ParsePixelFrame(b[:len(b)-4]); err == nil {
		t.Error("a declared length longer than the payload must be refused")
	}
}

// The size is computed in uint64 and bounded, so neither a 32-bit int nor a
// hostile DEVICE_INFO turns it into a wrapped length or a huge allocation.
func TestFrameBytesIsBounded(t *testing.T) {
	if got, err := FrameBytes(1, MaxFrameBytes/PixelWireBPP); err != nil || got != MaxFrameBytes {
		t.Fatalf("a frame exactly at the ceiling: %d %v", got, err)
	}
	for _, c := range []struct{ strips, leds uint32 }{
		{1, CapacityMax/3 + 1},
		{65535, 65535},           // ~17 GiB; overflows a 32-bit int
		{0xFFFFFFFF, 0xFFFFFFFF}, // would wrap even uint64 at the 4-byte stride
		{0x10000, 0x10000},       // wraps uint32 to 0
	} {
		if n, err := FrameBytes(c.strips, c.leds); err == nil {
			t.Errorf("%dx%d: want refusal, got %d", c.strips, c.leds, n)
		}
	}
	if n, err := FrameBytes(0, 64); err != nil || n != 0 {
		t.Errorf("zero strips is an empty frame, not an error: %d %v", n, err)
	}
}

// sled 6.2: limit = min(strips × leds × 4, envelope − 28 − 16), rounded down to
// a multiple of 4.
func TestSled62FrameLimitEnvelopeBound(t *testing.T) {
	n, err := FrameLimit(Geometry{Envelope: 1203, Strips: 4, LEDs: 1024, BPP: 3, HasLEDs: true})
	if err != nil || n != 1156 {
		t.Fatalf("got %d, %v; want 1156", n, err)
	}
}

func TestSled62FrameLimitCapacityBound(t *testing.T) {
	n, err := FrameLimit(Geometry{Envelope: 32768, Strips: 1, LEDs: 10, BPP: 3, HasLEDs: true})
	if err != nil || n != 40 {
		t.Fatalf("got %d, %v; want 40", n, err)
	}
}

// sled 5.3.2 accepts strips × leds × bpp up to 16 MiB, so FrameBytes must size
// every RGB geometry the decoder accepts.
func TestSled62FrameBytesAcceptsDecodedRGB(t *testing.T) {
	if _, err := DecodeGeometry(fields("envelope", "1200", "pixel", "", "strips", "128", "leds", "43690", "bpp", "3")); err != nil {
		t.Fatalf("decoder: %v", err)
	}
	n, err := FrameBytes(128, 43690)
	if err != nil || n != 22369280 {
		t.Fatalf("got %d, %v; want 22369280", n, err)
	}
}

func TestSled62FrameLimitNeedsLEDs(t *testing.T) {
	if n, err := FrameLimit(Geometry{Envelope: 1200}); err == nil {
		t.Fatalf("no strips/leds: got %d, want an error", n)
	}
}

// sled 6.1: a frame carries at least one pixel; a device discards one that
// carries none.
func TestSled61PixelFrameRefusesEmpty(t *testing.T) {
	if b, err := PixelFrame(0, 0, 0, nil); err == nil {
		t.Fatalf("empty frame built: % x", b)
	}
}

func TestSled61ParseRefusesEmpty(t *testing.T) {
	b := make([]byte, PixelFrameHeader) // pixel_byte_length 0
	if _, err := ParsePixelFrame(b); err == nil {
		t.Fatal("a frame with pixel_byte_length 0 parsed")
	}
}

func TestSled61PixelFrameForRefusesOverLimit(t *testing.T) {
	g := Geometry{Envelope: 1203, Strips: 4, LEDs: 1024, BPP: 3, HasLEDs: true}
	if _, err := PixelFrameFor(g, 0, 0, 0, make([]byte, 1156)); err != nil {
		t.Fatalf("1156 bytes (the limit): %v", err)
	}
	if _, err := PixelFrameFor(g, 0, 0, 0, make([]byte, 1160)); err == nil {
		t.Fatal("1160 bytes (over the limit) accepted")
	}
}
