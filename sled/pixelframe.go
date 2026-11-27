// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"encoding/binary"
	"fmt"
	"time"
)

// PixelFrameHeader is the fixed prefix of a PIXEL_FRAME payload:
//
//	[be64 signed frame_number][be64 signed not_before][be64 signed not_after]
//	[be32 pixel_byte_length][RGB/RGBW bytes]
//
// not_before and not_after are Unix nanoseconds; see Frame timing in the spec.
const PixelFrameHeader = 28

// PixelWireBPP is the wire stride: 4 bytes per pixel (R, G, B, W),
// UNCONDITIONALLY, whatever the strip is.
//
// On an RGB strip the device drops the fourth byte on ingest, so a frame is
// sized strips × leds × 4 for every device and one controller encoding serves
// both strip types.
//
// DEVICE_INFO's bpp describes the STRIP, for colour handling. It is not the
// wire stride and must not be used to size a frame: strips × leds × 3 is
// neither a whole number of wire pixels nor the length the controller sent, so
// sizing from it makes an RGB unit reject every frame.
const PixelWireBPP = 4

// PixelFrame builds a PIXEL_FRAME payload. pixels must be at least one and a
// whole number of 4-byte pixels (sled 6.1). It does not check the device's
// frame limit: PixelFrameFor does.
//
// frameNumber, notBefore and notAfter are signed on the wire; what a receiver
// does with the two timestamps is defined by Frame timing in the spec. Zero
// switches a timestamp off.
func PixelFrame(frameNumber, notBefore, notAfter int64, pixels []byte) ([]byte, error) {
	if len(pixels) == 0 {
		return nil, fmt.Errorf("sled: a PIXEL_FRAME carries at least one pixel")
	}
	if len(pixels)%PixelWireBPP != 0 {
		return nil, fmt.Errorf("sled: %d pixel bytes is not a whole number of %d-byte pixels",
			len(pixels), PixelWireBPP)
	}
	if len(pixels) > MaxFrameBytes {
		return nil, fmt.Errorf("sled: %d pixel bytes is over the %d-byte ceiling", len(pixels), MaxFrameBytes)
	}
	b := make([]byte, PixelFrameHeader+len(pixels))
	binary.BigEndian.PutUint64(b[0:], uint64(frameNumber))
	binary.BigEndian.PutUint64(b[8:], uint64(notBefore))
	binary.BigEndian.PutUint64(b[16:], uint64(notAfter))
	binary.BigEndian.PutUint32(b[24:], uint32(len(pixels)))
	copy(b[PixelFrameHeader:], pixels)
	return b, nil
}

// PixelFrameFor is PixelFrame for a device of geometry g: it also refuses more
// pixel bytes than FrameLimit(g) (sled 6.2), since exceeding the envelope ends
// the session (sled 3.6), and fails when g carries no strips and leds.
func PixelFrameFor(g Geometry, frameNumber, notBefore, notAfter int64, pixels []byte) ([]byte, error) {
	limit, err := FrameLimit(g)
	if err != nil {
		return nil, err
	}
	if len(pixels) > limit {
		return nil, fmt.Errorf("sled: %d pixel bytes is over the device's frame limit of %d", len(pixels), limit)
	}
	return PixelFrame(frameNumber, notBefore, notAfter, pixels)
}

// ParsedPixelFrame is a decoded PIXEL_FRAME (see Frame timing in the spec for
// the two timestamps). Pixels aliases the input.
type ParsedPixelFrame struct {
	FrameNumber int64
	NotBefore   int64
	NotAfter    int64
	Pixels      []byte
}

// MaxLead is the longest lead a sender may use (Frame timing, rule 6).
const MaxLead = time.Second // Frame timing rule 6: the lead MUST NOT exceed 1 s

// FrameTimes returns the two timestamps for a frame (Frame timing, rule 6):
// notBefore is now + lead, notAfter is notBefore + window. A window of 0
// or less gives notAfter 0 (no discarding); a negative lead counts as 0. A lead
// over MaxLead is clamped to it. A zero now means the caller has no clock, and
// gives both timestamps off.
func FrameTimes(now time.Time, lead, window time.Duration) (notBefore, notAfter int64) {
	if now.IsZero() {
		return 0, 0
	}
	if lead < 0 {
		lead = 0
	}
	if lead > MaxLead {
		lead = MaxLead
	}
	notBefore = now.Add(lead).UnixNano()
	if window > 0 {
		notAfter = notBefore + int64(window)
	}
	return notBefore, notAfter
}

// ParsePixelFrame validates and splits a PIXEL_FRAME payload.
//
// Unlike the response decoders, this one requires the declared length to match
// the remaining payload EXACTLY rather than ignoring trailing bytes: the spec
// says so, and a frame is the one payload where a length disagreement means the
// stream is misframed rather than that the peer is newer.
func ParsePixelFrame(p []byte) (ParsedPixelFrame, error) {
	if len(p) < PixelFrameHeader {
		return ParsedPixelFrame{}, ErrShort
	}
	n := int(binary.BigEndian.Uint32(p[24:]))
	if n != len(p)-PixelFrameHeader {
		return ParsedPixelFrame{}, fmt.Errorf(
			"sled: PIXEL_FRAME declares %d pixel bytes but carries %d", n, len(p)-PixelFrameHeader)
	}
	if n == 0 {
		return ParsedPixelFrame{}, fmt.Errorf("sled: PIXEL_FRAME carries no pixel")
	}
	if n%PixelWireBPP != 0 {
		return ParsedPixelFrame{}, fmt.Errorf(
			"sled: %d pixel bytes is not a whole number of %d-byte pixels", n, PixelWireBPP)
	}
	return ParsedPixelFrame{
		FrameNumber: int64(binary.BigEndian.Uint64(p[0:])),
		NotBefore:   int64(binary.BigEndian.Uint64(p[8:])),
		NotAfter:    int64(binary.BigEndian.Uint64(p[16:])),
		Pixels:      p[PixelFrameHeader:],
	}, nil
}

// MaxFrameBytes is the largest pixel_byte_length PixelFrame builds. It is the
// spec's capacity ceiling, which is also the largest envelope: no PIXEL_FRAME
// larger than this can be carried. FrameBytes can return more than this (a full
// frame of an RGB geometry near the ceiling); FrameLimit, bounded by envelope,
// never does.
const MaxFrameBytes = CapacityMax

// FrameBytes is the wire size of a full frame's pixel bytes for a device of
// this geometry. Note it does NOT take bpp: see PixelWireBPP.
//
// It returns a value for every strips × leds a valid DEVICE_INFO can carry, so
// it refuses only when strips × leds × 3 (the smallest bpp) exceeds CapacityMax:
// the result can then be up to about 22.4 MB, over MaxFrameBytes. What a
// controller may send is FrameLimit, which is bounded by envelope as well.
//
// The product is computed in uint64 — at the uint32 maxima it would overflow
// int on any platform, and at DEVICE_INFO's 65535 × 65535 it overflows a 32-bit
// int — and a geometry over the capacity ceiling is refused rather than
// returned, so a hostile geometry cannot become a multi-gigabyte allocation.
func FrameBytes(strips, ledsPerStrip uint32) (int, error) {
	// Each factor is bounded first: uint32 max squared times 4 would wrap even
	// uint64. Past that check the product is at most 2^50.
	if strips > CapacityMax || ledsPerStrip > CapacityMax {
		return 0, fmt.Errorf("sled: %d x %d frame is over the capacity ceiling %d",
			strips, ledsPerStrip, CapacityMax)
	}
	leds := uint64(strips) * uint64(ledsPerStrip)
	if leds*3 > CapacityMax {
		return 0, fmt.Errorf("sled: %d x %d LEDs is over the capacity ceiling %d",
			strips, ledsPerStrip, CapacityMax)
	}
	return int(leds * PixelWireBPP), nil
}

// FrameLimit is the largest pixel_byte_length a controller may send to a device
// of this geometry (sled 6.2):
//
//	min(strips × leds × 4, envelope − PixelFrameHeader − 16)
//
// rounded down to a multiple of 4. Exceeding the envelope term ends the session
// (sled 3.6). It is an error when the device advertised no strips and leds.
func FrameLimit(g Geometry) (int, error) {
	if !g.HasLEDs {
		return 0, fmt.Errorf("sled: no strips and leds advertised; no frame limit")
	}
	if g.Envelope < 80 {
		return 0, fmt.Errorf("sled: envelope %d is below 80", g.Envelope)
	}
	capacity := uint64(g.Strips) * uint64(g.LEDs) * PixelWireBPP
	limit := uint64(g.Envelope) - PixelFrameHeader - 16
	if capacity < limit {
		limit = capacity
	}
	return int(limit &^ 3), nil
}
