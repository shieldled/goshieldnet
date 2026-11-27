// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package sled encodes and decodes ShieldLED application-layer payloads
// (shieldnet-protocol/spec/application.md), the payloads carried inside a ShieldNet message:
// the three responses, PIXEL_FRAME and NTP_SERVER. The one-byte commands need
// no encoder.
//
// The v1 package deliberately stops at the message layer: it carries opaque
// (MessageType, payload) pairs and leaves the payload to its caller. This is
// that caller. Kind constants live in v1 (v1.CmdPing, v1.RespAck, ...) and are
// pinned to the spec by v1's own test; the layouts live here and are pinned to
// the spec's published golden vectors by response_test.go,
// pixelframe_test.go and ntpserver_test.go.
//
// Why the vectors and not a comparison against the firmware: the two
// implementations live in different repositories, nothing compiles both, and
// the firmware side cannot read this repo's sources. The specification is the
// artifact both sides share, so both sides assert against it.
//
// Forward compatibility follows the spec's R2/R3/R6. Trailing bytes beyond a
// known layout are ignored rather than rejected, so every decoder checks a
// minimum length and never an exact one. A payload SHORTER than its documented
// minimum is malformed, not an older peer, and is refused.
package sled

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// Sizes fixed by the specification.
const (
	AckHeaderSize       = 14
	AckMaxDetail        = 128
	StatusRespSize      = 78
	DeviceInfoMax       = 1024
	DeviceInfoMaxFields = 32
)

// ErrShort reports a payload below its documented minimum length. It is
// distinct from "unknown kind": a short payload is malformed, whereas an
// unknown kind is a peer this build does not know about (R2).
var ErrShort = errors.New("sled: payload shorter than its layout")

// ── ACK (0x80) ──────────────────────────────────────────────────────────────

// Ack is a command acknowledgement.
//
// OrigMessageNum is what correlates a response to the command that caused it.
// The spec requires correlation by that field and never by message order, so a
// device must echo the number it was asked with.
type Ack struct {
	OrigKind       uint8
	Status         uint8
	OrigMessageNum uint64
	Detail         []byte // aliases the input on decode; nil when empty
}

// ACK status codes (spec/application.md 10.3), the Status of an Ack.
// AckStatusName names them for diagnostics.
const (
	AckOK              = 0
	AckErrInvalidArg   = 1
	AckErrOOM          = 5
	AckErrUnknownKind  = 6
	AckErrModeMismatch = 7
)

var ackNames = map[uint8]string{
	AckOK: "OK", AckErrInvalidArg: "ERR_INVALID_ARG", AckErrOOM: "ERR_OOM",
	AckErrUnknownKind: "ERR_UNKNOWN_KIND", AckErrModeMismatch: "ERR_MODE_MISMATCH",
}

// AckStatusName returns a readable name, or a hex fallback for a status this
// build does not know — a newer device must not render as a blank.
func AckStatusName(status uint8) string {
	if n, ok := ackNames[status]; ok {
		return n
	}
	return fmt.Sprintf("status(0x%02x)", status)
}

// EncodeAck builds an ACK payload. An over-long detail is clamped rather than
// refused: the wire format bounds it at 128 bytes, and a diagnostic is not
// worth failing a response over.
func EncodeAck(a Ack) []byte {
	detail := a.Detail
	if len(detail) > AckMaxDetail {
		detail = detail[:AckMaxDetail]
	}
	b := make([]byte, AckHeaderSize+len(detail))
	b[0] = a.OrigKind
	b[1] = a.Status
	// b[2:4] reserved: zero on send, ignored on receive (R4)
	binary.BigEndian.PutUint64(b[4:], a.OrigMessageNum)
	binary.BigEndian.PutUint16(b[12:], uint16(len(detail)))
	copy(b[AckHeaderSize:], detail)
	return b
}

// DecodeAck parses an ACK. Detail aliases p rather than copying; a caller that
// retains it past p's lifetime must copy. Detail is at most AckMaxDetail bytes.
func DecodeAck(p []byte) (Ack, error) {
	if len(p) < AckHeaderSize {
		return Ack{}, ErrShort
	}
	dl := int(binary.BigEndian.Uint16(p[12:]))
	if len(p)-AckHeaderSize < dl {
		// A device claiming more detail than it sent must not yield a slice of
		// bytes that were never received.
		return Ack{}, fmt.Errorf("sled: ACK detail_len %d exceeds payload", dl)
	}
	a := Ack{
		OrigKind:       p[0],
		Status:         p[1],
		OrigMessageNum: binary.BigEndian.Uint64(p[4:]),
	}
	// The wire format bounds detail at AckMaxDetail and EncodeAck never sends
	// more, but detail_len is a be16, so a peer can claim up to 65535. Clamp on
	// decode as well: a diagnostic is not worth refusing an ACK over, and a
	// consumer that logs or stores Detail should not inherit an unbounded field.
	// (libshieldnet's sled_ack_decode does not clamp; it hands detail_len
	// through. The bytes past 128 are trailing data either way, which R3 ignores.)
	if dl > AckMaxDetail {
		dl = AckMaxDetail
	}
	if dl > 0 {
		a.Detail = p[AckHeaderSize : AckHeaderSize+dl]
	}
	return a, nil
}

// ── STATUS_RESP (0x81) ──────────────────────────────────────────────────────

// Status is the fixed 78-byte device status.
//
// TargetFPS is the configured value, not a measurement. Brightness is the live
// value, not the configured default. Conflating the pair makes a device look
// healthy while it is not.
//
// Ext is the extension block, bytes 32 to 75: an extension that the
// specification registers defines its content, and a device without one sends
// it zeroed. This package copies it and does not interpret it.
type Status struct {
	Frames             uint64
	Commands           uint64
	PixelFramesDropped uint64
	LEDRefreshErrors   uint32
	Mode               uint8
	Connected          bool
	OutputEnabled      bool
	Ext                [StatusExtSize]byte
	Brightness         uint8
	TargetFPS          uint8
}

// The extension block of STATUS: its offset and size.
const (
	StatusExtOffset = 32
	StatusExtSize   = 44
)

// EncodeStatus encodes s as a STATUS response payload of StatusRespSize
// octets, the inverse of DecodeStatus.
func EncodeStatus(s Status) []byte {
	b := make([]byte, StatusRespSize)
	binary.BigEndian.PutUint64(b[0:], s.Frames)
	binary.BigEndian.PutUint64(b[8:], s.Commands)
	binary.BigEndian.PutUint64(b[16:], s.PixelFramesDropped)
	binary.BigEndian.PutUint32(b[24:], s.LEDRefreshErrors)
	b[28] = s.Mode
	if s.Connected {
		b[29] = 1
	}
	if s.OutputEnabled {
		b[30] = 1
	}
	// b[31] reserved
	copy(b[StatusExtOffset:], s.Ext[:])
	b[76] = s.Brightness
	b[77] = s.TargetFPS
	return b
}

// DecodeStatus parses a STATUS_RESP. A longer payload is a newer peer (R6) and
// its trailing bytes are ignored; a shorter one is malformed.
func DecodeStatus(p []byte) (Status, error) {
	if len(p) < StatusRespSize {
		return Status{}, ErrShort
	}
	s := Status{
		Frames:             binary.BigEndian.Uint64(p[0:]),
		Commands:           binary.BigEndian.Uint64(p[8:]),
		PixelFramesDropped: binary.BigEndian.Uint64(p[16:]),
		LEDRefreshErrors:   binary.BigEndian.Uint32(p[24:]),
		Mode:               p[28],
		Connected:          p[29] != 0,
		OutputEnabled:      p[30] != 0,
		Brightness:         p[76],
		TargetFPS:          p[77],
	}
	copy(s.Ext[:], p[StatusExtOffset:StatusExtOffset+StatusExtSize])
	return s, nil
}

// ── DEVICE_INFO (0x84) ──────────────────────────────────────────────────────

// DeviceInfoField is one [namelen][name][vallen][value] pair. A field with an
// empty value is a capability advertisement (R7).
type DeviceInfoField struct {
	Name  string
	Value string
}

// IsCapability reports whether the field advertises a capability rather than
// carrying a value.
func (f DeviceInfoField) IsCapability() bool { return f.Value == "" }

// HasCapability reports whether any field carries the given name, whatever its
// value: a capability is tested by the presence of its name.
func HasCapability(fields []DeviceInfoField, name string) bool {
	for _, f := range fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// Uint32 parses the field's decimal-ASCII value. DEVICE_INFO carries numbers as
// text, so every consumer needs this and none should hand-roll it.
func (f DeviceInfoField) Uint32() (uint32, error) {
	// DEVICE_INFO's value grammar is "ASCII digits only — no sign, no leading zeros, no whitespace".
	// ParseUint accepts "+7", " 7" and "007"; the C counterpart
	// (response_decode.h sled_device_info_value_u32) refuses all three, so
	// accepting them here is a silent cross-implementation disagreement.
	if f.Value == "" || (len(f.Value) > 1 && f.Value[0] == '0') {
		return 0, fmt.Errorf("sled: field %q value %q is not canonical decimal", f.Name, f.Value)
	}
	for i := 0; i < len(f.Value); i++ {
		if f.Value[i] < '0' || f.Value[i] > '9' {
			return 0, fmt.Errorf("sled: field %q value %q is not canonical decimal", f.Name, f.Value)
		}
	}
	v, err := strconv.ParseUint(f.Value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("sled: field %q value %q is not a uint32: %w", f.Name, f.Value, err)
	}
	return uint32(v), nil
}

// deviceInfoRange returns the inclusive range shieldnet-protocol/spec/application.md 5.3.1 defines
// for a known DEVICE_INFO field, and whether the field has one. The spec states
// the ranges explicitly "because a decoder must reject outside them and two
// independent implementations cannot each invent their own" — which means one
// table here, read by both the encoder and the decoder, and not two that drift.
// A field with no defined range (x-* private use, and anything a later revision
// adds) is unconstrained by R2's forward-compatibility rule.
func deviceInfoRange(name string) (lo, hi uint64, ok bool) {
	switch name {
	case "envelope":
		return 80, 16777216, true
	case "strips", "leds":
		return 1, 65535, true
	case "bpp":
		return 3, 4, true // an enum of exactly {3,4}, which this range expresses
	}
	return 0, 0, false
}

// Uint32Checked is Uint32 plus the field's specified range.
//
// A value outside it is a protocol error the caller MUST reject: the spec is
// explicit that it is "never clamped, and never guessed at". Clamping is not the
// safe reading it looks like — a clamped geometry silently drives the wrong
// hardware, and a clamped envelope makes the controller send frames the device
// must reject, which is a header/body length disagreement and so a permanent
// stream desynchronisation.
func (f DeviceInfoField) Uint32Checked() (uint32, error) {
	v, err := f.Uint32()
	if err != nil {
		return 0, err
	}
	lo, hi, ok := deviceInfoRange(f.Name)
	if !ok {
		return v, nil
	}
	if uint64(v) < lo || uint64(v) > hi {
		return 0, fmt.Errorf("sled: field %q value %d is outside %d..%d", f.Name, v, lo, hi)
	}
	return v, nil
}

// CapacityMax is the spec's ceiling on strips × leds × bpp, the same as the
// largest envelope: a geometry over it MUST be rejected.
const CapacityMax = 16777216

// Geometry is the sizing part of DEVICE_INFO: what the device can receive
// (Envelope) and what it can drive (Strips × LEDs at BPP bytes per pixel).
// Envelope is always present; the other three are required only of a device
// advertising pixel (sled 5.3.3 rule 1) and are zero when absent.
type Geometry struct {
	Envelope uint32
	Strips   uint32
	LEDs     uint32
	BPP      uint8
	// HasLEDs is true when strips and leds were both advertised (always with
	// pixel). BPP may still be zero without pixel.
	HasLEDs bool
}

// checkGeometry applies the spec's ranges and its capacity ceiling. The encoder
// and DecodeGeometry both call it, so the two sides cannot disagree.
func checkGeometry(g Geometry) error {
	for _, f := range []struct {
		name string
		v    uint64
	}{{"envelope", uint64(g.Envelope)}, {"strips", uint64(g.Strips)}, {"leds", uint64(g.LEDs)}, {"bpp", uint64(g.BPP)}} {
		lo, hi, _ := deviceInfoRange(f.name)
		if f.v < lo || f.v > hi {
			return fmt.Errorf("sled: %s %d outside %d..%d", f.name, f.v, lo, hi)
		}
	}
	// In uint64: at the field maxima the product is ~1.7e10, which overflows a
	// 32-bit int.
	if uint64(g.Strips)*uint64(g.LEDs)*uint64(g.BPP) > CapacityMax {
		return fmt.Errorf("sled: geometry %dx%dx%d exceeds the capacity ceiling", g.Strips, g.LEDs, g.BPP)
	}
	return nil
}

// DecodeGeometry extracts and validates the geometry fields of DEVICE_INFO
// from a decoded field list (DecodeDeviceInfo).
//
// It enforces the spec's rules exactly (sled 5.3.3): envelope MUST be present;
// strips, leds and bpp MUST be present when the device advertises pixel, and
// are optional without it (rule 1 — a missing required field is a protocol
// error, never a fallback); a repeated name takes its LAST value (rule 4), and
// it is that value which is checked; each value present must be canonical
// decimal within its range, bpp exactly 3 or 4; and, when all three are
// present, strips × leds × bpp must not exceed CapacityMax. Any violation is an
// error and the caller MUST reject the DEVICE_INFO rather than substitute a
// default: a guessed geometry drives the wrong hardware, and a guessed envelope
// makes the controller send frames the device must reject.
func DecodeGeometry(fields []DeviceInfoField) (Geometry, error) {
	pixel := HasCapability(fields, "pixel")
	var v [4]uint32
	var present [4]bool
	for i, name := range []string{"envelope", "strips", "leds", "bpp"} {
		f, ok := lastField(fields, name) // rule 4: last value wins
		if !ok {
			if i == 0 || pixel {
				return Geometry{}, fmt.Errorf("sled: DEVICE_INFO lacks required field %q", name)
			}
			continue
		}
		x, err := f.Uint32Checked()
		if err != nil {
			return Geometry{}, err
		}
		v[i], present[i] = x, true
	}
	g := Geometry{Envelope: v[0], Strips: v[1], LEDs: v[2], BPP: uint8(v[3])} // bpp ∈ {3,4}, checked above
	g.HasLEDs = present[1] && present[2]
	if present[1] && present[2] && present[3] {
		if err := checkGeometry(g); err != nil {
			return Geometry{}, err
		}
	}
	return g, nil
}

// lastField returns the last field named name (rule 4: last value wins).
func lastField(fields []DeviceInfoField, name string) (DeviceInfoField, bool) {
	var out DeviceInfoField
	found := false
	for _, f := range fields {
		if f.Name == name {
			out, found = f, true
		}
	}
	return out, found
}

// EncodeDeviceInfo writes envelope, strips, leds and bpp in table order (only
// envelope is required of every device; the other three go with pixel, sled
// 5.3.3), then each capability as a name-only field.
//
// It refuses an out-of-range value rather than emitting it: a geometry outside
// the spec's bounds is a self-inflicted disconnect once a controller applies
// DEVICE_INFO's range checks, so it is caught at the boundary the device controls.
func EncodeDeviceInfo(envelope, strips, leds uint32, bpp uint8, caps []string) ([]byte, error) {
	return EncodeDeviceInfoFields(envelope, strips, leds, bpp, nil, caps)
}

// EncodeDeviceInfoFields writes envelope, strips, leds and bpp in table order,
// then fields, then each capability in caps as a name-only field. Each of
// fields must have a non-empty name and value; a field is for a value the
// four geometry fields do not carry, such as one an extension defines. A field
// named envelope, strips, leds or bpp, and a name used twice across fields and
// caps, are refused, since a decoder takes the last value of a repeated name
// (sled 5.3.3 rule 4). The geometry is checked as for EncodeDeviceInfo.
func EncodeDeviceInfoFields(envelope, strips, leds uint32, bpp uint8, fields []DeviceInfoField, caps []string) ([]byte, error) {
	if err := checkGeometry(Geometry{Envelope: envelope, Strips: strips, LEDs: leds, BPP: bpp}); err != nil {
		return nil, err
	}
	seen := map[string]bool{"envelope": true, "strips": true, "leds": true, "bpp": true}
	for _, f := range fields {
		if f.Name == "" || f.Value == "" {
			return nil, fmt.Errorf("sled: field %q needs a non-empty name and value", f.Name)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("sled: field %q would repeat a DEVICE_INFO field", f.Name)
		}
		seen[f.Name] = true
	}
	for _, c := range caps {
		if seen[c] {
			return nil, fmt.Errorf("sled: capability %q would repeat a DEVICE_INFO field", c)
		}
		seen[c] = true
	}
	n := 4 + len(fields) + len(caps)
	if n > DeviceInfoMaxFields {
		return nil, fmt.Errorf("sled: %d fields exceeds the maximum of %d", n, DeviceInfoMaxFields)
	}

	var b []byte
	add := func(name, value string) error {
		if len(name) > 255 || len(value) > 255 {
			return fmt.Errorf("sled: field %q does not fit a length byte", name)
		}
		b = append(b, byte(len(name)))
		b = append(b, name...)
		b = append(b, byte(len(value)))
		b = append(b, value...)
		return nil
	}
	for _, f := range []DeviceInfoField{
		{"envelope", strconv.FormatUint(uint64(envelope), 10)},
		{"strips", strconv.FormatUint(uint64(strips), 10)},
		{"leds", strconv.FormatUint(uint64(leds), 10)},
		{"bpp", strconv.FormatUint(uint64(bpp), 10)},
	} {
		if err := add(f.Name, f.Value); err != nil {
			return nil, err
		}
	}
	for _, f := range fields {
		if err := add(f.Name, f.Value); err != nil {
			return nil, err
		}
	}
	for _, c := range caps {
		if err := add(c, ""); err != nil {
			return nil, err
		}
	}
	if len(b) > DeviceInfoMax {
		return nil, fmt.Errorf("sled: DEVICE_INFO is %d bytes, over the %d limit", len(b), DeviceInfoMax)
	}
	return b, nil
}

// DecodeDeviceInfo walks the field list.
//
// It returns fields rather than a struct on purpose: the payload is open-ended
// by design (R7), and decoding only the four required fields into a struct
// would silently drop every capability and every field added later, which is
// the opposite of what R7 asks for.
func DecodeDeviceInfo(p []byte) ([]DeviceInfoField, error) {
	// DEVICE_INFO rule 5 (Bounded): "a receiver MUST reject a payload larger than 1024 bytes or carrying
	// more than 32 fields." These were enforced on encode only, so a device
	// answering with a 1 MiB payload of empty name/value pairs made the caller
	// allocate ~500k fields per query.
	if len(p) > DeviceInfoMax {
		return nil, fmt.Errorf("sled: DEVICE_INFO is %d bytes, over the %d limit", len(p), DeviceInfoMax)
	}
	var out []DeviceInfoField
	for off := 0; off < len(p); {
		if len(out) == DeviceInfoMaxFields {
			return nil, fmt.Errorf("sled: DEVICE_INFO carries more than %d fields", DeviceInfoMaxFields)
		}
		if len(p)-off < 1 {
			return nil, ErrShort
		}
		nl := int(p[off])
		off++
		if len(p)-off < nl {
			return nil, fmt.Errorf("sled: DEVICE_INFO name of %d bytes runs past the payload", nl)
		}
		name := string(p[off : off+nl])
		off += nl

		if len(p)-off < 1 {
			return nil, ErrShort
		}
		vl := int(p[off])
		off++
		if len(p)-off < vl {
			return nil, fmt.Errorf("sled: DEVICE_INFO value of %d bytes runs past the payload", vl)
		}
		out = append(out, DeviceInfoField{Name: name, Value: string(p[off : off+vl])})
		off += vl
	}
	return out, nil
}
