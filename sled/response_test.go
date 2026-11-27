// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"testing"
)

// The vectors are read from testdata/sled-vectors.json, a fixture extracted
// from spec/application.md (sections 10.1, 10.2 and Appendix A) in the
// shieldnet-protocol repository. The spec is the golden-vector source of truth;
// the fixture is its transcription, shared by every test here rather than pasted into each.
func vector(t *testing.T, pattern string, wantLen int) []byte {
	t.Helper()
	b := vectors(t, pattern)[0]
	if len(b) != wantLen {
		t.Fatalf("vector matching %q is %d bytes, want %d", pattern, len(b), wantLen)
	}
	return b
}

// vectors returns every fixture vector matching pattern, in order.
func vectors(t *testing.T, pattern string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/sled-vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct{ Vectors []string }
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	re := regexp.MustCompile(`^` + pattern + `[0-9a-f]*$`)
	var out [][]byte
	for _, v := range fx.Vectors {
		if !re.MatchString(v) {
			continue
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatalf("vector %q: %v", pattern, err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		t.Fatalf("vector matching %q not found in the fixture", pattern)
	}
	return out
}

func TestAckMatchesVector(t *testing.T) {
	want := vector(t, "0201000001", 36)
	got := EncodeAck(Ack{
		OrigKind:       0x02, // SET_FPS
		Status:         AckErrInvalidArg,
		OrigMessageNum: 0x0102030405060708,
		Detail:         []byte("fps out of range 1-255"),
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("ACK\n got %x\nwant %x", got, want)
	}

	back, err := DecodeAck(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.OrigKind != 0x02 || back.Status != AckErrInvalidArg ||
		back.OrigMessageNum != 0x0102030405060708 ||
		string(back.Detail) != "fps out of range 1-255" {
		t.Fatalf("ACK round-trip: %+v", back)
	}
}

// TestStatusMatchesVector asserts EVERY field of the spec's golden vector against
// the value the spec names for it, not just a round trip. A decode/encode pair
// that transposes two same-width neighbours — frames and commands, say —
// round-trips perfectly and is invisible on the wire only to this
// implementation; the firmware, which asserts the same vector, would
// disagree. The spec's field list (spec/application.md Appendix A.4, "STATUS
// (78 bytes)") is the authority for every constant below.
func TestStatusMatchesVector(t *testing.T) {
	// A.4.1 has the extension block patterned a0..cb, A.4.2 has it zeroed.
	all := vectors(t, "0102030405060708")
	if len(all) != 2 {
		t.Fatalf("the fixture has %d STATUS vectors, want 2 (A.4.1 and A.4.2)", len(all))
	}
	for i, want := range all {
		if len(want) != StatusRespSize {
			t.Fatalf("STATUS vector %d is %d bytes, want %d", i, len(want), StatusRespSize)
		}
		checkStatusVector(t, want, i == 0)
	}
}

func checkStatusVector(t *testing.T, want []byte, patterned bool) {
	t.Helper()
	back, err := DecodeStatus(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := EncodeStatus(back); !bytes.Equal(got, want) {
		t.Fatalf("STATUS re-encode\n got %x\nwant %x", got, want)
	}
	for i, b := range back.Ext {
		wantB := byte(0)
		if patterned {
			wantB = byte(0xa0 + i)
		}
		if b != wantB {
			t.Fatalf("ext[%d] = %#x, want %#x", i, b, wantB)
		}
	}

	for _, c := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"frames", back.Frames, 0x0102030405060708},
		{"commands", back.Commands, 0x1112131415161718},
		{"dropped", back.PixelFramesDropped, 0x2122232425262728},
		{"refresh_errors", uint64(back.LEDRefreshErrors), 0x31323334},
		{"mode", uint64(back.Mode), 1},
		{"brightness", uint64(back.Brightness), 0x90},
		{"target_fps", uint64(back.TargetFPS), 30},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
	if !bytes.Equal(back.Ext[:], want[StatusExtOffset:StatusExtOffset+StatusExtSize]) {
		t.Errorf("ext = %x, want bytes %d-%d of the vector", back.Ext, StatusExtOffset, StatusExtOffset+StatusExtSize-1)
	}
	if !back.Connected {
		t.Error("connected = false, want true")
	}
	if !back.OutputEnabled {
		t.Error("output_enabled = false, want true")
	}
}

func TestDeviceInfoMatchesVector(t *testing.T) {
	want := vector(t, "08656e76656c6f7065", 47)
	fields, err := DecodeDeviceInfo(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	byName := map[string]DeviceInfoField{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	for _, n := range []string{"envelope", "strips", "leds", "bpp"} {
		if _, ok := byName[n]; !ok {
			t.Fatalf("required field %q missing from the vector", n)
		}
	}
	var caps []string
	for _, f := range fields {
		if f.IsCapability() {
			caps = append(caps, f.Name)
		}
	}

	env, err := byName["envelope"].Uint32()
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	strips, _ := byName["strips"].Uint32()
	leds, _ := byName["leds"].Uint32()
	bpp, _ := byName["bpp"].Uint32()

	got, err := EncodeDeviceInfo(env, strips, leds, uint8(bpp), caps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DEVICE_INFO re-encode\n got %x\nwant %x", got, want)
	}
}

func TestHasCapability(t *testing.T) {
	for _, c := range []struct {
		name   string
		fields []DeviceInfoField
		want   bool
	}{
		{"empty value", []DeviceInfoField{{Name: "pts", Value: ""}}, true},
		{"valued", []DeviceInfoField{{Name: "pts", Value: "1"}}, true},
		{"absent", []DeviceInfoField{{Name: "x-cap"}, {Name: "pixel"}}, false},
		{"nil", nil, false},
	} {
		if got := HasCapability(c.fields, "pts"); got != c.want {
			t.Errorf("%s: HasCapability = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDeviceInfoPTSVector(t *testing.T) {
	want := vector(t, "08656e76656c6f7065[0-9a-f]*0370747300", 52)
	got, err := EncodeDeviceInfo(32768, 4, 1024, 3, []string{"pixel", "pts"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DEVICE_INFO with pts\n got %x\nwant %x", got, want)
	}
	fields, err := DecodeDeviceInfo(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !HasCapability(fields, "pts") {
		t.Error("pts missing from the decoded 52-byte vector")
	}
	old, err := DecodeDeviceInfo(vector(t, "08656e76656c6f7065", 47))
	if err != nil {
		t.Fatalf("decode 51: %v", err)
	}
	if HasCapability(old, "pts") {
		t.Error("the 47-byte vector must not advertise pts")
	}
	for name, fs := range map[string][]DeviceInfoField{"47": old, "52": fields} {
		if _, err := DecodeGeometry(fs); err != nil {
			t.Errorf("vector %s: DecodeGeometry: %v", name, err)
		}
	}
}

// ── the rules the vectors cannot express ────────────────────────────────────

// R3/R6 cut in opposite directions and are easy to get backwards.
func TestTrailingBytesIgnoredShortRefused(t *testing.T) {
	ack := EncodeAck(Ack{OrigKind: 0x07, OrigMessageNum: 42})
	if _, err := DecodeAck(ack[:len(ack)-1]); err == nil {
		t.Error("a short ACK must be refused")
	}
	if got, err := DecodeAck(append(ack, 0xAA, 0xBB)); err != nil || got.OrigMessageNum != 42 {
		t.Errorf("trailing bytes must be ignored (R3): %+v %v", got, err)
	}

	st := EncodeStatus(Status{Frames: 7})
	if _, err := DecodeStatus(st[:StatusRespSize-1]); err == nil {
		t.Error("a short STATUS is malformed, not an older peer")
	}
	if got, err := DecodeStatus(append(st, 0xAA)); err != nil || got.Frames != 7 {
		t.Errorf("a longer STATUS must decode (R6): %v", err)
	}
}

func TestAckRefusesOverclaimedDetail(t *testing.T) {
	b := EncodeAck(Ack{OrigKind: 0x07, Detail: []byte("xyz")})
	b[13] = 200 // claim 200 bytes of detail where 3 were sent
	if _, err := DecodeAck(b); err == nil {
		t.Error("an over-claimed detail_len must be refused, not yield a short slice")
	}
}

func TestAckDetailIsClampedNotRefused(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 200)
	b := EncodeAck(Ack{OrigKind: 0x07, Detail: long})
	if len(b) != AckHeaderSize+AckMaxDetail {
		t.Fatalf("clamped ACK is %d bytes, want %d", len(b), AckHeaderSize+AckMaxDetail)
	}
	got, err := DecodeAck(b)
	if err != nil || len(got.Detail) != AckMaxDetail {
		t.Fatalf("detail_len must carry the clamped length: %d %v", len(got.Detail), err)
	}
}

func TestDeviceInfoRefusesTruncatedFields(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"name runs past the payload", []byte{8, 'e', 'n', 'v'}},
		{"no value length", []byte{3, 'a', 'b', 'c'}},
		{"value runs past the payload", []byte{3, 'a', 'b', 'c', 250, 'x'}},
	} {
		if _, err := DecodeDeviceInfo(c.in); err == nil {
			t.Errorf("%s: must be refused", c.name)
		}
	}
}

func TestDeviceInfoRefusesOutOfRangeGeometry(t *testing.T) {
	for _, c := range []struct {
		name                   string
		envelope, strips, leds uint32
		bpp                    uint8
	}{
		{"envelope below the floor", 79, 1, 64, 4},
		{"zero strips", 1200, 0, 64, 4},
		{"bpp neither 3 nor 4", 1200, 1, 64, 2},
		{"geometry over the capacity ceiling", 1200, 65535, 65535, 4},
	} {
		if _, err := EncodeDeviceInfo(c.envelope, c.strips, c.leds, c.bpp, nil); err == nil {
			t.Errorf("%s: must be refused at the boundary the device controls", c.name)
		}
	}
}

func TestStatusRoundTripIsExact(t *testing.T) {
	in := Status{
		Frames: 1 << 40, Commands: 99, PixelFramesDropped: 7,
		LEDRefreshErrors: 0xDEADBEEF, Mode: 1, Connected: true, OutputEnabled: true,
		Brightness: 200, TargetFPS: 30,
	}
	for i := range in.Ext {
		in.Ext[i] = byte(0xa0 + i)
	}
	got, err := DecodeStatus(EncodeStatus(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(in, got) {
		t.Fatalf("STATUS round-trip\n got %+v\nwant %+v", got, in)
	}
}

// The extension block is copied verbatim at bytes 32-75 (STATUS, spec 5.2).
func TestStatusExtRoundTrip(t *testing.T) {
	in := Status{Frames: 1, Brightness: 0x90, TargetFPS: 30}
	for i := range in.Ext {
		in.Ext[i] = byte(0xa0 + i) // 0xa0 .. 0xcb
	}
	b := EncodeStatus(in)
	if len(b) != StatusRespSize {
		t.Fatalf("encoded %d bytes, want %d", len(b), StatusRespSize)
	}
	for i := 0; i < StatusExtSize; i++ {
		if b[32+i] != byte(0xa0+i) {
			t.Fatalf("byte %d = %#x, want %#x", 32+i, b[32+i], 0xa0+i)
		}
	}
	if b[31] != 0 || b[76] != 0x90 || b[77] != 30 {
		t.Fatalf("neighbours of the block changed: b[31]=%#x b[76]=%#x b[77]=%#x", b[31], b[76], b[77])
	}
	got, err := DecodeStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, in)
	}
}

// The spec's DEVICE_INFO ranges exist "because a decoder must reject outside
// them": a value out of range is a protocol error, "never clamped, and never
// guessed at". Uint32 parses; Uint32Checked is what a consumer must call.
func TestDeviceInfoUint32Checked(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		ok          bool
	}{
		{"envelope", "80", true},       // inclusive lower bound
		{"envelope", "16777216", true}, // inclusive upper bound
		{"envelope", "79", false},      // one below the spec's floor (sled 5.3.1)
		{"envelope", "16777217", false},
		{"strips", "1", true},
		{"strips", "65535", true},
		{"strips", "0", false}, // a device with no strips is not hardware
		{"strips", "65536", false},
		{"leds", "1", true},
		{"leds", "0", false},
		{"bpp", "3", true},
		{"bpp", "4", true},
		{"bpp", "2", false}, // an enum, not a range to round into
		{"bpp", "5", false},
		// R2: a field this revision does not define carries no range, and a
		// decoder must not invent one for it.
		{"x-vendor-thing", "999999", true},
	} {
		v, err := DeviceInfoField{Name: tc.name, Value: tc.value}.Uint32Checked()
		if tc.ok && err != nil {
			t.Errorf("%s=%s: unexpected error %v", tc.name, tc.value, err)
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("%s=%s: accepted, want rejected", tc.name, tc.value)
			}
			if v != 0 {
				t.Errorf("%s=%s: returned %d alongside an error — a caller that "+
					"ignores the error must not receive a usable-looking value",
					tc.name, tc.value, v)
			}
		}
	}

	// The encoder and the decoder must agree, since both read one range table.
	if _, err := EncodeDeviceInfo(79, 1, 1, 3, nil); err == nil {
		t.Error("EncodeDeviceInfo emitted an envelope its own decoder rejects")
	}
	if _, err := EncodeDeviceInfo(80, 1, 1, 3, nil); err != nil {
		t.Errorf("EncodeDeviceInfo refused the lowest envelope: %v", err)
	}
}

// detail_len is a be16, so a peer can claim far more than the 128 bytes the
// format allows. Decode clamps to AckMaxDetail, as encode does; the rest is
// trailing data (R3).
func TestAckDecodeClampsDetail(t *testing.T) {
	b := make([]byte, AckHeaderSize+300)
	b[0] = 0x07
	b[12], b[13] = 0x01, 0x2C // detail_len = 300, all present
	for i := AckHeaderSize; i < len(b); i++ {
		b[i] = 'x'
	}
	a, err := DecodeAck(b)
	if err != nil {
		t.Fatalf("an over-long detail must be clamped, not refused: %v", err)
	}
	if len(a.Detail) != AckMaxDetail {
		t.Fatalf("detail is %d bytes, want %d", len(a.Detail), AckMaxDetail)
	}
	// An over-claim beyond the payload is still refused, clamp or not.
	b[12], b[13] = 0x02, 0x00
	if _, err := DecodeAck(b); err == nil {
		t.Error("detail_len beyond the payload must still be refused")
	}
}

func fields(kv ...string) []DeviceInfoField {
	var out []DeviceInfoField
	for i := 0; i < len(kv); i += 2 {
		out = append(out, DeviceInfoField{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func TestDecodeGeometry(t *testing.T) {
	// What EncodeDeviceInfo writes decodes to the geometry it was built from.
	enc, err := EncodeDeviceInfo(1200, 2, 300, 4, []string{"x-cap", "pixel"})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := DecodeDeviceInfo(enc)
	if err != nil {
		t.Fatal(err)
	}
	g, err := DecodeGeometry(fs)
	if err != nil || g != (Geometry{Envelope: 1200, Strips: 2, LEDs: 300, BPP: 4, HasLEDs: true}) {
		t.Fatalf("round trip: %+v %v", g, err)
	}

	// Rule 4: order is not significant and a repeated name takes its last value.
	g, err = DecodeGeometry(fields("bpp", "3", "leds", "1", "x-a", "z", "strips", "1",
		"envelope", "99", "envelope", "80", "leds", "64"))
	if err != nil || g != (Geometry{Envelope: 80, Strips: 1, LEDs: 64, BPP: 3, HasLEDs: true}) {
		t.Fatalf("last value wins: %+v %v", g, err)
	}
	// ...and it is the last value that is checked: an earlier bad one is moot,
	// a later bad one is fatal.
	if _, err := DecodeGeometry(fields("envelope", "1", "envelope", "1200",
		"strips", "1", "leds", "1", "bpp", "4")); err != nil {
		t.Errorf("an overridden out-of-range value must not count: %v", err)
	}
	if _, err := DecodeGeometry(fields("envelope", "1200", "envelope", "79",
		"strips", "1", "leds", "1", "bpp", "4")); err == nil {
		t.Error("a final out-of-range value must be refused")
	}
}

func TestDecodeGeometryRejects(t *testing.T) {
	ok := []string{"envelope", "1200", "strips", "1", "leds", "64", "bpp", "4", "pixel", ""} // pixel: the three geometry fields are required (sled 5.3.3 rule 1)
	with := func(name, value string) []DeviceInfoField {
		fs := fields(ok...)
		for i := range fs {
			if fs[i].Name == name {
				fs[i].Value = value
			}
		}
		return fs
	}
	without := func(name string) []DeviceInfoField {
		var out []DeviceInfoField
		for _, f := range fields(ok...) {
			if f.Name != name {
				out = append(out, f)
			}
		}
		return out
	}
	cases := map[string][]DeviceInfoField{
		"missing envelope":           without("envelope"),
		"missing strips":             without("strips"),
		"missing leds":               without("leds"),
		"missing bpp":                without("bpp"),
		"no fields at all":           nil,
		"envelope below 80":          with("envelope", "79"),
		"envelope above the ceiling": with("envelope", "16777217"),
		"zero strips":                with("strips", "0"),
		"leds above 65535":           with("leds", "65536"),
		"bpp 2":                      with("bpp", "2"),
		"bpp 5":                      with("bpp", "5"),
		"envelope as a capability":   with("envelope", ""),
		"non-canonical decimal":      with("leds", "064"),
		"signed":                     with("strips", "+1"),
		"over uint32":                with("envelope", "99999999999"),
		"capacity over the ceiling":  fields("envelope", "1200", "strips", "65535", "leds", "65535", "bpp", "4"),
		"capacity one over":          fields("envelope", "1200", "strips", "4096", "leds", "1025", "bpp", "4"),
	}
	for name, fs := range cases {
		if g, err := DecodeGeometry(fs); err == nil {
			t.Errorf("%s: want refusal, got %+v", name, g)
		}
	}
	// Exactly at the capacity ceiling is accepted.
	if _, err := DecodeGeometry(fields("envelope", "1200", "strips", "4096", "leds", "1024", "bpp", "4")); err != nil {
		t.Errorf("capacity exactly at the ceiling: %v", err)
	}
	if _, err := DecodeGeometry(fields("envelope", "80", "strips", "1", "leds", "64", "bpp", "4")); err != nil {
		t.Errorf("envelope 80: %v", err)
	}
}

// sled 5.3.3 rule 1: envelope is always required; strips, leds and bpp only
// with pixel, and each one present is still validated.
func TestSled533GeometryOptionalWithoutPixel(t *testing.T) {
	g, err := DecodeGeometry(fields("envelope", "1200", "x-cap", ""))
	if err != nil {
		t.Fatalf("envelope only, no pixel: %v", err)
	}
	if g.HasLEDs || g.Envelope != 1200 {
		t.Fatalf("got %+v, want Envelope 1200 and HasLEDs false", g)
	}
}

func TestSled533GeometryRequiredWithPixel(t *testing.T) {
	if g, err := DecodeGeometry(fields("envelope", "1200", "pixel", "", "leds", "64", "bpp", "3")); err == nil {
		t.Fatalf("pixel without strips accepted: %+v", g)
	}
}

func TestSled533StripsLedsWithoutBPP(t *testing.T) {
	g, err := DecodeGeometry(fields("envelope", "1200", "strips", "2", "leds", "10"))
	if err != nil {
		t.Fatalf("strips and leds without bpp or pixel: %v", err)
	}
	if !g.HasLEDs || g.BPP != 0 || g.Strips != 2 || g.LEDs != 10 {
		t.Fatalf("got %+v, want Strips 2, LEDs 10, BPP 0, HasLEDs true", g)
	}
}

func TestSled533GeometryValidatedWithoutPixel(t *testing.T) {
	if g, err := DecodeGeometry(fields("envelope", "1200", "bpp", "5")); err == nil {
		t.Fatalf("bpp 5 without pixel accepted: %+v", g)
	}
}

func TestEncodeDeviceInfoFields(t *testing.T) {
	got, err := EncodeDeviceInfoFields(80, 2, 3, 4, []DeviceInfoField{{"x-fld", "16"}}, []string{"pixel"})
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	for _, kv := range [][2]string{{"envelope", "80"}, {"strips", "2"}, {"leds", "3"}, {"bpp", "4"}, {"x-fld", "16"}, {"pixel", ""}} {
		want = append(want, byte(len(kv[0])))
		want = append(want, kv[0]...)
		want = append(want, byte(len(kv[1])))
		want = append(want, kv[1]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded\n %x\nwant\n %x", got, want)
	}
	for name, c := range map[string]struct {
		fields []DeviceInfoField
		caps   []string
	}{
		"empty name":       {[]DeviceInfoField{{"", "1"}}, nil},
		"empty value":      {[]DeviceInfoField{{"x-fld", ""}}, nil},
		"field named leds": {[]DeviceInfoField{{"leds", "5"}}, nil},
		"field and cap":    {[]DeviceInfoField{{"x-fld", "1"}}, []string{"x-fld"}},
		"cap named bpp":    {nil, []string{"bpp"}},
		"field used twice": {[]DeviceInfoField{{"x-fld", "1"}, {"x-fld", "2"}}, nil},
	} {
		if _, err := EncodeDeviceInfoFields(80, 2, 3, 4, c.fields, c.caps); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
