// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// uuidBytes parses a canonical UUID string into 16 bytes.
func uuidBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("bad test UUID %q", s)
	}
	var id [16]byte
	copy(id[:], b)
	return id
}

func TestDecodeDeviceID(t *testing.T) {
	got, err := DecodeDeviceID("a1b2c3d4e5f60000")
	if err != nil {
		t.Fatal(err)
	}
	if want := [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0, 0}; got != want {
		t.Errorf("got %x, want %x", got, want)
	}
	for _, bad := range []string{
		strings.Repeat("a", 14), strings.Repeat("a", 18), strings.Repeat("z", 16), "",
	} {
		if _, err := DecodeDeviceID(bad); err == nil {
			t.Errorf("DecodeDeviceID(%q) accepted", bad)
		}
	}
}

func TestDeviceIDFromInstance(t *testing.T) {
	want := [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0, 0}
	for _, in := range []string{
		"00000000-0000-0000-0000-a1b2c3d4e5f6",
		"12345678-9abc-def0-1234-a1b2c3d4e5f6",
	} {
		got, err := DeviceIDFromInstance(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %x, want %x", in, got, want)
		}
	}
	if _, err := DeviceIDFromInstance("living-room"); err == nil {
		t.Error("a non-UUID instance was accepted")
	}
}

func TestDeviceIDFromInstanceRejectsNonCanonical(t *testing.T) {
	for _, in := range []string{
		"a1b2c3d4e5f6",
		"{00000000-0000-0000-0000-a1b2c3d4e5f6}",
		"00000000-0000-0000-0000-a1b2c3d4e5fg",
		"00000000_0000-0000-0000-a1b2c3d4e5f6",
		"000000000-000-0000-0000-a1b2c3d4e5f6",
	} {
		if _, err := DeviceIDFromInstance(in); err == nil {
			t.Errorf("DeviceIDFromInstance(%q) accepted", in)
		}
	}
}

func TestDecodePSK(t *testing.T) {
	got, err := DecodePSK(" " + strings.Repeat("ab", 32) + " ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Errorf("len = %d, want 32", len(got))
	}
	for _, bad := range []string{
		strings.Repeat("a", 63), strings.Repeat("a", 66), strings.Repeat("z", 64), "",
	} {
		if _, err := DecodePSK(bad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("DecodePSK(%q) err = %v, want ErrInvalidKey", bad, err)
		}
	}
}

func TestDeviceIDFromUUID(t *testing.T) {
	want := [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0, 0}
	for _, in := range []string{
		"00000000-0000-0000-0000-a1b2c3d4e5f6",
		"12345678-9abc-def0-1234-a1b2c3d4e5f6",
	} {
		got := DeviceIDFromUUID(uuidBytes(t, in))
		if got != want {
			t.Fatalf("%s: got %x, want %x", in, got, want)
		}
	}
}
