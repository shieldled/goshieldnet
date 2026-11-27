// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"testing"
)

// Assert the RFC's derivation-input and wire lengths (§3.5). If any of these fail,
// a field is misplaced and every downstream vector would be wrong.
func TestLengths(t *testing.T) {
	nonce := make([]byte, 24)
	dev := make([]byte, 8)
	etag := make([]byte, 8)
	cookie := make([]byte, 16)
	aepoch := make([]byte, 8)
	eC := make([]byte, 32)
	eS := make([]byte, 32)

	ctx := Context(nonce, etag, cookie, aepoch, dev)
	if len(ctx) != 65 {
		t.Errorf("context = %d, want 65", len(ctx))
	}
	ctx2 := Context2(ctx, eC, eS)
	if len(ctx2) != 129 {
		t.Errorf("context2 = %d, want 129", len(ctx2))
	}
	// master salt = L("shieldled/v1/master")(20) + context2(129) = 149
	salt := append(L("shieldled/v1/master"), ctx2...)
	if len(salt) != 149 {
		t.Errorf("master salt = %d, want 149", len(salt))
	}
	// init_mac input = L("init")(18) + type + version + nonce(24) + dev(8) = 52
	initIn := append(L("shieldled/v1/init"), append([]byte{TypeINIT, Version}, append(nonce, dev...)...)...)
	if len(initIn) != 52 {
		t.Errorf("init_mac input = %d, want 52", len(initIn))
	}
	// client_tag input = L("finish")(20) + type + version + context(65) + e_c(32) = 119
	ctIn := append(L("shieldled/v1/finish"), append([]byte{TypeFIN, Version}, append(ctx, eC...)...)...)
	if len(ctIn) != 119 {
		t.Errorf("client_tag input = %d, want 119", len(ctIn))
	}
}

func TestMessageRoundTrip(t *testing.T) {
	n24 := bytes.Repeat([]byte{0xa1}, 24)
	d8 := bytes.Repeat([]byte{0xb2}, 8)
	m16 := bytes.Repeat([]byte{0xc3}, 16)
	t8 := bytes.Repeat([]byte{0xd4}, 8)
	c16 := bytes.Repeat([]byte{0xe5}, 16)
	os18 := bytes.Repeat([]byte{0xf6}, 18)
	k32 := bytes.Repeat([]byte{0x17}, 32)

	init := EncodeINIT(n24, d8, m16)
	if len(init) != 256 {
		t.Fatalf("INIT len = %d, want 256", len(init))
	}
	fi, err := DecodeINIT(init)
	if err != nil || !bytes.Equal(fi.ClientNonce, n24) || !bytes.Equal(fi.DeviceID, d8) || !bytes.Equal(fi.InitMAC, m16) {
		t.Fatalf("INIT round trip: %v", err)
	}

	retry := EncodeRETRY(t8, c16, t8, d8, os18, m16)
	if len(retry) != 84 {
		t.Fatalf("RETRY len = %d, want 84", len(retry))
	}
	if _, err := DecodeRETRY(retry); err != nil {
		t.Fatalf("RETRY decode: %v", err)
	}

	fin := EncodeFINISH(n24, t8, c16, t8, k32, m16)
	if len(fin) != 256 {
		t.Fatalf("FINISH len = %d, want 256", len(fin))
	}
	if _, err := DecodeFINISH(fin); err != nil {
		t.Fatalf("FINISH decode: %v", err)
	}

	admit := EncodeADMIT(t8, k32, m16, m16)
	if len(admit) != 82 {
		t.Fatalf("ADMIT len = %d, want 82", len(admit))
	}
	if _, err := DecodeADMIT(admit); err != nil {
		t.Fatalf("ADMIT decode: %v", err)
	}
}

func TestWrongLengthRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func([]byte) error
		good int
	}{
		{"INIT", func(b []byte) error { _, e := DecodeINIT(b); return e }, 256},
		{"RETRY", func(b []byte) error { _, e := DecodeRETRY(b); return e }, 84},
		{"FINISH", func(b []byte) error { _, e := DecodeFINISH(b); return e }, 256},
		{"ADMIT", func(b []byte) error { _, e := DecodeADMIT(b); return e }, 82},
	} {
		for _, n := range []int{tc.good - 1, tc.good + 1, 10, 0} {
			if err := tc.fn(make([]byte, n)); err == nil {
				t.Errorf("%s accepted length %d (good=%d)", tc.name, n, tc.good)
			}
		}
	}
}

func TestNonZeroPaddingRejected(t *testing.T) {
	n24 := make([]byte, 24)
	d8 := make([]byte, 8)
	m16 := make([]byte, 16)
	init := EncodeINIT(n24, d8, m16)
	init[58] = 1 // the FIRST padding octet — catches an off-by-one in the check start
	if _, err := DecodeINIT(init); err != ErrPadding {
		t.Errorf("INIT non-zero padding: got %v, want ErrPadding", err)
	}
	fin := EncodeFINISH(n24, d8, m16, d8, make([]byte, 32), m16)
	fin[114] = 1 // the first FINISH padding octet
	if _, err := DecodeFINISH(fin); err != ErrPadding {
		t.Errorf("FINISH non-zero padding: got %v, want ErrPadding", err)
	}
}

// The §8.3 boundary case: d32 exactly 0x80000000 must take the negative branch.
func TestReconstructBoundary(t *testing.T) {
	// hwm low32 = 0, seq_wire = 0x80000000 -> d32 = 0x80000000 -> negative branch.
	got := Reconstruct(0x80000000, 0)
	want := int64(0) + (int64(0x80000000) - 0x100000000) // = -0x80000000
	if got != want {
		t.Errorf("d32==0x80000000: got %d, want %d", got, want)
	}
	// One below the boundary stays positive.
	if got := Reconstruct(0x7FFFFFFF, 0); got != 0x7FFFFFFF {
		t.Errorf("d32==0x7FFFFFFF: got %d, want %d", got, int64(0x7FFFFFFF))
	}
	// Normal forward step.
	if got := Reconstruct(1001, 1000); got != 1001 {
		t.Errorf("forward: got %d, want 1001", got)
	}
	// A delayed datagram below the mark reconstructs below hwm, not above.
	if got := Reconstruct(999, 1000); got != 999 {
		t.Errorf("delayed: got %d, want 999", got)
	}
	// Across the 2^32 boundary: hwm just below 2^32, seq_wire wrapped to 2.
	hwm := uint64(0x1_0000_0000 - 1) // 4294967295
	if got := Reconstruct(2, hwm); got != 0x1_0000_0002 {
		t.Errorf("wrap: got %d, want %d", got, int64(0x1_0000_0002))
	}
}

// The header check must reject a right-length datagram with a bad MAGIC, a wrong
// VERSION, or the wrong TYPE (a misdirected message — a client must reject INIT,
// a device must reject RETRY, etc., §5). None of these is a length or padding error,
// so they need their own coverage.
func TestHeaderRejection(t *testing.T) {
	good := EncodeINIT(fx(1, 24), fx(2, 8), fx(3, 16))

	badMagic := append([]byte(nil), good...)
	badMagic[0] ^= 0xff
	if _, err := DecodeINIT(badMagic); err != ErrMagic {
		t.Errorf("bad MAGIC: got %v, want ErrMagic", err)
	}

	badVer := append([]byte(nil), good...)
	badVer[9] = Version + 1
	if _, err := DecodeINIT(badVer); err != ErrMagic {
		t.Errorf("wrong VERSION: got %v, want ErrMagic", err)
	}

	// Right length and header shape, wrong type byte: an INIT decoder must reject a
	// FINISH (both are 256 octets), and vice versa — the type gate, not the length.
	wrongType := append([]byte(nil), good...)
	wrongType[8] = TypeFIN
	if _, err := DecodeINIT(wrongType); err != ErrType {
		t.Errorf("wrong TYPE: got %v, want ErrType", err)
	}
	// A real FINISH (correct type byte) is 256 octets but must not decode as INIT.
	fin := EncodeFINISH(fx(1, 24), fx(2, 8), fx(3, 16), fx(4, 8), fx(5, 32), fx(6, 16))
	if _, err := DecodeINIT(fin); err != ErrType {
		t.Errorf("FINISH-as-INIT: got %v, want ErrType", err)
	}
}

// Decoders return sub-slices that alias the input buffer, not copies. This is
// deliberate (zero-copy parse) but a caller that reuses the buffer would see fields
// change under it — pin the behaviour so a future change to copy-on-decode is a
// conscious one, and callers know the contract.
func TestDecoderAliasesInput(t *testing.T) {
	b := EncodeINIT(fx(0xaa, 24), fx(2, 8), fx(3, 16))
	f, err := DecodeINIT(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.ClientNonce[0] != 0xaa {
		t.Fatal("setup")
	}
	b[10] = 0xbb // mutate the source buffer in the client_nonce region
	if f.ClientNonce[0] != 0xbb {
		t.Fatal("decoder unexpectedly copied — contract is a view; update callers/docs if changing")
	}
}
