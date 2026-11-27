// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// L must be uint8(len) || label with no terminator — a known-answer check, since a
// wrong prefix or an accidental NUL would silently poison every derivation.
func TestL_ExactBytes(t *testing.T) {
	got := L("req")
	want := []byte{3, 'r', 'e', 'q'}
	if !bytes.Equal(got, want) {
		t.Fatalf("L(\"req\") = %x, want %x", got, want)
	}
	if L("")[0] != 0 || len(L("")) != 1 {
		t.Fatalf("L(\"\") = %x, want [00]", L(""))
	}
	long := L("shieldled/v1/master")
	if long[0] != 19 || string(long[1:]) != "shieldled/v1/master" {
		t.Fatalf("L(master) prefix/body wrong: %x", long)
	}
}

// hmac128 must be exactly the leading 16 octets of the full HMAC-SHA-256.
func TestHMAC128_IsTruncatedHMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	msg := []byte("shieldnet")
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	full := h.Sum(nil)
	got := hmac128(key, msg)
	if len(got) != 16 || !bytes.Equal(got, full[:16]) {
		t.Fatalf("hmac128 = %x, want %x", got, full[:16])
	}
}

// The zero salt must be 32 octets of zero (§0: salt="" means 32 zeros).
func TestZeroSalt(t *testing.T) {
	if len(zeroSalt) != 32 || !allZero(zeroSalt) {
		t.Fatalf("zeroSalt = %x, want 32 zero octets", zeroSalt)
	}
}

// k_dev is deterministic, and distinct device_ids give distinct keys (the per-device
// isolation §0 relies on). The controller-derives and device-provisioned routes are
// the same function, so identity is what "both routes agree" reduces to here.
func TestDeriveKDev(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	dev1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dev2 := []byte{1, 2, 3, 4, 5, 6, 7, 9}

	a := DeriveKDev(psk, dev1)
	b := DeriveKDev(psk, dev1)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatalf("k_dev not deterministic")
	}
	if bytes.Equal(a, DeriveKDev(psk, dev2)) {
		t.Fatalf("k_dev collides across device_id")
	}
	// A different PSK yields a different k_dev for the same device.
	if bytes.Equal(a, DeriveKDev(bytes.Repeat([]byte{0x43}, 32), dev1)) {
		t.Fatalf("k_dev collides across PSK")
	}
}

// k_req and k_resp are distinct, deterministic, and both 32 octets (§4.1).
func TestDeriveStatic(t *testing.T) {
	kDev := DeriveKDev(bytes.Repeat([]byte{0x42}, 32), make([]byte, 8))
	s := DeriveStatic(kDev)
	if len(s.KReq) != 32 || len(s.KResp) != 32 {
		t.Fatalf("static key lengths %d/%d, want 32/32", len(s.KReq), len(s.KResp))
	}
	if bytes.Equal(s.KReq, s.KResp) {
		t.Fatalf("k_req == k_resp — labels not separating")
	}
	if !bytes.Equal(s.KReq, DeriveStatic(kDev).KReq) {
		t.Fatalf("k_req not deterministic")
	}
}
