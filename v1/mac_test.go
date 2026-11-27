// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// fixtures: fixed-width filler fields for MAC coverage tests.
func fx(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// Each MAC must cover every field it lists: flipping any input field must change the
// output. This catches a dropped field or a wrong concatenation order — the exact
// divergence golden vectors exist to prevent, tested here as a property.
func TestMACFieldCoverage(t *testing.T) {
	kReq := fx(1, 32)
	kResp := fx(2, 32)
	nonce := fx(3, 24)
	dev := fx(4, 8)
	etag := fx(5, 8)
	cookie := fx(6, 16)
	aepoch := fx(7, 8)
	obs := fx(8, 18)
	eC := fx(9, 32)
	eS := fx(10, 32)
	cs := fx(11, 32) // cookie_secret
	csrc := fx(12, 18)

	ctx := Context(nonce, etag, cookie, aepoch, dev)
	ctx2 := Context2(ctx, eC, eS)

	// init_mac covers client_nonce and device_id (and the key).
	base := InitMAC(kReq, nonce, dev)
	if bytes.Equal(base, InitMAC(kReq, fx(0x33, 24), dev)) {
		t.Error("init_mac ignores client_nonce")
	}
	if bytes.Equal(base, InitMAC(kReq, nonce, fx(0x44, 8))) {
		t.Error("init_mac ignores device_id")
	}
	if bytes.Equal(base, InitMAC(fx(0xff, 32), nonce, dev)) {
		t.Error("init_mac ignores k_req")
	}

	// retry_mac covers all six of its listed fields.
	rbase := RetryMAC(kResp, nonce, etag, cookie, aepoch, dev, obs)
	for i, alt := range []struct {
		name string
		mac  []byte
	}{
		{"client_nonce", RetryMAC(kResp, fx(0x33, 24), etag, cookie, aepoch, dev, obs)},
		{"epoch_tag", RetryMAC(kResp, nonce, fx(0x33, 8), cookie, aepoch, dev, obs)},
		{"cookie", RetryMAC(kResp, nonce, etag, fx(0x33, 16), aepoch, dev, obs)},
		{"admission_epoch", RetryMAC(kResp, nonce, etag, cookie, fx(0x33, 8), dev, obs)},
		{"device_id", RetryMAC(kResp, nonce, etag, cookie, aepoch, fx(0x33, 8), obs)},
		{"observed_source", RetryMAC(kResp, nonce, etag, cookie, aepoch, dev, fx(0x33, 18))},
	} {
		if bytes.Equal(rbase, alt.mac) {
			t.Errorf("retry_mac ignores %s (case %d)", alt.name, i)
		}
	}

	// cookie covers epoch_tag, canonical_source, client_nonce (and cookie_secret).
	cbase := Cookie(cs, etag, csrc, nonce)
	if bytes.Equal(cbase, Cookie(cs, fx(0x33, 8), csrc, nonce)) {
		t.Error("cookie ignores epoch_tag")
	}
	if bytes.Equal(cbase, Cookie(cs, etag, fx(0x33, 18), nonce)) {
		t.Error("cookie ignores canonical_source")
	}
	if bytes.Equal(cbase, Cookie(cs, etag, csrc, fx(0x33, 24))) {
		t.Error("cookie ignores client_nonce")
	}

	// client_tag covers context and e_c.
	ctbase := ClientTag(kReq, ctx, eC)
	if bytes.Equal(ctbase, ClientTag(kReq, Context(fx(0x33, 24), etag, cookie, aepoch, dev), eC)) {
		t.Error("client_tag ignores context")
	}
	if bytes.Equal(ctbase, ClientTag(kReq, ctx, fx(0x33, 32))) {
		t.Error("client_tag ignores e_c")
	}

	// admit_pre covers context2.
	if bytes.Equal(AdmitPre(kResp, ctx2), AdmitPre(kResp, Context2(ctx, fx(0x33, 32), eS))) {
		t.Error("admit_pre ignores context2")
	}

	// epoch_tag is 8 octets and covers cookie_epoch.
	et := EpochTag(cs, fx(0, 4))
	if len(et) != 8 {
		t.Errorf("epoch_tag len = %d, want 8", len(et))
	}
	if bytes.Equal(et, EpochTag(cs, fx(1, 4))) {
		t.Error("epoch_tag ignores cookie_epoch")
	}
}

// context must be a prefix of context2 (context2 = context || e_c || e_s).
func TestContextPrefix(t *testing.T) {
	ctx := Context(fx(1, 24), fx(2, 8), fx(3, 16), fx(4, 8), fx(5, 8))
	ctx2 := Context2(ctx, fx(6, 32), fx(7, 32))
	if !bytes.HasPrefix(ctx2, ctx) {
		t.Fatal("context2 does not start with context")
	}
	if len(ctx2) != len(ctx)+64 {
		t.Fatalf("context2 len = %d, want %d", len(ctx2), len(ctx)+64)
	}
}

// master separates on context2 and on k_dev; the four session keys and admit_tag are
// all distinct; and master is deterministic. dh is exercised with a real agreement.
func TestMasterAndSessionKeys(t *testing.T) {
	// A real X25519 agreement so dh is a valid 32-octet secret.
	privA := fx(0x11, 32)
	privB := fx(0x22, 32)
	pubB, _ := curve25519.X25519(privB, curve25519.Basepoint)
	dh, err := DH(privA, pubB)
	if err != nil {
		t.Fatalf("DH: %v", err)
	}
	kDev := DeriveKDev(fx(0x42, 32), fx(0, 8))
	ctx2 := Context2(Context(fx(1, 24), fx(2, 8), fx(3, 16), fx(4, 8), fx(5, 8)), fx(6, 32), fx(7, 32))

	m := Master(ctx2, kDev, dh)
	if !bytes.Equal(m, Master(ctx2, kDev, dh)) {
		t.Fatal("master not deterministic")
	}
	// Different transcript → different master (no cross-session key collision).
	ctx2b := Context2(Context(fx(0x99, 24), fx(2, 8), fx(3, 16), fx(4, 8), fx(5, 8)), fx(6, 32), fx(7, 32))
	if bytes.Equal(m, Master(ctx2b, kDev, dh)) {
		t.Error("master collides across context2")
	}
	// Different k_dev → different master (device separation reaches the session keys).
	if bytes.Equal(m, Master(ctx2, DeriveKDev(fx(0x42, 32), fx(9, 8)), dh)) {
		t.Error("master collides across k_dev")
	}

	sk := DeriveSession(m)
	all := [][]byte{sk.KC2S, sk.KS2C, sk.KKcpC2S, sk.KKcpS2C, AdmitTag(m)}
	for i := range all {
		if i < 4 && len(all[i]) != 32 {
			t.Errorf("session key %d len = %d, want 32", i, len(all[i]))
		}
		for j := i + 1; j < len(all); j++ {
			if bytes.Equal(all[i], all[j]) {
				t.Errorf("derived keys %d and %d collide — labels not separating", i, j)
			}
		}
	}
	if len(AdmitTag(m)) != 16 {
		t.Errorf("admit_tag len = %d, want 16", len(AdmitTag(m)))
	}
}

// DH: a valid agreement is symmetric; an all-zero (low-order) point is rejected with
// a non-nil error (the contract — not the error identity, per §4.5).
func TestDH(t *testing.T) {
	privA := fx(0x11, 32)
	privB := fx(0x22, 32)
	pubA, _ := curve25519.X25519(privA, curve25519.Basepoint)
	pubB, _ := curve25519.X25519(privB, curve25519.Basepoint)
	ab, err := DH(privA, pubB)
	if err != nil {
		t.Fatalf("DH(a,B): %v", err)
	}
	ba, err := DH(privB, pubA)
	if err != nil {
		t.Fatalf("DH(b,A): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("X25519 not symmetric")
	}
	// RFC 7748 order-8 low-order point → all-zero secret → rejected.
	low := []byte{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00}
	if _, err := DH(privA, low); err == nil {
		t.Fatal("DH accepted a low-order point (all-zero secret)")
	}
}
