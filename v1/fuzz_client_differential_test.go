// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Differential fuzzing of the client receive path.
//
// Mode 2 of the oracle runs the C client's §3.5/§7.3/§7.4 checks; this runs the
// Go equivalents on the same datagram and compares the accept/reject decision.
// That boundary is where the client validates what a device sends, and no
// golden vector reaches it: vectors cover inputs both ends already accept, and
// every interesting case here is a rejection.
//
// Only the DECISION is compared, not the reason. The two implementations report
// failures differently — C returns a distinct sn_cw_result per check, Go returns
// an error or a bool — and demanding identical reasons would pin an internal
// taxonomy rather than the protocol. What must never differ is whether a
// datagram is admitted.

import (
	"bytes"
	"crypto/hmac"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// Every one of these is mirrored byte for byte in fuzz/sn_oracle.c's mode 2.
// If one moves, both move, or the comparison silently becomes meaningless.
func clientFixtures(t testing.TB) (psk, devID, nonce, ownCS, ecPriv, eC,
	kDev, kResp, context, sentAE []byte) {
	t.Helper()
	psk = bytes.Repeat([]byte{0x11}, 32)
	devID = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce = bytes.Repeat([]byte{0xAB}, 24)
	ecPriv = bytes.Repeat([]byte{0x07}, 32)

	ownCS = make([]byte, 18)
	ownCS[10], ownCS[11] = 0xff, 0xff
	ownCS[12], ownCS[13], ownCS[14], ownCS[15] = 192, 168, 4, 2
	ownCS[16], ownCS[17] = 0x13, 0x88 // port 5000

	kDev = DeriveKDev(psk, devID)
	kResp = DeriveStatic(kDev).KResp

	var pub [32]byte
	var priv [32]byte
	copy(priv[:], ecPriv)
	curve25519.ScalarBaseMult(&pub, &priv)
	eC = pub[:]

	epochTag := bytes.Repeat([]byte{0x5a}, 8)
	cookie := bytes.Repeat([]byte{0x6b}, 16)
	sentAE = bytes.Repeat([]byte{0x7c}, 8)
	context = Context(nonce, epochTag, cookie, sentAE, devID)
	return
}

// The Go mirror of sn_decode_retry + sn_check_retry: §7.3 steps 1-4 in order.
func goCheckRetry(dg, kResp, nonce, ownCS, devID []byte) bool {
	f, err := DecodeRETRY(dg)
	if err != nil {
		return false
	}
	if !hmac.Equal(f.ObservedSource, ownCS) {
		return false
	}
	want := RetryMAC(kResp, nonce, f.EpochTag, f.Cookie, f.AdmissionEpoch,
		f.DeviceID, f.ObservedSource)
	if !hmac.Equal(want, f.RetryMAC) {
		return false
	}
	return hmac.Equal(f.DeviceID, devID)
}

// The Go mirror of sn_decode_admit + sn_check_admit: §7.4 steps 1-4, with
// admit_pre before the X25519, which is the ordering the C side pins too.
func goCheckAdmit(dg, kDev, kResp, context, sentAE, eC, ecPriv []byte) bool {
	a, err := DecodeADMIT(dg)
	if err != nil {
		return false
	}
	if !hmac.Equal(a.AdmissionEpoch, sentAE) {
		return false
	}
	ctx2 := Context2(context, eC, a.ES)
	if !hmac.Equal(AdmitPre(kResp, ctx2), a.AdmitPre) {
		return false
	}
	dh, err := curve25519.X25519(ecPriv, a.ES)
	if err != nil { // §4.5: both sides reject a low-order point (all-zero output)
		return false
	}
	master := Master(ctx2, kDev, dh)
	return hmac.Equal(AdmitTag(master), a.AdmitTag)
}

func FuzzDifferentialClientReceive(f *testing.F) {
	o := startOracle(f)
	psk, devID, nonce, ownCS, ecPriv, eC, kDev, kResp, context, sentAE := clientFixtures(f)
	_ = psk

	// Seeds: the shapes that reach past the length check at all.
	f.Add(make([]byte, RetryLen))
	f.Add(make([]byte, AdmitLen))
	f.Add([]byte{})
	// The §3.5 datagram: a 10-octet header that would send an unguarded RETRY
	// handler reading observed_source at 50 and retry_mac at 68.
	f.Add([]byte{'S', 'L', 'D', '1', 'Z', '0', '0', '1', 0x02, 0x03})
	for _, s := range validSeeds() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, dg []byte) {
		if len(dg) > 65535 {
			return
		}
		v, err := o.askClient(dg)
		if err != nil {
			t.Skipf("oracle unavailable: %v", err)
		}

		cRetryOK := v.raw[0] == 0 && v.raw[1] == 0
		gRetryOK := goCheckRetry(dg, kResp, nonce, ownCS, devID)
		if cRetryOK != gRetryOK {
			t.Fatalf("RETRY decision differs: C=%v Go=%v (decode=%d check=%d) datagram=%x",
				cRetryOK, gRetryOK, v.raw[0], v.raw[1], dg)
		}

		cAdmitOK := v.raw[2] == 0 && v.raw[3] == 0
		gAdmitOK := goCheckAdmit(dg, kDev, kResp, context, sentAE, eC, ecPriv)
		if cAdmitOK != gAdmitOK {
			t.Fatalf("ADMIT decision differs: C=%v Go=%v (decode=%d check=%d) datagram=%x",
				cAdmitOK, gAdmitOK, v.raw[2], v.raw[3], dg)
		}
	})
}
