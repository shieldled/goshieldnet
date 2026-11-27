// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net/netip"
	"testing"

	"golang.org/x/crypto/curve25519"
)

var testPSK = bytes.Repeat([]byte{0x11}, 32)

// deterministic ephemeral source for the device
func fixedRand(fill byte) func([]byte) {
	return func(b []byte) {
		for i := range b {
			b[i] = fill
		}
	}
}

// clientFINISH builds the FINISH a §7 client would send after this RETRY, with a
// caller-chosen e_c private key. Returns (finish, ecPub, context).
func clientFINISH(deviceID, nonce, ecPriv, retry []byte) ([]byte, []byte, []byte) {
	rf, _ := DecodeRETRY(retry)
	ecPub, _ := curve25519.X25519(ecPriv, curve25519.Basepoint)
	static := DeriveStatic(DeriveKDev(testPSK, deviceID))
	context := Context(nonce, rf.EpochTag, rf.Cookie, rf.AdmissionEpoch, deviceID)
	ct := ClientTag(static.KReq, context, ecPub)
	fin := EncodeFINISH(nonce, rf.EpochTag, rf.Cookie, rf.AdmissionEpoch, ecPub, ct)
	return fin, ecPub, context
}

func TestFINISHFullAdmission(t *testing.T) {
	d, deviceID := testDevice()
	d.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	src := netip.MustParseAddrPort("192.168.4.2:5000")

	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	fin, ecPub, context := clientFINISH(deviceID, nonce, ecPriv, retry)

	admit := d.HandleFINISH(fin, src, 8000)
	if admit == nil {
		t.Fatal("valid FINISH dropped")
	}
	af, err := DecodeADMIT(admit)
	if err != nil {
		t.Fatalf("ADMIT does not decode: %v", err)
	}
	// admission_epoch in ADMIT is the value the client presented (§3.4).
	rf, _ := DecodeRETRY(retry)
	if !bytes.Equal(af.AdmissionEpoch, rf.AdmissionEpoch) {
		t.Error("ADMIT admission_epoch is not the presented value")
	}
	// client re-derives the session and checks admit_pre / admit_tag / keys.
	context2 := Context2(context, ecPub, af.ES)
	static := DeriveStatic(DeriveKDev(testPSK, deviceID))
	if !bytes.Equal(AdmitPre(static.KResp, context2), af.AdmitPre) {
		t.Error("admit_pre does not verify at client")
	}
	dh, err := DH(ecPriv, af.ES)
	if err != nil {
		t.Fatal(err)
	}
	master := Master(context2, DeriveKDev(testPSK, deviceID), dh)
	if !bytes.Equal(AdmitTag(master), af.AdmitTag) {
		t.Error("admit_tag does not verify at client")
	}
	ck := DeriveSession(master)
	dk := d.pending[d.findPending(Canonicalize(src.Addr(), src.Port()))].keys
	if !bytes.Equal(ck.KC2S, dk.KC2S) || !bytes.Equal(ck.KKcpS2C, dk.KKcpS2C) {
		t.Error("client and device derived different session keys")
	}
	// admission_epoch advanced exactly once.
	if bytes.Equal(d.admissionEpoch, rf.AdmissionEpoch) {
		t.Error("admission_epoch did not advance on acceptance")
	}
}

func TestFINISHVerbatimResend(t *testing.T) {
	d, deviceID := testDevice()
	d.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	fin, _, _ := clientFINISH(deviceID, nonce, bytes.Repeat([]byte{0x07}, 32), retry)

	a1 := d.HandleFINISH(fin, src, 8000)
	aeAfterFirst := append([]byte(nil), d.admissionEpoch...)
	a2 := d.HandleFINISH(fin, src, 8100) // same FINISH, later time
	if !bytes.Equal(a1, a2) {
		t.Error("resend did not return the stored ADMIT verbatim")
	}
	if !bytes.Equal(d.admissionEpoch, aeAfterFirst) {
		t.Error("resend advanced admission_epoch (must not)")
	}
}

func TestFINISHRejections(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	elsewhere := netip.MustParseAddrPort("192.168.4.9:5000")

	// replay from a different tuple → cookie recompute fails
	d, deviceID := testDevice()
	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	fin, _, _ := clientFINISH(deviceID, nonce, ecPriv, retry)
	if d.HandleFINISH(fin, elsewhere, 8000) != nil {
		t.Error("FINISH replayed from another tuple was admitted")
	}
	if d.findPending(Canonicalize(elsewhere.Addr(), elsewhere.Port())) >= 0 {
		t.Error("replayed FINISH installed a record")
	}

	// bad client_tag → drop, no state
	d2, _ := testDevice()
	retry2 := d2.HandleINIT(validINIT(d2.kReq, nonce, deviceID), src, 8000)
	fin2, _, _ := clientFINISH(deviceID, nonce, ecPriv, retry2)
	fin2[98] ^= 0xFF // flip client_tag
	aeBefore := append([]byte(nil), d2.admissionEpoch...)
	if d2.HandleFINISH(fin2, src, 8000) != nil {
		t.Error("FINISH with bad client_tag was admitted")
	}
	if !bytes.Equal(d2.admissionEpoch, aeBefore) {
		t.Error("bad client_tag altered admission_epoch")
	}

	// admission_epoch mismatch → drop (flip the presented value)
	d3, _ := testDevice()
	retry3 := d3.HandleINIT(validINIT(d3.kReq, nonce, deviceID), src, 8000)
	fin3, _, _ := clientFINISH(deviceID, nonce, ecPriv, retry3)
	fin3[58] ^= 0x01 // flip admission_epoch → cookie/tag still bind? no; but step 4 checks first-class
	if d3.HandleFINISH(fin3, src, 8000) != nil {
		t.Error("FINISH with wrong admission_epoch was admitted")
	}

	// all-zero DH: e_c a low-order point (32 zero octets) → curve25519 rejects
	d4, _ := testDevice()
	retry4 := d4.HandleINIT(validINIT(d4.kReq, nonce, deviceID), src, 8000)
	rf, _ := DecodeRETRY(retry4)
	static := DeriveStatic(DeriveKDev(testPSK, deviceID))
	lowOrder := make([]byte, 32) // all zero → X25519 error
	context := Context(nonce, rf.EpochTag, rf.Cookie, rf.AdmissionEpoch, deviceID)
	ct := ClientTag(static.KReq, context, lowOrder)
	finLow := EncodeFINISH(nonce, rf.EpochTag, rf.Cookie, rf.AdmissionEpoch, lowOrder, ct)
	if d4.HandleFINISH(finLow, src, 8000) != nil {
		t.Error("FINISH with all-zero DH was admitted")
	}
}

func TestFINISHReplaceAndEvict(t *testing.T) {
	d, deviceID := testDevice()
	d.SetRandSource(fixedRand(0x42))
	nonce := bytes.Repeat([]byte{0xAB}, 24)

	admitFrom := func(dev *Device, portSuffix string, ecFill byte, now uint64) {
		src := netip.MustParseAddrPort("192.168.4.2:" + portSuffix)
		retry := dev.HandleINIT(validINIT(dev.kReq, nonce, deviceID), src, 8000)
		fin, _, _ := clientFINISH(deviceID, nonce, bytes.Repeat([]byte{ecFill}, 32), retry)
		if dev.HandleFINISH(fin, src, now) == nil {
			t.Fatalf("admission from :%s failed", portSuffix)
		}
	}

	// fill both slots from two distinct tuples
	admitFrom(d, "5000", 0x07, 8000)
	admitFrom(d, "5001", 0x08, 8001)
	g0 := d.pending[d.findPending(Canonicalize(netip.MustParseAddr("192.168.4.2"), 5000))].generation

	// same tuple again → replace, generation advances, still 2 used slots
	admitFrom(d, "5000", 0x09, 8002)
	i := d.findPending(Canonicalize(netip.MustParseAddr("192.168.4.2"), 5000))
	if d.pending[i].generation == g0 {
		t.Error("replace did not advance generation")
	}
	used := 0
	for _, r := range d.pending {
		if r.used {
			used++
		}
	}
	if used != 2 {
		t.Errorf("after replace: %d used slots, want 2", used)
	}

	// a third distinct tuple with both slots full → oldest (:5001) evicted
	admitFrom(d, "5002", 0x0A, 8003)
	if d.findPending(Canonicalize(netip.MustParseAddr("192.168.4.2"), 5001)) >= 0 {
		t.Error("oldest slot (:5001) was not evicted")
	}
	if d.findPending(Canonicalize(netip.MustParseAddr("192.168.4.2"), 5002)) < 0 {
		t.Error("newest tuple (:5002) not installed")
	}
}
