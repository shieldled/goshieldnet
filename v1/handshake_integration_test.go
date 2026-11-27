// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// An end-to-end admission transcript driven entirely in Go: the controller and the
// device each build their real messages and derive keys from what the other sent,
// and the two must arrive at the SAME master and exchange envelope traffic. This is
// an integration test of composition — that the transcript binding (context/context2)
// and the two derivation routes actually agree — not just of the primitives in
// isolation. It is the closest thing to the C<->Go interop test until the C side and
// the golden vectors exist, and it would catch a mismatch where each primitive is
// self-consistent but the pieces do not compose (e.g. the two sides feeding context2
// in a different order).
func TestHandshakeEndToEnd(t *testing.T) {
	// Provisioning. The controller holds the PSK; the device holds k_dev. Both must
	// reach the same k_dev — the controller by derivation, the device by provision.
	psk := fx(0xA5, 32)
	deviceID := fx(0x11, 8)
	kDevController := DeriveKDev(psk, deviceID)
	kDevDevice := DeriveKDev(psk, deviceID) // provisioned; same value by construction
	if !bytes.Equal(kDevController, kDevDevice) {
		t.Fatal("k_dev routes disagree")
	}
	stC := DeriveStatic(kDevController)
	stD := DeriveStatic(kDevDevice)

	// Per-attempt randomness (fixed here for determinism).
	clientNonce := fx(0x22, 24)
	ecPriv := fx(0x66, 32)
	esPriv := fx(0x77, 32)
	eC, _ := curve25519.X25519(ecPriv, curve25519.Basepoint)
	eS, _ := curve25519.X25519(esPriv, curve25519.Basepoint)

	// Device per-boot / per-attempt state that reaches the wire.
	epochTag := fx(0x33, 8)
	cookie := fx(0x44, 16) // the device minted this in RETRY; the client echoes it
	admissionEpoch := fx(0x55, 8)

	// --- INIT: controller -> device ---
	initMAC := InitMAC(stC.KReq, clientNonce, deviceID)
	init := EncodeINIT(clientNonce, deviceID, initMAC)
	fi, err := DecodeINIT(init)
	if err != nil {
		t.Fatalf("device rejected INIT: %v", err)
	}
	// Device verifies init_mac over what it received.
	if !bytes.Equal(InitMAC(stD.KReq, fi.ClientNonce, fi.DeviceID), fi.InitMAC) {
		t.Fatal("device could not verify init_mac")
	}

	// --- FINISH: controller -> device (carries e_c, echoes epoch_tag/cookie/aepoch) ---
	ctxC := Context(clientNonce, epochTag, cookie, admissionEpoch, deviceID)
	clientTag := ClientTag(stC.KReq, ctxC, eC)
	fin := EncodeFINISH(clientNonce, epochTag, cookie, admissionEpoch, eC, clientTag)
	ff, err := DecodeFINISH(fin)
	if err != nil {
		t.Fatalf("device rejected FINISH: %v", err)
	}
	// Device rebuilds context from the FINISH (using ITS OWN device_id) and verifies.
	ctxD := Context(ff.ClientNonce, ff.EpochTag, ff.Cookie, ff.AdmissionEpoch, deviceID)
	if !bytes.Equal(ClientTag(stD.KReq, ctxD, ff.EC), ff.ClientTag) {
		t.Fatal("device could not verify client_tag — transcript disagreement")
	}

	// --- Both sides derive master ---
	// Device: dh = X25519(es_priv, e_c_from_finish); context2 = context || e_c || e_s.
	dhDevice, err := DH(esPriv, ff.EC)
	if err != nil {
		t.Fatalf("device DH: %v", err)
	}
	ctx2D := Context2(ctxD, ff.EC, eS)
	masterDevice := Master(ctx2D, kDevDevice, dhDevice)

	// Controller: dh = X25519(ec_priv, e_s_from_admit); context2 = its own context || e_c || e_s.
	dhController, err := DH(ecPriv, eS)
	if err != nil {
		t.Fatalf("controller DH: %v", err)
	}
	ctx2C := Context2(ctxC, eC, eS)
	masterController := Master(ctx2C, kDevController, dhController)

	if !bytes.Equal(masterDevice, masterController) {
		t.Fatalf("masters disagree:\n  device     %x\n  controller %x", masterDevice, masterController)
	}

	// --- ADMIT: device -> controller ---
	admitPre := AdmitPre(stD.KResp, ctx2D)
	admitTag := AdmitTag(masterDevice)
	admit := EncodeADMIT(admissionEpoch, eS, admitPre, admitTag)
	af, err := DecodeADMIT(admit)
	if err != nil {
		t.Fatalf("controller rejected ADMIT: %v", err)
	}
	// Controller verifies admit_pre (static-schedule check, before trusting the DH)
	// and admit_tag (proof the device derived the same master).
	if !bytes.Equal(AdmitPre(stC.KResp, ctx2C), af.AdmitPre) {
		t.Fatal("controller could not verify admit_pre")
	}
	if !bytes.Equal(AdmitTag(masterController), af.AdmitTag) {
		t.Fatal("controller could not verify admit_tag")
	}

	// --- Envelope traffic both directions, keyed by the agreed master ---
	skD := DeriveSession(masterDevice)
	skC := DeriveSession(masterController)

	// Controller (c2s) sends; device receives and decrypts.
	c2sMsg := []byte("set brightness 128")
	env, err := Seal(skC.KKcpC2S, true, 1, c2sMsg)
	if err != nil {
		t.Fatalf("controller Seal: %v", err)
	}
	got, err := Open(skD.KKcpC2S, true, 1, env)
	if err != nil || !bytes.Equal(got, c2sMsg) {
		t.Fatalf("device could not open c2s: got=%q err=%v", got, err)
	}
	// Device (s2c) replies; controller decrypts.
	s2cMsg := []byte("ack")
	env2, err := Seal(skD.KKcpS2C, false, 1, s2cMsg)
	if err != nil {
		t.Fatalf("device Seal: %v", err)
	}
	got2, err := Open(skC.KKcpS2C, false, 1, env2)
	if err != nil || !bytes.Equal(got2, s2cMsg) {
		t.Fatalf("controller could not open s2c: got=%q err=%v", got2, err)
	}
}

// A tampered FINISH must not let the device derive the controller's master — the
// client_tag gate holds, and even past it a flipped e_c changes dh and thus master.
func TestHandshakeRejectsTamperedFINISH(t *testing.T) {
	psk := fx(0xA5, 32)
	deviceID := fx(0x11, 8)
	st := DeriveStatic(DeriveKDev(psk, deviceID))
	nonce, etag, cookie, aepoch := fx(0x22, 24), fx(0x33, 8), fx(0x44, 16), fx(0x55, 8)
	eC, _ := curve25519.X25519(fx(0x66, 32), curve25519.Basepoint)

	ctx := Context(nonce, etag, cookie, aepoch, deviceID)
	tag := ClientTag(st.KReq, ctx, eC)
	fin := EncodeFINISH(nonce, etag, cookie, aepoch, eC, tag)

	// Flip a bit in e_c on the wire; the device's recomputed client_tag must not match.
	fin[70] ^= 0x01
	ff, err := DecodeFINISH(fin)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ctxD := Context(ff.ClientNonce, ff.EpochTag, ff.Cookie, ff.AdmissionEpoch, deviceID)
	if bytes.Equal(ClientTag(st.KReq, ctxD, ff.EC), ff.ClientTag) {
		t.Fatal("device accepted a tampered FINISH")
	}
}
