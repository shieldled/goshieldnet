// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net/netip"
	"testing"
)

func testDevice() (*Device, []byte) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	deviceID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cookieSecret := bytes.Repeat([]byte{0x22}, 32)
	admissionEpoch := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	local := []netip.Prefix{netip.MustParsePrefix("192.168.4.1/24")}
	return mustDev(NewDevice(psk, deviceID, cookieSecret, admissionEpoch, local, 8000)), deviceID
}

func validINIT(kReq, nonce, deviceID []byte) []byte {
	mac := InitMAC(kReq, nonce, deviceID)
	return EncodeINIT(nonce, deviceID, mac)
}

func TestHandleINITProducesVerifiableRETRY(t *testing.T) {
	d, deviceID := testDevice()
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	src := netip.MustParseAddrPort("192.168.4.2:5000")

	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	if retry == nil {
		t.Fatal("valid INIT dropped")
	}
	f, err := DecodeRETRY(retry)
	if err != nil {
		t.Fatalf("RETRY does not decode: %v", err)
	}
	// observed_source is this datagram's canonical_source.
	wantCS := Canonicalize(src.Addr(), src.Port())
	if !bytes.Equal(f.ObservedSource, wantCS) {
		t.Errorf("observed_source: got %x want %x", f.ObservedSource, wantCS)
	}
	// epoch_tag, admission_epoch, device_id are the device's own.
	if !bytes.Equal(f.EpochTag, d.epochTag) {
		t.Errorf("epoch_tag mismatch")
	}
	if !bytes.Equal(f.AdmissionEpoch, d.admissionEpoch) {
		t.Errorf("admission_epoch mismatch")
	}
	if !bytes.Equal(f.DeviceID, deviceID) {
		t.Errorf("device_id mismatch")
	}
	// cookie recomputes from cookie_secret over epoch_tag||canonical_source||nonce.
	wantCookie := Cookie(d.cookieSecret, d.epochTag, wantCS, nonce)
	if !bytes.Equal(f.Cookie, wantCookie) {
		t.Errorf("cookie mismatch")
	}
	// retry_mac verifies under k_resp.
	wantMAC := RetryMAC(d.kResp, nonce, f.EpochTag, f.Cookie, f.AdmissionEpoch, f.DeviceID, f.ObservedSource)
	if !bytes.Equal(f.RetryMAC, wantMAC) {
		t.Errorf("retry_mac does not verify")
	}
}

func TestHandleINITRejects(t *testing.T) {
	d, deviceID := testDevice()
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	src := netip.MustParseAddrPort("192.168.4.2:5000")

	// wrong device_id → drop, no crypto
	other := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	if d.HandleINIT(validINIT(d.kReq, nonce, other), src, 8000) != nil {
		t.Error("INIT for another device_id was answered")
	}

	// bad init_mac → drop
	bad := validINIT(d.kReq, nonce, deviceID)
	bad[42] ^= 0xFF // flip a byte of init_mac
	if d.HandleINIT(bad, src, 8000) != nil {
		t.Error("INIT with bad init_mac was answered")
	}

	// wrong length → drop
	if d.HandleINIT(make([]byte, 100), src, 8000) != nil {
		t.Error("short INIT was answered")
	}

	// non-zero padding → drop
	padbad := validINIT(d.kReq, nonce, deviceID)
	padbad[200] = 0x01
	if d.HandleINIT(padbad, src, 8000) != nil {
		t.Error("INIT with non-zero padding was answered")
	}
}

func TestRollEpochKeepsPrevious(t *testing.T) {
	d, _ := testDevice() // built at nowMS=8000 → epoch 2
	first := append([]byte(nil), d.epochTag...)
	d.RollEpoch(8500) // same epoch (8500/4000 == 2) → no change
	if !bytes.Equal(d.epochTag, first) || d.prevEpochTag != nil {
		t.Error("roll within an epoch changed state")
	}
	d.RollEpoch(12000) // epoch 3
	if bytes.Equal(d.epochTag, first) {
		t.Error("epoch_tag did not advance")
	}
	if !bytes.Equal(d.prevEpochTag, first) {
		t.Error("previous epoch_tag not retained")
	}
}

// mustDev unwraps NewDevice for fixtures whose inputs are known-good.
func mustDev(d *Device, err error) *Device {
	if err != nil {
		panic(err)
	}
	return d
}
