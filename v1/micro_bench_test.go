// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net/netip"
	"testing"
)

func BenchmarkEnvelopeSeal(b *testing.B) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	payload := bytes.Repeat([]byte{0x11}, 1000)
	b.SetBytes(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Seal(key, true, uint64(i+1), payload)
	}
}

func BenchmarkEnvelopeOpen(b *testing.B) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	env, _ := Seal(key, true, 1, bytes.Repeat([]byte{0x11}, 1000))
	b.SetBytes(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Open(key, true, 1, env)
	}
}

// The device's per-admission cost (§6.2 step 6): X25519 + the §4.5 derivation.
func BenchmarkDeviceFINISH(b *testing.B) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	deviceID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		d := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x22}, 32), []byte{0, 1, 2, 3, 4, 5, 6, 7}, []netip.Prefix{netip.MustParsePrefix("192.168.4.1/24")}, 8000))
		d.SetRandSource(fixedRand(0x42))
		retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
		fin, _, _ := clientFINISH(deviceID, nonce, ecPriv, retry)
		b.StartTimer()
		d.HandleFINISH(fin, src, 8000)
	}
}

// The client's processing of ADMIT (transport 4.3, the pending-record budget):
// the checks, one X25519 and the key derivation, in checkADMIT.
func BenchmarkClientADMIT(b *testing.B) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	deviceID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)
	epoch := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	src := netip.MustParseAddrPort("192.168.4.2:5000")
	d := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x22}, 32), epoch, []netip.Prefix{netip.MustParsePrefix("192.168.4.1/24")}, 8000))
	d.SetRandSource(fixedRand(0x42))
	retry := d.HandleINIT(validINIT(d.kReq, nonce, deviceID), src, 8000)
	fin, ecPub, context := clientFINISH(deviceID, nonce, ecPriv, retry)
	admit := d.HandleFINISH(fin, src, 8000)
	cli, err := NewClient("192.168.4.1:9", psk, deviceID, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer cli.Close()
	cli.skipSrcCheck = true
	if _, ok := cli.checkADMIT(admit, context, ecPriv, ecPub, epoch, map[string][]byte{}); !ok {
		b.Fatal("the ADMIT does not verify")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cli.checkADMIT(admit, context, ecPriv, ecPub, epoch, map[string][]byte{})
	}
}
