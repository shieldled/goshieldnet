// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net/netip"
	"testing"
	"unsafe"
)

// The decoders and the classifier are the first code an attacker's bytes reach:
// Classify runs at §5 step 0 and the Decode* pair run before any MAC is checked
// (HandleINIT calls DecodeINIT, then compares device_id). They must terminate,
// never panic, and never return fields that outlive or overrun the input.

// validSeeds returns one well-formed datagram of each type. Seeding with these
// matters more than it looks: every decoder rejects on total length before
// reading a field, so a corpus of random bytes never gets past the front door
// and the field-parsing paths go untested. A first run of this fuzzer did
// 18M executions and grew coverage by one edge for exactly that reason.
func validSeeds() [][]byte {
	b := func(n int, fill byte) []byte {
		v := make([]byte, n)
		for i := range v {
			v[i] = fill
		}
		return v
	}
	return [][]byte{
		EncodeINIT(b(24, 0x11), b(8, 0x22), b(16, 0x33)),
		EncodeRETRY(b(8, 0x44), b(16, 0x55), b(8, 0x66), b(8, 0x22), b(18, 0x77), b(16, 0x88)),
		EncodeFINISH(b(24, 0x11), b(8, 0x44), b(16, 0x55), b(8, 0x66), b(32, 0x99), b(16, 0xAA)),
		EncodeADMIT(b(8, 0x66), b(32, 0xBB), b(16, 0xCC), b(16, 0xDD)),
	}
}

func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 256))  // INIT-sized
	f.Add(make([]byte, 1400)) // MTU
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})
	for _, s := range validSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		local := []netip.Prefix{netip.MustParsePrefix("192.168.4.0/24")}
		for _, role := range []Role{RoleDevice, RoleClient} {
			for _, src := range []netip.Addr{
				netip.MustParseAddr("192.168.4.2"),
				netip.MustParseAddr("0.0.0.0"),
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("255.255.255.255"),
			} {
				_ = Classify(role, src, local, b)
			}
			_ = classifyDatagram(role, b)
		}
	})
}

// A decoder that reports success must not hand back slices that overrun the
// input, and must be deterministic. §7.2 additionally requires the caller to
// copy retained fields, which only holds if the decoder's slices really do
// alias the input it was given.
func FuzzDecodeWire(f *testing.F) {
	f.Add(make([]byte, RequestLen))
	f.Add(make([]byte, RetryLen))
	f.Add(make([]byte, RequestLen))
	f.Add(make([]byte, AdmitLen))
	f.Add([]byte{})
	for _, s := range validSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		orig := append([]byte(nil), b...)

		if fi, err := DecodeINIT(b); err == nil {
			within(t, "INIT.ClientNonce", b, fi.ClientNonce)
			within(t, "INIT.DeviceID", b, fi.DeviceID)
			within(t, "INIT.InitMAC", b, fi.InitMAC)
		}
		if fr, err := DecodeRETRY(b); err == nil {
			within(t, "RETRY.EpochTag", b, fr.EpochTag)
			within(t, "RETRY.Cookie", b, fr.Cookie)
			within(t, "RETRY.AdmissionEpoch", b, fr.AdmissionEpoch)
			within(t, "RETRY.DeviceID", b, fr.DeviceID)
			within(t, "RETRY.ObservedSource", b, fr.ObservedSource)
			within(t, "RETRY.RetryMAC", b, fr.RetryMAC)
		}
		if ff, err := DecodeFINISH(b); err == nil {
			within(t, "FINISH.ClientNonce", b, ff.ClientNonce)
			within(t, "FINISH.EpochTag", b, ff.EpochTag)
			within(t, "FINISH.Cookie", b, ff.Cookie)
			within(t, "FINISH.AdmissionEpoch", b, ff.AdmissionEpoch)
			within(t, "FINISH.EC", b, ff.EC)
			within(t, "FINISH.ClientTag", b, ff.ClientTag)
		}
		if fa, err := DecodeADMIT(b); err == nil {
			within(t, "ADMIT.AdmissionEpoch", b, fa.AdmissionEpoch)
			within(t, "ADMIT.ES", b, fa.ES)
			within(t, "ADMIT.AdmitPre", b, fa.AdmitPre)
			within(t, "ADMIT.AdmitTag", b, fa.AdmitTag)
		}

		// A decoder must not mutate what it was handed.
		if string(orig) != string(b) {
			t.Fatalf("decoder mutated its input")
		}
	})
}

// within reports a returned slice that is not contained in the input buffer —
// either an overrun or an unexpected copy, both of which change what §7.2's
// copy requirement means for the caller.
//
// The length check alone could not express this: an out-of-range sub-slice
// panics before it can be returned, and a copy is the same length as the
// original, so every call was a no-op. Comparing the backing pointers is what
// actually distinguishes "a view into the caller's buffer" from "a copy".
func within(t *testing.T, name string, buf, s []byte) {
	t.Helper()
	if len(s) == 0 {
		return
	}
	if len(s) > len(buf) {
		t.Fatalf("%s: length %d exceeds input %d", name, len(s), len(buf))
	}
	base := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	got := uintptr(unsafe.Pointer(unsafe.SliceData(s)))
	if got < base || got+uintptr(len(s)) > base+uintptr(len(buf)) {
		t.Fatalf("%s: returned slice is not a view into the input buffer", name)
	}
}
