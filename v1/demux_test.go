// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net/netip"
	"testing"
)

// A device interface on 192.168.4.1/24 with a v6 ULA, matching source_test.go.
func demuxLocal() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("192.168.4.1/24"),
		netip.MustParsePrefix("fd00::abcd/64"),
	}
}

func ctrl(typ byte, n int) []byte {
	b := make([]byte, n)
	copy(b, Magic)
	b[8] = typ
	b[9] = Version
	return b
}

func TestClassifyDropsRejectedSource(t *testing.T) {
	// A valid-looking INIT from a multicast source is dropped at step 0, before
	// the magic/type is ever examined.
	d := ctrl(TypeINIT, RequestLen)
	src := netip.MustParseAddr("224.0.0.1")
	if got := Classify(RoleDevice, src, demuxLocal(), d); got != ClassDrop {
		t.Errorf("rejected source: got %d, want ClassDrop", got)
	}
}

func TestClassifyDirection(t *testing.T) {
	good := netip.MustParseAddr("192.168.4.2")
	local := demuxLocal()
	cases := []struct {
		name string
		role Role
		typ  byte
		n    int
		want Class
	}{
		{"device INIT", RoleDevice, TypeINIT, RequestLen, ClassINIT},
		{"device FINISH", RoleDevice, TypeFIN, RequestLen, ClassFINISH},
		{"device RETRY (wrong dir)", RoleDevice, TypeRETRY, RetryLen, ClassDrop},
		{"device ADMIT (wrong dir)", RoleDevice, TypeADMIT, AdmitLen, ClassDrop},
		{"client RETRY", RoleClient, TypeRETRY, RetryLen, ClassRETRY},
		{"client ADMIT", RoleClient, TypeADMIT, AdmitLen, ClassADMIT},
		{"client INIT (wrong dir)", RoleClient, TypeINIT, RequestLen, ClassDrop},
		{"client FINISH (wrong dir)", RoleClient, TypeFIN, RequestLen, ClassDrop},
	}
	for _, c := range cases {
		if got := Classify(c.role, good, local, ctrl(c.typ, c.n)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestClassifyReservedAndUnknownTypesDrop(t *testing.T) {
	good := netip.MustParseAddr("192.168.4.2")
	local := demuxLocal()
	for _, typ := range []byte{0x00, 0x03, 0x04, 0x07, 0xff} {
		if got := Classify(RoleDevice, good, local, ctrl(typ, RequestLen)); got != ClassDrop {
			t.Errorf("type %#x: got %d, want ClassDrop", typ, got)
		}
	}
}

func TestClassifyEnvelopeFallthrough(t *testing.T) {
	good := netip.MustParseAddr("192.168.4.2")
	local := demuxLocal()
	// No MAGIC → envelope path regardless of length.
	env := make([]byte, 100)
	if got := Classify(RoleDevice, good, local, env); got != ClassEnvelope {
		t.Errorf("non-magic 100B: got %d, want ClassEnvelope", got)
	}
	// Too short to hold a header, non-magic → still envelope (§8 rejects on length).
	if got := Classify(RoleDevice, good, local, []byte{1, 2, 3}); got != ClassEnvelope {
		t.Errorf("3B: got %d, want ClassEnvelope", got)
	}
	// First 8 octets happen to equal MAGIC but N < HEADER_LEN → envelope path,
	// since the type octet cannot be read.
	short := append([]byte{}, Magic...)
	if got := Classify(RoleDevice, good, local, short); got != ClassEnvelope {
		t.Errorf("8B magic-only: got %d, want ClassEnvelope", got)
	}
}

func TestClassifyRoutesWrongLengthControlByType(t *testing.T) {
	// A MAGIC+INIT datagram of the wrong length still routes to ClassINIT; the
	// decoder (§3.5), not the demux, rejects the length.
	good := netip.MustParseAddr("192.168.4.2")
	if got := Classify(RoleDevice, good, demuxLocal(), ctrl(TypeINIT, 100)); got != ClassINIT {
		t.Errorf("short INIT: got %d, want ClassINIT (decoder checks length)", got)
	}
}
