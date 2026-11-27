// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net/netip"
	"testing"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// canonical_source: IPv4 becomes the mapped form ::ffff:a.b.c.d and the port is
// big-endian; a v6 address is carried as-is.
func TestCanonicalize(t *testing.T) {
	got := Canonicalize(mustAddr("192.168.4.2"), 0x1234)
	want := append(
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 4, 2},
		0x12, 0x34,
	)
	if !bytes.Equal(got, want) {
		t.Errorf("v4 mapped:\n  got  %x\n  want %x", got, want)
	}
	if len(got) != 18 {
		t.Errorf("canonical_source len = %d, want 18", len(got))
	}
	// A genuine v6 source keeps its address; port big-endian.
	g6 := Canonicalize(mustAddr("fd00::1"), 1)
	if g6[15] != 1 || g6[16] != 0 || g6[17] != 1 {
		t.Errorf("v6 canonicalisation wrong: %x", g6)
	}
}

// §4.3 / §15 accept and reject sets, tested separately (the RFC is emphatic these
// are where two implementations most plausibly diverge). local prefixes model the
// receiving interface: 192.168.4.0/24 (so 192.168.4.1 is the device and
// 192.168.4.255 the subnet broadcast) and a v6 ULA.
func TestSourceRejection(t *testing.T) {
	local := []netip.Prefix{
		netip.MustParsePrefix("192.168.4.1/24"),
		netip.MustParsePrefix("fd00::abcd/64"),
	}

	accept := []string{
		"192.168.4.2", // SoftAP client
		"10.0.0.5",    // RFC1918
		"172.16.0.5",  // RFC1918
		"169.254.1.1", // IPv4 link-local
		"100.64.0.1",  // CGNAT
		"fe80::1",     // IPv6 link-local
		"fd00::1",     // ULA (not the device's own fd00::abcd)
		"2001:db8::1", // global v6
	}
	for _, s := range accept {
		if SourceRejected(mustAddr(s), local) {
			t.Errorf("accepted address %s was rejected", s)
		}
	}

	reject := []string{
		"224.0.0.1",       // v4 multicast
		"239.1.1.1",       // v4 multicast (administratively scoped)
		"255.255.255.255", // limited broadcast
		"192.168.4.255",   // subnet broadcast of the local /24
		"0.0.0.0",         // 0.0.0.0/8
		"127.0.0.1",       // loopback
		"192.168.4.1",     // the device's own address
		"ff02::1",         // v6 multicast
		"::",              // unspecified
		"::1",             // loopback
		"::ffff:1.2.3.4",  // v4-mapped arriving as a genuine v6 source
		"::0.0.1.2",       // IPv4-compatible (::/96), deprecated
		"fd00::abcd",      // the device's own v6 address
	}
	for _, s := range reject {
		if !SourceRejected(mustAddr(s), local) {
			t.Errorf("rejected address %s was accepted", s)
		}
	}
}

// The predicate must not depend on port and must reject an invalid address.
func TestSourceEdge(t *testing.T) {
	if !SourceRejected(netip.Addr{}, nil) {
		t.Error("invalid address accepted")
	}
	// With no local prefixes, a plain RFC1918 unicast is still accepted.
	if SourceRejected(mustAddr("10.1.2.3"), nil) {
		t.Error("RFC1918 rejected with empty local set")
	}
}

// Prefix length bounds, mirroring libshieldnet's test_sn_source.c. /31 is
// RFC 3021 point-to-point and /32 a host route: neither has a broadcast, so the
// all-ones host (the peer) is a legitimate source. The interface's own address
// is still rejected. An out-of-range v4 prefix length fails closed.
func TestSourcePrefixBounds(t *testing.T) {
	p31 := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/31")}
	p32 := []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}
	p30 := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")}
	type tc struct {
		name   string
		addr   string
		local  []netip.Prefix
		reject bool
	}
	cases := []tc{
		{"/31 peer 10.0.0.1", "10.0.0.1", p31, false},
		{"/31 own 10.0.0.0", "10.0.0.0", p31, true},
		{"/32 other 10.0.0.8", "10.0.0.8", p32, false},
		{"/32 own 10.0.0.7", "10.0.0.7", p32, true},
		{"/30 bcast 10.0.0.3", "10.0.0.3", p30, true},
		{"/30 peer 10.0.0.2", "10.0.0.2", p30, false},
	}
	// netip cannot carry an out-of-range length: PrefixFrom keeps the address
	// and reports Bits() == -1, which is how a misconfigured table reaches us.
	for _, bits := range []int{-200, -1, 33} {
		bad := []netip.Prefix{netip.PrefixFrom(mustAddr("10.0.0.1"), bits)}
		cases = append(cases,
			tc{"bits out of range: v4 fails closed", "10.0.0.2", bad, true},
			// a v6 source is not judged against a v4 prefix's length
			tc{"bits out of range: v6 source unaffected", "fd00::1", bad, false},
		)
	}
	for _, c := range cases {
		if got := SourceRejected(mustAddr(c.addr), c.local); got != c.reject {
			t.Errorf("%s (%s against %v): rejected=%v, want %v", c.name, c.addr, c.local, got, c.reject)
		}
	}
}
