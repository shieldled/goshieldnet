// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"net/netip"
)

// §4.3: canonical_source and the source-rejection predicate.
//
// canonical_source = ipv6_address[16] || port_be[2], IPv4 as IPv4-mapped IPv6
// (::ffff:a.b.c.d), never the deprecated IPv4-compatible form.
//
// The rejection list is a LIST, not an acceptance category (§4.3): applied to the
// received source IN ITS OWN FAMILY, before canonicalisation, so a scope macro on
// the mapped form cannot silently reject every IPv4 controller. The only threat is
// group-address amplification; RFC1918, 169.254/16, 100.64/10, fe80::/10 and fc00::/7
// are all accepted.

// Canonicalize returns the 18-octet canonical_source for a source address and port.
func Canonicalize(addr netip.Addr, port uint16) []byte {
	a16 := addr.As16() // ::ffff:a.b.c.d for a v4 address — the mapped form
	out := make([]byte, 18)
	copy(out[:16], a16[:])
	binary.BigEndian.PutUint16(out[16:], port)
	return out
}

// SourceRejected reports whether a datagram from addr MUST be dropped (§4.3).
//
// local is the set of prefixes assigned to the receiving interface — the
// (address, netmask) table §4.3 needs: the interface's own address is prefix.Addr(),
// and the subnet broadcast is the all-ones host of the prefix. §4.3 requires the
// admission socket bound to one interface, so this is that interface's prefixes.
func SourceRejected(addr netip.Addr, local []netip.Prefix) bool {
	if !addr.IsValid() {
		return true
	}
	// Own-interface address, and (for v4) the broadcast of any local subnet.
	for _, p := range local {
		if p.Addr() == addr {
			return true
		}
		if addr.Is4() && p.Addr().Is4() {
			// An out-of-range prefix length (netip reports it as Bits() == -1)
			// has no broadcast to compute: a misconfigured interface table fails
			// closed, which bring-up notices at once, rather than silently
			// skipping the broadcast reject. Matches libshieldnet's sn_source.c.
			if p.Bits() < 0 || p.Bits() > 32 {
				return true
			}
			// /31 (RFC 3021 point-to-point) and /32 have no broadcast address:
			// the all-ones host is the peer, or this interface itself.
			if p.Bits() >= 31 {
				continue
			}
			if subnetBroadcast(p) == addr {
				return true
			}
		}
	}
	if addr.Is4() {
		return sourceRejected4(addr)
	}
	// A v4-mapped address arriving as a genuine v6 source is rejected (::ffff:0:0/96):
	// it would canonicalise as a v4 peer.
	if addr.Is4In6() {
		return true
	}
	return sourceRejected6(addr)
}

func sourceRejected4(addr netip.Addr) bool {
	b := addr.As4()
	switch {
	case b[0] >= 224 && b[0] <= 239: // 224.0.0.0/4 multicast
		return true
	case b == [4]byte{255, 255, 255, 255}: // limited broadcast
		return true
	case b[0] == 0: // 0.0.0.0/8
		return true
	case b[0] == 127: // 127.0.0.0/8 loopback
		return true
	}
	return false
}

func sourceRejected6(addr netip.Addr) bool {
	b := addr.As16()
	if b[0] == 0xff { // ff00::/8 multicast
		return true
	}
	if addr == netip.IPv6Unspecified() || addr == netip.IPv6Loopback() { // :: and ::1
		return true
	}
	// ::/96 IPv4-compatible (deprecated): first 12 octets zero (:: and ::1 handled above).
	for _, x := range b[:12] {
		if x != 0 {
			return false
		}
	}
	return true
}

// subnetBroadcast returns the all-ones-host address of a v4 prefix. The caller
// guarantees a valid prefix (0 <= Bits() <= 32); Masked() of an invalid one is
// the zero Prefix, whose Addr().As4() panics.
func subnetBroadcast(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	a := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		byteIdx := 3 - i/8
		a[byteIdx] |= 1 << (uint(i) % 8)
	}
	return netip.AddrFrom4(a)
}
