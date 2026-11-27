// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net"
	"testing"
)

// §4.3 — a dual-stack socket must NOT be treated as v6-only, or every IPv4
// controller is silently rejected forever. LocalAddr says "::" for both, so only
// IPV6_V6ONLY separates them.
func TestDualStackSocketAcceptsIPv4Controllers(t *testing.T) {
	for _, tc := range []struct {
		network, addr string
		wantV6Only    bool
	}{
		{"udp", ":0", false},        // dual-stack: v4 peers must be accepted
		{"udp", "0.0.0.0:0", false}, // still dual-stack, LocalAddr is "::"
		{"udp4", ":0", false},       // plain v4
	} {
		c, err := net.ListenPacket(tc.network, tc.addr)
		if err != nil {
			continue
		}
		got := isV6Socket(c)
		if got != tc.wantV6Only {
			t.Errorf("Listen(%q,%q): isV6Socket=%v want %v — a v4 controller "+
				"would be %s", tc.network, tc.addr, got, tc.wantV6Only,
				map[bool]string{true: "REJECTED", false: "accepted"}[got])
		}
		c.Close()
	}
	// A genuinely v6-only socket must still enforce the rule.
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err == nil {
		if !isV6Socket(c) {
			t.Error("udp6 socket not detected as v6-only; ::ffff:0:0/96 unenforced")
		}
		c.Close()
	}
}
