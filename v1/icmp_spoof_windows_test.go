//go:build windows

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "testing"

// sendSpoofedICMP needs to send on a raw IPv4 ICMP socket: Windows' syscall
// has no IPPROTO_ICMP and its Sendto always fails; see icmp_spoof_other_test.go.
func sendSpoofedICMP(t *testing.T, cliPort, srvPort int, code byte, mtu uint16) {
	t.Skip("raw ICMP sockets are not available on Windows")
}
