//go:build linux

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net"
	"syscall"
)

// setPMTUProbe stops the kernel acting on ICMP "fragmentation needed": with
// IP_PMTUDISC_PROBE it neither lowers its cached path MTU nor fails sends with
// EMSGSIZE on the strength of one, so a spoofed ICMP cannot shrink or break
// the session's path (§7.6, §8.4: datagrams are sized to WIRE_MTU, not to path
// MTU discovery). Best effort; errors leave the default in place.
func setPMTUProbe(pc net.PacketConn) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_PROBE)
	})
}
