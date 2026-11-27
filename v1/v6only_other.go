//go:build !windows

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "syscall"

// getsockoptV6Only reads IPV6_V6ONLY from fd for isV6Socket; see v6only_windows.go.
func getsockoptV6Only(fd uintptr) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
}
