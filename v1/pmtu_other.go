//go:build !linux

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "net"

// setPMTUProbe is a no-op off Linux; see pmtu_linux.go.
func setPMTUProbe(net.PacketConn) {}
