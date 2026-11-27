//go:build !windows

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func icmpCsum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// sendSpoofedICMP sends an ICMP destination-unreachable (code 3: port, code 4:
// frag-needed with mtu) quoting the client's 127.0.0.1 4-tuple. Needs a raw
// socket; skips without one.
func sendSpoofedICMP(t *testing.T, cliPort, srvPort int, code byte, mtu uint16) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("raw socket: %v", err)
	}
	defer syscall.Close(fd)
	inner := make([]byte, 28)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:], 28+32)
	inner[8] = 64
	inner[9] = 17
	copy(inner[12:16], []byte{127, 0, 0, 1})
	copy(inner[16:20], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(inner[10:], icmpCsum(inner[:20]))
	binary.BigEndian.PutUint16(inner[20:], uint16(cliPort))
	binary.BigEndian.PutUint16(inner[22:], uint16(srvPort))
	binary.BigEndian.PutUint16(inner[24:], 8+32)
	msg := append([]byte{3, code, 0, 0, 0, 0, byte(mtu >> 8), byte(mtu)}, inner...)
	binary.BigEndian.PutUint16(msg[2:], icmpCsum(msg))
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("sendto: %v", err)
	}
}
