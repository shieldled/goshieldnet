//go:build !linux

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"net"
	"time"
)

// drainQueued passes the datagrams that arrive on conn within phaseDrainMS, at
// most maxDrainDatagrams of them, to handle until it returns true, and reports
// whether it did; see drain_linux.go. Off Linux there is no portable
// non-blocking read (Go's poller fails a read whose deadline has passed
// without looking at the socket buffer), so the drain reads with a short
// deadline of its own. A read error is skipped (transport 10.6), except a
// timeout and a closed socket, which end the drain.
func drainQueued(conn *net.UDPConn, handle func([]byte) bool) bool {
	if err := conn.SetReadDeadline(time.Now().Add(phaseDrainMS * time.Millisecond)); err != nil {
		return false
	}
	buf := make([]byte, 2048)
	for read := 0; read < maxDrainDatagrams; {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || isTimeoutErr(err) {
				return false
			}
			continue
		}
		read++
		if handle(buf[:n]) {
			return true
		}
	}
	return false
}
