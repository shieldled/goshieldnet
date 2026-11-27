//go:build linux

// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// maxDrainErrors bounds consecutive read errors in one drain, so an errno that
// repeated for ever could not hold the attempt.
const maxDrainErrors = 64

// drainQueued passes the datagrams already queued on conn to handle, without
// waiting for more, until handle returns true; it reports whether it did. It
// stops after maxDrainDatagrams datagrams or phaseDrainMS, whichever comes
// first
// (transport 10.3 rule 4: a reply already queued when a timer expires is read
// before the timer acts). A read error is skipped — among them the pending
// error a connected UDP socket reports for an ICMP message, under whichever
// errno Linux maps it to, which transport 10.6 says to ignore — except EBADF
// (the socket is closed), which ends the drain.
func drainQueued(conn *net.UDPConn, handle func([]byte) bool) bool {
	// A raw read after an expired deadline fails without calling the callback.
	// The callers set a fresh deadline before each blocking read, so it is not
	// restored.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	buf := make([]byte, 2048)
	done := false
	end := time.Now().Add(phaseDrainMS * time.Millisecond)
	// The callback always returns true: false would make the runtime wait for
	// readability, with no deadline.
	_ = rc.Read(func(fd uintptr) bool {
		for errs, read := 0, 0; errs < maxDrainErrors && read < maxDrainDatagrams && time.Now().Before(end); {
			n, _, rerr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			switch {
			case rerr == nil:
				errs = 0
				read++
				if handle(buf[:n]) {
					done = true
					return true
				}
			case errors.Is(rerr, syscall.EAGAIN), errors.Is(rerr, syscall.EBADF):
				return true
			default:
				errs++ // EINTR, or an ICMP error (transport 10.6): skip it
			}
		}
		return true
	})
	return done
}
