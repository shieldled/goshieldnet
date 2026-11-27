// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// transport 10.3 rule 4 reads what is queued at a timer's expiry; it must not
// let a socket fed faster than it is drained hold the attempt past the phase.
func TestTransport10DrainIsBounded(t *testing.T) {
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	_ = rx.SetReadBuffer(1 << 20)
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	for i := 0; i < 200; i++ {
		tx.Write([]byte{byte(i)})
	}
	time.Sleep(50 * time.Millisecond)
	n := 0
	start := time.Now()
	drainQueued(rx, func([]byte) bool {
		n++
		time.Sleep(time.Millisecond) // slower than the sender
		return false
	})
	elapsed := time.Since(start)
	if n > maxDrainDatagrams {
		t.Errorf("one drain handled %d datagrams, want at most %d", n, maxDrainDatagrams)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("one drain took %s, want about %d ms", elapsed, phaseDrainMS)
	}
}

// The datagram bound ends a drain whose handler is fast: with nothing slowing
// it, only maxDrainDatagrams can stop it within the time bound.
func TestTransport10DrainDatagramBound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the datagram bound is in the linux drain; drain_other.go is time-bounded only")
	}
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	_ = rx.SetReadBuffer(1 << 20)
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	for i := 0; i < 200; i++ {
		tx.Write([]byte{byte(i)})
	}
	time.Sleep(50 * time.Millisecond)
	n := 0
	drainQueued(rx, func([]byte) bool {
		n++
		return false
	})
	if n != maxDrainDatagrams {
		t.Errorf("one drain handled %d datagrams, want exactly %d", n, maxDrainDatagrams)
	}
}
