// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Goroutine-leak guard over the full client lifecycle. Every goroutine this
// package starts on a success path must be gone once Close returns; a leaked
// reader holds the socket and wedges the next attempt (see
// TestNoReadLoopSurvivesFailedAttempt for the failure that motivated this).
func TestNoGoroutineLeakAcrossSessions(t *testing.T) {
	settle := func() int {
		var n int
		for i := 0; i < 50; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
			n = runtime.NumGoroutine()
		}
		return n
	}

	psk := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}

	runOnce := func() {
		sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		dev := mustDev(NewDevice(psk, deviceID, bytes.Repeat([]byte{0x44}, 32),
			[]byte{0, 1, 2, 3, 4, 5, 6, 7}, local, 8000))
		srv := NewServer(dev, sconn)
		srv.skipSrcCheck = true
		go srv.Serve()

		cli, err := NewClient(sconn.LocalAddr().String(), psk, deviceID, local)
		if err != nil {
			t.Fatal(err)
		}
		cli.skipSrcCheck = true
		if err := cli.TakeControl([]byte("leak-probe")); err != nil {
			t.Fatalf("TakeControl: %v", err)
		}
		_, _ = cli.Send([]byte("payload"))
		cli.Close()
		srv.Close()
		sconn.Close()
	}

	runOnce() // prime: first run allocates package-level machinery
	base := settle()

	for i := 0; i < 15; i++ {
		runOnce()
	}
	after := settle()

	if after > base+2 { // small slack for runtime-internal workers
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		var stuck []string
		for _, g := range strings.Split(string(buf), "\n\n") {
			if strings.Contains(g, "goshieldnet/v1.") {
				if i := strings.Index(g, "\n"); i > 0 {
					stuck = append(stuck, strings.TrimSpace(g[:i]))
				}
			}
		}
		t.Fatalf("goroutine leak: %d before, %d after 15 sessions (+%d)\nshieldnet goroutines still live:\n  %s",
			base, after, after-base, strings.Join(stuck, "\n  "))
	}
	t.Logf("goroutines: %d before, %d after 15 full sessions", base, after)
}
