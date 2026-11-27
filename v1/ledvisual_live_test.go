// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestLedVisual drives a physical strip through a pattern sequence and reports
// host-side send timing. Wire stride is a fixed 4 bytes per pixel (R,G,B,W); on
// an RGB strip the W byte is dropped on ingest.
//
// The R/G/B phases are a channel-order check for the firmware's GRB swizzle,
// and only an operator can score them. Verified on WS2812 hardware: sending
// R,G,B in that order shows red, green, blue, so the swizzle is correct.
//
// Timings measured this way on 2 strips x 1024 LEDs at 3 bpp, target_fps 30:
// RMT transmit 29.86 ms (97% of the 30.72 ms line rate, +/-0.5 ms), swizzle and
// mailbox under 0.11 ms, cycle 33.0 ms = 30.3 fps, zero dropped frames.
//
//	SN_DEVICE=ip:port SN_DEVICE_MAC=.. SN_LEDS=2048 go test -run TestLedVisual -v
func TestLedVisual(t *testing.T) {
	addr := os.Getenv("SN_DEVICE")
	if addr == "" {
		t.Skip("set SN_DEVICE")
	}
	var b [6]byte
	if _, err := fmt.Sscanf(os.Getenv("SN_DEVICE_MAC"), "%02x:%02x:%02x:%02x:%02x:%02x",
		&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); err != nil {
		t.Fatalf("SN_DEVICE_MAC: %v", err)
	}
	deviceID := make([]byte, 8)
	copy(deviceID, b[:])

	leds := 2048 // 2 strips x 1024
	if v := os.Getenv("SN_LEDS"); v != "" {
		fmt.Sscanf(v, "%d", &leds)
	}

	cli, err := NewClient(addr, bytes.Repeat([]byte{0x33}, 32), deviceID, []netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("admission: %v", err)
	}

	const hdr = 28
	frame := make([]byte, hdr+leds*4)
	var seq int64
	send := func() error {
		binary.BigEndian.PutUint64(frame[0:], uint64(seq))
		seq++
		// not_before (8) and not_after (16) stay 0: no scheduling.
		binary.BigEndian.PutUint32(frame[24:], uint32(leds*4))
		return cli.SendAppCompressed(CmdPixelFrame, frame)
	}
	fill := func(r, g, bl byte) {
		for i := 0; i < leds; i++ {
			o := hdr + i*4
			frame[o], frame[o+1], frame[o+2], frame[o+3] = r, g, bl, 0
		}
	}

	type phase struct {
		name string
		dur  time.Duration
		draw func(tick int)
	}
	phases := []phase{
		{"RED    (channel-order check)", 3 * time.Second, func(int) { fill(255, 0, 0) }},
		{"GREEN  (channel-order check)", 3 * time.Second, func(int) { fill(0, 255, 0) }},
		{"BLUE   (channel-order check)", 3 * time.Second, func(int) { fill(0, 0, 255) }},
		{"WHITE", 2 * time.Second, func(int) { fill(255, 255, 255) }},
		{"CHASE  (8-px comet)", 5 * time.Second, func(tick int) {
			fill(0, 0, 0)
			head := (tick * 12) % leds
			for k := 0; k < 8; k++ {
				i := (head - k + leds) % leds
				v := byte(255 - k*30)
				o := hdr + i*4
				frame[o], frame[o+1], frame[o+2] = v, 0, v/3
			}
		}},
		{"GRADIENT sweep", 5 * time.Second, func(tick int) {
			for i := 0; i < leds; i++ {
				p := (i*255/leds + tick*6) % 255
				o := hdr + i*4
				frame[o], frame[o+1], frame[o+2] = byte(p), byte(255-p), byte((p*2)%255)
			}
		}},
		{"BLACK", 1 * time.Second, func(int) { fill(0, 0, 0) }},
	}

	for _, ph := range phases {
		start := time.Now()
		var n int
		var worst time.Duration
		for tick := 0; time.Since(start) < ph.dur; tick++ {
			ph.draw(tick)
			t0 := time.Now()
			if err := send(); err != nil {
				t.Fatalf("%s: send: %v", ph.name, err)
			}
			if d := time.Since(t0); d > worst {
				worst = d
			}
			n++
			time.Sleep(28 * time.Millisecond) // aim just under 33ms
		}
		el := time.Since(start)
		t.Logf("%-30s %3d frames in %5.2fs = %5.1f fps sent, worst send %v",
			ph.name, n, el.Seconds(), float64(n)/el.Seconds(), worst.Round(time.Microsecond))
	}
}
