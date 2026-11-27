// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestSetFPSLive drives SLED_CMD_SET_FPS against real firmware.
//
// What it asserts: the device admits a session and accepts the command without
// error. What it cannot assert: that the render rate actually changed — that is
// only observable on the device's UART, so the resulting rate has to be read
// there. Measured by hand this way: 10 -> 10.0 fps, 20 -> 20.0, 30 -> 30.3.
//
// The ceiling is the RMT transmit, not this setting: ~30.7 ms for 24576 bits
// (1024 LEDs at 3 bpp, or 768 at 4 bpp — the same figure), so ~33 fps. Asking
// for more is clamped by the hardware rather than rejected. Periods also
// quantise to the FreeRTOS tick, since period = pdMS_TO_TICKS(1000/fps).
//
//	SN_DEVICE=ip:port SN_DEVICE_MAC=aa:bb:.. SN_FPS=30 go test -run TestSetFPSLive
func TestSetFPSLive(t *testing.T) {
	addr := os.Getenv("SN_DEVICE")
	if addr == "" {
		t.Skip("set SN_DEVICE=<ip:port> to run against hardware")
	}
	mac := os.Getenv("SN_DEVICE_MAC")
	var b [6]byte
	if _, err := fmt.Sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); err != nil {
		t.Fatalf("SN_DEVICE_MAC must be aa:bb:cc:dd:ee:ff (the device_id is MAC||00 00): %v", err)
	}
	deviceID := make([]byte, 8)
	copy(deviceID, b[:])

	fps := 30
	if v := os.Getenv("SN_FPS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &fps); err != nil || fps < 1 || fps > 255 {
			t.Fatalf("SN_FPS must be 1..255, got %q", v)
		}
	}

	cli, err := NewClient(addr, bytes.Repeat([]byte{0x33}, 32), deviceID, []netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true // the device enforces §4.3; this host is not on its prefix list
	defer cli.Close()

	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("admission: %v", err)
	}
	if err := cli.SendApp(CmdSetFPS, []byte{byte(fps)}); err != nil {
		t.Fatalf("SET_FPS %d: %v", fps, err)
	}
	t.Logf("SET_FPS %d accepted; read the resulting rate from the device UART", fps)

	// Hold the session open so the new rate is observable on the UART.
	hold := 20 * time.Second
	if v := os.Getenv("SN_HOLD_SECONDS"); v != "" {
		var s int
		if _, err := fmt.Sscanf(v, "%d", &s); err == nil && s > 0 {
			hold = time.Duration(s) * time.Second
		}
	}
	time.Sleep(hold)
}
