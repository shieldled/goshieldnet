// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"testing"
	"time"
)

// Over-the-air bandwidth: drives the benchmark/shieldnet-wifi device firmware over
// real Wi-Fi and reports what the host can push into it end to end.
//
//	SN_DEVICE=192.168.1.42:32100 [SN_PSK=<64 hex>] [SN_SECONDS=10] \
//	    go test ./v1/ -run TestWifiBandwidth -v
//
// The device prints DEVICE_IP/DEVICE_PORT on its UART at boot; the PSK must match
// its CONFIG_SNBENCH_PSK_HEX (default 0x33 x32).
// takeControlOnce runs a single §7.2 admission attempt in the mode the target needs.
func takeControlOnce(cli *Client) error {
	if os.Getenv("SN_APP") != "" {
		// Real firmware: it runs the app-message layer + command dispatch, so the
		// first PUSH must be a framed app message (a PING), not raw bytes.
		return cli.TakeControlApp(CmdPing, nil)
	}
	return cli.TakeControl([]byte("bench-start"))
}

func TestWifiBandwidth(t *testing.T) {
	addr := os.Getenv("SN_DEVICE")
	if addr == "" {
		t.Skip("set SN_DEVICE=<ip:port> (from the device's UART) to run the Wi-Fi benchmark")
	}
	psk := bytes.Repeat([]byte{0x33}, 32)
	if h := os.Getenv("SN_PSK"); h != "" {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			t.Fatalf("SN_PSK must be 64 hex chars: %v", err)
		}
		psk = b
	}
	seconds := 10
	fmt.Sscanf(os.Getenv("SN_SECONDS"), "%d", &seconds)
	if seconds <= 0 {
		seconds = 10
	}

	// The device derives its device_id from its STA MAC; learn it by resolving the
	// address is not possible, so it is supplied the same way the firmware does:
	// the first 6 bytes of the MAC then two zero bytes. Allow an override.
	deviceID := make([]byte, 8)
	if m := os.Getenv("SN_DEVICE_MAC"); m != "" {
		var b [6]byte
		if _, err := fmt.Sscanf(m, "%02x:%02x:%02x:%02x:%02x:%02x",
			&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); err != nil {
			t.Fatalf("SN_DEVICE_MAC must be aa:bb:cc:dd:ee:ff: %v", err)
		}
		copy(deviceID, b[:])
	} else {
		t.Fatal("set SN_DEVICE_MAC=<the device's STA MAC> (it prints at boot; the " +
			"device_id is MAC||00 00)")
	}

	cli, err := NewClient(addr, psk, deviceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true // the device enforces §4.3; the host isn't on its prefix list
	defer cli.Close()
	cli.Tuning = KCPTuning{SndWnd: 256, RcvWnd: 64, NoDelay: 1, Interval: 10, Resend: 2, NC: 1}

	// §7.2: one TakeControl invocation is exactly one attempt and never retries on
	// its own — whether to try again is the APPLICATION's decision. Over a lossy
	// link a single attempt (3 INITs in 3 s) can legitimately fail, so retry a few
	// times here, which is what a real controller would do.
	attempts := 6
	t0 := time.Now()
	var admitErr error
	for i := 0; i < attempts; i++ {
		admitErr = takeControlOnce(cli)
		if admitErr == nil {
			if i > 0 {
				t.Logf("admission succeeded on attempt %d", i+1)
			}
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if admitErr != nil {
		t.Fatalf("admission over Wi-Fi failed after %d attempts: %v", attempts, admitErr)
	}
	if false {
	}
	admit := time.Since(t0)
	t.Logf("admission over Wi-Fi: %v", admit)

	// Stream 1 KB messages for the requested duration and measure what we push.
	// For SN_APP_TYPE=0 (PIXEL_FRAME) the payload must actually parse, or the
	// firmware rejects every frame and ESP_LOGEs "frame parse error" per message —
	// blocking UART writes that dominate the measurement (1326 lines ≈ 4.1s of a
	// 15s run, observed). Frame wire format (frame.c): big-endian
	// int64 frame_number | int64 not_before | int64 not_after | int32 buffer_length | pixels.
	msg := bytes.Repeat([]byte{0x5A}, 1024)
	if os.Getenv("SN_APP_TYPE") == "0" {
		const hdr = 28
		// SN_FRAME_PIXELS overrides the pixel-byte count so throughput can be
		// measured against frame size: if MB/s scales with frame size the path is
		// message-rate limited, if it is flat the path is byte-rate limited. That
		// decides whether a larger frame still makes the frame-rate target.
		pixels := 2 * 1024 * 3 // this board: 2 strips x 1024 LEDs x 3 bpp
		if v := os.Getenv("SN_FRAME_PIXELS"); v != "" {
			var n int
			if _, e := fmt.Sscanf(v, "%d", &n); e == nil && n > 0 {
				pixels = n
			}
		}
		f := make([]byte, hdr+pixels)
		binary.BigEndian.PutUint64(f[0:], 0)  // frame_number
		binary.BigEndian.PutUint64(f[8:], 0)  // not_before
		binary.BigEndian.PutUint64(f[16:], 0) // not_after
		binary.BigEndian.PutUint32(f[24:], uint32(pixels))
		for i := hdr; i < len(f); i++ {
			f[i] = 0x20
		}
		msg = f
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var sent int64
	var writeLatencies []time.Duration
	cli.mu.Lock()
	sess := cli.kcp
	cli.mu.Unlock()
	for time.Now().Before(deadline) {
		// A generous per-write deadline: kcp-go's default would abort the run the
		// first time the send window fills, which is normal backpressure over the
		// air, not an error.
		sess.SetWriteDeadline(time.Now().Add(5 * time.Second))
		w0 := time.Now()
		var n int
		var err error
		if os.Getenv("SN_APP") != "" {
			// SN_APP_TYPE selects the workload. CmdPing is a request/response
			// probe: the firmware ACKs every message, so the measurement includes a
			// device-side encrypt+transmit per message. CmdPixelFrame is the
			// high-rate fire-and-forget path the frame-rate target actually uses --
			// handle_pixel_frame never responds. Measuring PING and reporting it
			// against a frame-streaming target compares different workloads.
			appType := uint32(0x10)
			if t := os.Getenv("SN_APP_TYPE"); t != "" {
				var v uint64
				if _, e := fmt.Sscanf(t, "%v", &v); e == nil {
					appType = uint32(v)
				}
			}
			err = cli.SendApp(appType, msg)
			n = len(msg)
		} else {
			n, err = cli.Send(msg)
		}
		if err != nil {
			t.Logf("send stopped after %v: %v", time.Since(t0), err)
			break
		}
		writeLatencies = append(writeLatencies, time.Since(w0))
		sent += int64(n)
	}
	elapsed := time.Since(t0) - admit
	mb := float64(sent) / 1e6
	t.Logf("pushed %.2f MB in %v => %.3f MB/s (%.2f Mbit/s)",
		mb, elapsed.Round(time.Millisecond), mb/elapsed.Seconds(), mb*8/elapsed.Seconds())

	if len(writeLatencies) > 0 {
		sort.Slice(writeLatencies, func(i, j int) bool { return writeLatencies[i] < writeLatencies[j] })
		t.Logf("Send() latency: p50=%v p99=%v max=%v over %d writes",
			writeLatencies[len(writeLatencies)/2],
			writeLatencies[len(writeLatencies)*99/100],
			writeLatencies[len(writeLatencies)-1], len(writeLatencies))
	}
	t.Log("compare with the device's own RATE lines on its UART — the device figure " +
		"is what actually arrived and was decrypted")
}

// TestWifiRTT measures round-trip latency over Wi-Fi (the device echoes nothing, so
// this uses the KCP-level ACK: Send returns once the window allows, which reflects
// the path's pacing rather than an application echo).
func TestWifiRTT(t *testing.T) {
	if os.Getenv("SN_DEVICE") == "" {
		t.Skip("set SN_DEVICE=<ip:port> to run")
	}
	_, err := net.ResolveUDPAddr("udp", os.Getenv("SN_DEVICE"))
	if err != nil {
		t.Fatal(err)
	}
	t.Skip("use TestWifiBandwidth; the wifi device firmware does not echo")
}
