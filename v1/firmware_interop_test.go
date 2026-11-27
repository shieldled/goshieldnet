// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"
)

// The full-stack proof: the Go controller drives a REAL command (PING) against the
// ShieldLED firmware, built for the host (its network layer and command
// dispatch). Set SLED_HOST_BIN to that binary to run it.
func TestFirmwarePingInterop(t *testing.T) {
	bin := os.Getenv("SLED_HOST_BIN")
	if bin == "" {
		t.Skip("set SLED_HOST_BIN to the firmware's host binary to run")
	}
	home, _ := os.UserHomeDir()
	const port = "39100"
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+home+"/.local/lib",
		"SLED_KEY="+bytesHex(bytes.Repeat([]byte{0x33}, 32)),
		"SLED_HOST_MAC=02:00:00:00:00:01",
		"SLED_PORT="+port,
		"SLED_NUM_STRIPS=1", "SLED_LEDS_PER_STRIP=8",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(600 * time.Millisecond) // firmware init (render/socket)

	deviceID := []byte{0x02, 0, 0, 0, 0, 0x01, 0, 0} // MAC || 0,0
	cli, err := NewClient("127.0.0.1:"+port, bytes.Repeat([]byte{0x33}, 32), deviceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()

	const cmdPing = CmdPing
	const respAck = 0x80
	if err := cli.TakeControlApp(cmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp(PING) against firmware: %v", err)
	}
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	ck.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, body, err := cli.RecvApp()
	if err != nil {
		t.Fatalf("RecvApp: %v", err)
	}
	if typ != respAck {
		t.Errorf("response kind: got %#x want RESP_ACK %#x", typ, respAck)
	}
	if len(body) < 1 || body[0] != cmdPing {
		t.Errorf("ACK body should echo orig kind PING; got % x", body)
	}
	t.Logf("firmware answered PING with RESP_ACK, %d-byte body", len(body))
}

func bytesHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[2*i] = hexd[x>>4]
		out[2*i+1] = hexd[x&0xf]
	}
	return string(out)
}
