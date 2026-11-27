// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Verifies the board-config -> KCP tuning path: the host reads SHIELDNET_*
// from its environment (the host board's config source) and applies it via
// sn_device_set_tuning. Asserts the effective window reflects the override, and
// that a session with a matched non-default tuning still admits and exchanges data.
func TestBoardConfigTuning(t *testing.T) {
	bin := buildCHost(t)
	home, _ := os.UserHomeDir()
	cmd := exec.Command(bin, "0", "0908070605040302") // PSK via SHIELDNET_PSK, never argv
	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+home+"/.local/lib",
		"SHIELDNET_PSK="+strings.Repeat("33", 32),
		"SHIELDNET_RCV_WND=64",
		"SHIELDNET_SND_WND=128",
		"SHIELDNET_KCP_INTERVAL=10",
		"SHIELDNET_TICK_MS=5",
	)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	// the host prints its effective tuning to stderr
	errsc := bufio.NewScanner(stderr)
	tuningLine := ""
	for errsc.Scan() {
		if strings.HasPrefix(errsc.Text(), "tuning:") {
			tuningLine = errsc.Text()
			break
		}
	}
	if !strings.Contains(tuningLine, "rcv_wnd=64") ||
		!strings.Contains(tuningLine, "snd_wnd=128") ||
		!strings.Contains(tuningLine, "interval=10") ||
		!strings.Contains(tuningLine, "tick=5") {
		t.Fatalf("board config did not reach the device tuning: %q", tuningLine)
	}

	sc := bufio.NewScanner(stdout)
	port := ""
	if sc.Scan() {
		port = strings.TrimPrefix(sc.Text(), "PORT ")
	}
	if port == "" {
		t.Fatal("no port")
	}
	time.Sleep(100 * time.Millisecond)

	cli, err := NewClient("127.0.0.1:"+port, bytes.Repeat([]byte{0x33}, 32), []byte{9, 8, 7, 6, 5, 4, 3, 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	cli.Tuning = KCPTuning{SndWnd: 128, RcvWnd: 64, NoDelay: 1, Interval: 10, Resend: 2, NC: 1}
	defer cli.Close()

	if err := cli.TakeControl([]byte("frame-0")); err != nil {
		t.Fatalf("TakeControl with tuned window: %v", err)
	}
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	ck.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := cli.Recv(buf)
	if err != nil {
		t.Fatalf("recv echo: %v", err)
	}
	if string(buf[:n]) != "frame-0" {
		t.Errorf("echo: got %q", buf[:n])
	}
}
