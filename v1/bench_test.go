// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// spawnCHost starts the C sn_host and returns (client, kill). The client is
// admitted (ESTABLISHED). Used by the benchmarks below.
func spawnCHostClient(t *testing.T, firstMsg []byte) (*Client, func(), time.Duration) {
	bin := buildCHost(t)
	home, _ := os.UserHomeDir()
	cmd := exec.Command(bin, "0", "0908070605040302") // PSK via SHIELDNET_PSK, never argv
	// Data-plane window. SN_KCP_TUNING_DEFAULT's rcv_wnd of 8 is the RFC §11
	// control-plane figure and cannot sustain a throughput run: a sender may hold
	// at most rcv_wnd segments per round trip. These benchmarks previously passed
	// only because a configure_kcp ordering bug clamped every session up to
	// ikcp's 128 regardless of configuration; with that fixed the window is
	// honoured, so a data-plane run has to ask for one.
	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+home+"/.local/lib",
		"SHIELDNET_PSK="+strings.Repeat("33", 32),
		"SHIELDNET_RCV_WND=64",
		"SHIELDNET_SND_WND=64",
		"SHIELDNET_KCP_INTERVAL=10")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	kill := func() { cmd.Process.Kill(); cmd.Wait() }
	sc := bufio.NewScanner(stdout)
	port := ""
	if sc.Scan() {
		port = strings.TrimPrefix(sc.Text(), "PORT ")
	}
	if port == "" {
		kill()
		t.Fatal("no port")
	}
	time.Sleep(100 * time.Millisecond)
	cli, err := NewClient("127.0.0.1:"+port, bytes.Repeat([]byte{0x33}, 32), []byte{9, 8, 7, 6, 5, 4, 3, 2}, nil)
	if err != nil {
		kill()
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	t0 := time.Now()
	if err := cli.TakeControl(firstMsg); err != nil {
		cli.Close()
		kill()
		t.Fatalf("TakeControl: %v", err)
	}
	admit := time.Since(t0)
	return cli, func() { cli.Close(); kill() }, admit
}

func TestBenchAdmission(t *testing.T) {
	const runs = 20
	var ds []time.Duration
	for i := 0; i < runs; i++ {
		_, stop, d := spawnCHostClient(t, []byte("x"))
		ds = append(ds, d)
		stop()
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	t.Logf("admission latency over %d runs: min=%v p50=%v max=%v", runs, ds[0], ds[runs/2], ds[runs-1])
}

func TestBenchRTT(t *testing.T) {
	cli, stop, admit := spawnCHostClient(t, []byte("start"))
	defer stop()
	t.Logf("admission: %v", admit)
	// drain the echo of the first message
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	buf := make([]byte, 2048)
	ck.SetReadDeadline(time.Now().Add(2 * time.Second))
	cli.Recv(buf)

	const n = 100
	msg := bytes.Repeat([]byte{0xAA}, 64)
	var rtts []time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := cli.Send(msg); err != nil {
			t.Fatal(err)
		}
		ck.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := cli.Recv(buf); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		rtts = append(rtts, time.Since(t0))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	t.Logf("echo RTT over %d msgs: min=%v p50=%v p99=%v max=%v",
		n, rtts[0], rtts[n/2], rtts[n*99/100], rtts[n-1])
}

func TestBenchThroughput(t *testing.T) {
	cli, stop, _ := spawnCHostClient(t, []byte("start"))
	defer stop()
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	buf := make([]byte, 4096)
	ck.SetReadDeadline(time.Now().Add(2 * time.Second))
	cli.Recv(buf) // drain first echo

	const (
		count   = 3000
		msgSize = 1000
	)
	msg := bytes.Repeat([]byte{0x5A}, msgSize)
	var wg sync.WaitGroup
	wg.Add(1)
	var recvErr error
	t0 := time.Now()
	go func() {
		defer wg.Done()
		got := 0
		for got < count*msgSize {
			ck.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := cli.Recv(buf)
			if err != nil {
				recvErr = err
				return
			}
			got += n
		}
	}()
	for i := 0; i < count; i++ {
		if _, err := cli.Send(msg); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	elapsed := time.Since(t0)
	if recvErr != nil {
		t.Fatalf("recv: %v", recvErr)
	}
	total := float64(count * msgSize)
	fmt.Printf("throughput: %d msgs x %dB echoed in %v => %.2f msg/s, %.2f MB/s (round-trip)\n",
		count, msgSize, elapsed, float64(count)/elapsed.Seconds(), total/elapsed.Seconds()/1e6)
	t.Logf("throughput: %.0f msg/s, %.2f MB/s round-trip", float64(count)/elapsed.Seconds(), total/elapsed.Seconds()/1e6)
}
