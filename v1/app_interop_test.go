// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Full stack: the Go controller's post-admission app-message layer (framing +
// XChaCha under the transport's k_c2s/k_s2c) round-trips against the C device running the
// REAL protocol_read_message + crypto_decrypt/encrypt over the transport (app-echo mode).
// Proves the kept app layer works over the transport end to end.
func TestAppLayerOverInterop(t *testing.T) {
	bin := buildCHost(t)
	home, _ := os.UserHomeDir()
	cmd := exec.Command(bin, "0", "0908070605040302") // PSK via SHIELDNET_PSK, never argv
	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+home+"/.local/lib",
		"SHIELDNET_PSK="+strings.Repeat("33", 32),
		"SHIELDNET_APP_ECHO=1",
	)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
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
	defer cli.Close()

	// first app message rides the promoting PUSH (§8.5(c))
	const msgType = 0x42
	if err := cli.TakeControlApp(msgType, []byte("app-command-one")); err != nil {
		t.Fatalf("TakeControlApp: %v", err)
	}
	// the device decrypts, dispatches (echo), and returns a framed response
	cli.mu.Lock()
	ck := cli.kcp
	cli.mu.Unlock()
	ck.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, pt, err := cli.RecvApp()
	if err != nil {
		t.Fatalf("RecvApp: %v", err)
	}
	if typ != msgType || string(pt) != "app-command-one" {
		t.Errorf("echo 1: type=%#x payload=%q", typ, pt)
	}

	// two more app round-trips over the established session
	for i, msg := range []string{"second", "third-and-longer-payload"} {
		if err := cli.SendApp(msgType, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		ck.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, pt, err := cli.RecvApp()
		if err != nil {
			t.Fatalf("RecvApp %d: %v", i, err)
		}
		if string(pt) != msg {
			t.Errorf("echo %d: got %q want %q", i, pt, msg)
		}
	}

	// A COMPRESSED bulk payload, decompressed by the real C device
	// (sn_agent_dispatch.c honours FlagCompressed against OriginalSize). This is
	// the only test that proves transport §13's bulk-content carve-out actually
	// works across the two implementations rather than only in Go.
	bulk := artifactLike(4096)
	if err := cli.SendAppCompressed(msgType, bulk); err != nil {
		t.Fatal(err)
	}
	ck.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, pt, err = cli.RecvApp()
	if err != nil {
		t.Fatalf("RecvApp compressed: %v", err)
	}
	if !bytes.Equal(pt, bulk) {
		t.Errorf("compressed echo: %d bytes back, want %d", len(pt), len(bulk))
	}

	// A PADDED control message, stripped by the real C device against
	// OriginalSize. Proves transport §13's size-class ladder is agreed across the
	// two implementations — an 8-octet parameter write goes out as 64 octets and
	// must come back as 8, not 64.
	ctrl := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := cli.SendAppPadded(msgType, ctrl); err != nil {
		t.Fatal(err)
	}
	ck.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, pt, err = cli.RecvApp()
	if err != nil {
		t.Fatalf("RecvApp padded: %v", err)
	}
	if !bytes.Equal(pt, ctrl) {
		t.Errorf("padded echo: got %v (%d bytes), want %v", pt, len(pt), ctrl)
	}

	// A message spanning MANY KCP segments, incompressible so it cannot shrink
	// into one. Message-layer §1.1 requires KCP stream mode on both peers
	// precisely because "a message of this layer is length-prefixed and may span
	// many MTU-sized KCP receive items". Every other case here fits one segment,
	// where message mode and stream mode are indistinguishable.
	big := make([]byte, 1800) // >1 MSS (~1356) but within the C host's 2048 buffer
	if _, err := crand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := cli.SendApp(msgType, big); err != nil {
		t.Fatal(err)
	}
	ck.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, pt, err = cli.RecvApp()
	if err != nil {
		t.Fatalf("RecvApp multi-segment: %v", err)
	}
	if !bytes.Equal(pt, big) {
		t.Errorf("multi-segment echo: got %d bytes, want %d", len(pt), len(big))
	}

	// A frame the C device MUST reject rather than hang on: uncompressed, with
	// OriginalSize far larger than the body it carries.
	//
	// sn_agent_dispatch.c walks the §13 pad-class ladder as
	// `while (cls < hdr.original_size) cls <<= 1`, and original_size was bounded
	// only on the COMPRESSED branch. With a 32-bit size_t — every ESP32 target —
	// cls reaches 0x80000000, shifts to 0, and the loop never terminates: a
	// watchdog reset driven by one authenticated frame.
	//
	// BE CLEAR ABOUT WHAT THIS TEST PINS. It does NOT reproduce that hang, and
	// cannot: the host build has a 64-bit size_t, where the same ladder simply
	// terminates at 0x100000000. Reverting the bound in sn_agent_dispatch.c
	// leaves this test passing — verified, not assumed. What it does pin is the
	// agreed §7 behaviour on both sides: a header/body length disagreement is a
	// REJECTED frame, so the device drops it and the session survives. The bound
	// is what makes that true on a 32-bit target as well, and only a 32-bit build
	// (or a target-emulating one) could assert the termination directly.
	//
	// This runs last on purpose: if the device does hang, the read below fails
	// rather than every earlier assertion.
	num := cli.txNum.Add(1)
	cli.mu.Lock()
	kc2s := append([]byte(nil), cli.kC2S...)
	cli.mu.Unlock()
	aead, err := chacha20poly1305.NewX(kc2s)
	if err != nil {
		t.Fatal(err)
	}
	shortBody := []byte("short")
	badHdr := appHeader(uint32(len(shortBody)+aead.Overhead()), 0xFFFFFFFF, msgType, num)
	if _, err := ck.Write(append(badHdr, aead.Seal(nil, appNonce(num), shortBody, badHdr)...)); err != nil {
		t.Fatal(err)
	}

	// The device must drop that frame and keep the session: §7 calls a
	// header/body length disagreement a rejected frame, not a desync.
	if err := cli.SendApp(msgType, []byte("after-the-bad-frame")); err != nil {
		t.Fatal(err)
	}
	ck.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, pt, err = cli.RecvApp()
	if err != nil {
		t.Fatalf("device did not survive an oversized OriginalSize (hung, or dropped the session): %v", err)
	}
	if string(pt) != "after-the-bad-frame" {
		t.Errorf("after the bad frame: got %q", pt)
	}
}
