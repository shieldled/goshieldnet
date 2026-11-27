// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cross-language interop: a real C host device (over raw ikcp) driven by the
// real Go controller. Proves the two implementations speak on the wire, not just
// that each matches the spec. The C host echoes application messages back.
//
// Set SN_HOST_BIN to a prebuilt sn_host to skip the in-test build.
func buildCHost(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("SN_HOST_BIN"); b != "" {
		return b
	}
	if libShieldnetDir() == "" {
		requireOrSkip(t, "no C host: set SN_HOST_BIN to a prebuilt sn_host, or SHIELDNET_LIB_DIR to a libshieldnet tree, to run C<->Go interop")
	}
	hostDir, err := filepath.Abs(filepath.Join(libShieldnetDir(), "host"))
	if err != nil || !dirExists(hostDir) {
		requireOrSkip(t, "C host source not found; set SN_HOST_BIN to run C<->Go interop")
	}
	buildDir := t.TempDir()
	home, _ := os.UserHomeDir()
	env := append(os.Environ(), "PKG_CONFIG_PATH="+home+"/.local/lib/pkgconfig")
	for _, args := range [][]string{
		{"cmake", "-S", hostDir, "-B", buildDir},
		{"cmake", "--build", buildDir},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			requireOrSkip(t, "cannot build C host ("+err.Error()+"): "+string(out))
		}
	}
	return filepath.Join(buildDir, "sn_host")
}

func dirExists(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

// libShieldnetDir is the libshieldnet source tree (a checkout of
// https://github.com/shieldled/libshieldnet)
// that the interop tests build sn_host/sn_client_host from and the fuzz tests
// look for binaries under. It comes from SHIELDNET_LIB_DIR, as an absolute path
// (go test runs in the package directory, so a relative one resolves from v1/);
// "" means unset. CI sets SN_HOST_BIN/SN_CLIENT_HOST_BIN instead and never
// reaches this.
func libShieldnetDir() string { return os.Getenv("SHIELDNET_LIB_DIR") }

func TestLibShieldnetDir(t *testing.T) {
	t.Setenv("SHIELDNET_LIB_DIR", "")
	if got := libShieldnetDir(); got != "" {
		t.Errorf("unset: got %q, want empty", got)
	}
	t.Setenv("SHIELDNET_LIB_DIR", "/x/libshieldnet")
	if got := libShieldnetDir(); got != "/x/libshieldnet" {
		t.Errorf("set: got %q, want /x/libshieldnet", got)
	}
}

func TestCDeviceGoClientInterop(t *testing.T) {
	bin := buildCHost(t)
	psk := strings.Repeat("33", 32)   // matches bytes.Repeat(0x33, 32)
	deviceIDHex := "0908070605040302" // device_id {9,8,7,6,5,4,3,2}

	home, _ := os.UserHomeDir()
	// sn_host takes the PSK from the environment, never argv (it refuses a
	// command-line PSK so ps cannot show it): sn_host <port> <device-id-hex>.
	cmd := exec.Command(bin, "0", deviceIDHex)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+home+"/.local/lib", "SHIELDNET_PSK="+psk)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	// read the bound port
	sc := bufio.NewScanner(stdout)
	port := ""
	if sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PORT ") {
			port = strings.TrimPrefix(line, "PORT ")
		}
	}
	if port == "" {
		t.Fatal("host did not report a port")
	}
	time.Sleep(100 * time.Millisecond) // let the tick + recv loop come up

	pskBytes := bytes.Repeat([]byte{0x33}, 32)
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	cli, err := NewClient("127.0.0.1:"+port, pskBytes, deviceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli.skipSrcCheck = true
	defer cli.Close()

	if err := cli.TakeControl([]byte("hello-c-device")); err != nil {
		t.Fatalf("TakeControl against C device: %v", err)
	}

	// the C device echoes the first message back
	cli.mu.Lock()
	ckcp := cli.kcp
	cli.mu.Unlock()
	buf := make([]byte, 128)
	ckcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := cli.Recv(buf)
	if err != nil {
		t.Fatalf("recv echo: %v", err)
	}
	if string(buf[:n]) != "hello-c-device" {
		t.Errorf("echo: got %q want hello-c-device", buf[:n])
	}

	// a second round-trip over the established session
	if _, err := cli.Send([]byte("second-msg")); err != nil {
		t.Fatal(err)
	}
	ckcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = cli.Recv(buf)
	if err != nil {
		t.Fatalf("recv echo 2: %v", err)
	}
	if string(buf[:n]) != "second-msg" {
		t.Errorf("echo2: got %q", buf[:n])
	}
}
