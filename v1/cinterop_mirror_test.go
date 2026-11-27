// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Mirror-direction interop: the real C client (libshieldnet's sn_client_host)
// against the real Go device. cinterop_test.go proves the C device and the Go
// controller agree; this proves the other pairing, C client and Go device.
//
// It runs where the C sources are already checked out and already building,
// in the CI of the C implementation. This repository's own CI does not check
// them out, so here it skips — unless SHIELDNET_REQUIRE_INTEROP is set, which
// is what that job does, mirroring SHIELDNET_REQUIRE_ORACLE for the fuzz
// oracles. A skip there is a red build.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// §4.3 rejects loopback, so the device must listen on a real address. Returns
// the first non-loopback IPv4 the host has.
func nonLoopbackV4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interfaces: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil {
					ad, _ := netip.AddrFromSlice(v4)
					return ad
				}
			}
		}
	}
	requireOrSkip(t, "no non-loopback IPv4 address; §4.3 refuses loopback so the "+
		"C client cannot be admitted over it")
	return netip.Addr{}
}

func requireOrSkip(t *testing.T, msg string) {
	t.Helper()
	if os.Getenv("SHIELDNET_REQUIRE_INTEROP") != "" {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

// Builds libshieldnet's sn_client_host, or skips when the C tree is absent, as
// in this repository's CI.
func buildCClientHost(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("SN_CLIENT_HOST_BIN"); b != "" {
		return b
	}
	if libShieldnetDir() == "" {
		requireOrSkip(t, "no C client: set SN_CLIENT_HOST_BIN to a prebuilt sn_client_host, "+
			"or SHIELDNET_LIB_DIR to a libshieldnet tree")
	}
	hostDir, err := filepath.Abs(filepath.Join(libShieldnetDir(), "host"))
	if err != nil || !dirExists(hostDir) {
		requireOrSkip(t, "C client source not found; set SN_CLIENT_HOST_BIN or run "+
			"this from a CI job that checks out libshieldnet")
	}
	buildDir := t.TempDir()
	home, _ := os.UserHomeDir()
	env := append(os.Environ(), "PKG_CONFIG_PATH="+home+"/.local/lib/pkgconfig")
	for _, args := range [][]string{
		{"cmake", "-S", hostDir, "-B", buildDir},
		{"cmake", "--build", buildDir, "--target", "sn_client_host", "-j", "4"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			requireOrSkip(t, "cannot build the C client ("+err.Error()+"): "+string(out))
		}
	}
	return filepath.Join(buildDir, "sn_client_host")
}

func TestGoDeviceCClientInterop(t *testing.T) {
	// Before the base case: a t.Skip there would skip this subtest with it, and
	// the gate is meant to fail, not skip, when SN_CLIENT_HOST_BIN is missing.
	// libshieldnet's sn_client_send_app_compressed, against the independent Go
	// receiver: the flag must be in the AAD the C side sealed, or the Go side
	// cannot open the frame at all. Gated because older builds of sn_client_host
	// have no SHIELDNET_COMPRESS switch, and neither does the copy a plain `go test ./...`
	// builds (buildCClientHost).
	t.Run("compressed", func(t *testing.T) {
		if os.Getenv("SHIELDNET_INTEROP_COMPRESS") != "1" {
			t.Skip("set SHIELDNET_INTEROP_COMPRESS=1 (and SN_CLIENT_HOST_BIN to a libshieldnet " +
				"sn_client_host) to run")
		}
		if os.Getenv("SN_CLIENT_HOST_BIN") == "" {
			t.Fatal("SHIELDNET_INTEROP_COMPRESS=1 needs SN_CLIENT_HOST_BIN: the host built " +
				"from an older libshieldnet tree has no SHIELDNET_COMPRESS switch")
		}
		msg := strings.Repeat("A", 2048)
		goDeviceCClientInterop(t, []string{"SHIELDNET_COMPRESS=1"}, msg, func(srv *Server) {
			// The C client opens with a PING (0x07) and then sends msg compressed.
			// Read both frames through recvAppWith, which strips the flag, behind
			// a reader that keeps each frame's 20-byte header: MessageType is
			// bytes 8..12, and Server's public API does not expose the flag.
			srv.dev.rec.Lock()
			p := srv.primary
			var key []byte
			if p != nil {
				key = append([]byte(nil), p.kC2S...)
			}
			srv.dev.rec.Unlock()
			if p == nil {
				t.Fatal("no primary")
			}
			_ = p.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			p.app.rxMu.Lock()
			defer p.app.rxMu.Unlock()
			var gotType uint32
			var got []byte
			var rawType uint32
			for i := 0; i < 2; i++ {
				rr := &headRecorder{r: p.conn}
				typ, _, body, err := recvAppWith(rr, key, &p.app.rxNum, &p.app.rxStage, srv.maxMsgPayload(), 0, srv.maxMsgPayload())
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if i == 0 {
					if typ != 0x07 {
						t.Fatalf("first frame type = %#x, want the PING (0x07)", typ)
					}
					continue
				}
				gotType, got, rawType = typ, body, binary.BigEndian.Uint32(rr.head[8:12])
			}
			if gotType != 0x00 {
				t.Errorf("message kind = %#x, want 0x00", gotType)
			}
			if !bytes.Equal(got, []byte(msg)) {
				t.Errorf("Go device received %d bytes, not the original %d", len(got), len(msg))
			}
			if rawType&FlagCompressed == 0 {
				t.Errorf("received MessageType %#x does not have FlagCompressed set", rawType)
			}
		})
	})

	goDeviceCClientInterop(t, nil, "", nil)
}

// headRecorder keeps the first 20 bytes read through it: one frame's header.
type headRecorder struct {
	r    io.Reader
	head [appHeaderSize]byte
	n    int
}

func (h *headRecorder) Read(b []byte) (int, error) {
	n, err := h.r.Read(b)
	if h.n < len(h.head) {
		h.n += copy(h.head[h.n:], b[:n])
	}
	return n, err
}

// goDeviceCClientInterop admits the C client to a Go device and, if afterAdmit
// is set, hands it the server before telling the client it may stop. msg, if
// not empty, is the client's message argument; extraEnv is added to its
// environment.
func goDeviceCClientInterop(t *testing.T, extraEnv []string, msg string, afterAdmit func(*Server)) {
	bin := buildCClientHost(t)
	addr := nonLoopbackV4(t)

	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0x33
	}
	deviceID := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	cookieSecret := make([]byte, 32)
	if _, err := rand.Read(cookieSecret); err != nil {
		t.Fatal(err)
	}
	admissionEpoch := []byte{0, 0, 0, 0, 0, 0, 0, 1} // §4.2: nonzero, top 8 bits clear

	conn, err := net.ListenPacket("udp4", net.JoinHostPort(addr.String(), "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	defer conn.Close()

	// The device's own prefixes, so §4.3 can reject a source that is one of
	// them. The C client is on this same host, so leave it empty: what must be
	// rejected here is loopback, which the predicate refuses regardless.
	dev := mustDev(NewDevice(psk, deviceID, cookieSecret, admissionEpoch, nil,
		uint64(time.Now().UnixMilli())))
	srv := NewServer(dev, conn)
	go srv.Serve()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	// sn_client_host <host> <port> <device-id-hex>: the PSK goes in the
	// environment, never argv (the C host refuses a command-line PSK). conv is
	// drawn fresh per commit (§8.4); this test admits once and asserts nothing
	// about conv, so it leaves SHIELDNET_CONV unset.
	args := []string{addr.String(), port, hex.EncodeToString(deviceID)}
	if msg != "" {
		args = append(args, msg)
	}
	cmd := exec.Command(bin, args...)
	home, _ := os.UserHomeDir()
	cmd.Env = append(append(os.Environ(),
		"LD_LIBRARY_PATH="+home+"/.local/lib",
		"SHIELDNET_PSK="+hex.EncodeToString(psk)), extraEnv...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	// The C client prints ADMITTED once §7 completes and the promoting PUSH is
	// acknowledged. That is the whole assertion: the two implementations agreed
	// on INIT, RETRY, FINISH, ADMIT, the key schedule and the first envelope.
	admitted := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "ADMITTED") {
				admitted <- true
				return
			}
		}
		admitted <- false
	}()

	select {
	case ok := <-admitted:
		if !ok {
			t.Fatal("C client exited without admitting to the Go device")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the C client to admit")
	}

	if srv.Primary() == nil {
		t.Fatal("Go device reports no primary after the C client admitted")
	}
	if afterAdmit != nil {
		afterAdmit(srv)
	}
	_ = stdin.Close() // tells the C client it may stop
}
