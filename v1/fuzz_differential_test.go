// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Differential fuzzing against the C implementation.
//
// The cross-language golden vectors only cover inputs both ends already agree
// are valid. What they cannot cover is divergence on *invalid* input, which is
// the case that matters: a datagram the device drops and the controller accepts
// (or the reverse) means the two no longer share a view of the protocol, and
// §5 step 0 is where an attacker's bytes first land.
//
// The C half is libshieldnet's fuzz/sn_oracle.c, held open as a pipe rather than
// exec'd per input — this fuzzer runs fast enough that a fork per input would
// be the whole cost.
//
//	SHIELDNET_ORACLE=/path/to/sn_oracle go test -run '^$' -fuzz FuzzDifferentialClassify

type oracle struct {
	mu  sync.Mutex
	bin string
	in  io.WriteCloser
	out io.Reader
	cmd *exec.Cmd
}

func startOracle(t testing.TB) *oracle {
	t.Helper()
	bin := os.Getenv("SHIELDNET_ORACLE")
	if bin == "" {
		// Default to the build tree the fuzz CMakeLists produces.
		cands := []string{"/tmp/oracle_build/sn_oracle"}
		if d := libShieldnetDir(); d != "" {
			cands = append(cands, filepath.Join(d, "fuzz", "build", "sn_oracle"))
		}
		for _, c := range cands {
			if _, err := os.Stat(c); err == nil {
				bin = c
				break
			}
		}
	}
	if bin == "" {
		// A permanently-skipping test reports green while running nothing. Make
		// the reason visible, and let a job that means to run it say so: with
		// SHIELDNET_REQUIRE_ORACLE set, an absent oracle is a failure.
		msg := "no sn_oracle binary found — build it from libshieldnet's " +
			"fuzz/ and set SHIELDNET_ORACLE (or SHIELDNET_LIB_DIR), or run the C-side " +
			"coverage in that repository's own workflow"
		if os.Getenv("SHIELDNET_REQUIRE_ORACLE") != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	o := &oracle{bin: bin}
	if err := o.spawn(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.stop)
	return o
}

func (o *oracle) spawn() error {
	cmd := exec.Command(o.bin)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr // a sanitizer report lands here
	if err := cmd.Start(); err != nil {
		return err
	}
	o.in, o.out, o.cmd = in, out, cmd

	// Version handshake. Without it a stale oracle speaking an older framing
	// leaves every read blocked forever: `go test` then hangs instead of
	// failing, which is how a 100s "test run" happened rather than an error.
	// Bounded: an older oracle writes nothing until it is sent a request, so an
	// unbounded read here blocks forever and `go test` hangs instead of failing.
	var banner [4]byte
	type res struct{ err error }
	ch := make(chan res, 1)
	go func() { _, err := io.ReadFull(o.out, banner[:]); ch <- res{err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("oracle %s produced no banner (%v) — rebuild it from "+
				"libshieldnet's fuzz/", o.bin, r.err)
		}
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		return fmt.Errorf("oracle %s sent no banner within 3s — it is probably a stale "+
			"build speaking an older framing; rebuild it from libshieldnet's fuzz/", o.bin)
	}
	if string(banner[:3]) != "SNO" || banner[3] != oracleProtocol {
		return fmt.Errorf("oracle %s speaks protocol %v, this harness speaks %d — "+
			"rebuild it from libshieldnet's fuzz/", o.bin, banner, oracleProtocol)
	}
	return nil
}

// oracleProtocol must match the banner in libshieldnet's fuzz/sn_oracle.c.
const oracleProtocol = 3

func (o *oracle) stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cmd == nil {
		return
	}
	o.in.Close()
	o.cmd.Process.Kill()
	o.cmd.Wait()
	o.cmd = nil
}

type verdict struct {
	raw            [16]byte
	classDevice    byte
	classClient    byte
	classDeviceSrc byte
	reconstruct    int64
}

// ask sends one request. A dead oracle is retried once on a fresh process: the
// fuzzing engine runs many worker processes and tears them down, so a broken
// pipe on its own does not mean the C crashed on this input — an earlier
// lifecycle event looks identical, and blaming the current input produces a
// "crasher" that does not reproduce. Only a death that survives a restart with
// the same input is reported.
func (o *oracle) ask(b []byte) (verdict, error) { return o.retry(0, b) }

// askParsers runs the post-authentication command parsers (mode 1). They have no
// Go counterpart, so there is nothing to compare — the verdict bytes are
// returned only so a caller can see the parse outcomes; what is being tested is
// that the sanitized oracle survives.
func (o *oracle) askParsers(b []byte) (verdict, error) { return o.retry(1, b) }

// askClient runs the client receive path (mode 2): the C client's
// §3.5/§7.3/§7.4 checks, which Go mirrors exactly, so these verdicts ARE
// comparable — unlike mode 1's.
func (o *oracle) askClient(b []byte) (verdict, error) { return o.retry(2, b) }

func (o *oracle) retry(mode byte, b []byte) (verdict, error) {
	if v, err := o.ask1(mode, b); err == nil {
		return v, nil
	}
	o.stop()
	if err := o.spawn(); err != nil {
		return verdict{}, err
	}
	return o.ask1(mode, b)
}

func (o *oracle) ask1(mode byte, b []byte) (verdict, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cmd == nil {
		return verdict{}, io.ErrClosedPipe
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(b)))
	hdr[4] = mode
	if _, err := o.in.Write(hdr[:]); err != nil {
		return verdict{}, err
	}
	if len(b) > 0 {
		if _, err := o.in.Write(b); err != nil {
			return verdict{}, err
		}
	}
	var resp [16]byte
	if _, err := io.ReadFull(o.out, resp[:]); err != nil {
		return verdict{}, err
	}
	return verdict{
		raw:            resp,
		classDevice:    resp[0],
		classClient:    resp[1],
		classDeviceSrc: resp[2],
		reconstruct:    int64(binary.BigEndian.Uint64(resp[3:])),
	}, nil
}

func FuzzDifferentialClassify(f *testing.F) {
	o := startOracle(f)
	for _, s := range validSeeds() {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 256))
	f.Add(make([]byte, 84))

	// Must mirror the oracle's prefix exactly, including that the prefix carries
	// the *interface* address rather than the masked network address — that is
	// how the firmware derives it (esp_netif_get_ip_info), and SourceRejected
	// compares p.Addr() directly as "own address". Writing 192.168.4.0/24 here
	// against the oracle's 192.168.4.1 made the two disagree on 192.168.4.0 for
	// harness reasons alone.
	local := []netip.Prefix{netip.MustParsePrefix("192.168.4.1/24")}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65000 {
			return // the oracle's buffer bound, not a protocol limit
		}
		got, err := o.ask(b)
		if err != nil {
			// The oracle is built with ASan/UBSan and -fno-sanitize-recover, so a
			// memory-safety or UB finding kills it mid-request and surfaces here
			// as a broken pipe. The sanitizer's report is on the oracle's stderr,
			// which is wired to this test's.
			t.Fatalf("oracle died twice on the same %d-byte input (%v) — reproducible, so "+
				"this is a C-side crash rather than a worker teardown; the ASan/UBSan "+
				"report is on stderr above", len(b), err)
		}

		if want, have := byte(classifyDatagram(RoleDevice, b)), got.classDevice; want != have {
			t.Fatalf("classifyDatagram(device) len=%d: Go=%d C=%d", len(b), want, have)
		}
		if want, have := byte(classifyDatagram(RoleClient, b)), got.classClient; want != have {
			t.Fatalf("classifyDatagram(client) len=%d: Go=%d C=%d", len(b), want, have)
		}

		src := netip.MustParseAddr("192.168.4.2")
		if len(b) > 0 {
			src = netip.AddrFrom4([4]byte{192, 168, 4, b[0]})
		}
		if want, have := byte(Classify(RoleDevice, src, local, b)), got.classDeviceSrc; want != have {
			t.Fatalf("Classify(device, %v) len=%d: Go=%d C=%d", src, len(b), want, have)
		}

		// sn_reconstruct drives the replay window; the two must agree bit for bit.
		if len(b) >= 12 {
			seqWire := binary.BigEndian.Uint32(b[0:4])
			hwm := binary.BigEndian.Uint64(b[4:12])
			if want := Reconstruct(seqWire, hwm); want != got.reconstruct {
				t.Fatalf("reconstruct(seq=%d hwm=%d): Go=%d C=%d",
					seqWire, hwm, want, got.reconstruct)
			}
		}
	})
}

// FuzzCommandParsers exercises the post-authentication parsers in
// command_parse.h. They sit behind AEAD, so a fuzzer working from the network
// side can never reach them — random bytes cannot forge a MAC — and they were
// therefore untested by any fuzzing at all. Calling them directly is the only
// way to cover them.
//
// There is no Go counterpart to compare against, so this is crash and UB
// fuzzing: the value comes entirely from the oracle being built with ASan and
// UBSan.
func FuzzCommandParsers(f *testing.F) {
	o := startOracle(f)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 300))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65000 {
			return
		}
		if _, err := o.askParsers(b); err != nil {
			t.Fatalf("oracle died twice on the same %d-byte command payload (%v) — "+
				"reproducible, so a parser crashed; the ASan/UBSan report is on stderr above",
				len(b), err)
		}
	})
}
