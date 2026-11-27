// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Sequence fuzzing for the C device's admission and promotion state machine.
//
// Single-datagram fuzzing cannot reach this. Both of the worst defects found on
// hardware this cycle were sequence bugs -- a retiring session consuming the
// incoming session's stream, and a promotion over a live primary leaving a freed
// kcp pointer -- and neither is expressible as one malformed packet.
//
// The input is a program of protocol operations, not a datagram: random bytes
// cannot produce a valid FINISH (it carries a device-issued cookie and a
// PSK-keyed MAC), so a fuzzer working at the wire level never gets past
// admission and never reaches the state worth testing. libshieldnet's
// fuzz/sn_state_fuzz supplies the cryptographically valid steps; the fuzzer chooses
// the order, the sources, the timing and the payloads, and the harness checks
// its invariants after every step.
//
// One process per program, unlike the oracle: each program runs real X25519 and
// must start from a clean device, and state leaking between programs would both
// mask bugs and invent them.
//
//	SHIELDNET_STATE_FUZZ=/path/to/sn_state_fuzz go test -run '^$' -fuzz FuzzDeviceStateMachine
func FuzzDeviceStateMachine(f *testing.F) {
	bin := os.Getenv("SHIELDNET_STATE_FUZZ")
	if bin == "" {
		cands := []string{"/tmp/oracle_asan/sn_state_fuzz"}
		if d := libShieldnetDir(); d != "" {
			cands = append(cands, filepath.Join(d, "fuzz", "build", "sn_state_fuzz"))
		}
		for _, c := range cands {
			if _, err := os.Stat(c); err == nil {
				bin = c
				break
			}
		}
	}
	if bin == "" {
		msg := "no sn_state_fuzz binary found — build it from libshieldnet's " +
			"fuzz/ and set SHIELDNET_STATE_FUZZ (or SHIELDNET_LIB_DIR); that repository's " +
			"workflow also runs the coverage-guided build of the same fuzzer"
		if os.Getenv("SHIELDNET_REQUIRE_ORACLE") != "" {
			f.Fatal(msg)
		}
		f.Skip(msg)
	}

	// op, arg pairs. Seeds spell out the orders that produced real bugs.
	f.Add([]byte{0, 0, 1, 0, 3, 0})             // admit, send, drain
	f.Add([]byte{0, 0, 0, 0})                   // promote over a live primary
	f.Add([]byte{0, 0, 1, 0, 6, 0, 3, 0})       // admit, send, release, drain
	f.Add([]byte{0, 0, 5, 0, 0, 0})             // epoch roll between admissions
	f.Add([]byte{0, 0, 0, 1, 1, 0, 1, 1, 3, 0}) // two sessions interleaved
	f.Add([]byte{0, 0, 4, 255, 3, 0})           // admit, long idle, drain
	f.Add([]byte{0, 0, 2, 7, 1, 0})             // junk mid-session
	f.Add([]byte{0, 0, 7, 0, 0, 0})             // promote over a live primary, allocation fails
	f.Add([]byte{0, 0, 7, 0, 0, 0, 3, 0, 1, 0}) // ...then drain and send on the wreckage

	f.Fuzz(func(t *testing.T, prog []byte) {
		// Programs are steps, not bytes; long ones only cost time.
		if len(prog) > 128 {
			prog = prog[:128]
		}
		cmd := exec.Command(bin)
		cmd.Stdin = bytes.NewReader(prog)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			return
		}
		out := stderr.String()
		// The harness aborts on a broken invariant; ASan/UBSan abort on their
		// own findings. Both are real, and the message says which.
		t.Fatalf("state machine failed on a %d-step program: %v\n%s",
			len(prog)/2, err, strings.TrimSpace(out))
	})
}
