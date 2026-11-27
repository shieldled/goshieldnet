// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Sequence fuzzing for the C client's §7 state machine.
//
// The mirror of FuzzDeviceStateMachine. The differential fuzzer compares single
// datagrams between the two implementations; this compares nothing — it drives
// ORDERINGS, which is where a state machine breaks rather than where a parser
// does. A client that admits twice, frees a session it is still reading from,
// or keeps a secret after returning to IDLE fails here and nowhere else.
//
// One process per program, like the device's: each runs real X25519 against a
// real device and must start clean, and state leaking between programs would
// both mask bugs and invent them.
//
//	SHIELDNET_CLIENT_FUZZ=/path/to/sn_client_fuzz go test -run '^$' -fuzz FuzzClientStateMachine

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzClientStateMachine(f *testing.F) {
	bin := os.Getenv("SHIELDNET_CLIENT_FUZZ")
	if bin == "" {
		cands := []string{"/tmp/oracle_asan/sn_client_fuzz"}
		if d := libShieldnetDir(); d != "" {
			cands = append(cands, filepath.Join(d, "fuzz", "build", "sn_client_fuzz"))
		}
		for _, c := range cands {
			if _, err := os.Stat(c); err == nil {
				bin = c
				break
			}
		}
	}
	if bin == "" {
		msg := "no sn_client_fuzz binary found — build it from libshieldnet's " +
			"fuzz/ and set SHIELDNET_CLIENT_FUZZ (or SHIELDNET_LIB_DIR)"
		if os.Getenv("SHIELDNET_REQUIRE_ORACLE") != "" {
			f.Fatal(msg)
		}
		f.Skip(msg)
	}

	// op, arg pairs: 0 take_control, 1 let the device answer, 2 deliver,
	// 3 advance time, 4 replay an earlier datagram, 5 junk.
	full := []byte{0, 0, 1, 0, 2, 0, 1, 0, 2, 0, 3, 2, 1, 0, 2, 0, 3, 2, 1, 0, 2, 0}
	f.Add(full)                                         // a complete admission through to ESTABLISHED
	f.Add([]byte{0, 0, 0, 0})                           // §7.2 is one-shot: the second must be refused
	f.Add([]byte{0, 0, 3, 255, 3, 255, 3, 255, 3, 255}) // no answer: three INITs, then the attempt ends
	f.Add([]byte{0, 0, 1, 0, 2, 0, 3, 255, 3, 255})     // RETRY, then the FINISH phase cap
	f.Add([]byte{0, 0, 1, 0, 2, 0, 4, 0, 4, 0})         // the same RETRY delivered again
	f.Add([]byte{0, 0, 5, 1, 5, 3, 1, 0, 2, 0})         // junk before anything valid
	f.Add(append(append([]byte{}, full...), 4, 0))      // replay after ESTABLISHED
	f.Add(append(append([]byte{}, full...), 0, 0))      // take_control on a live client
	f.Add(append(append([]byte{}, full...), 5, 1))      // junk at an established session

	f.Fuzz(func(t *testing.T, prog []byte) {
		// Programs are steps, not bytes; long ones only cost time.
		if len(prog) > 128 {
			prog = prog[:128]
		}
		cmd := exec.Command(bin)
		cmd.Stdin = bytes.NewReader(prog)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("client state machine failed on a %d-step program: %v\n%s",
				len(prog)/2, err, strings.TrimSpace(stderr.String()))
		}
	})
}
