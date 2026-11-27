// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"bytes"
	"strings"
	"testing"

	v1 "github.com/shieldled/goshieldnet/v1"
)

const optionsTestAddr = "127.0.0.1:9"

var optionsTestPSK = bytes.Repeat([]byte{0x33}, 32)

func TestOptionsReachV1(t *testing.T) {
	c, err := Dial(optionsTestAddr, optionsTestPSK, [8]byte{}, Options{AllowSameHost: true, FinishPhaseMS: 2000, MidFrameBudgetMS: 1234})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.cli.FinishPhaseMS != 2000 {
		t.Errorf("v1 FinishPhaseMS = %d, want 2000", c.cli.FinishPhaseMS)
	}
	if c.cli.MidFrameBudgetMS != 1234 {
		t.Errorf("v1 MidFrameBudgetMS = %d, want 1234", c.cli.MidFrameBudgetMS)
	}
}

func TestOptionsFinishPhaseRefusedByDial(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, ms := range []int{-1, v1.CookieEpochMS, v1.CookieEpochMS + 1} {
			c, err := Dial(optionsTestAddr, optionsTestPSK, [8]byte{}, Options{AllowSameHost: true, LegacyAdmission: legacy, FinishPhaseMS: ms})
			if err == nil {
				c.Close()
				t.Errorf("Dial(FinishPhaseMS %d, legacy %v) succeeded, want an error", ms, legacy)
				continue
			}
			if c != nil {
				t.Errorf("Dial(FinishPhaseMS %d, legacy %v) returned a client with its error", ms, legacy)
			}
			if !strings.Contains(err.Error(), "FinishPhaseMS") {
				t.Errorf("Dial(FinishPhaseMS %d, legacy %v): err = %v, want it to name FinishPhaseMS", ms, legacy, err)
			}
		}
		for _, ms := range []int{0, 1, v1.CookieEpochMS - 1} {
			c, err := Dial(optionsTestAddr, optionsTestPSK, [8]byte{}, Options{AllowSameHost: true, LegacyAdmission: legacy, FinishPhaseMS: ms})
			if err != nil {
				t.Errorf("Dial(FinishPhaseMS %d, legacy %v): %v, want success", ms, legacy, err)
				continue
			}
			c.Close()
		}
	}
}

// Dial replicates v1's FinishPhaseMS rule; this fails if the two drift apart.
func TestOptionsFinishPhaseMatchesV1(t *testing.T) {
	for _, v := range []int{-1, 0, 1, v1.CookieEpochMS - 1, v1.CookieEpochMS, v1.CookieEpochMS + 1} {
		c, err := Dial(optionsTestAddr, optionsTestPSK, [8]byte{}, Options{AllowSameHost: true, FinishPhaseMS: v})
		dialRefused := err != nil
		if !dialRefused {
			c.Close()
		}
		cli, err := v1.NewClient(optionsTestAddr, optionsTestPSK, make([]byte, 8), nil)
		if err != nil {
			t.Fatal(err)
		}
		cli.Close()
		cli.FinishPhaseMS = v
		err = cli.TakeControlApp(v1.CmdPing, nil)
		v1Refused := err != nil && strings.Contains(err.Error(), "FinishPhaseMS")
		if dialRefused != v1Refused {
			t.Errorf("FinishPhaseMS %d: Dial refuses = %v, v1 refuses = %v", v, dialRefused, v1Refused)
		}
	}
}
