// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

// The sled command numbering is declared twice: here as Go constants, and in
// the firmware's command.h as SLED_CMD_*/SLED_RESP_* macros. The two live in
// different repositories, so nothing compiles both, and 052 renumbered every
// kind — an edit that touched one side and not the other would compile clean
// in both languages and be wrong on the wire.
//
// spec/application.md (in the shieldnet-protocol repository) is the artifact
// both repositories share, so both sides pin to it rather than to each other.
// This is the Go half; the firmware has its own half.
// The spec's kind tables are transcribed into testdata/sled-vectors.json.

// Every kind the spec declares, mapped to the constant that must carry it.
// A kind added to the spec with no entry here fails the completeness check
// below, which is the point: a new command must not reach the wire with only
// one of the two implementations knowing its number.
var specToConst = map[string]uint32{
	"PIXEL_FRAME":     CmdPixelFrame,
	"SET_BRIGHTNESS":  CmdSetBrightness,
	"SET_FPS":         CmdSetFPS,
	"SET_MODE":        CmdSetMode,
	"ON":              CmdOn,
	"OFF":             CmdOff,
	"PING":            CmdPing,
	"GET_STATUS":      CmdGetStatus,
	"GET_MODE":        CmdGetMode,
	"GET_DEVICE_INFO": CmdGetDeviceInfo,
	"NTP_SERVER":      CmdNTPServer,

	"ACK":         RespAck,
	"STATUS":      RespStatus,
	"DEVICE_INFO": RespDeviceInfo,
}

func specKinds(t *testing.T) map[string]uint32 {
	t.Helper()
	raw, err := os.ReadFile("../testdata/sled-vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct{ Commands, Responses map[string]string }
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	kinds := map[string]uint32{}
	for _, table := range []map[string]string{fx.Commands, fx.Responses} {
		for name, hex := range table {
			v, err := strconv.ParseUint(hex, 0, 8)
			if err != nil {
				t.Fatalf("fixture kind %s=%q: %v", name, hex, err)
			}
			if _, dup := kinds[name]; dup {
				// A name shared by both directions would make the map ambiguous.
				t.Errorf("%s is declared as both a command and a response kind", name)
			}
			kinds[name] = uint32(v)
		}
	}
	return kinds
}

func TestKindsMatchSpec(t *testing.T) {
	kinds := specKinds(t)

	if len(kinds) != len(specToConst) {
		t.Errorf("spec declares %d kinds, this test maps %d", len(kinds), len(specToConst))
	}
	for name, want := range kinds {
		got, ok := specToConst[name]
		if !ok {
			t.Errorf("spec declares %s = 0x%02x with no Go constant", name, want)
			continue
		}
		if got != want {
			t.Errorf("%s: Go has 0x%02x, spec says 0x%02x", name, got, want)
		}
	}
	for name := range specToConst {
		if _, ok := kinds[name]; !ok {
			t.Errorf("Go declares %s but the spec does not", name)
		}
	}
}

// The numbering must stay dense and collision-free within each range. A
// duplicate is the failure a renumbering actually produces — two kinds sharing
// a value dispatches one of them to the wrong handler, and every individual
// constant still looks reasonable in review.
func TestKindsAreDistinct(t *testing.T) {
	seen := map[uint32]string{}
	for name, v := range specToConst {
		if prev, dup := seen[v]; dup {
			// Commands and responses are disjoint ranges (responses are >= 0x80),
			// so any collision at all is a real one.
			t.Errorf("0x%02x is both %s and %s", v, prev, name)
		}
		seen[v] = name
	}
}

// Commands are 0x00-0x7F and responses 0x80-0xFF (specification 3.1). Assert
// the constants were filed in the right half.
func TestKindRangesAreAsDocumented(t *testing.T) {
	responses := map[string]bool{"ACK": true, "STATUS": true, "DEVICE_INFO": true}
	for name, v := range specToConst {
		switch {
		case responses[name] && v < 0x80:
			t.Errorf("%s is a response but is 0x%02x, below 0x80", name, v)
		case !responses[name] && v >= 0x80:
			t.Errorf("%s is a command but is 0x%02x, at or above 0x80", name, v)
		}
	}
}

func TestSpecParseFoundEverything(t *testing.T) {
	// A fixture that silently parses to nothing would make every check above pass
	// vacuously, which is the classic way a spec-parsing test rots.
	kinds := specKinds(t)
	if len(kinds) != 14 {
		t.Fatalf("parsed %d kinds from the fixture, want 14 (11 commands + 3 responses): %s",
			len(kinds), fmt.Sprint(kinds))
	}
}
