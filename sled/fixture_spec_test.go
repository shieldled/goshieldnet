// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/shieldled/goshieldnet/v1"
)

// loadSpec reads spec/application.md of the shieldnet-protocol checkout, and
// skips (fails under SHIELDNET_REQUIRE_SPEC) when it is not there.
func loadSpec(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SHIELDNET_PROTOCOL_DIR")
	if dir == "" {
		dir = filepath.FromSlash("../../shieldnet-protocol")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve spec dir: %v", err)
	}
	specPath := filepath.Join(dir, "spec", "application.md")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		msg := fmt.Sprintf("spec %s not readable (%v); set SHIELDNET_PROTOCOL_DIR to a shieldnet-protocol checkout "+
			"(a relative value resolves from sled/, the test's directory)", specPath, err)
		if os.Getenv("SHIELDNET_REQUIRE_SPEC") != "" {
			t.Fatalf("%s (SHIELDNET_REQUIRE_SPEC is set)", msg)
		}
		t.Skip(msg + "; set SHIELDNET_REQUIRE_SPEC=1 to fail instead")
	}
	return string(raw)
}

// TestFixtureMatchesSpec checks testdata/sled-vectors.json against
// spec/application.md in the shieldnet-protocol repository (sections 10.1 and 10.2 and
// Appendix A), so a spec change that is not transcribed into the fixture is
// noticed. It parses the spec independently of the fixture and skips when the
// spec is not checked out.
func TestFixtureMatchesSpec(t *testing.T) {
	spec := loadSpec(t)

	// Rows are | `0xNN` | `NAME` | part |; the patterns hold backticks, which a
	// raw string cannot.
	rowRe := regexp.MustCompile("(?m)^\\|\\s*\x600x([0-9A-Fa-f]{2})\x60\\s*\\|\\s*\x60([A-Z_]+)\x60\\s*\\|")
	table := func(from, to string) map[string]string {
		i := strings.Index(spec, from)
		if i < 0 {
			t.Fatalf("spec heading %q not found", from)
		}
		rest := spec[i+len(from):]
		j := strings.Index(rest, to)
		if j < 0 {
			t.Fatalf("spec heading %q not found after %q", to, from)
		}
		out := map[string]string{}
		for _, m := range rowRe.FindAllStringSubmatch(rest[:j], -1) {
			out[m[2]] = "0x" + strings.ToLower(m[1])
		}
		if len(out) == 0 {
			t.Fatalf("no kind rows found between %q and %q", from, to)
		}
		return out
	}
	wantCmds := table("### 10.1 Command kinds", "### 10.2 Response kinds")
	wantResps := table("### 10.2 Response kinds", "### 10.3 ")

	wantVecs := regexp.MustCompile(`(?m)^[0-9a-f]{8,}$`).FindAllString(spec, -1)
	if len(wantVecs) == 0 {
		t.Fatal("no vector lines found in the spec")
	}

	// Appendix A.6: the last cell of each table row is a payload, shorter than
	// the 8 hex digits the vector lines need, so it has its own fixture key.
	extRe := regexp.MustCompile("(?m)^\\|.*\\|\\s*\x60([0-9a-f]+)\x60\\s*\\|\\s*$")
	a6 := strings.Index(spec, "### A.6 ")
	if a6 < 0 {
		t.Fatal(`spec heading "### A.6 " not found`)
	}
	rest := spec[a6+len("### A.6 "):]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		t.Fatal(`spec heading "## " not found after "### A.6 "`)
	}
	var wantCore []string
	for _, m := range extRe.FindAllStringSubmatch(rest[:end], -1) {
		wantCore = append(wantCore, m[1])
	}
	sort.Strings(wantCore)
	if len(wantCore) == 0 {
		t.Fatal("no payload rows found in spec A.6")
	}

	// Reserved rows: | `0xNN` | — | program extension (reserved) |, the Name
	// cell is an em dash.
	reservedRe := regexp.MustCompile("(?m)^\\|\\s*\x600x[0-9A-Fa-f]{2}\x60\\s*\\|\\s*—\\s*\\|\\s*program extension \\(reserved\\)\\s*\\|\\s*$")
	i101 := strings.Index(spec, "### 10.1 Command kinds")
	i102 := strings.Index(spec, "### 10.2 Response kinds")
	i103 := strings.Index(spec, "### 10.3 ")
	if i101 < 0 || i102 < i101 || i103 < i102 {
		t.Fatal("spec headings 10.1, 10.2 and 10.3 not found in order")
	}
	const wantReservedCmds, wantReservedResps = 10, 2
	if n := len(reservedRe.FindAllString(spec[i101:i102], -1)); n != wantReservedCmds {
		t.Errorf("table 10.1 has %d reserved rows, want %d", n, wantReservedCmds)
	}
	if n := len(reservedRe.FindAllString(spec[i102:i103], -1)); n != wantReservedResps {
		t.Errorf("table 10.2 has %d reserved rows, want %d", n, wantReservedResps)
	}

	fxRaw, err := os.ReadFile("../testdata/sled-vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Commands, Responses map[string]string
		Vectors             []string
		CoreTableVectors    map[string]string `json:"core_table_vectors"`
	}
	if err := json.Unmarshal(fxRaw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	diffMaps := func(name string, spec, fixture map[string]string) {
		for k, sv := range spec {
			fv, ok := fixture[k]
			switch {
			case !ok:
				t.Errorf("%s: %s is in the spec (%s) but not in the fixture", name, k, sv)
			case fv != sv:
				t.Errorf("%s: %s is %s in the spec but %s in the fixture", name, k, sv, fv)
			}
		}
		for k, fv := range fixture {
			if _, ok := spec[k]; !ok {
				t.Errorf("%s: %s (%s) is in the fixture but not in the spec", name, k, fv)
			}
		}
	}
	diffMaps("commands", wantCmds, fx.Commands)
	diffMaps("responses", wantResps, fx.Responses)

	if len(wantVecs) != len(fx.Vectors) {
		t.Errorf("vectors: the spec has %d, the fixture %d", len(wantVecs), len(fx.Vectors))
	}
	for i := 0; i < len(wantVecs) && i < len(fx.Vectors); i++ {
		if wantVecs[i] != fx.Vectors[i] {
			t.Errorf("vectors[%d]: spec %s, fixture %s", i, wantVecs[i], fx.Vectors[i])
		}
	}

	var gotCore []string
	for k, v := range fx.CoreTableVectors {
		if k != "_comment" {
			gotCore = append(gotCore, v)
		}
	}
	sort.Strings(gotCore)
	if strings.Join(wantCore, " ") != strings.Join(gotCore, " ") {
		t.Errorf("core_table_vectors: the spec has %v, the fixture %v (both sorted)", wantCore, gotCore)
	}
}

// TestCoreKindsMatchSpec pins v1.IsCoreCommand to the Part column of the spec's
// table 10.1: a kind is core exactly when its row says core.
func TestCoreKindsMatchSpec(t *testing.T) {
	spec := loadSpec(t)
	i := strings.Index(spec, "### 10.1 Command kinds")
	j := strings.Index(spec, "### 10.2 Response kinds")
	if i < 0 || j < i {
		t.Fatal("spec headings 10.1 and 10.2 not found")
	}
	rowRe := regexp.MustCompile("(?m)^\\|\\s*\x600x([0-9A-Fa-f]{2})\x60\\s*\\|[^|]*\\|\\s*([^|]+?)\\s*\\|\\s*$")
	core := map[uint32]bool{}
	rows := 0
	for _, m := range rowRe.FindAllStringSubmatch(spec[i:j], -1) {
		k, err := strconv.ParseUint(m[1], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		rows++
		core[uint32(k)] = m[2] == "core"
	}
	if rows != 11+9+1 {
		t.Fatalf("parsed %d rows of table 10.1, want 21", rows)
	}
	for k := uint32(0); k <= 0x7F; k++ {
		if got := v1.IsCoreCommand(k); got != core[k] {
			t.Errorf("IsCoreCommand(%#x) = %v, the spec says core = %v", k, got, core[k])
		}
	}
}
