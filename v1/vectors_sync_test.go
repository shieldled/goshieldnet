// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestVectorsMatchSpecRepo checks that the vector files in testdata/ are
// byte-exact copies of the canonical ones in shieldnet-protocol/vectors/, so a
// spec revision that is not copied here is noticed. It skips when the spec is
// not checked out.
func TestVectorsMatchSpecRepo(t *testing.T) {
	dir := os.Getenv("SHIELDNET_PROTOCOL_DIR")
	if dir == "" {
		dir = filepath.FromSlash("../../shieldnet-protocol")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve spec dir: %v", err)
	}
	vecDir := filepath.Join(dir, "vectors")
	if _, err := os.ReadDir(vecDir); err != nil {
		msg := fmt.Sprintf("spec vectors %s not readable (%v); set SHIELDNET_PROTOCOL_DIR to a shieldnet-protocol checkout "+
			"(a relative value resolves from v1/, the test's directory)", vecDir, err)
		if os.Getenv("SHIELDNET_REQUIRE_SPEC") != "" {
			t.Fatalf("%s (SHIELDNET_REQUIRE_SPEC is set)", msg)
		}
		t.Skip(msg + "; set SHIELDNET_REQUIRE_SPEC=1 to fail instead")
	}
	for _, name := range []string{"shieldnet-v1-vectors.json", "shieldnet-msglayer-vectors.json"} {
		want, err := os.ReadFile(filepath.Join(vecDir, name))
		if err != nil {
			t.Errorf("%s: read spec copy: %v", name, err)
			continue
		}
		got, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			t.Errorf("%s: read testdata copy: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("testdata/%s differs from %s; copy the spec repo's file", name, filepath.Join(vecDir, name))
		}
	}
}
