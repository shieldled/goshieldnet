// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile's mode is subject to umask
		t.Fatal(err)
	}
	return p
}

func TestLoadFromFile(t *testing.T) {
	t.Setenv("T_KEY", "")
	t.Setenv("T_KEY_FILE", writeKey(t, keyHex+"\n", 0o600))
	k, err := Load("T_KEY_FILE", "T_KEY")
	if err != nil || len(k) != KeyLen || k[31] != 0x1f {
		t.Fatalf("Load: %x %v", k, err)
	}
}

func TestLoadRefusesGroupOrWorldReadableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		t.Setenv("T_KEY_FILE", writeKey(t, keyHex, mode))
		if _, err := Load("T_KEY_FILE", "T_KEY"); err == nil || !strings.Contains(err.Error(), "group/other") {
			t.Errorf("mode %04o: want refusal, got %v", mode, err)
		}
	}
}

func TestLoadFromHexEnvAndUnsetsIt(t *testing.T) {
	t.Setenv("T_KEY_FILE", "")
	t.Setenv("T_KEY", keyHex)
	k, err := Load("T_KEY_FILE", "T_KEY")
	if err != nil || len(k) != KeyLen {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := os.LookupEnv("T_KEY"); ok {
		t.Error("the hex variable must be unset after it is read")
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	t.Setenv("T_KEY_FILE", "")
	for _, v := range []string{keyHex[:62], keyHex + "00", "zz" + keyHex[2:], " " + keyHex} {
		t.Setenv("T_KEY", v)
		if _, err := Load("T_KEY_FILE", "T_KEY"); err == nil {
			t.Errorf("%q: want error", v)
		}
	}
	t.Setenv("T_KEY_FILE", writeKey(t, strings.Repeat("a", 200), 0o600))
	if _, err := Load("T_KEY_FILE", "T_KEY"); err == nil {
		t.Error("an over-long key file must be refused")
	}
}

func TestLoadNotSet(t *testing.T) {
	t.Setenv("T_KEY_FILE", "")
	t.Setenv("T_KEY", "")
	if _, err := Load("T_KEY_FILE", "T_KEY"); !errors.Is(err, ErrNotSet) {
		t.Fatalf("want ErrNotSet, got %v", err)
	}
}
