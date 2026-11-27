// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestDecodeMode(t *testing.T) {
	for _, c := range []struct {
		detail []byte
		want   ModeInfo
	}{
		{[]byte{0x01, 0x01}, ModeInfo{Mode: ModePixel, OutputEnabled: true}},
		{[]byte{0x07, 0x00}, ModeInfo{Mode: 7, OutputEnabled: false}},              // undefined mode kept raw (R5)
		{[]byte{0x01, 0x02, 0xff}, ModeInfo{Mode: ModePixel, OutputEnabled: true}}, // trailing byte ignored (R3)
	} {
		got, err := DecodeMode(c.detail)
		if err != nil {
			t.Errorf("DecodeMode(%x): %v", c.detail, err)
			continue
		}
		if got != c.want {
			t.Errorf("DecodeMode(%x) = %+v, want %+v", c.detail, got, c.want)
		}
	}
	if _, err := DecodeMode([]byte{0x01}); !errors.Is(err, ErrShort) {
		t.Errorf("DecodeMode(01): err = %v, want ErrShort", err)
	}
}

// TestModeDetailVector checks DecodeMode against the GET_MODE ACK detail
// vector of the fixture (spec/application.md A.6).
func TestModeDetailVector(t *testing.T) {
	raw, err := os.ReadFile("../testdata/sled-vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		CoreTableVectors map[string]string `json:"core_table_vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	want := fx.CoreTableVectors["GET_MODE_DETAIL"]
	b, err := hex.DecodeString(want)
	if err != nil || want == "" {
		t.Fatalf("fixture GET_MODE_DETAIL %q: %v", want, err)
	}
	m, err := DecodeMode(b)
	if err != nil {
		t.Fatal(err)
	}
	if m != (ModeInfo{Mode: ModePixel, OutputEnabled: true}) {
		t.Errorf("DecodeMode(%s) = %+v, want PIXEL with output enabled", want, m)
	}
}
