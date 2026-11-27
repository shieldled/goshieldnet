// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"testing"

	v1 "github.com/shieldled/goshieldnet/v1"
)

// sled 3.5: control and configuration is never compressed, whatever bulk says.
func TestSled35ControlNeverCompressed(t *testing.T) {
	if got := category(v1.CmdSetFPS, []byte{30}, true); got != catControl {
		t.Fatalf("SET_FPS with bulk=true: category %d, want catControl", got)
	}
}

// sled 3.5: a pixel frame is never padded, whatever bulk says.
func TestSled35PixelFrameNeverPadded(t *testing.T) {
	if got := category(v1.CmdPixelFrame, make([]byte, 32), false); got != catStream {
		t.Fatalf("PIXEL_FRAME with bulk=false: category %d, want catStream", got)
	}
}

// sled 3.5: a kind that is not core follows bulk, whatever its payload.
func TestSled35NonCoreKindFollowsBulk(t *testing.T) {
	for _, kind := range []uint32{0x03, 0x20, 0x5F} {
		if got := category(kind, []byte{1, 0, 0}, true); got != catBulk {
			t.Errorf("kind %#x with bulk=true: category %d, want catBulk", kind, got)
		}
		if got := category(kind, []byte{1, 0, 0}, false); got != catControl {
			t.Errorf("kind %#x with bulk=false: category %d, want catControl", kind, got)
		}
	}
}
