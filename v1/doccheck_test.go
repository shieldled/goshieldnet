// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "testing"

// Pins the numbers docs/tuning.md states, so the doc cannot drift from the code.
func TestTuningDocNumbers(t *testing.T) {
	def := &Client{}
	if got := def.sendWindowSegments(); got != 23 {
		t.Errorf("default effective SndWnd = %d, tuning.md says 23", got)
	}
	raised := &Client{SendQueueMax: 256 * 1024}
	if got := raised.sendWindowSegments(); got != 187 {
		t.Errorf("SendQueueMax=256KiB effective SndWnd = %d, tuning.md says 187", got)
	}
	if SendQueueMaxDefault != 32*1024 {
		t.Errorf("SendQueueMaxDefault = %d, tuning.md says 32 KiB", SendQueueMaxDefault)
	}
	if DefaultKCPTuning.SndWnd != 32 || DefaultKCPTuning.RcvWnd != 8 ||
		DefaultKCPTuning.Interval != 20 {
		t.Errorf("DefaultKCPTuning = %+v, tuning.md documents {32, 8, 1, 20, 2, 1}", DefaultKCPTuning)
	}
	if TickIntervalMS != 500 {
		t.Errorf("TickIntervalMS = %d, tuning.md says 500", TickIntervalMS)
	}
}
