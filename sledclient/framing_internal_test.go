// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import "testing"

func TestFrameFor(t *testing.T) {
	for _, tc := range []struct {
		cat   wireCategory
		known bool
		n     int
		want  framing
	}{
		{catStream, false, 10, frameCompressed},
		{catStream, true, 5000, frameCompressed},
		{catControl, false, 64, framePadded},
		{catControl, false, 65, framePlain},
		{catControl, true, 5000, framePadded},
		{catBulk, false, 64, frameBulk},
		{catBulk, false, 65, frameCompressed},
		{catBulk, true, 5000, frameBulk},
	} {
		if got := frameFor(tc.cat, tc.known, tc.n); got != tc.want {
			t.Errorf("frameFor(%d, %v, %d) = %d, want %d", tc.cat, tc.known, tc.n, got, tc.want)
		}
	}
}
