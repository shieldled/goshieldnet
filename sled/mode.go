// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

// SET_MODE / STATUS mode values (spec/application.md 4.3: 1=PIXEL; 0 and 2-255
// are for extensions and implementations).
const ModePixel uint8 = 1

// ModeInfo is the answer to GET_MODE (spec/application.md 4.3).
type ModeInfo struct {
	Mode          uint8 // raw: compare against ModePixel
	OutputEnabled bool
}

// DecodeMode parses GET_MODE's ACK detail, [u8 mode][u8 output_enabled]
// (spec/application.md 4.3). Bytes beyond the two are ignored (R3). An undefined mode is
// returned as is, not as an error (R5 item 3).
func DecodeMode(detail []byte) (ModeInfo, error) {
	if len(detail) < 2 {
		return ModeInfo{}, ErrShort
	}
	return ModeInfo{Mode: detail[0], OutputEnabled: detail[1] != 0}, nil
}
