// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "testing"

// The mustLen guards added to the encoders must panic on a wrong-width field, so a
// vector-generation mistake fails loudly instead of emitting a plausible-but-wrong
// datagram.
func TestEncoderWidthGuards(t *testing.T) {
	ok24, ok8, ok16, ok32, ok18 := fx(1, 24), fx(2, 8), fx(3, 16), fx(4, 32), fx(5, 18)
	cases := []struct {
		name string
		fn   func()
	}{
		{"INIT nonce", func() { EncodeINIT(fx(1, 23), ok8, ok16) }},
		{"INIT device_id", func() { EncodeINIT(ok24, fx(2, 7), ok16) }},
		{"INIT init_mac", func() { EncodeINIT(ok24, ok8, fx(3, 15)) }},
		{"RETRY epoch_tag", func() { EncodeRETRY(fx(1, 7), ok16, ok8, ok8, ok18, ok16) }},
		{"RETRY cookie", func() { EncodeRETRY(ok8, fx(3, 15), ok8, ok8, ok18, ok16) }},
		{"RETRY admission_epoch", func() { EncodeRETRY(ok8, ok16, fx(2, 7), ok8, ok18, ok16) }},
		{"RETRY device_id", func() { EncodeRETRY(ok8, ok16, ok8, fx(2, 9), ok18, ok16) }},
		{"RETRY observed_source", func() { EncodeRETRY(ok8, ok16, ok8, ok8, fx(5, 17), ok16) }},
		{"RETRY retry_mac", func() { EncodeRETRY(ok8, ok16, ok8, ok8, ok18, fx(3, 15)) }},
		{"FINISH client_nonce", func() { EncodeFINISH(fx(1, 25), ok8, ok16, ok8, ok32, ok16) }},
		{"FINISH epoch_tag", func() { EncodeFINISH(ok24, fx(2, 9), ok16, ok8, ok32, ok16) }},
		{"FINISH cookie", func() { EncodeFINISH(ok24, ok8, fx(3, 17), ok8, ok32, ok16) }},
		{"FINISH admission_epoch", func() { EncodeFINISH(ok24, ok8, ok16, fx(2, 7), ok32, ok16) }},
		{"FINISH e_c", func() { EncodeFINISH(ok24, ok8, ok16, ok8, fx(4, 31), ok16) }},
		{"FINISH client_tag", func() { EncodeFINISH(ok24, ok8, ok16, ok8, ok32, fx(3, 17)) }},
		{"ADMIT admission_epoch", func() { EncodeADMIT(fx(2, 7), ok32, ok16, ok16) }},
		{"ADMIT e_s", func() { EncodeADMIT(ok8, fx(4, 33), ok16, ok16) }},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected panic on wrong width, got none", c.name)
				}
			}()
			c.fn()
		}()
	}
	// A correct call must NOT panic.
	_ = EncodeINIT(ok24, ok8, ok16)
	_ = EncodeRETRY(ok8, ok16, ok8, ok8, ok18, ok16)
	_ = EncodeFINISH(ok24, ok8, ok16, ok8, ok32, ok16)
	_ = EncodeADMIT(ok8, ok32, ok16, ok16)
}
