// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/shieldled/goshieldnet/sled"
)

func TestLedsPerStripThatFitUsesSpecLimit(t *testing.T) {
	old := geom
	t.Cleanup(func() { geom = old })
	geom = &sled.Geometry{Envelope: 72, Strips: 1, LEDs: 64, BPP: 3}
	if got := ledsPerStripThatFit(1, 64); got != 7 {
		t.Errorf("envelope 72: got %d, want 7", got)
	}
	geom = &sled.Geometry{Envelope: 1200, Strips: 1, LEDs: 1000, BPP: 3}
	if got := ledsPerStripThatFit(1, 1000); got != 289 {
		t.Errorf("envelope 1200: got %d, want 289", got)
	}
}

func TestAckResultNonOKIsError(t *testing.T) {
	if err := ackResult("X", sled.Ack{Status: sled.AckOK}); err != nil {
		t.Errorf("OK ACK: %v", err)
	}
	err := ackResult("X", sled.Ack{Status: sled.AckErrInvalidArg})
	var ae *ackError
	if !errors.As(err, &ae) || ae.status != sled.AckErrInvalidArg {
		t.Fatalf("non-OK ACK: %v", err)
	}
	if !strings.Contains(err.Error(), sled.AckStatusName(sled.AckErrInvalidArg)) {
		t.Errorf("message %q lacks the status name", err)
	}
}
