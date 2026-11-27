// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"sync"
	"testing"
)

// transport 10.3 rule 4: a RETRY queued when the INIT retransmit timer expires
// is read before INIT is sent again.
func TestTransport10QueuedRetryBeforeResend(t *testing.T) {
	_, px, cli := proxiedPair(t, TypeRETRY, TypeINIT)
	var once sync.Once
	setPhaseHook(t, func(phase string, final bool) {
		if phase != "retry" || final {
			return
		}
		once.Do(func() {
			px.release(t)
			px.mark.Store(true)
		})
	})
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp: %v", err)
	}
	if n := px.countAfter.Load(); n != 0 {
		t.Fatalf("%d INIT sent after the RETRY was queued, want 0", n)
	}
}

// transport 10.3 rule 4: at the RETRY phase's end, a RETRY already queued
// still counts.
func TestTransport10QueuedRetryAtPhaseEnd(t *testing.T) {
	_, px, cli := proxiedPair(t, TypeRETRY, TypeINIT)
	var once sync.Once
	setPhaseHook(t, func(phase string, final bool) {
		if phase != "retry" || !final {
			return
		}
		once.Do(func() { px.release(t) })
	})
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp: %v", err)
	}
}
