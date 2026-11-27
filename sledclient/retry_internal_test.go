// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shieldled/goshieldnet/sledclient/sledclienttest"
	v1 "github.com/shieldled/goshieldnet/v1"
)

// transport 9.5: ErrSendQueueFull is transient. Refused while asking for a
// pending DEVICE_INFO again, it is returned, not kept as the session's end.
func TestSled536RetrySendQueueFullNotTerminal(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdGetDeviceInfo: true}})
	c, err := Dial(dev.Addr, dev.PSK, dev.ID, Options{AllowSameHost: true, ReplyTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.Ping(ctx); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("first Ping: err = %v, want a no-answer timeout", err)
	}
	testHookRetrySend = func(error) error { return v1.ErrSendQueueFull }
	defer func() { testHookRetrySend = nil }()
	if err := c.Ping(ctx); !errors.Is(err, v1.ErrSendQueueFull) {
		t.Fatalf("second Ping: err = %v, want ErrSendQueueFull", err)
	}
	testHookRetrySend = nil
	dev.SetSilent(v1.CmdGetDeviceInfo, false)
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("third Ping: %v, want the retry to go through", err)
	}
}

// deadlineOnly has a deadline but is never done, so context.AfterFunc cannot
// run and the DEVICE_INFO wait ends at the deadline with the callback unrun.
type deadlineOnly struct {
	context.Context
	dl time.Time
}

func (d deadlineOnly) Deadline() (time.Time, bool) { return d.dl, true }

// When the DEVICE_INFO wait ends at the context's deadline and the AfterFunc
// has not run, this package closes the client itself.
func TestSled536DeadlineDuringWaitCloses(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdGetDeviceInfo: true}})
	c, err := Dial(dev.Addr, dev.PSK, dev.ID, Options{AllowSameHost: true, ReplyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Ping(deadlineOnly{context.Background(), time.Now().Add(200 * time.Millisecond)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping: err = %v, want context.DeadlineExceeded", err)
	}
	if !c.cliClosed.Load() {
		t.Fatal("cliClosed is false: the client was not closed after the deadline")
	}
}
