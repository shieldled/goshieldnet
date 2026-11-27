// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func readErr(f func() error) chan error {
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	return ch
}

func waitErr(t *testing.T, ch chan error, d time.Duration) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatal("reader did not return")
		return nil
	}
}

func TestClientTeardownCloseWhileReadingIdle(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	ch := readErr(func() error { _, _, err := cli.RecvApp(); return err })
	time.Sleep(200 * time.Millisecond)
	cli.Close()
	err := waitErr(t, ch, 5*time.Second)
	if errors.Is(err, ErrDesync) || !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("got %v, want ErrNotEstablished", err)
	}
}

func TestClientTeardownCloseWhileReadingMidFrame(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	for i := 0; i < 200 && srv.Primary() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Primary() == nil {
		t.Fatal("no primary")
	}
	if _, err := srv.Primary().Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, err := cli.RecvApp()
	if err == nil || !isTimeoutErr(err) {
		t.Fatalf("precondition: want timeout, got %v", err)
	}
	cli.rxMu.Lock()
	n := cli.rxStage.hdrN
	cli.rxMu.Unlock()
	if n != 10 {
		t.Fatalf("precondition: hdrN = %d, want 10", n)
	}
	cli.SetReadDeadline(time.Time{})
	ch := readErr(func() error { _, _, err := cli.RecvApp(); return err })
	time.Sleep(200 * time.Millisecond)
	cli.Close()
	err = waitErr(t, ch, 5*time.Second)
	if errors.Is(err, ErrDesync) || !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("got %v, want ErrNotEstablished", err)
	}
}

func TestClientTeardownDeadWhileReading(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out SESSION_DEAD_MS")
	}
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	ch := readErr(func() error { _, _, err := cli.RecvApp(); return err })
	time.Sleep(200 * time.Millisecond)
	srv.Close()
	cli.SendApp(CmdPing, []byte("x"))
	err := waitErr(t, ch, msDur(SessionDeadMS)+5*time.Second)
	if !errors.Is(err, ErrSessionDead) {
		t.Fatalf("got %v, want ErrSessionDead", err)
	}
	for i := 0; !cli.SessionDead() && i < 60; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if err := cli.SetReadDeadline(time.Time{}); !errors.Is(err, ErrSessionDead) {
		t.Fatalf("SetReadDeadline after liveness: got %v, want ErrSessionDead", err)
	}
}

func TestTakeControlNotIdle(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	err := cli.TakeControlApp(CmdPing, nil)
	if !errors.Is(err, ErrNotIdle) {
		t.Fatalf("got %v, want ErrNotIdle", err)
	}
}

func TestClientTeardownRawRecvClose(t *testing.T) {
	_, cli, cleanup := loopbackPair(t)
	defer cleanup()
	ch := readErr(func() error { _, err := cli.Recv(make([]byte, 64)); return err })
	time.Sleep(200 * time.Millisecond)
	cli.Close()
	err := waitErr(t, ch, 5*time.Second)
	if !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("got %v, want ErrNotEstablished", err)
	}
}

// The §7.2 stamps are milliseconds since c.base on the monotonic clock, so they
// are small; a Unix-millisecond stamp is about 1.7e12.
func TestClientStampsAreMonotonic(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	if !strings.Contains(cli.base.String(), "m=") {
		t.Fatalf("base carries no monotonic reading: %v", cli.base)
	}
	if err := cli.SendApp(CmdPing, []byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	const bound = 60_000
	for name, v := range map[string]int64{
		"lastRx":           cli.lastRx.Load(),
		"outstandingSince": cli.outstandingSince.Load(),
	} {
		if v <= 0 || v > bound {
			t.Errorf("%s = %d, want a monotonic stamp in (0, %d]", name, v, bound)
		}
	}
}

// afterRead must leave an error alone while the session is still current: a
// genuine desync on a live session is ErrDesync, not a teardown sentinel.
func TestAfterReadLiveSessionKeepsError(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	cli.mu.Lock()
	sess := cli.kcp
	cli.mu.Unlock()
	if err := cli.afterRead(sess, ErrDesync); !errors.Is(err, ErrDesync) {
		t.Fatalf("live session: got %v, want ErrDesync unchanged", err)
	}
	cli.Close()
	if err := cli.afterRead(sess, ErrDesync); !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("after Close: got %v, want ErrNotEstablished", err)
	}
}

func TestClientTeardownCloseWhileReadingAppNum(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	ch := readErr(func() error { _, _, _, err := cli.RecvAppNum(); return err })
	time.Sleep(200 * time.Millisecond)
	cli.Close()
	err := waitErr(t, ch, 5*time.Second)
	if errors.Is(err, ErrDesync) || !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("got %v, want ErrNotEstablished", err)
	}
}

func TestClientSendAppDeadTeardownMidWrite(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	testHookBeforeSendWrite = func() { cli.teardownAs(true) }
	defer func() { testHookBeforeSendWrite = nil }()
	err := cli.SendApp(CmdPing, []byte("x"))
	if !errors.Is(err, ErrSessionDead) {
		t.Fatalf("got %v, want ErrSessionDead", err)
	}
}

func TestClientSendRawDeadTeardownMidWrite(t *testing.T) {
	_, cli, cleanup := loopbackPair(t)
	defer cleanup()
	testHookBeforeSendWrite = func() { cli.teardownAs(true) }
	defer func() { testHookBeforeSendWrite = nil }()
	_, err := cli.Send([]byte("x"))
	if !errors.Is(err, ErrSessionDead) {
		t.Fatalf("got %v, want ErrSessionDead", err)
	}
}

func TestClientSendAppCloseMidWrite(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	testHookBeforeSendWrite = func() { cli.Close() }
	defer func() { testHookBeforeSendWrite = nil }()
	err := cli.SendApp(CmdPing, []byte("x"))
	if !errors.Is(err, ErrNotEstablished) || errors.Is(err, ErrSessionDead) {
		t.Fatalf("got %v, want ErrNotEstablished and not ErrSessionDead", err)
	}
}

func TestSessionDeadFalseAfterClose(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	cli.Close()
	cli.teardownAs(true)
	if cli.SessionDead() {
		t.Fatal("SessionDead true after a local Close")
	}
	cleanup()

	_, cli2, cleanup2 := loopbackPairApp(t)
	defer cleanup2()
	cli2.teardownAs(true)
	if !cli2.SessionDead() {
		t.Fatal("SessionDead false after a liveness teardown")
	}
}

func TestMarkOutstandingPublishesTimestampFirst(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	cli.base = time.Now().Add(-time.Minute)
	cli.lastRx.Store(cli.monoMS() - 2*SessionDeadMS)
	cli.outstandingSince.Store(1)
	cli.outstanding.Store(false)
	mid := true
	testHookMidMarkOutstanding = func() { mid = cli.livenessExpired() }
	defer func() { testHookMidMarkOutstanding = nil }()
	cli.markOutstanding()
	if mid {
		t.Fatal("liveness expired between the timestamp and the gate")
	}
	if cli.livenessExpired() {
		t.Fatal("liveness expired right after the first write")
	}
}

func TestLivenessExpired(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	cli.base = time.Now().Add(-time.Minute)
	old := cli.monoMS() - 2*SessionDeadMS
	fresh := cli.monoMS()
	cases := []struct {
		name          string
		gate          bool
		lastRx, since int64
		want          bool
	}{
		{"gate closed, old stamps", false, old, old, false},
		{"gate open, both old", true, old, old, true},
		{"gate open, since fresh", true, old, fresh, false},
		{"gate open, both zero", true, 0, 0, false},
	}
	for _, tc := range cases {
		cli.lastRx.Store(tc.lastRx)
		cli.outstandingSince.Store(tc.since)
		cli.outstanding.Store(tc.gate)
		if got := cli.livenessExpired(); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
