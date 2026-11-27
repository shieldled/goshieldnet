// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// oversizeHeader is a 20-octet message header declaring a Size of size.
func oversizeHeader(size uint32) []byte {
	return appHeader(size, 0, CmdPing, 99)
}

func stateOf(c *Client) clientState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// exchangeAfterRetake admits cli again and checks the server reads the
// admitting message.
func exchangeAfterRetake(t *testing.T, srv *Server, cli *Client) {
	t.Helper()
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("re-admission: %v", err)
	}
	p := primaryOf(t, srv)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); err != nil {
		t.Fatalf("server read after re-admission: %v", err)
	}
	_ = p.SetReadDeadline(time.Time{})
}

// message layer 8: a desynchronised stream ends the session.
func TestMsg8ClientDesyncEndsSession(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	p := primaryOf(t, srv)
	if _, err := p.Write(oversizeHeader(uint32(cli.maxMsgPayload()) + 1)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := cli.RecvApp(); !errors.Is(err, ErrDesync) {
		t.Fatalf("RecvApp: err = %v, want ErrDesync", err)
	}
	if st := stateOf(cli); st != stIdle {
		t.Fatalf("client state %d after ErrDesync, want IDLE", st)
	}
	if cli.SessionDead() {
		t.Error("SessionDead after a desync teardown")
	}
	exchangeAfterRetake(t, srv, cli)
}

func TestMsg8ServerDesyncDropsPrimary(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	p := primaryOf(t, srv)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); err != nil { // the admitting PING
		t.Fatal(err)
	}
	hdr := oversizeHeader(uint32(srv.maxMsgPayload()) + 1)
	if binary.BigEndian.Uint32(hdr) <= uint32(srv.maxMsgPayload()) {
		t.Fatal("precondition: header not over the server's bound")
	}
	if _, err := cli.Send(hdr); err != nil {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); !errors.Is(err, ErrDesync) {
		t.Fatalf("RecvAppNumGen: err = %v, want ErrDesync", err)
	}
	if gen, ok := srv.PrimaryGen(); ok {
		t.Fatalf("PrimaryGen = %d, true after ErrDesync; want no primary", gen)
	}
}

// 067's mid-frame budget: with no read deadline the watchdog closes the kcp
// session, and the client still ends the session so it can admit again.
func TestMsg8BudgetEndsSession(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	cli.MidFrameBudgetMS = 200
	p := primaryOf(t, srv)
	if _, err := p.Write(oversizeHeader(100)[:8]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := cli.RecvApp(); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrDesync) {
			t.Fatalf("RecvApp: err = %v, want ErrDesync", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RecvApp did not return after the mid-frame budget")
	}
	if st := stateOf(cli); st != stIdle {
		t.Fatalf("client state %d after a budget ErrDesync, want IDLE", st)
	}
	exchangeAfterRetake(t, srv, cli)
}

// The server's mid-frame budget: a header cut short ends the session, as it
// does for the client (TestMsg8BudgetEndsSession).
func TestMsg8ServerBudgetEndsSession(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	p := primaryOf(t, srv)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, _, err := srv.RecvAppNumGen(); err != nil { // the admitting PING
		t.Fatal(err)
	}
	srv.MidFrameBudgetMS = 200
	if _, err := cli.Send(oversizeHeader(100)[:8]); err != nil {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, _, _, _, err := srv.RecvAppNumGen()
	wantBudgetDesync(t, "server RecvAppNumGen", err)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("budget desync took %s, want under 2s", d)
	}
}

// setLiveness opens §7.2's gate with both stamps silentMS old. It stores
// atomics only; c.base is read by the readLoop and must not be written here.
func setLiveness(cli *Client, silentMS int64) {
	last := cli.monoMS() - silentMS
	cli.lastRx.Store(last)
	cli.outstandingSince.Store(last)
	cli.outstanding.Store(true)
}

func appSession(t *testing.T) (*Client, *kcp.UDPSession, func()) {
	t.Helper()
	_, cli, cleanup := loopbackPairApp(t)
	cli.mu.Lock()
	sess := cli.kcp
	cli.mu.Unlock()
	return cli, sess, cleanup
}

func TestTransport10StallAndDeadTogetherEndDead(t *testing.T) {
	cli, sess, cleanup := appSession(t)
	defer cleanup()
	setLiveness(cli, SessionDeadMS) // both 10 s clocks started on one envelope
	err := cli.endIfDesync(sess, joinErr(ErrDesync, errPartialTooLong))
	if !errors.Is(err, ErrSessionDead) || errors.Is(err, ErrDesync) {
		t.Fatalf("stall and dead session together: err = %v, want ErrSessionDead", err)
	}
	if !cli.SessionDead() {
		t.Fatal("stall and dead session together: SessionDead() = false, want true")
	}
	if st := stateOf(cli); st != stIdle {
		t.Fatalf("client state %d, want IDLE", st)
	}
}

func TestTransport10StallWithDataOutstandingStaysDesync(t *testing.T) {
	cli, sess, cleanup := appSession(t)
	defer cleanup()
	setLiveness(cli, SessionDeadMS) // a command sent SESSION_DEAD_MS ago...
	cli.lastRx.Store(cli.monoMS())  // ...and an envelope accepted just now
	err := cli.endIfDesync(sess, joinErr(ErrDesync, errPartialTooLong))
	if !errors.Is(err, ErrDesync) {
		t.Fatalf("stall on a live session: err = %v, want ErrDesync", err)
	}
	if cli.SessionDead() {
		t.Fatal("stall on a live session: SessionDead() = true, want false")
	}
}

func TestTransport10DeadTeardownBeforeStallEndsDead(t *testing.T) {
	cli, sess, cleanup := appSession(t)
	defer cleanup()
	cli.teardownIf(sess, true)
	err := cli.endIfDesync(sess, joinErr(ErrDesync, errPartialTooLong))
	if !errors.Is(err, ErrSessionDead) || errors.Is(err, ErrDesync) {
		t.Fatalf("stall reported after the dead teardown: err = %v, want ErrSessionDead", err)
	}
}

func TestTransport10StallJustBeforeDeadStaysDesync(t *testing.T) {
	cli, sess, cleanup := appSession(t)
	defer cleanup()
	setLiveness(cli, SessionDeadMS-100) // 100 ms short of SESSION_DEAD_MS
	err := cli.endIfDesync(sess, joinErr(ErrDesync, errPartialTooLong))
	if !errors.Is(err, ErrDesync) || cli.SessionDead() {
		t.Fatalf("stall 100 ms before the dead limit: err = %v, SessionDead() = %v, want ErrDesync and false", err, cli.SessionDead())
	}
}

func TestTransport10StallWithNothingOutstandingStaysDesync(t *testing.T) {
	cli, sess, cleanup := appSession(t)
	defer cleanup()
	last := cli.monoMS() - SessionDeadMS // stamps old, gate never opened:
	cli.lastRx.Store(last)               // an idle session is never dead
	cli.outstandingSince.Store(last)     // (transport 10.3)
	err := cli.endIfDesync(sess, joinErr(ErrDesync, errPartialTooLong))
	if !errors.Is(err, ErrDesync) || cli.SessionDead() {
		t.Fatalf("stall with nothing outstanding: err = %v, SessionDead() = %v, want ErrDesync and false", err, cli.SessionDead())
	}
}
