// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"net"
	"testing"
	"time"
)

// exchangeOne sends one control message from cli and reads it on srv.
func exchangeOne(t *testing.T, srv *Server, cli *Client, b byte) {
	t.Helper()
	if err := cli.SendAppPadded(CmdPing, []byte{b}); err != nil {
		t.Fatalf("SendAppPadded: %v", err)
	}
	p := primaryOf(t, srv)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer p.SetReadDeadline(time.Time{})
	for {
		_, _, got, _, err := srv.RecvAppNumGen()
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		if len(got) == 1 && got[0] == b {
			return
		}
	}
}

// transport 10.3: a client can end its session and take control again.
func TestTransport103EndSessionThenRetake(t *testing.T) {
	srv, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	exchangeOne(t, srv, cli, 1)
	if err := cli.EndSession(); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	if st := stateOf(cli); st != stIdle {
		t.Fatalf("state %d after EndSession, want IDLE", st)
	}
	if err := cli.EndSession(); err != nil {
		t.Fatalf("EndSession in IDLE: %v", err)
	}
	if err := cli.TakeControlApp(CmdPing, nil); err != nil {
		t.Fatalf("TakeControlApp after EndSession: %v", err)
	}
	exchangeOne(t, srv, cli, 2)
}

func TestTransport103EndSessionAfterClose(t *testing.T) {
	_, cli, cleanup := loopbackPairApp(t)
	defer cleanup()
	cli.Close()
	if err := cli.EndSession(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("EndSession after Close: err = %v, want net.ErrClosed", err)
	}
}
