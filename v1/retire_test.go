// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// transport 12.2 item 6: from the claim on, nothing is sealed on the retired
// session. kcp-go sends from goroutines of its own (the update timer, the
// output pipeline), so the test writes on the retired session at the claim
// and gives that pipeline time to reach the socket.
func TestTransport122RetiredSendsNothingAfterClaim(t *testing.T) {
	srv, mock, keys, addr := admitted(t)
	defer srv.Close()
	env, err := Seal(keys.KKcpC2S, true, 1, kcpPush(0x11223344, make([]byte, 20)))
	if err != nil {
		t.Fatal(err)
	}
	srv.handlePacket(env, addr)
	old := srv.Primary()
	if old == nil {
		t.Fatal("no first primary")
	}

	addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 4, 3), Port: 5001}
	keys2 := readmit(t, srv, mock, addr2, 0x61)
	env2, err := Seal(keys2.KKcpC2S, true, 1, kcpPush(0x55667788, make([]byte, 20)))
	if err != nil {
		t.Fatal(err)
	}
	before := mock.count()
	testHookRetiredClaimed = func(retired *kcp.UDPSession) {
		if retired != old {
			t.Errorf("retired session is not the first primary")
		}
		n := mock.count()
		_, _ = retired.Write([]byte("data the client never acknowledges"))
		for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && mock.count() == n; {
			time.Sleep(5 * time.Millisecond)
		}
	}
	defer func() { testHookRetiredClaimed = nil }()
	srv.handlePacket(env2, addr2)
	if p := srv.Primary(); p == old || p == nil {
		t.Fatal("the second client was not promoted")
	}
	mock.mu.Lock()
	sent := append([][]byte(nil), mock.sent[before:]...)
	mock.mu.Unlock()
	for i, d := range sent {
		var w replayWindow
		if _, _, ok := w.open(keys.KKcpS2C, false, d); ok {
			t.Fatalf("datagram %d after the claim opens under the retired session's k_kcp_s2c", i)
		}
	}
}
