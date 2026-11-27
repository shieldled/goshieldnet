// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// mockConn is the server's shared socket for tests: it captures every WriteTo
// (RETRY/ADMIT and the shim's sealed s2c datagrams). ReadFrom blocks — the test
// drives handlePacket directly rather than via Serve.
type mockConn struct {
	closeOnce sync.Once
	mu        sync.Mutex
	sent      [][]byte
	done      chan struct{}
}

func newMockConn() *mockConn { return &mockConn{done: make(chan struct{})} }

func (m *mockConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-m.done
	return 0, nil, net.ErrClosed
}
func (m *mockConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	m.mu.Lock()
	m.sent = append(m.sent, append([]byte(nil), p...))
	m.mu.Unlock()
	return len(p), nil
}
func (m *mockConn) Close() error { m.closeOnce.Do(func() { close(m.done) }); return nil }
func (m *mockConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 168, 4, 1), Port: 7000}
}
func (m *mockConn) SetDeadline(time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(time.Time) error { return nil }
func (m *mockConn) lastSent() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return nil
	}
	return m.sent[len(m.sent)-1]
}
func (m *mockConn) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.sent) }

// a hand-built KCP PUSH sn=0 (frg=0), what a client's first message looks like.
func kcpPush(conv uint32, payload []byte) []byte {
	b := make([]byte, KcpOverhead+len(payload))
	binary.LittleEndian.PutUint32(b[0:], conv)
	b[4] = kcpCmdPush
	b[5] = 0                                  // frg
	binary.LittleEndian.PutUint16(b[6:], 128) // wnd
	binary.LittleEndian.PutUint32(b[8:], 0)   // ts
	binary.LittleEndian.PutUint32(b[12:], 0)  // sn
	binary.LittleEndian.PutUint32(b[16:], 0)  // una
	binary.LittleEndian.PutUint32(b[20:], uint32(len(payload)))
	copy(b[KcpOverhead:], payload)
	return b
}

func TestServerPromotionAndEstablished(t *testing.T) {
	mock := newMockConn()
	defer mock.Close()
	dev, deviceID := testDevice()
	dev.SetRandSource(fixedRand(0x42))
	srv := NewServer(dev, mock)

	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 4, 2), Port: 5000}
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)

	// INIT → RETRY
	srv.handlePacket(validINIT(dev.kReq, nonce, deviceID), clientAddr)
	if mock.count() != 1 {
		t.Fatalf("no RETRY emitted (%d sent)", mock.count())
	}
	retry := mock.lastSent()

	// FINISH → ADMIT
	fin, ecPub, context := clientFINISH(deviceID, nonce, ecPriv, retry)
	srv.handlePacket(fin, clientAddr)
	if mock.count() != 2 {
		t.Fatalf("no ADMIT emitted")
	}
	admit := mock.lastSent()

	// client derives session keys from ADMIT
	af, err := DecodeADMIT(admit)
	if err != nil {
		t.Fatal(err)
	}
	context2 := Context2(context, ecPub, af.ES)
	dh, err := DH(ecPriv, af.ES)
	if err != nil {
		t.Fatal(err)
	}
	master := Master(context2, DeriveKDev(testPSK, deviceID), dh)
	keys := DeriveSession(master)

	// build + seal the promoting PUSH sn=0 under k_kcp_c2s, seq_full=1
	conv := uint32(0x11223344)
	push := kcpPush(conv, []byte("hello-server"))
	env, err := Seal(keys.KKcpC2S, true, 1, push)
	if err != nil {
		t.Fatal(err)
	}

	// promote
	srv.handlePacket(env, clientAddr)
	if srv.Primary() == nil {
		t.Fatal("no primary after promoting PUSH")
	}
	if srv.primary.convID != conv {
		t.Errorf("conv not bound: got %#x", srv.primary.convID)
	}
	if dev.findPending(Canonicalize(netip.MustParseAddr("192.168.4.2"), 5000)) >= 0 {
		t.Error("pending record not cleared after promotion")
	}

	// the server reads the first message off the established KCP stream
	prim := srv.Primary()
	prim.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := prim.Read(buf)
	if err != nil {
		t.Fatalf("primary read: %v", err)
	}
	if string(buf[:n]) != "hello-server" {
		t.Errorf("first message: got %q", buf[:n])
	}

	// duplicate promoting datagram → replay-drop at the primary, no new session
	genBefore := srv.primary.gen
	sessBefore := srv.primary.conn
	srv.handlePacket(env, clientAddr)
	if srv.primary.gen != genBefore || srv.primary.conn != sessBefore {
		t.Error("duplicate promoting datagram created a new session")
	}

	// server → client app data: kcp-go flush seals an s2c datagram the client opens
	before := mock.count()
	prim.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := prim.Write([]byte("ack-from-server")); err != nil {
		t.Fatal(err)
	}
	// wait for the kcp-go flush to emit
	deadline := time.Now().Add(2 * time.Second)
	for mock.count() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mock.count() == before {
		t.Fatal("server never emitted an s2c datagram")
	}
	sealed := mock.lastSent()
	// client opens it under k_kcp_s2c
	var s2cWin replayWindow
	if _, _, ok := s2cWin.open(keys.KKcpS2C, false, sealed); !ok {
		t.Error("client could not open the server's s2c datagram")
	}
}
