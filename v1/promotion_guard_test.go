// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// kcpSeg builds a KCP segment with an explicit command and sequence number, so a
// test can offer the device something that is NOT the §8.5(a)3 promoting PUSH.
func kcpSeg(conv uint32, cmd byte, sn uint32, payload []byte) []byte {
	b := kcpPush(conv, payload)
	b[4] = cmd
	binary.LittleEndian.PutUint32(b[12:], sn)
	return b
}

// admitted runs INIT/RETRY/FINISH/ADMIT against a mock-backed server and returns
// the session keys a client would derive, ready to seal a promoting datagram.
func admitted(t *testing.T) (*Server, *mockConn, SessionKeys, *net.UDPAddr) {
	t.Helper()
	mock := newMockConn()
	dev, deviceID := testDevice()
	dev.SetRandSource(fixedRand(0x42))
	srv := NewServer(dev, mock)

	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 4, 2), Port: 5000}
	nonce := bytes.Repeat([]byte{0xAB}, 24)
	ecPriv := bytes.Repeat([]byte{0x07}, 32)

	srv.handlePacket(validINIT(dev.kReq, nonce, deviceID), clientAddr)
	retry := mock.lastSent()
	fin, ecPub, context := clientFINISH(deviceID, nonce, ecPriv, retry)
	srv.handlePacket(fin, clientAddr)
	admit := mock.lastSent()

	af, err := DecodeADMIT(admit)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := DH(ecPriv, af.ES)
	if err != nil {
		t.Fatal(err)
	}
	master := Master(Context2(context, ecPub, af.ES), DeriveKDev(testPSK, deviceID), dh)
	return srv, mock, DeriveSession(master), clientAddr
}

// §8.5(a)3 — a pending record is promoted ONLY by a KCP PUSH with sn == 0. The
// guards existed but nothing constructed a datagram that violates them: every
// test reached promotion through kcpPush, which satisfies all of them. Removing
// either check left the whole suite green while any envelope that opened under a
// pending record's keys — an ACK, a mid-stream segment — installed a primary
// whose replay window is marked at an arbitrary sequence.
func TestPromotionRequiresPushSnZero(t *testing.T) {
	const kcpCmdAck = 82 // IKCP_CMD_ACK

	for _, tc := range []struct {
		name string
		seg  []byte
	}{
		{"ACK, not PUSH", kcpSeg(0x11223344, kcpCmdAck, 0, []byte("x"))},
		{"PUSH with sn=1", kcpSeg(0x11223344, kcpCmdPush, 1, []byte("x"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, keys, addr := admitted(t)
			defer srv.Close()

			env, err := Seal(keys.KKcpC2S, true, 1, tc.seg)
			if err != nil {
				t.Fatal(err)
			}
			srv.handlePacket(env, addr)
			if srv.Primary() != nil {
				t.Fatal("promoted on a datagram that is not a PUSH sn=0")
			}
		})
	}

	// The control: the same path with a conforming PUSH sn=0 DOES promote, so the
	// cases above are rejected by the guard and not by some unrelated failure.
	t.Run("PUSH sn=0 promotes", func(t *testing.T) {
		srv, _, keys, addr := admitted(t)
		defer srv.Close()
		env, err := Seal(keys.KKcpC2S, true, 1, kcpPush(0x11223344, []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		srv.handlePacket(env, addr)
		if srv.Primary() == nil {
			t.Fatal("a conforming promoting PUSH did not promote")
		}
	})
}

// §8.1 step 3 — when a primary and a pending record share one tuple, a datagram
// that fails to open under the primary MUST fall through to the pending
// candidate. That is the re-admission case: the same client, same source port,
// admitting again while the device still holds its old session. Turning the
// candidate loop's `continue` into a `return` left every existing test green,
// because no test ever put both records on one tuple, and poisoned the tuple
// until the client changed port or the device rebooted.
func TestReadmitOnALiveTupleFallsThrough(t *testing.T) {
	srv, mock, keys, addr := admitted(t)
	defer srv.Close()

	// establish a primary on this tuple
	env, err := Seal(keys.KKcpC2S, true, 1, kcpPush(0x11223344, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	srv.handlePacket(env, addr)
	if srv.Primary() == nil {
		t.Fatal("no primary to re-admit over")
	}
	first := srv.Primary()

	// the same client admits again from the SAME source port: a second pending
	// record now shares the tuple with the live primary.
	nonce2 := bytes.Repeat([]byte{0xCD}, 24)
	ecPriv2 := bytes.Repeat([]byte{0x09}, 32)
	deviceID := srv.dev.DeviceID
	srv.handlePacket(validINIT(srv.dev.kReq, nonce2, deviceID), addr)
	retry2 := mock.lastSent()
	fin2, ecPub2, context2 := clientFINISH(deviceID, nonce2, ecPriv2, retry2)
	srv.handlePacket(fin2, addr)
	af2, err := DecodeADMIT(mock.lastSent())
	if err != nil {
		t.Fatal(err)
	}
	dh2, err := DH(ecPriv2, af2.ES)
	if err != nil {
		t.Fatal(err)
	}
	keys2 := DeriveSession(Master(Context2(context2, ecPub2, af2.ES), DeriveKDev(testPSK, deviceID), dh2))

	// the new promoting PUSH cannot open under the primary's key; it must fall
	// through to the pending record and promote.
	env2, err := Seal(keys2.KKcpC2S, true, 1, kcpPush(0x55667788, []byte("y")))
	if err != nil {
		t.Fatal(err)
	}
	srv.handlePacket(env2, addr)

	p := srv.Primary()
	if p == nil {
		t.Fatal("re-admission on a live tuple did not promote: the tuple is poisoned")
	}
	if p == first {
		t.Fatal("still the old primary: the second candidate was never tried")
	}
	if srv.primary.convID != 0x55667788 {
		t.Errorf("conv = %#x, want the re-admitted session's %#x", srv.primary.convID, 0x55667788)
	}
}
