// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// segOf builds one KCP segment.
func segOf(cmd byte, sn, una uint32, payload []byte) []byte {
	b := make([]byte, KcpOverhead+len(payload))
	binary.LittleEndian.PutUint32(b[0:], 0x01020304)
	b[4] = cmd
	binary.LittleEndian.PutUint16(b[6:], 128)
	binary.LittleEndian.PutUint32(b[kcpSnOff:], sn)
	binary.LittleEndian.PutUint32(b[kcpUnaOff:], una)
	binary.LittleEndian.PutUint32(b[kcpLenOff:], uint32(len(payload)))
	copy(b[KcpOverhead:], payload)
	return b
}

const kcpCmdAck = 82 // IKCP_CMD_ACK

// clientShim is a client-direction shim wired to cli's outstanding gate.
func clientShim(cli *Client) *sessionConn {
	sh := newSessionConn(newMockConn(), &net.UDPAddr{}, bytes.Repeat([]byte{0x11}, 32), true, 0)
	sh.onPush = cli.markOutstanding
	return sh
}

// transport 10.3: outstanding means unacknowledged. A device that acknowledges
// part of the data and goes silent still times out.
func TestTransport103PartialAckStaysOutstanding(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	cli.base = time.Now().Add(-time.Minute)
	sh := clientShim(cli)
	for sn := uint32(0); sn <= 5; sn++ {
		if _, err := sh.WriteTo(segOf(kcpCmdPush, sn, 0, []byte{1}), nil); err != nil {
			t.Fatal(err)
		}
	}
	if !cli.outstanding.Load() {
		t.Fatal("precondition: PUSHes sent but the gate is closed")
	}
	cli.inboundAccepted(sh, segOf(kcpCmdAck, 2, 3, nil))
	if !cli.outstanding.Load() {
		t.Fatal("una=3 with sn up to 5 sent closed the gate")
	}
	old := cli.monoMS() - 2*SessionDeadMS
	cli.lastRx.Store(old)
	cli.outstandingSince.Store(old)
	if !cli.livenessExpired() {
		t.Fatal("livenessExpired false with data unacknowledged for SESSION_DEAD_MS")
	}
	cli.inboundAccepted(sh, segOf(kcpCmdAck, 5, 6, nil))
	if cli.outstanding.Load() {
		t.Fatal("una=6 acknowledges sn 0..5 but the gate stayed open")
	}
}

func TestTransport103LatePushReopensGate(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	sh := clientShim(cli)
	for sn := uint32(0); sn <= 5; sn++ {
		sh.WriteTo(segOf(kcpCmdPush, sn, 0, []byte{1}), nil)
	}
	cli.inboundAccepted(sh, segOf(kcpCmdAck, 5, 6, nil))
	if cli.outstanding.Load() {
		t.Fatal("precondition: una=6 did not close the gate")
	}
	sh.WriteTo(segOf(kcpCmdPush, 6, 0, []byte{1}), nil)
	if !cli.outstanding.Load() {
		t.Fatal("a PUSH with sn=6 going out did not reopen the gate")
	}
	sh.wipe()
	cli.outstanding.Store(false)
	sh.WriteTo(segOf(kcpCmdPush, 7, 0, []byte{1}), nil)
	if cli.outstanding.Load() {
		t.Fatal("a PUSH refused by a wiped shim opened the gate")
	}
}

func TestTransport103SegmentWalkBounds(t *testing.T) {
	good := segOf(kcpCmdPush, 9, 4, []byte{1, 2, 3})
	for _, b := range [][]byte{
		nil,
		good[:KcpOverhead-1],                    // truncated header
		good[:KcpOverhead+1],                    // len runs past the datagram
		append(append([]byte(nil), good...), 1), // trailing junk shorter than a header
	} {
		maxPushSn(b)
		maxUna(b)
	}
	huge := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(huge[kcpLenOff:], 0xFFFFFFFF)
	if _, ok := maxPushSn(huge); ok {
		t.Error("a segment whose len overruns the datagram was counted")
	}
	if _, ok := maxUna(huge); ok {
		t.Error("the una of a segment whose len overruns the datagram was counted")
	}
	// sn wraps: 0 follows 0xFFFFFFFF.
	wrap := append(segOf(kcpCmdPush, 0xFFFFFFFF, 0, nil), segOf(kcpCmdPush, 0, 0, nil)...)
	if sn, ok := maxPushSn(wrap); !ok || sn != 0 {
		t.Errorf("maxPushSn across the wrap = %d, %v; want 0", sn, ok)
	}
	if una, ok := maxUna(append(segOf(kcpCmdAck, 0, 0xFFFFFFFF, nil), segOf(kcpCmdAck, 0, 1, nil)...)); !ok || una != 1 {
		t.Errorf("maxUna across the wrap = %d, %v; want 1", una, ok)
	}
	sh := newSessionConn(newMockConn(), &net.UDPAddr{}, bytes.Repeat([]byte{0x11}, 32), true, 0)
	sh.onPush = func() {}
	sh.WriteTo(segOf(kcpCmdPush, 0xFFFFFFFF, 0, nil), nil)
	sh.WriteTo(segOf(kcpCmdPush, 0, 0, nil), nil)
	if sh.maxSn != 0 {
		t.Errorf("recorded maxSn across the wrap = %d, want 0", sh.maxSn)
	}
}

// A retransmit of a PUSH the peer's una already covers is not unacknowledged
// data: it must not reopen the gate, or an idle session whose ACK for the
// duplicate is lost is declared dead (transport 10.3 rule 5).
func TestTransport103AckedRetransmitKeepsGateClosed(t *testing.T) {
	_, cli, cleanup := loopbackPairIdle(t)
	defer cleanup()
	sh := clientShim(cli)
	sh.WriteTo(segOf(kcpCmdPush, 0, 0, []byte{1}), nil)
	cli.inboundAccepted(sh, segOf(kcpCmdAck, 0, 1, nil))
	if cli.outstanding.Load() {
		t.Fatal("precondition: una=1 did not close the gate")
	}
	sh.WriteTo(segOf(kcpCmdPush, 0, 0, []byte{1}), nil) // retransmit of sn 0
	if cli.outstanding.Load() {
		t.Fatal("a retransmit of an acknowledged sn reopened the gate")
	}
	sh.WriteTo(segOf(kcpCmdPush, 1, 0, []byte{1}), nil) // sn at una
	if !cli.outstanding.Load() {
		t.Fatal("a PUSH with sn at una did not open the gate")
	}
}
