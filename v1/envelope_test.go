// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Round trip, plus the on-wire layout: ct || seq_wire[4] || tag[16], seq_wire the
// low 32 bits of seq_full big-endian.
func TestEnvelopeRoundTripAndLayout(t *testing.T) {
	key := fx(0x55, 32)
	msg := []byte("a KCP datagram")
	seqFull := uint64(0x0000_00AB_1234_5678)

	env, err := Seal(key, true, seqFull, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(env) != len(msg)+EnvelopeLen {
		t.Fatalf("envelope len = %d, want %d", len(env), len(msg)+EnvelopeLen)
	}
	// seq_wire field sits between ciphertext and tag and equals low32(seq_full).
	ctLen := len(env) - EnvelopeLen
	gotSW := binary.BigEndian.Uint32(env[ctLen : ctLen+4])
	if gotSW != uint32(seqFull&0xFFFFFFFF) {
		t.Errorf("seq_wire on wire = %#x, want %#x", gotSW, uint32(seqFull&0xFFFFFFFF))
	}
	// ciphertext is not the plaintext (it is encrypted).
	if bytes.Contains(env[:ctLen], msg) {
		t.Error("plaintext visible in ciphertext")
	}

	pt, err := Open(key, true, seqFull, env)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("round trip: pt=%q err=%v", pt, err)
	}
}

// Open must fail on every altered input: wrong key, wrong direction, wrong seq_full
// (the nonce), a tampered ciphertext, or a tampered tag/seq_wire (the AD).
func TestEnvelopeRejects(t *testing.T) {
	key := fx(0x55, 32)
	msg := []byte("payload")
	seq := uint64(42)
	env, _ := Seal(key, true, seq, msg)

	if _, err := Open(fx(0x56, 32), true, seq, env); err == nil {
		t.Error("Open accepted a wrong key")
	}
	if _, err := Open(key, false, seq, env); err == nil {
		t.Error("Open accepted the wrong direction (S2C vs C2S)")
	}
	if _, err := Open(key, true, seq+1, env); err == nil {
		t.Error("Open accepted a wrong seq_full (nonce)")
	}
	// Tamper the ciphertext.
	bad := append([]byte(nil), env...)
	bad[0] ^= 0xff
	if _, err := Open(key, true, seq, bad); err == nil {
		t.Error("Open accepted a tampered ciphertext")
	}
	// Tamper the tag.
	bad2 := append([]byte(nil), env...)
	bad2[len(bad2)-1] ^= 0xff
	if _, err := Open(key, true, seq, bad2); err == nil {
		t.Error("Open accepted a tampered tag")
	}
	// Tamper the seq_wire field (the AD).
	bad3 := append([]byte(nil), env...)
	bad3[len(bad3)-EnvelopeLen] ^= 0xff
	if _, err := Open(key, true, seq, bad3); err == nil {
		t.Error("Open accepted a tampered seq_wire (AD)")
	}
	// Too-short envelope.
	if _, err := Open(key, true, seq, make([]byte, EnvelopeLen-1)); err == nil {
		t.Error("Open accepted an undersized envelope")
	}
}

// The two directions must use different nonces, so the same seq_full under one key
// gives different ciphertext per direction — the property that keeps c2s and s2c
// from sharing a keystream.
func TestEnvelopeDirectionSeparation(t *testing.T) {
	key := fx(0x55, 32)
	msg := []byte("same message same seq")
	c2s, _ := Seal(key, true, 7, msg)
	s2c, _ := Seal(key, false, 7, msg)
	if bytes.Equal(c2s, s2c) {
		t.Fatal("c2s and s2c envelopes identical — direction not in the nonce")
	}
}
