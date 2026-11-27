// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Transport envelope, §3.6. On the wire: ciphertext[n] || seq_wire[4] || tag[16].
// nonce = direction_label[4] || seq_full[8] big-endian; AD = seq_wire (the 4 wire
// octets). Detached ChaCha20-Poly1305-IETF.

// Direction labels, §3.6.
var (
	dirC2S = []byte("C2S\x00")
	dirS2C = []byte("S2C\x00")
)

// ErrEnvelope is a failed AEAD open or a malformed envelope datagram.
var ErrEnvelope = errors.New("shieldnet: envelope open failed")

func nonce(dir []byte, seqFull uint64) []byte {
	n := make([]byte, 12)
	copy(n[:4], dir)
	binary.BigEndian.PutUint64(n[4:], seqFull)
	return n
}

// seqWireBE returns seq_full's low 32 bits as 4 big-endian octets — the AD and the
// on-wire seq_wire field.
func seqWireBE(seqFull uint64) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, seqWireOf(seqFull))
	return b
}

// Seal wraps a KCP datagram into an envelope. key is k_kcp_<dir>; c2s selects the
// direction label. Returns ciphertext || seq_wire || tag.
func Seal(key []byte, c2s bool, seqFull uint64, kcpDatagram []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	dir := dirS2C
	if c2s {
		dir = dirC2S
	}
	sw := seqWireBE(seqFull)
	// Detached: Seal with a nil dst and empty additional prefix gives ct||tag; we
	// then reassemble as ct || seq_wire || tag to match §3.6's layout.
	sealed := aead.Seal(nil, nonce(dir, seqFull), kcpDatagram, sw)
	ctLen := len(sealed) - chacha20poly1305.Overhead
	out := make([]byte, 0, ctLen+EnvelopeLen)
	out = append(out, sealed[:ctLen]...) // ciphertext
	out = append(out, sw...)             // seq_wire
	out = append(out, sealed[ctLen:]...) // tag
	return out, nil
}

// Open reverses Seal. key is k_kcp_<dir>; c2s selects the label; seqFull is the
// reconstructed 64-bit sequence (§8.3), not the wire value. Returns the KCP datagram.
func Open(key []byte, c2s bool, seqFull uint64, envelope []byte) ([]byte, error) {
	// §3.6: the UPPER bound belongs here, not only in the callers. An unbounded
	// Open would AEAD-authenticate a 64 KiB reassembled datagram — the one §12
	// cost that would otherwise scale with an attacker-chosen length. The lower
	// bound here is only what this function itself needs to parse; §7.5's real
	// floor of KCP_OVERHEAD + ENVELOPE_LEN is about what the envelope WRAPS, so
	// it is applied on each receive path (replayWindow.open, tryOpen) instead.
	if len(envelope) < EnvelopeLen || len(envelope) > WireMTU {
		return nil, ErrEnvelope
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	dir := dirS2C
	if c2s {
		dir = dirC2S
	}
	ctLen := len(envelope) - EnvelopeLen
	ct := envelope[:ctLen]
	sw := envelope[ctLen : ctLen+4]
	tag := envelope[ctLen+4:]
	// Reassemble ct||tag for the detached-equivalent Open.
	sealed := make([]byte, 0, ctLen+chacha20poly1305.Overhead)
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	pt, err := aead.Open(nil, nonce(dir, seqFull), sealed, sw)
	if err != nil {
		return nil, ErrEnvelope
	}
	return pt, nil
}
