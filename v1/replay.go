// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/binary"
	"math"
	"sync/atomic"
)

// This file covers §8.2–§8.4: the per-direction replay window, the §8.3 range
// check, and the outbound seq_full allocator. Promotion (§8.5) and the primary
// session that owns these live in server.go; here they stand alone so the AEAD +
// replay logic is testable without KCP.

// ReplayWindow is REPLAY_WINDOW (§2).
const ReplayWindow = 256

// replayWindow is one direction's anti-replay state (§8.2): a uint64 high-water
// mark and a REPLAY_WINDOW-bit map of which sequences at or below it are marked.
// Bit offset o corresponds to seq = hwm - o. A fresh window has hwm 0 and no
// marks, so the first datagram (seq_full 1, §3.6) is above the mark and accepted.
type replayWindow struct {
	hwm  uint64
	bits [ReplayWindow / 8]byte
}

func (w *replayWindow) getBit(o uint64) bool { return w.bits[o/8]&(1<<(o%8)) != 0 }

func (w *replayWindow) setBit(o uint64) { w.bits[o/8] |= 1 << (o % 8) }

func (w *replayWindow) putBit(o uint64, v bool) {
	if v {
		w.bits[o/8] |= 1 << (o % 8)
	} else {
		w.bits[o/8] &^= 1 << (o % 8)
	}
}

// shiftUp moves every mark up by n offsets (a mark for seq keeps its seq as hwm
// grows); marks that fall past REPLAY_WINDOW age out. O(REPLAY_WINDOW).
func (w *replayWindow) shiftUp(n uint64) {
	if n >= ReplayWindow {
		for i := range w.bits {
			w.bits[i] = 0
		}
		return
	}
	for b := ReplayWindow - 1; b >= 0; b-- {
		set := false
		if uint64(b) >= n {
			set = w.getBit(uint64(b) - n)
		}
		w.putBit(uint64(b), set)
	}
}

// inRange applies §8.3's candidate range check against the given hwm: a candidate
// is viable iff it is ≥ 1 and not more than REPLAY_WINDOW below hwm. A failure
// here falls through exactly like an AEAD failure (§8.1 step 3).
//
// The `<=` is deliberate: offset == REPLAY_WINDOW passes here and is then refused
// by the window (testAndMark's offset >= ReplayWindow), so it costs one wasted
// AEAD open, never an accepted replay. It matches libshieldnet's sn_in_range
// (src/sn_replay.c) on purpose: the two implementations keep one §8.3 check, and
// the differential oracle (fuzz_differential_test.go) compares the reconstructed
// candidate that feeds it, so tightening one side alone would make them disagree.
func inRange(candidate int64, hwm uint64) bool {
	if candidate < 1 {
		return false
	}
	return int64(hwm)-candidate <= ReplayWindow
}

// wouldAccept reports whether seq would be accepted, WITHOUT marking — for
// §8.5(a)2, where the sn==0 check (a3) must run before the mark (a4).
func (w *replayWindow) wouldAccept(seq uint64) bool {
	if seq > w.hwm {
		return true
	}
	offset := w.hwm - seq
	return offset < ReplayWindow && !w.getBit(offset)
}

// testAndMark implements §8.2's accept test against the current hwm and marks on
// acceptance, as one atomic operation (§8.1 step 4). Returns false — without
// marking — for a replay or an aged-out sequence. seq is the reconstructed
// 64-bit value, and marking happens only after the AEAD has verified.
func (w *replayWindow) testAndMark(seq uint64) bool {
	if seq > w.hwm {
		w.shiftUp(seq - w.hwm)
		w.hwm = seq
		w.setBit(0)
		return true
	}
	offset := w.hwm - seq
	if offset >= ReplayWindow || w.getBit(offset) {
		return false
	}
	w.setBit(offset)
	return true
}

// open attempts one §8.1 candidate: reconstruct seq_full from the wire sequence
// against hwm (§8.3), range-check it, open the AEAD holding no lock, and on
// success test-and-mark the window. Returns (plaintext, seqFull, true) or a false
// third value to fall through to the next candidate / drop. key is k_kcp_<dir>.
func (w *replayWindow) open(key []byte, c2s bool, datagram []byte) ([]byte, uint64, bool) {
	// §3.6/§7.5: a received datagram carries a KCP segment inside the envelope,
	// so the floor is KCP_OVERHEAD + ENVELOPE_LEN, not ENVELOPE_LEN. Open itself
	// cannot apply that bound — it is the envelope primitive and knows nothing of
	// what it wraps — so it belongs on each receive path.
	if len(datagram) < KcpOverhead+EnvelopeLen {
		return nil, 0, false
	}
	seqWire := binary.BigEndian.Uint32(datagram[len(datagram)-EnvelopeLen : len(datagram)-16])
	candidate := Reconstruct(seqWire, w.hwm)
	if !inRange(candidate, w.hwm) { // §8.3 → fall through
		return nil, 0, false
	}
	pt, err := Open(key, c2s, uint64(candidate), datagram)
	if err != nil { // AEAD failure → fall through
		return nil, 0, false
	}
	if !w.testAndMark(uint64(candidate)) { // replay of an opened datagram → drop
		return nil, 0, false
	}
	return pt, uint64(candidate), true
}

// sender allocates outbound seq_full values. §10.1 requires a lock-free CAS that
// fails closed on wrap rather than an atomic add, so two producers (the tick and
// the RX-path ACK flush) never emit two datagrams under one nonce. The stored
// value is the NEXT seq_full to hand out; it starts at 1 (§3.6). A stored 0 is
// the exhausted sentinel.
type sender struct {
	next atomic.Uint64
}

func newSender() *sender {
	s := &sender{}
	s.next.Store(1)
	return s
}

// alloc returns the next seq_full, or (0,false) once the space is exhausted —
// fail closed rather than wrap (§3.6).
func (s *sender) alloc() (uint64, bool) {
	for {
		cur := s.next.Load()
		if cur == 0 {
			return 0, false
		}
		nextv := uint64(0)
		if cur != math.MaxUint64 {
			nextv = cur + 1
		}
		if s.next.CompareAndSwap(cur, nextv) {
			return cur, true
		}
	}
}
