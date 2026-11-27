// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"math"
	"math/rand"
	"testing"
)

func TestReplayWindowAcceptAdvance(t *testing.T) {
	var w replayWindow
	// first datagram seq_full=1 accepted, advances hwm
	if !w.testAndMark(1) || w.hwm != 1 {
		t.Fatal("seq 1 not accepted")
	}
	// duplicate rejected, no state change
	if w.testAndMark(1) {
		t.Error("seq 1 replay accepted")
	}
	// forward jump accepted
	if !w.testAndMark(100) || w.hwm != 100 {
		t.Error("seq 100 not accepted")
	}
	// in-window backfill (never seen) accepted
	if !w.testAndMark(50) {
		t.Error("in-window backfill 50 rejected")
	}
	// same backfill now a replay
	if w.testAndMark(50) {
		t.Error("backfill replay accepted")
	}
	// exactly REPLAY_WINDOW below hwm is aged out; one above the edge is in window
	var w2 replayWindow
	w2.testAndMark(1000)
	if w2.testAndMark(1000 - ReplayWindow) { // 744: exactly window below → offset 256 → aged
		t.Error("aged-out sequence (offset == window) accepted")
	}
	if !w2.testAndMark(1000 - ReplayWindow + 1) { // 745: offset 255 → in window
		t.Error("edge-of-window sequence rejected")
	}
}

func TestInRange(t *testing.T) {
	if inRange(0, 10) {
		t.Error("candidate 0 accepted")
	}
	if inRange(-5, 10) {
		t.Error("negative candidate accepted")
	}
	if !inRange(11, 10) {
		t.Error("candidate above hwm rejected")
	}
	// exactly REPLAY_WINDOW below hwm is in range; more is not
	if !inRange(1000-ReplayWindow, 1000) {
		t.Error("exactly window below rejected")
	}
	if inRange(1000-ReplayWindow-1, 1000) {
		t.Error("more than window below accepted")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	send := newSender()
	var rw replayWindow
	// At least KCP_OVERHEAD: rw.open applies §7.5's floor, so a payload shorter
	// than the KCP segment it stands in for is rejected before the AEAD.
	payload := []byte("kcp datagram bytes, padded to a full segment")

	for i := 0; i < 5; i++ {
		seq, ok := send.alloc()
		if !ok {
			t.Fatal("alloc failed")
		}
		env, err := Seal(key, true, seq, payload)
		if err != nil {
			t.Fatal(err)
		}
		pt, gotSeq, accepted := rw.open(key, true, env)
		if !accepted {
			t.Fatalf("datagram %d not accepted", i)
		}
		if gotSeq != seq {
			t.Errorf("seq: got %d want %d", gotSeq, seq)
		}
		if !bytes.Equal(pt, payload) {
			t.Error("plaintext mismatch")
		}
	}
	// replay the first datagram (seq 1) → rejected (aged/marked, or below window)
	env1, _ := Seal(key, true, 1, payload)
	if _, _, ok := rw.open(key, true, env1); ok {
		t.Error("replayed datagram accepted")
	}
}

func TestOpenWrongKeyFallsThrough(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	wrong := bytes.Repeat([]byte{0x5B}, 32)
	var rw replayWindow
	env, _ := Seal(key, true, 1, []byte("a stand-in kcp segment, >= 24 bytes"))
	if _, _, ok := rw.open(wrong, true, env); ok {
		t.Error("opened under the wrong key")
	}
	// window untouched by a failed open → the right key still works
	if _, _, ok := rw.open(key, true, env); !ok {
		t.Error("failed open marked the window")
	}
}

func TestReadmitSeqOneFallsThrough(t *testing.T) {
	// §8.3: a client re-admitting on a tuple its old session holds sends
	// seq_wire=1 against a primary whose hwm is high; it must fail the range
	// check (fall through), not be mistaken for a primary datagram.
	key := bytes.Repeat([]byte{0x5A}, 32)
	rw := replayWindow{hwm: 5000}
	env, _ := Seal(key, true, 1, []byte("readmit push, >= KCP_OVERHEAD bytes"))
	if _, _, ok := rw.open(key, true, env); ok {
		t.Error("seq_full=1 accepted against hwm 5000 (should fall through)")
	}
}

func TestSenderFailClosedOnWrap(t *testing.T) {
	s := newSender()
	s.next.Store(math.MaxUint64)
	last, ok := s.alloc()
	if !ok || last != math.MaxUint64 {
		t.Fatalf("last alloc: got %d,%v", last, ok)
	}
	if _, ok := s.alloc(); ok {
		t.Error("allocated past the limit instead of failing closed")
	}
}

// Differential fuzz of the sliding window against a straightforward reference
// model, mirroring the C suite's fuzz_replay_window. This is the regression test
// for shiftUp: the window is only correct while it stays behaviourally identical
// to the obvious implementation, and the other cases here never exercise a
// multi-bit slide. A divergence here is a replay-acceptance bug.
func TestReplayWindowDifferentialFuzz(t *testing.T) {
	// Large enough that hwm does not saturate before the loop ends: the walk
	// advances ~55/iteration, so 60k iterations need >3.3M of range. At 200000
	// the window stopped sliding after ~3500 iterations and 94% of the run
	// exercised nothing.
	const refMax = 4000000
	seen := make([]bool, refMax+1)
	var refHWM uint64

	refAccept := func(seq uint64) bool {
		if seq == 0 || seq > refMax {
			return false
		}
		if refHWM != 0 && seq+ReplayWindow <= refHWM {
			return false // aged out
		}
		if seen[seq] {
			return false // replay
		}
		seen[seq] = true
		if seq > refHWM {
			refHWM = seq
		}
		return true
	}

	var w replayWindow
	rng := rand.New(rand.NewSource(0xB1A5E)) // fixed seed: reproducible failures
	seq := int64(1)
	accepted := make([]int64, 0, 4096)

	for i := 0; i < 60000; i++ {
		var cand int64
		switch r := rng.Intn(100); {
		case r < 40:
			cand = seq + 1 + int64(rng.Intn(3))
		case r < 58:
			cand = seq + 1 + int64(rng.Intn(600)) // jump: multi-byte slide
		case r < 72:
			cand = seq - int64(rng.Intn(300)) // backfill, in and out of window
		case r < 86 && len(accepted) > 0:
			// Re-probe a mark we already set. This is what actually tests
			// shiftUp: if a slide loses a bit, the replay is wrongly accepted.
			cand = accepted[rng.Intn(len(accepted))]
		case r < 96:
			// Probe the window edge exactly, where an off-by-one lives.
			cand = int64(refHWM) - int64(ReplayWindow) + int64(rng.Intn(3))
		default:
			cand = seq // immediate replay
		}
		if cand < 1 {
			cand = 1
		}
		if cand > refMax {
			cand = refMax
		}

		prevHWM := refHWM
		want := refAccept(uint64(cand))
		got := w.testAndMark(uint64(cand))
		if want != got {
			t.Fatalf("i=%d seq=%d hwm=%d: want accept=%v, got %v", i, cand, prevHWM, want, got)
		}
		if w.hwm != refHWM {
			t.Fatalf("i=%d seq=%d: hwm divergence impl=%d ref=%d", i, cand, w.hwm, refHWM)
		}
		if got {
			if len(accepted) < cap(accepted) {
				accepted = append(accepted, cand)
			} else {
				accepted[rng.Intn(len(accepted))] = cand
			}
		}

		// Compare the entire window against the model, not just this call's
		// verdict. A slide that corrupts a bit is otherwise invisible until a
		// probe happens to land on that exact sequence while it is still in
		// window, which a random walk almost never does.
		for o := uint64(0); o < ReplayWindow; o++ {
			if w.hwm <= o {
				break // seq would be < 1
			}
			at := w.hwm - o
			implBit := w.getBit(o)
			refBit := at <= refMax && seen[at]
			if implBit != refBit {
				t.Fatalf("i=%d off=%d seq=%d hwm=%d: window bit impl=%v ref=%v",
					i, o, at, w.hwm, implBit, refBit)
			}
		}

		if int64(refHWM) > seq {
			seq = int64(refHWM)
		}
	}
}
