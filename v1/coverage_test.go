// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// §6.2 step 3a — a FINISH is accepted against the CURRENT or the PREVIOUS epoch
// tag as of the caller's clock, and nothing else. Making the check return true
// unconditionally defeats epoch rotation entirely (the cookie is recomputed from
// the attacker-supplied tag), so pin both sides of it.
func TestEpochTagAcceptsCurrentAndPreviousOnly(t *testing.T) {
	dev, _ := testDevice()
	now := uint64(10*CookieEpochMS + 7)
	cur, prev := dev.epochTagsAt(now)
	tagOf := func(ep uint32) []byte { return EpochTag(dev.cookieSecret, be4(ep)) }

	if !bytes.Equal(cur, tagOf(10)) || !bytes.Equal(prev, tagOf(9)) {
		t.Fatal("epochTagsAt did not return epochs 10 and 9 for a clock in epoch 10")
	}
	if !epochTagKnown(tagOf(10), cur, prev) {
		t.Error("current epoch tag rejected")
	}
	if !epochTagKnown(tagOf(9), cur, prev) {
		t.Error("previous epoch tag rejected: a RETRY minted just before the " +
			"boundary has its FINISH silently dropped")
	}
	for _, ep := range []uint32{8, 11} {
		if epochTagKnown(tagOf(ep), cur, prev) {
			t.Errorf("epoch %d's tag accepted in epoch 10", ep)
		}
	}
	if epochTagKnown(bytes.Repeat([]byte{0x99}, 8), cur, prev) {
		t.Error("an unknown epoch tag was accepted: epoch rotation is defeated")
	}
	if _, p0 := dev.epochTagsAt(5); p0 != nil {
		t.Error("epoch 0 has no previous epoch, but one was returned")
	}
}

// §2 sizes COOKIE_EPOCH_MS so a suppressed capture is useful for at most 8 s.
// The acceptance window must follow the caller's clock, not the cached tags: a
// stalled maintenance tick must neither keep an old tag live nor reject a fresh
// one.
func TestMissedTickDoesNotWidenTheEpochWindow(t *testing.T) {
	dev, _ := testDevice()
	dev.RollEpoch(0)
	stale := append([]byte(nil), dev.epochTag...)

	// The tick stalls across four epochs; the cache still holds epoch 0.
	cur, prev := dev.epochTagsAt(4 * CookieEpochMS)
	if epochTagKnown(stale, cur, prev) {
		t.Error("a tag four epochs old is still accepted; the window widened past §2's bound")
	}
	if !epochTagKnown(EpochTag(dev.cookieSecret, be4(4)), cur, prev) {
		t.Error("the current epoch's tag is rejected while the tick is stalled")
	}

	// rollEpochLocked still refuses to keep a previous tag across a jump.
	dev.rollEpochLocked(4 * CookieEpochMS)
	if dev.prevEpochTag != nil {
		t.Error("prevEpochTag survived a multi-epoch jump")
	}
}

// §10.1 requires alloc to be a CAS precisely so two producers never receive the
// same seq_full — a duplicate is direct ChaCha20 keystream reuse under one key.
// The existing tests were single-threaded, so replacing the CAS loop with a
// plain Add left them all passing.
func TestSenderAllocIsDuplicateFreeUnderConcurrency(t *testing.T) {
	const goroutines, each = 8, 500
	s := newSender()

	var mu sync.Mutex
	seen := make(map[uint64]bool, goroutines*each)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := make([]uint64, 0, each)
			for i := 0; i < each; i++ {
				v, ok := s.alloc()
				if !ok {
					t.Error("alloc exhausted early")
					return
				}
				got = append(got, v)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, v := range got {
				if seen[v] {
					t.Errorf("seq_full %d allocated twice: keystream reuse", v)
				}
				seen[v] = true
			}
		}()
	}
	wg.Wait()
	if len(seen) != goroutines*each {
		t.Errorf("allocated %d distinct sequences, want %d", len(seen), goroutines*each)
	}
}

// The same property for the message layer's MessageNum (§6.4).
func TestAppMessageNumIsDuplicateFreeUnderConcurrency(t *testing.T) {
	const goroutines, each = 8, 500
	p := &appPeer{}

	var mu sync.Mutex
	seen := make(map[uint64]bool, goroutines*each)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := make([]uint64, 0, each)
			for i := 0; i < each; i++ {
				n := p.nextTx()
				if n == 0 {
					t.Error("MessageNum space exhausted early")
					return
				}
				got = append(got, n)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, n := range got {
				if seen[n] {
					t.Errorf("MessageNum %d allocated twice: nonce reuse under k_c2s", n)
				}
				seen[n] = true
			}
		}()
	}
	wg.Wait()
	if len(seen) != goroutines*each {
		t.Errorf("allocated %d distinct MessageNums, want %d", len(seen), goroutines*each)
	}
}

// §4.2 keeps admission_epoch's top 8 bits clear. The fail-closed branch had no
// test, so relaxing the bound to `>` would let the value wrap into the reserved
// range unnoticed.
func TestAdmissionEpochFailsClosedAtTheBoundary(t *testing.T) {
	be := func(v uint64) []byte {
		b := make([]byte, 8)
		for i := 7; i >= 0; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		return b
	}
	if _, ok := incAdmissionEpoch(be(admissionEpochMax - 2)); !ok {
		t.Error("refused a value still inside §4.2's range")
	}
	if _, ok := incAdmissionEpoch(be(admissionEpochMax - 1)); ok {
		t.Error("incrementing to 2^56 was allowed: the top 8 bits are no longer clear")
	}
	if _, ok := incAdmissionEpoch(be(admissionEpochMax)); ok {
		t.Error("a value already at the ceiling was incremented")
	}
}

// §6.3 — installSlot wipes the keys of the record it is about to reuse, whether
// it is replacing the same tuple or evicting the oldest. The existing test only
// asserted which slots were occupied afterwards, so deleting both wipeKeys calls
// left an evicted client's session keys resident.
func TestInstallSlotWipesTheRecordItReuses(t *testing.T) {
	fill := func(r *pendingRecord, b byte) {
		r.used = true
		r.keys = SessionKeys{
			KC2S: bytes.Repeat([]byte{b}, 32), KS2C: bytes.Repeat([]byte{b}, 32),
			KKcpC2S: bytes.Repeat([]byte{b}, 32), KKcpS2C: bytes.Repeat([]byte{b}, 32),
		}
	}
	live := func(r *pendingRecord) bool {
		for _, k := range [][]byte{r.keys.KC2S, r.keys.KS2C, r.keys.KKcpC2S, r.keys.KKcpS2C} {
			for _, b := range k {
				if b != 0 {
					return true
				}
			}
		}
		return false
	}

	t.Run("replacing the same tuple", func(t *testing.T) {
		dev, _ := testDevice()
		tuple := bytes.Repeat([]byte{0x01}, len(dev.pending[0].tuple))
		fill(&dev.pending[0], 0xAA)
		copy(dev.pending[0].tuple[:], tuple)
		keys := dev.pending[0].keys

		if got := dev.installSlot(tuple); got != 0 {
			t.Fatalf("slot = %d, want the matching one (0)", got)
		}
		if live(&pendingRecord{keys: keys}) {
			t.Error("the replaced record's keys are still resident")
		}
	})

	t.Run("evicting the oldest", func(t *testing.T) {
		dev, _ := testDevice()
		for i := range dev.pending {
			fill(&dev.pending[i], byte(0xB0+i))
			copy(dev.pending[i].tuple[:], bytes.Repeat([]byte{byte(i + 1)}, len(dev.pending[i].tuple)))
			dev.pending[i].expiry = uint32(1000 + i)
		}
		evictedKeys := dev.pending[0].keys // slot 0 has the earliest expiry

		got := dev.installSlot(bytes.Repeat([]byte{0xEE}, len(dev.pending[0].tuple)))
		if got != 0 {
			t.Fatalf("evicted slot = %d, want the oldest (0)", got)
		}
		if live(&pendingRecord{keys: evictedKeys}) {
			t.Error("the evicted record's keys are still resident")
		}
	})
}

// The §7 receive rules for compressed and padded frames, exercised through
// recvAppWith itself.
//
// These branches were previously reached only by app_interop_test.go, which
// skips without a built C host — so on a default `go test ./...` run the whole
// decompression and pad-validation path was unexecuted, and the test named for
// the length rules never called the function that implements them.
func TestRecvAppCompressionAndPaddingRules(t *testing.T) {
	key := bytes.Repeat([]byte{0x5C}, 32)
	recv := func(frame []byte) (uint32, []byte, error) {
		var rx uint64
		typ, _, p, err := recvAppWith(bytes.NewReader(frame), key, &rx, &rxStage{}, MaxMsgPayloadDefault, 0, MaxMsgPayloadDefault)
		return typ, p, err
	}

	t.Run("compressed round trip", func(t *testing.T) {
		payload := bytes.Repeat([]byte("shieldnet"), 200) // compresses well
		f, err := frameAppWith(key, 1, anyBulkKind, payload, true, false, MaxMsgPayloadDefault)
		if err != nil {
			t.Fatal(err)
		}
		typ, got, err := recv(f)
		if err != nil {
			t.Fatalf("compressed frame rejected: %v", err)
		}
		if typ != anyBulkKind {
			t.Errorf("type = %#x, want %#x (FlagCompressed must be cleared)", typ, anyBulkKind)
		}
		if !bytes.Equal(got, payload) {
			t.Error("decompressed payload differs from the original")
		}
	})

	t.Run("decompressed length must EQUAL OriginalSize", func(t *testing.T) {
		// A block that inflates to fewer bytes than OriginalSize claims. Accepting
		// it (`>` rather than `!=`) hands the caller a short plaintext padded with
		// whatever the freshly allocated buffer's tail holds.
		payload := bytes.Repeat([]byte("shieldnet"), 200)
		f, err := frameAppWith(key, 1, anyBulkKind, payload, true, false, MaxMsgPayloadDefault)
		if err != nil {
			t.Fatal(err)
		}
		// overstate OriginalSize by one, re-sealing so the AAD still matches
		size := binary.BigEndian.Uint32(f[0:])
		enc := f[appHeaderSize:]
		hdr := appHeader(size, uint32(len(payload))+1, anyBulkKind|FlagCompressed, 1)
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := aead.Open(nil, appNonce(1), enc, f[:appHeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		bad := append(hdr, aead.Seal(nil, appNonce(1), pt, hdr)...)
		if _, _, err := recv(bad); !errors.Is(err, ErrRejected) {
			t.Errorf("err = %v, want ErrRejected: the block is one byte short of OriginalSize", err)
		}
	})

	t.Run("compressed with OriginalSize 0", func(t *testing.T) {
		body := []byte{0x00}
		f := sealFrame(t, key, anyBulkKind|FlagCompressed, 1, 0, body)
		if _, _, err := recv(f); !errors.Is(err, ErrRejected) {
			t.Errorf("err = %v, want ErrRejected", err)
		}
	})

	t.Run("uncompressed body must be origSize or its pad class", func(t *testing.T) {
		payload := []byte("twelve bytes")
		for _, tc := range []struct {
			name string
			body []byte
			ok   bool
		}{
			{"exact length", payload, true},
			{"padded to the class", append(payload, make([]byte, padClass(len(payload))-len(payload))...), true},
			{"one over the exact length", append(payload, 0), false},
			{"one over the class", append(payload, make([]byte, padClass(len(payload))-len(payload)+1)...), false},
			{"a larger class than the smallest that fits", make([]byte, 2*padClass(len(payload))), false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := sealFrame(t, key, CmdPing, 1, uint32(len(payload)), tc.body)
				_, got, err := recv(f)
				switch {
				case tc.ok && err != nil:
					t.Errorf("rejected a conforming body: %v", err)
				case tc.ok && !bytes.Equal(got, payload):
					t.Errorf("payload = %q, want %q (the pad must be stripped)", got, payload)
				case !tc.ok && !errors.Is(err, ErrRejected):
					t.Errorf("err = %v, want ErrRejected", err)
				}
			})
		}
	})
}
