// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// Message layer 8 item 2: a receiver bounds how long a message may remain
// partly read, measured from its first octet, and treats expiry as "partial
// message" (ErrDesync), never as a timeout.

// slowChunkReader is chunkReader with one more marker: an empty, non-nil chunk
// sleeps slowTimeoutWait and then reports a timeout, so a timeout arrives past
// the budget within one call and the entry check cannot pre-empt it.
type slowChunkReader struct{ chunkReader }

const slowTimeoutWait = 60 * time.Millisecond

var slowTimeout = []byte{}

func (d *slowChunkReader) Read(p []byte) (int, error) {
	if d.i < len(d.chunks) && d.chunks[d.i] != nil && len(d.chunks[d.i]) == 0 {
		d.i++
		time.Sleep(slowTimeoutWait)
		return 0, deadlineExpired{}
	}
	return d.chunkReader.Read(p)
}

func midFrameFrame(t *testing.T, key []byte, num uint64) ([]byte, []byte) {
	t.Helper()
	payload := bytes.Repeat([]byte{0x5A}, 64)
	f, err := frameAppWith(key, num, CmdPing, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	return f, payload
}

func wantBudgetDesync(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrDesync) {
		t.Fatalf("%s: err = %v, want ErrDesync", what, err)
	}
	if isTimeoutErr(err) {
		t.Fatalf("%s: %v classifies as a timeout", what, err)
	}
}

func TestRecvAppMidFrameBudget(t *testing.T) {
	const budget = 50 * time.Millisecond
	key := bytes.Repeat([]byte{0x7E}, 32)
	frame, payload := midFrameFrame(t, key, 1)
	reader := func(chunks ...[]byte) *slowChunkReader {
		return &slowChunkReader{chunkReader{chunks: chunks}}
	}
	recv := func(r io.Reader, stage *rxStage) (uint32, []byte, error) {
		var rx uint64
		typ, _, p, err := recvAppWith(r, key, &rx, stage, MaxAppPayload, budget, MaxAppPayload)
		return typ, p, err
	}
	delivered := func(t *testing.T, typ uint32, p []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("frame not delivered: %v", err)
		}
		if typ != CmdPing || !bytes.Equal(p, payload) {
			t.Fatalf("frame: type %#x len %d", typ, len(p))
		}
	}

	t.Run("a: timeout inside the budget is a bare timeout", func(t *testing.T) {
		var stage rxStage
		before := time.Now()
		_, _, err := recv(reader(frame[:8], nil), &stage)
		if !isTimeoutErr(err) || errors.Is(err, ErrDesync) {
			t.Fatalf("err = %v, want a bare timeout", err)
		}
		if stage.start.Before(before) || stage.start.After(time.Now()) {
			t.Fatalf("staged frame's first-octet time %v not recorded during the call", stage.start)
		}
	})
	t.Run("b-hdr: header timeout past the budget", func(t *testing.T) {
		var stage rxStage
		_, _, err := recv(reader(frame[:8], slowTimeout), &stage)
		wantBudgetDesync(t, "header", err)
		if stage.hdrN != 0 {
			t.Fatalf("stage.hdrN = %d after ErrDesync, want 0", stage.hdrN)
		}
	})
	t.Run("b-body: body timeout past the budget", func(t *testing.T) {
		var stage rxStage
		_, _, err := recv(reader(frame[:30], slowTimeout), &stage)
		wantBudgetDesync(t, "body", err)
		if stage.hdrN != 0 || stage.body != nil {
			t.Fatalf("stage not reset: hdrN %d, body %v", stage.hdrN, stage.body != nil)
		}
	})
	t.Run("c: header split inside the budget is delivered", func(t *testing.T) {
		var stage rxStage
		r := reader(frame[:8], nil, frame[8:])
		if _, _, err := recv(r, &stage); !isTimeoutErr(err) {
			t.Fatalf("first call: %v", err)
		}
		typ, p, err := recv(r, &stage)
		delivered(t, typ, p, err)
	})
	t.Run("d: body split inside the budget is delivered", func(t *testing.T) {
		var stage rxStage
		r := reader(frame[:30], nil, frame[30:])
		if _, _, err := recv(r, &stage); !isTimeoutErr(err) {
			t.Fatalf("first call: %v", err)
		}
		typ, p, err := recv(r, &stage)
		delivered(t, typ, p, err)
	})
	t.Run("b': the clock runs from the first octet", func(t *testing.T) {
		var stage rxStage
		r := reader(frame[:4], nil, frame[4:8], nil, nil)
		if _, _, err := recv(r, &stage); !isTimeoutErr(err) {
			t.Fatalf("call 1: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
		if _, _, err := recv(r, &stage); !isTimeoutErr(err) || errors.Is(err, ErrDesync) {
			t.Fatalf("call 2: %v, want a bare timeout", err)
		}
		time.Sleep(30 * time.Millisecond)
		_, _, err := recv(r, &stage)
		wantBudgetDesync(t, "call 3 (60 ms since the first octet, 30 ms since the last)", err)
	})
	t.Run("f: entry check, without reading", func(t *testing.T) {
		var stage rxStage
		r := reader(frame[:8], nil, frame[8:])
		if _, _, err := recv(r, &stage); !isTimeoutErr(err) {
			t.Fatalf("first call: %v", err)
		}
		time.Sleep(60 * time.Millisecond)
		_, _, err := recv(r, &stage)
		wantBudgetDesync(t, "resumed past the budget", err)
		if stage.hdrN != 0 {
			t.Fatalf("stage.hdrN = %d, want 0", stage.hdrN)
		}
		if r.i != 2 || !bytes.Equal(r.chunks[2], frame[8:]) {
			t.Fatal("the remainder was consumed; the entry check must not read")
		}
	})
}

// kcpPair returns a dialled and an accepted stream-mode KCP session over
// loopback, with no crypt. The accepted side exists once the dialler has
// written, so write runs first.
func kcpPair(t *testing.T, first []byte) (dialer, accepted *kcp.UDPSession) {
	t.Helper()
	ln, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	d, err := kcp.DialWithOptions(ln.Addr().String(), nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	d.SetStreamMode(true) //lint:ignore SA1019 stream mode is what v1 uses
	d.SetNoDelay(1, 10, 2, 1)
	if _, err := d.Write(first); err != nil {
		t.Fatal(err)
	}
	ln.SetDeadline(time.Now().Add(3 * time.Second))
	a, err := ln.AcceptKCP()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	a.SetStreamMode(true) //lint:ignore SA1019 stream mode is what v1 uses
	a.SetNoDelay(1, 10, 2, 1)
	return d, a
}

type recvResult struct {
	typ uint32
	p   []byte
	err error
	at  time.Duration
}

func recvAsync(r io.Reader, key []byte, budget time.Duration) <-chan recvResult {
	ch := make(chan recvResult, 1)
	start := time.Now()
	go func() {
		var rx uint64
		var stage rxStage
		typ, _, p, err := recvAppWith(r, key, &rx, &stage, MaxAppPayload, budget, MaxAppPayload)
		ch <- recvResult{typ, p, err, time.Since(start)}
	}()
	return ch
}

func waitWatchdog(t *testing.T, ch <-chan recvResult, min, max time.Duration) {
	t.Helper()
	select {
	case res := <-ch:
		wantBudgetDesync(t, "watchdog", res.err)
		// joinErr keeps the cause as text, so text is what can be checked.
		if !strings.Contains(res.err.Error(), errPartialTooLong.Error()) {
			t.Fatalf("the error does not say the partial frame outlived the budget: %v", res.err)
		}
		if strings.Contains(res.err.Error(), "closed pipe") {
			t.Fatalf("the close leaked out as the error: %v", res.err)
		}
		if res.at < min {
			t.Fatalf("returned after %v, before the budget", res.at)
		}
	case <-time.After(max):
		t.Fatalf("no return within %v: the watchdog did not cut the read short", max)
	}
}

// The test that matters: a kcp-go Read that began with no deadline ignores one
// set later, so only closing the session can end it. No read deadline is ever
// set here.
func TestRecvAppMidFrameWatchdogKCP(t *testing.T) {
	key := bytes.Repeat([]byte{0x7E}, 32)
	frame, _ := midFrameFrame(t, key, 1)
	for _, c := range []struct {
		name string
		cut  int
	}{{"header", 8}, {"body", 30}} {
		t.Run(c.name, func(t *testing.T) {
			_, a := kcpPair(t, frame[:c.cut])
			waitWatchdog(t, recvAsync(a, key, 200*time.Millisecond), 180*time.Millisecond, 3*time.Second)
		})
	}
}

// The same over net.Pipe: quick and deterministic, but it does not prove the
// kcp path (net.Pipe honours a late deadline).
func TestRecvAppMidFrameWatchdog(t *testing.T) {
	key := bytes.Repeat([]byte{0x7E}, 32)
	frame, _ := midFrameFrame(t, key, 1)
	for _, c := range []struct {
		name string
		cut  int
	}{{"header", 8}, {"body", 30}} {
		t.Run(c.name, func(t *testing.T) {
			w, r := net.Pipe()
			t.Cleanup(func() { w.Close(); r.Close() })
			go w.Write(frame[:c.cut])
			waitWatchdog(t, recvAsync(r, key, 100*time.Millisecond), 90*time.Millisecond, 2*time.Second)
		})
	}
}

// A timer left armed from a delivered frame would close the session under the
// next, idle read.
func TestRecvAppMidFrameWatchdogDisarmed(t *testing.T) {
	const budget = 500 * time.Millisecond
	key := bytes.Repeat([]byte{0x7E}, 32)
	f1, payload := midFrameFrame(t, key, 1)
	f2, _ := midFrameFrame(t, key, 2)
	d, a := kcpPair(t, f1[:8])
	go func() {
		time.Sleep(20 * time.Millisecond)
		d.Write(f1[8:])
		time.Sleep(2*budget + 50*time.Millisecond)
		d.Write(f2)
	}()
	var rx uint64
	var stage rxStage
	for i, num := range []uint64{1, 2} {
		typ, gotNum, p, err := recvAppWith(a, key, &rx, &stage, MaxAppPayload, budget, MaxAppPayload)
		if err != nil {
			t.Fatalf("frame %d: %v", i+1, err)
		}
		if typ != CmdPing || gotNum != num || !bytes.Equal(p, payload) {
			t.Fatalf("frame %d: type %#x num %d len %d", i+1, typ, gotNum, len(p))
		}
	}
}

// raceReader returns the first 8 octets of its frame, then blocks until Close
// and returns the rest with a nil error: a read that completes after the
// watchdog fired.
type raceReader struct {
	frame  []byte
	off    int
	closed chan struct{}
	once   sync.Once
}

func (r *raceReader) Read(p []byte) (int, error) {
	if r.off == 0 {
		r.off = copy(p, r.frame[:8])
		return r.off, nil
	}
	<-r.closed
	if r.off >= len(r.frame) {
		return 0, io.EOF
	}
	n := copy(p, r.frame[r.off:])
	r.off += n
	return n, nil
}

func (r *raceReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func TestRecvAppMidFrameWatchdogRace(t *testing.T) {
	key := bytes.Repeat([]byte{0x7E}, 32)
	frame, _ := midFrameFrame(t, key, 1)
	r := &raceReader{frame: frame, closed: make(chan struct{})}
	var rx uint64
	var stage rxStage
	typ, _, p, err := recvAppWith(r, key, &rx, &stage, MaxAppPayload, 100*time.Millisecond, MaxAppPayload)
	wantBudgetDesync(t, "read completed after the watchdog fired", err)
	if p != nil || typ != 0 {
		t.Fatalf("a frame was delivered: type %#x len %d", typ, len(p))
	}
}
