// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

// chunkReader replays a frame in fragments, with a nil fragment standing for the
// caller's read deadline expiring. This is the shape of a real KCP stream: a
// 20-octet header and a body both span segments, and a device that sets a read
// deadline to stay responsive to session replacement will land in the middle of
// one sooner or later.
type chunkReader struct {
	chunks [][]byte
	i      int
}

type deadlineExpired struct{}

func (deadlineExpired) Error() string   { return "i/o timeout" }
func (deadlineExpired) Timeout() bool   { return true }
func (deadlineExpired) Temporary() bool { return true }

func (d *chunkReader) Read(p []byte) (int, error) {
	if d.i >= len(d.chunks) {
		return 0, io.EOF
	}
	c := d.chunks[d.i]
	if c == nil {
		d.i++
		return 0, deadlineExpired{}
	}
	n := copy(p, c)
	if n < len(c) {
		d.chunks[d.i] = c[n:]
	} else {
		d.i++
	}
	return n, nil
}

// A read deadline that expires mid-frame is §1.2's FIRST row, not its third: no
// message was delivered, but nothing was lost either and the session survives.
// Reporting ErrDesync there hands the caller's own liveness timer the power to
// kill a healthy session — and, now that a conforming device acts on ErrDesync
// by dropping the primary (Server.DropPrimary), that would be a real teardown.
func TestRecvAppResumesAcrossAReadDeadline(t *testing.T) {
	key := bytes.Repeat([]byte{0x7E}, 32)
	payload := bytes.Repeat([]byte("frame body "), 40)
	frame, err := frameAppWith(key, 1, CmdPing, payload, false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	// Split so a deadline expires inside the header AND inside the body.
	r := &chunkReader{chunks: [][]byte{
		frame[:8], nil, // header, interrupted
		frame[8:20], nil, // header completed, then interrupted again
		frame[20:30], nil, // body, interrupted
		frame[30:],
	}}

	var rx uint64
	var stage rxStage
	for i := 0; i < 3; i++ {
		_, _, _, err := recvAppWith(r, key, &rx, &stage, MaxAppPayload, 0, MaxAppPayload)
		if !isTimeoutErr(err) {
			t.Fatalf("interruption %d: err = %v, want a bare timeout", i, err)
		}
		if errors.Is(err, ErrDesync) {
			t.Fatalf("interruption %d reported ErrDesync: a read deadline is not a desynchronisation", i)
		}
	}
	typ, num, got, err := recvAppWith(r, key, &rx, &stage, MaxAppPayload, 0, MaxAppPayload)
	if err != nil {
		t.Fatalf("resumed frame: %v", err)
	}
	if typ != CmdPing || num != 1 || !bytes.Equal(got, payload) {
		t.Fatalf("resumed frame: type %#x num %d len %d", typ, num, len(got))
	}
	if stage.hdrN != 0 || stage.body != nil {
		t.Error("a completed frame left staging behind; the next call would re-read it")
	}
}

// The distinction only means anything if a genuine short read still reports
// ErrDesync — otherwise resuming has merely muted §1.2's third row.
func TestRecvAppStillDesyncsOnATruncatedStream(t *testing.T) {
	key := bytes.Repeat([]byte{0x7E}, 32)
	frame, err := frameAppWith(key, 1, CmdPing, []byte("payload"), false, false, MaxAppPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{8, 20, len(frame) - 4} {
		var rx uint64
		var stage rxStage
		_, _, _, err := recvAppWith(bytes.NewReader(frame[:cut]), key, &rx, &stage, MaxAppPayload, 0, MaxAppPayload)
		if !errors.Is(err, ErrDesync) {
			t.Errorf("stream cut at %d: err = %v, want ErrDesync", cut, err)
		}
	}
	// Nothing at all consumed is the first row: the session survives, unwrapped.
	var rx uint64
	var stage rxStage
	_, _, _, err = recvAppWith(bytes.NewReader(nil), key, &rx, &stage, MaxAppPayload, 0, MaxAppPayload)
	if !errors.Is(err, io.EOF) || errors.Is(err, ErrDesync) {
		t.Errorf("empty stream: err = %v, want a bare io.EOF", err)
	}
}

// isTimeoutErr must survive wrapping: kcp-go returns its timeouts through
// pkg/errors, whose *withStack does not itself implement net.Error, so a type
// assertion silently classifies every kcp timeout as a hard error.
func TestIsTimeoutErrSeesThroughWrapping(t *testing.T) {
	var raw net.Error = deadlineExpired{}
	if !isTimeoutErr(raw) {
		t.Fatal("bare timeout not recognised")
	}
	// kcp-go hands back its timeouts inside a pkg/errors *withStack, which does
	// not implement net.Error itself; any %w wrapping has the same shape.
	if !isTimeoutErr(fmt.Errorf("kcp read: %w", raw)) {
		t.Error("wrapped timeout not recognised")
	}
	if isTimeoutErr(io.EOF) {
		t.Error("io.EOF reported as a timeout")
	}
}
