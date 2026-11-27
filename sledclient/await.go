// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"errors"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

// ErrNoAnswer is returned by Await when the deadline passes before the ACK
// for the awaited message arrives.
var ErrNoAnswer = errors.New("sledclient: no answer")

// expectedResponse is the typed response kind a query is answered with
// (spec/application.md 5).
func expectedResponse(origKind uint8) (uint32, bool) {
	switch uint32(origKind) {
	case v1.CmdGetStatus:
		return v1.RespStatus, true
	case v1.CmdGetDeviceInfo:
		return v1.RespDeviceInfo, true
	}
	return 0, false
}

// Await reads replies on cli until the ACK whose orig_message_num is wantNum
// arrives, and returns it with the typed response kept since the previous
// foreign ACK. Correlation is by message number alone (spec/application.md 3.3): the
// matching ACK closes the exchange whatever its orig_kind, which Reply.Ack
// carries. An ACK for any other message closes some earlier exchange, so a
// typed response kept before it is discarded. An undecodable ACK is skipped
// (and passed to logf). A command kind (below 0x80) is skipped (3.1). origKind
// is the awaited command's kind: for a query (GET_STATUS, GET_DEVICE_INFO)
// only its own response kind is kept and any other is skipped; for any other
// command the last response kind seen is kept. Skipped
// messages count against no bound (3.3 rule 3). A non-OK ACK is returned in the
// Reply (see Reply.Err), not as an error. Rejected and replayed frames are
// passed to logf (when non-nil) and reading continues. Await sets cli's read
// deadline and clears it on return. It must be the only reader of cli while it
// runs.
func Await(cli *v1.Client, wantNum uint64, origKind uint8, deadline time.Time, logf func(string, ...any)) (Reply, error) {
	want, _ := expectedResponse(origKind)
	return awaitKind(cli, wantNum, origKind, want, deadline, logf)
}

// awaitKind is Await with the typed response kind given: when respKind is not
// 0 only that kind is kept and any other typed response is skipped; when it is
// 0 the last typed response seen before the ACK is kept.
func awaitKind(cli *v1.Client, wantNum uint64, origKind uint8, respKind uint32, deadline time.Time, logf func(string, ...any)) (Reply, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := cli.SetReadDeadline(deadline); err != nil {
		return Reply{}, err
	}
	defer cli.SetReadDeadline(time.Time{})

	var keptKind uint32
	var keptTyped []byte
	for {
		kind, payload, err := cli.RecvApp()
		switch {
		case err == nil:
			// sled 3.1: bits 8–30 of MessageType are reserved and ignored on
			// receive; the application kind is the low byte.
			k := kind & 0xFF
			if k == v1.RespAck {
				a, derr := sled.DecodeAck(payload)
				if derr != nil {
					logf("undecodable ACK skipped: %v\n", derr)
					break
				}
				if a.OrigMessageNum != wantNum {
					// Closes some earlier exchange: anything kept belongs to it.
					keptKind, keptTyped = 0, nil
					break
				}
				a.Detail = append([]byte(nil), a.Detail...)
				return Reply{Ack: a, Kind: keptKind, Typed: keptTyped}, nil
			}
			if k < 0x80 {
				break // a command kind: a controller skips it (sled 3.1)
			}
			// A typed response carries no message number, so it is kept and the
			// ACK is still awaited, if it is one the command can be answered with.
			if respKind != 0 && k != respKind {
				break
			}
			keptKind, keptTyped = k, append([]byte(nil), payload...)

		case errors.Is(err, v1.ErrRejected):
			// Read in full and refused. The stream is still frame-aligned, so
			// the session survives and reading continues; tearing it down here
			// would hand any host that can reach the port a denial of service.
			logf("frame rejected, session survives: %v\n", err)

		case errors.Is(err, v1.ErrReplay):
			logf("replayed message number, ignoring: %v\n", err)

		case isTimeout(err):
			if time.Now().Before(deadline) {
				continue
			}
			return Reply{}, ErrNoAnswer

		default:
			return Reply{}, err
		}
		if !time.Now().Before(deadline) {
			return Reply{}, ErrNoAnswer
		}
	}
}
