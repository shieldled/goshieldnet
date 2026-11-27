// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package sledclienttest is an in-process ShieldNet v1 sled device for tests.
//
// The device is the goshieldnet v1 server, bound to the first non-loopback
// IPv4 of the host: v1 rejects loopback by design, so a client talking to it
// must be dialled with AllowSameHost.
//
// Tests that need the device skip locally when the host has no non-loopback
// IPv4, and fail instead when the CI environment variable is set (see
// SkipOrFail).
package sledclienttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

// Options shapes how the device answers.
type Options struct {
	Status   sled.Status      // answered to GET_STATUS
	AckFor   map[uint32]uint8 // per-command ACK status; missing = sled.AckOK
	Silent   map[uint32]bool  // commands that get no answer at all
	StrayAck map[uint32]uint8 // before the real ACK, send an ACK with OrigMessageNum+1000 and this status
	NoTyped  bool             // answer GET_STATUS with an ACK but no RespStatus

	DeviceInfo        *DeviceInfo      // when set, GET_DEVICE_INFO is answered with RespDeviceInfo built from it, then the ACK
	WrongKindAck      map[uint32]uint8 // before the real ACK, send an ACK with the right message number, OrigKind+1 and this status
	TypedThenStrayAck bool             // GET_STATUS: send RespStatus, then an OK ACK for num+1000, then the real ACK
	ResponseTypeBits  uint32           // OR'd into the MessageType of every response the device sends; bits 8–30 only

	RawDeviceInfo []byte // when non-nil, GET_DEVICE_INFO is answered with these bytes verbatim as RespDeviceInfo; wins over DeviceInfo
	ModeDetail    []byte // when set, the ACK to GET_MODE carries it as Detail
	// Extension, when set, answers every command kind that is not a core
	// command kind (v1.IsCoreCommand). It returns the typed response (respKind
	// 0 for none), the ACK status, and handled=false to fall back to the
	// default below. Silent, StrayAck, WrongKindAck and Unsolicited apply as
	// for any kind; an AckFor entry for the kind overrides the status
	// Extension returns. A non-core kind that Extension does not handle (or
	// with Extension nil) is answered with the AckFor entry if there is one,
	// else ERR_UNKNOWN_KIND with no typed response, as a conforming device.
	Extension func(kind uint32, payload []byte) (respKind uint32, typed []byte, status uint8, detail []byte, handled bool)
	// EnforceEnvelope makes the device's receive bound (v1.Server.MaxMsgPayload)
	// the envelope it advertises, so an oversized message desynchronises it as
	// on hardware. It needs DeviceInfo; with NoDeviceInfo or RawDeviceInfo it is
	// ignored.
	EnforceEnvelope   bool
	Unsolicited       map[uint32]uint32 // for command kind K, send the 4-byte message DE AD BE EF of this response kind between the typed response and the ACK
	MalformedAckFirst bool              // before the real ACK, send an ACK whose payload is 3 bytes
	CommandKindFirst  bool              // before the real ACK, send a message of command kind 0x07
	NoDeviceInfo      bool              // GET_DEVICE_INFO is answered with an ACK only; without it, and with DeviceInfo and RawDeviceInfo nil, defaultDeviceInfo is answered
}

// defaultDeviceInfo is what the device answers GET_DEVICE_INFO with when
// Options sets neither DeviceInfo, RawDeviceInfo nor NoDeviceInfo.
func defaultDeviceInfo() *DeviceInfo {
	return &DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: []string{"pixel", "pts"}}
}

// DeviceInfo is the geometry a device reports in RespDeviceInfo.
type DeviceInfo struct {
	Envelope, Strips, LEDs uint32
	BPP                    uint8
	Fields                 []sled.DeviceInfoField // valued fields, encoded after the geometry and before Caps; a name and value are required
	Caps                   []string
}

func encodeDeviceInfo(info *DeviceInfo) ([]byte, error) {
	return sled.EncodeDeviceInfoFields(info.Envelope, info.Strips, info.LEDs, info.BPP, info.Fields, info.Caps)
}

// Received is one command the device saw.
type Received struct {
	Kind    uint32
	Payload []byte
}

// Device is a running in-process device.
type Device struct {
	Addr string
	PSK  []byte
	ID   [8]byte

	srv  *v1.Server
	opts Options

	mu       sync.Mutex
	received []Received
}

// LANIPv4 returns the first non-loopback IPv4 of the host. It skips the test
// locally, and fails it when CI is set, if there is none.
func LANIPv4(t testing.TB) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				return n.IP.String()
			}
		}
	}
	SkipOrFail(t, "no non-loopback IPv4")
	return ""
}

// SkipOrFail skips locally but fails in CI (CI is set), where a skipped
// network test would hide a gap.
func SkipOrFail(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("%s (CI is set: network tests must not skip)", reason)
	}
	t.Skip(reason)
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// New starts a device on the host's LAN IPv4 and stops it when the test ends.
// It skips locally, and fails under CI, without a non-loopback IPv4.
func New(t testing.TB, opts Options) *Device {
	t.Helper()
	ip := LANIPv4(t)
	if opts.DeviceInfo != nil && len(opts.DeviceInfo.Fields) > 0 {
		if _, err := encodeDeviceInfo(opts.DeviceInfo); err != nil {
			t.Fatal(err)
		}
	}

	psk := make([]byte, 32)
	cookie := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}
	id := [8]byte{1, 2, 3, 4, 5, 6, 0, 0}
	epoch := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	dev, err := v1.NewDeviceFromKDev(v1.DeriveKDev(psk, id[:]), id[:], cookie, epoch, nil, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := v1.NewServer(dev, conn)
	srv.MaxMsgPayload = v1.MaxAppPayload
	if opts.EnforceEnvelope && opts.DeviceInfo != nil && opts.RawDeviceInfo == nil && !opts.NoDeviceInfo {
		srv.MaxMsgPayload = int(opts.DeviceInfo.Envelope)
	}
	srv.SendQueueMax = v1.MaxAppPayload
	srv.Tuning = v1.KCPTuning{SndWnd: 32, RcvWnd: 256, NoDelay: 1, Interval: 10, Resend: 2, NC: 1}
	go srv.Serve()

	d := &Device{
		Addr: conn.LocalAddr().String(),
		PSK:  psk,
		ID:   id,
		srv:  srv,
		opts: opts,
	}
	// The maps are shared with the respond loop under d.mu from here on.
	d.opts.AckFor = make(map[uint32]uint8, len(opts.AckFor))
	for k, v := range opts.AckFor {
		d.opts.AckFor[k] = v
	}
	d.opts.Silent = make(map[uint32]bool, len(opts.Silent))
	for k, v := range opts.Silent {
		d.opts.Silent[k] = v
	}
	d.opts.RawDeviceInfo = bytes.Clone(opts.RawDeviceInfo)
	if opts.DeviceInfo == nil && opts.RawDeviceInfo == nil && !opts.NoDeviceInfo {
		d.opts.DeviceInfo = defaultDeviceInfo()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
		_ = srv.Close()
	})
	go func() {
		defer close(done)
		d.respond(ctx)
	}()
	return d
}

// Received returns every command seen so far, in order. The result is a copy.
func (d *Device) Received() []Received {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Received, len(d.received))
	for i, r := range d.received {
		out[i] = Received{Kind: r.Kind, Payload: append([]byte(nil), r.Payload...)}
	}
	return out
}

// Server returns the underlying v1 server.
func (d *Device) Server() *v1.Server { return d.srv }

// SetAckFor changes one command's ACK status while the device is running.
func (d *Device) SetAckFor(kind uint32, status uint8) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.opts.AckFor == nil {
		d.opts.AckFor = map[uint32]uint8{}
	}
	d.opts.AckFor[kind] = status
}

// SetSilent makes the device answer kind with nothing at all (on), or as usual
// (off), while it is running.
func (d *Device) SetSilent(kind uint32, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.opts.Silent == nil {
		d.opts.Silent = map[uint32]bool{}
	}
	d.opts.Silent[kind] = on
}

// SetRawDeviceInfo changes the bytes GET_DEVICE_INFO is answered with while the
// device is running (see Options.RawDeviceInfo); nil reverts to DeviceInfo.
func (d *Device) SetRawDeviceInfo(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opts.RawDeviceInfo = bytes.Clone(p)
}

func (d *Device) respond(ctx context.Context) {
	srv := d.srv
	var typeBits uint32
	send := func(kind uint32, payload []byte) {
		_ = srv.SendAppPadded(kind|(typeBits&^0x800000FF), payload)
	}
	ack := func(kind uint32, num uint64, status uint8, detail []byte) {
		send(v1.RespAck, sled.EncodeAck(sled.Ack{OrigKind: uint8(kind), Status: status, OrigMessageNum: num, Detail: detail}))
	}
	for ctx.Err() == nil {
		p := srv.Primary()
		if p == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		_ = p.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		kind, num, payload, _, err := srv.RecvAppNumGen()
		if err != nil {
			if isTimeoutErr(err) ||
				errors.Is(err, v1.ErrSessionClosed) || errors.Is(err, v1.ErrNotEstablished) ||
				errors.Is(err, v1.ErrRejected) || errors.Is(err, v1.ErrReplay) {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Record before answering, so Received never lags behind an ACK the
		// client has already seen.
		d.mu.Lock()
		d.received = append(d.received, Received{Kind: kind, Payload: append([]byte(nil), payload...)})
		silent := d.opts.Silent[kind]
		stray, hasStray := d.opts.StrayAck[kind]
		wrong, hasWrong := d.opts.WrongKindAck[kind]
		status, hasAckFor := d.opts.AckFor[kind]
		info := d.opts.DeviceInfo
		noTyped := d.opts.NoTyped
		devStatus := d.opts.Status
		typedThenStray := d.opts.TypedThenStrayAck
		typeBits = d.opts.ResponseTypeBits
		raw := d.opts.RawDeviceInfo
		modeDetail := d.opts.ModeDetail
		extension := d.opts.Extension
		unsolicited, hasUnsolicited := d.opts.Unsolicited[kind]
		malformedAck := d.opts.MalformedAckFirst
		commandKind := d.opts.CommandKindFirst
		d.mu.Unlock()

		// Real devices never answer these.
		if kind == v1.CmdPixelFrame || kind == v1.CmdNTPServer {
			continue
		}
		if silent {
			continue
		}
		if hasStray {
			ack(kind, num+1000, stray, nil)
		}
		if hasWrong {
			send(v1.RespAck, sled.EncodeAck(sled.Ack{OrigKind: uint8(kind) + 1, Status: wrong, OrigMessageNum: num}))
		}
		if kind == v1.CmdGetDeviceInfo && raw != nil {
			send(v1.RespDeviceInfo, raw)
		} else if kind == v1.CmdGetDeviceInfo && info != nil {
			payload, err := encodeDeviceInfo(info)
			if err != nil {
				continue
			}
			send(v1.RespDeviceInfo, payload)
		}
		var detail []byte
		if kind == v1.CmdGetMode {
			detail = modeDetail
		}
		if !v1.IsCoreCommand(kind) {
			handled := false
			if extension != nil {
				var respKind uint32
				var typed []byte
				var st uint8
				respKind, typed, st, detail, handled = extension(kind, payload)
				if handled {
					if respKind != 0 {
						send(respKind, typed)
					}
					if !hasAckFor {
						status = st
					}
				}
			}
			if !handled && !hasAckFor {
				status = sled.AckErrUnknownKind
			}
		}
		if kind == v1.CmdGetStatus && !noTyped {
			send(v1.RespStatus, sled.EncodeStatus(devStatus))
		}
		if kind == v1.CmdGetStatus && typedThenStray {
			ack(kind, num+1000, sled.AckOK, nil)
		}
		if hasUnsolicited {
			send(unsolicited, []byte{0xDE, 0xAD, 0xBE, 0xEF})
		}
		if malformedAck {
			send(v1.RespAck, []byte{1, 2, 3})
		}
		if commandKind {
			send(v1.CmdPing, nil)
		}
		ack(kind, num, status, detail)
	}
}
