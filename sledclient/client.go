// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

// defaultReplyTimeout bounds one exchange. A device that promotes the session
// and then never answers would otherwise block RecvApp forever: the
// transport's liveness timer only runs while data is outstanding, and a fully
// acknowledged session has none.
const defaultReplyTimeout = 5 * time.Second

// Options tunes a Client. The zero value is the production default.
type Options struct {
	AllowSameHost bool                          // pass local=nil (device on this host); loopback stays rejected
	ReplyTimeout  time.Duration                 // per exchange; <= 0 means 5s
	Logf          func(format string, a ...any) // rejected/replayed-frame notices; nil = silent

	// LegacyAdmission restores admission as it was before DEVICE_INFO was read
	// at admission: the first call's own command admits the session, and
	// DEVICE_INFO is read and recorded only by DeviceInfo. It is the option for
	// a device that does not answer GET_DEVICE_INFO, and it restores admission
	// only. Every call that needs DEVICE_INFO returns ErrDeviceInfoNotRead
	// until DeviceInfo has succeeded, so against a device that never answers
	// GET_DEVICE_INFO these are refused for the whole session, as the spec
	// requires (spec/application.md 1.4, 4.2, 6.2): SetNTPServer, DoExtension,
	// DoPrivate, and Do or Send of v1.CmdPixelFrame or v1.CmdNTPServer. Do and
	// Send of any other public kind still go out, and no message is checked
	// against envelope.
	LegacyAdmission bool

	// FinishPhaseMS and MidFrameBudgetMS set the v1.Client fields of the same
	// names (see their documentation); zero keeps v1's default. Transport 4.3
	// tells a deployment whose devices take long to process FINISH to raise
	// FinishPhaseMS; the first call's context must then allow for it. Dial
	// refuses a FinishPhaseMS that is negative or at or above v1.CookieEpochMS.
	// MidFrameBudgetMS has no floor: a small value ends the session with
	// ErrDesync when a reply arrives split across segments.
	FinishPhaseMS    int
	MidFrameBudgetMS int
}

// Client is one ShieldNet v1 session to a sled device. It is not safe for
// concurrent use.
//
// By default the first call admits the session with GET_DEVICE_INFO and
// records the answer (spec/application.md 3.4, 5.3.6) before it sends its own command.
//
// A call that returns v1.ErrDesync or v1.ErrSessionDead has lost the session: v1
// has ended it (message layer 8, transport 10.3), and every later call fails.
// Dial a new Client to admit again.
type Client struct {
	cli      *v1.Client
	promoted bool
	opts     Options
	info     deviceInfoRecord

	// admitErr is a terminal admission failure: admission is one attempt, and
	// every later call returns it. badFields is the field list of a DEVICE_INFO
	// refused at admission, when it decoded that far.
	admitErr  error
	badFields []sled.DeviceInfoField
	// cliClosed is set when this package closed cli itself (a context ended
	// during admission, or a bad DEVICE_INFO), so Close does not report the
	// second close's error.
	cliClosed atomic.Bool
}

// deviceInfoRecord is this session's DEVICE_INFO: read at admission (or, with
// LegacyAdmission, by DeviceInfo) and replaced by a successful DeviceInfo. Any
// future re-admission of the same Client must clear it first: DEVICE_INFO
// belongs to one session (spec/application.md 5.3.6).
type deviceInfoRecord struct {
	set    bool
	fields []sled.DeviceInfoField
	geom   sled.Geometry
}

// Dial prepares a session to the device at addr. It does no network I/O: the
// session is admitted by the first command.
func Dial(addr string, psk []byte, deviceID [8]byte, opts Options) (*Client, error) {
	// local is used only to validate the client's own source address. Both ends
	// apply the own-address rule, so a device on this same machine needs it
	// disabled here too; loopback stays rejected regardless.
	if ms := opts.FinishPhaseMS; ms < 0 || ms >= v1.CookieEpochMS {
		return nil, fmt.Errorf("sledclient: FinishPhaseMS %d out of range: must be 0 (default) or positive and below %d", ms, v1.CookieEpochMS)
	}
	local := LocalPrefixes()
	if opts.AllowSameHost {
		local = nil
	}
	cli, err := v1.NewClient(addr, psk, deviceID[:], local)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}
	cli.FinishPhaseMS = opts.FinishPhaseMS
	cli.MidFrameBudgetMS = opts.MidFrameBudgetMS
	return &Client{cli: cli, opts: opts}, nil
}

// Close ends the session. After this package has closed the session itself
// (a context ended during admission, or a bad DEVICE_INFO) it returns nil.
func (c *Client) Close() error {
	if c.cliClosed.Load() {
		return nil
	}
	return c.cli.Close()
}

// closeCli closes the v1 client on this package's own initiative.
func (c *Client) closeCli() {
	c.cliClosed.Store(true)
	_ = c.cli.Close()
}

// Reply is one exchange: the ACK plus any typed response that preceded it.
type Reply struct {
	Ack   sled.Ack
	Kind  uint32 // typed response kind, 0 if none
	Typed []byte
}

// AckError is a refusal: the device answered, with a non-OK status.
type AckError struct {
	Kind, Status uint8
	Detail       []byte
}

// Error returns the ACK status name, followed by the device's detail text when
// it sent one.
func (e *AckError) Error() string {
	name := sled.AckStatusName(e.Status)
	if len(e.Detail) > 0 {
		return name + ": " + string(e.Detail)
	}
	return name
}

// IsAckError reports whether err is, or wraps, a device refusal.
func IsAckError(err error) bool {
	var ae *AckError
	return errors.As(err, &ae)
}

// Err is nil when the device accepted the command, and an *AckError otherwise.
func (r Reply) Err() error {
	if r.Ack.Status == sled.AckOK {
		return nil
	}
	return &AckError{Kind: r.Ack.OrigKind, Status: r.Ack.Status, Detail: r.Ack.Detail}
}

// ErrNoResponsePayload means the device acknowledged a query without sending
// the typed response that should have preceded the ACK.
var ErrNoResponsePayload = errors.New("sledclient: acknowledged without a response payload")

// ErrDeviceInfoNotRead means a call that needs DEVICE_INFO was made before it
// was recorded in this session (spec/application.md 5.3.6). sledclient returns it only
// with Options.LegacyAdmission: by default admission reads DEVICE_INFO. Call
// DeviceInfo first: a GET_DEVICE_INFO sent through Do is not recorded.
var ErrDeviceInfoNotRead = errors.New("sledclient: DEVICE_INFO not read in this session")

// ErrBadDeviceInfo means the device's DEVICE_INFO was refused: a non-OK ACK, no
// typed response, or a malformed or out-of-range field (spec/application.md 5.3.2,
// 5.3.3). The error wraps the cause. At admission it is terminal: the caller's
// command is not sent, the session is closed, and every later call returns it.
var ErrBadDeviceInfo = errors.New("sledclient: bad DEVICE_INFO")

// ErrExceedsEnvelope means a message would exceed the device's envelope
// (spec/application.md 3.6: payload + 16 > envelope), or a pixel frame its frame
// limit (6.2). Sending it would end the session; nothing was sent and the
// session is untouched.
var ErrExceedsEnvelope = errors.New("sledclient: message exceeds the device's envelope")

// ErrNotAdvertised means this session's DEVICE_INFO lacks the capability a
// call needs; the error wraps it with the capability's name. Nothing was sent.
var ErrNotAdvertised = errors.New("sledclient: capability not advertised")

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// replyTimeout is Options.ReplyTimeout, or its default.
func (c *Client) replyTimeout() time.Duration {
	if c.opts.ReplyTimeout <= 0 {
		return defaultReplyTimeout
	}
	return c.opts.ReplyTimeout
}

// testHookRetrySend, when set by a test, replaces the error of the send that
// asks for a pending DEVICE_INFO again.
var testHookRetrySend func(error) error

// ensureAdmitted admits the session with GET_DEVICE_INFO and records the
// answer, unless that is done (spec/application.md 3.4, 5.3.6). read reports whether
// DEVICE_INFO was read during this call. With LegacyAdmission it does nothing:
// transmit admits with the caller's command.
//
// Admission is one attempt: a handshake failure, a context that ends during
// it or during the DEVICE_INFO wait, a bad DEVICE_INFO and a lost session are
// stored and returned by every later call. Only a ReplyTimeout expiry with the
// context still live leaves the session admitted with DEVICE_INFO pending; the
// next call asks again.
func (c *Client) ensureAdmitted(ctx context.Context) (read bool, err error) {
	if c.opts.LegacyAdmission {
		return false, nil
	}
	if c.admitErr != nil {
		return false, c.admitErr
	}
	if c.promoted && c.info.set {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	timeout := c.replyTimeout()
	if c.promoted {
		// DEVICE_INFO pending after a ReplyTimeout: ask again on the admitted
		// session. A late reply to the earlier request is skipped by number.
		err := c.cli.SendAppPadded(v1.CmdGetDeviceInfo, nil)
		if testHookRetrySend != nil {
			err = testHookRetrySend(err)
		}
		if err != nil {
			// A full send queue is transient (transport 9.5): the session is
			// alive and the next call asks again. Anything else ends it.
			if !errors.Is(err, v1.ErrSendQueueFull) {
				c.admitErr = err
			}
			return false, err
		}
		r, werr := c.await(ctx, c.cli.LastTxNum(), uint8(v1.CmdGetDeviceInfo), timeout)
		if errors.Is(werr, ErrNoAnswer) || errors.Is(werr, context.DeadlineExceeded) {
			return false, werr
		}
		return true, c.admitResult(r, werr)
	}

	// Admission is a single attempt: a failed one is not retried by the next
	// call.
	c.promoted = true
	stop := context.AfterFunc(ctx, c.closeCli)
	// sled 3.6: the first message is sent before envelope is known and is never
	// padded beyond the smallest class: GET_DEVICE_INFO is empty, so it is
	// padded to class 64, Size 80, which every device accepts.
	if err := c.cli.TakeControlAppPadded(v1.CmdGetDeviceInfo, nil); err != nil {
		if !stop() || ctx.Err() != nil {
			c.admitErr = ctx.Err()
		} else {
			c.admitErr = fmt.Errorf("take control: %w", err)
		}
		return false, c.admitErr
	}
	// The AfterFunc stays armed through the DEVICE_INFO wait: cancelling ctx
	// then closes the client, as it does during the handshake.
	r, werr := c.await(ctx, c.cli.LastTxNum(), uint8(v1.CmdGetDeviceInfo), timeout)
	stopped := stop()
	// The context first: at its deadline either side may win.
	if !stopped || ctx.Err() != nil || errors.Is(werr, context.DeadlineExceeded) {
		if stopped {
			c.closeCli()
		}
		c.admitErr = ctx.Err()
		if c.admitErr == nil {
			c.admitErr = context.DeadlineExceeded
		}
		return false, c.admitErr
	}
	if errors.Is(werr, ErrNoAnswer) {
		return false, werr // not terminal: the next call asks again
	}
	return true, c.admitResult(r, werr)
}

// admitResult records the admission DEVICE_INFO exchange, or stores its
// failure as terminal.
func (c *Client) admitResult(r Reply, werr error) error {
	if werr != nil {
		// ErrDesync, ErrSessionDead, ErrNotEstablished, ...: the session is gone.
		c.admitErr = werr
		return werr
	}
	fields, rec, err := decodeDeviceInfo(r)
	if err != nil {
		c.admitErr, c.badFields = err, fields
		// The device keeps its primary until the next promotion either way
		// (transport 12.5); closing releases the socket and goroutines.
		c.closeCli()
		return err
	}
	c.recordInfo(rec)
	return nil
}

// decodeDeviceInfo validates a GET_DEVICE_INFO reply (spec/application.md 5.3). Any
// failure wraps ErrBadDeviceInfo; fields is returned whenever the payload
// decoded as a field list, so a caller can show what the device sent.
func decodeDeviceInfo(r Reply) ([]sled.DeviceInfoField, deviceInfoRecord, error) {
	bad := func(cause error) error { return fmt.Errorf("%w: %w", ErrBadDeviceInfo, cause) }
	if err := r.Err(); err != nil {
		return nil, deviceInfoRecord{}, bad(err)
	}
	if r.Kind != v1.RespDeviceInfo {
		return nil, deviceInfoRecord{}, bad(ErrNoResponsePayload)
	}
	fields, err := sled.DecodeDeviceInfo(r.Typed)
	if err != nil {
		return nil, deviceInfoRecord{}, bad(err)
	}
	g, err := sled.DecodeGeometry(fields)
	if err != nil {
		return fields, deviceInfoRecord{}, bad(err)
	}
	return fields, deviceInfoRecord{set: true, fields: append([]sled.DeviceInfoField(nil), fields...), geom: g}, nil
}

// recordInfo makes rec this session's DEVICE_INFO, and gives v1 the device's
// envelope as the peer's receive bound (message layer 7.3), so padding never
// picks a class whose Size exceeds it (spec/application.md 3.6).
func (c *Client) recordInfo(rec deviceInfoRecord) {
	c.info = rec
	// DecodeGeometry has checked envelope >= 80, the least v1 accepts.
	_ = c.cli.SetPeerReceiveBound(int(rec.geom.Envelope))
}

// checkEnvelope refuses a payload whose message would exceed the recorded
// envelope (spec/application.md 3.6). It covers the compressed case too: OriginalSize
// is len(payload). Before DEVICE_INFO is recorded (LegacyAdmission only) it
// checks nothing.
func (c *Client) checkEnvelope(payload []byte) error {
	if !c.info.set {
		return nil
	}
	if env := int(c.info.geom.Envelope); len(payload)+16 > env {
		return fmt.Errorf("%w: %d-byte payload, envelope %d", ErrExceedsEnvelope, len(payload), env)
	}
	return nil
}

// ErrInvalidKind means Do or Send was given a kind this controller must not
// send: one with any bit above bit 7 set (spec/application.md 3.1: bits 8–30 are sent
// as zero), a response kind (0x80 and up), or a private kind (0x60–0x7F)
// outside DoPrivate. Nothing was sent and admission was not spent.
var ErrInvalidKind = errors.New("sledclient: invalid command kind")

// checkKind refuses, for Do and Send, a kind that is not a command kind
// (spec/application.md 3.1) or is a private one (7.8: DoPrivate).
func checkKind(kind uint32) error {
	if kind > 0x7F {
		return fmt.Errorf("%w: %#x", ErrInvalidKind, kind)
	}
	if kind >= 0x60 {
		return fmt.Errorf("%w: private kind %#x: use DoPrivate", ErrInvalidKind, kind)
	}
	return nil
}

// requireCap refuses a call unless this session's DEVICE_INFO has been read
// and advertises name.
func (c *Client) requireCap(name string) error {
	if !c.info.set {
		return ErrDeviceInfoNotRead
	}
	if !sled.HasCapability(c.info.fields, name) {
		return fmt.Errorf("%w: %s", ErrNotAdvertised, name)
	}
	return nil
}

// guardKind refuses, for Do and Send, a core kind the device did not
// advertise: NTP_SERVER without pts (spec/application.md 4.2), PIXEL_FRAME without
// pixel (1.4, 6.2), a malformed frame, or one over the frame limit (6.2).
func (c *Client) guardKind(kind uint32, payload []byte) error {
	switch kind {
	case v1.CmdNTPServer:
		return c.requireCap("pts")
	case v1.CmdPixelFrame:
		if err := c.requireCap("pixel"); err != nil {
			return err
		}
		f, err := sled.ParsePixelFrame(payload)
		if err != nil {
			return err
		}
		limit, err := sled.FrameLimit(c.info.geom)
		if err != nil {
			return err
		}
		if len(f.Pixels) > limit {
			return fmt.Errorf("%w: %d pixel bytes, frame limit %d", ErrExceedsEnvelope, len(f.Pixels), limit)
		}
	}
	return nil
}

// wireCategory is how a message travels (spec/application.md 3.5; message layer
// 6.3).
type wireCategory int

const (
	catControl wireCategory = iota // padded, never compressed
	catBulk                        // compressed if that shrinks it, else padded
	catStream                      // compressed if that shrinks it, never padded
)

// category assigns a kind to its category. The core kinds (v1.IsCoreCommand)
// have a fixed category whatever bulk says: PIXEL_FRAME is streaming data and
// every other one is control. For any other kind bulk chooses: true is bulk
// content, false control.
func category(kind uint32, payload []byte, bulk bool) wireCategory {
	if kind == v1.CmdPixelFrame {
		return catStream
	}
	if v1.IsCoreCommand(kind) {
		return catControl
	}
	if bulk {
		return catBulk
	}
	return catControl
}

// framing is how transmit frames one command on the wire.
type framing int

const (
	framePadded     framing = iota // SendAppPadded / TakeControlAppPadded
	framePlain                     // SendApp / TakeControlApp: neither padded nor compressed
	frameCompressed                // SendAppCompressed
	frameBulk                      // SendAppBulk: compressed if that shrinks it, else padded
)

// frameFor picks the framing for a command of category cat and n payload
// bytes. envelopeKnown is whether this session's DEVICE_INFO is recorded.
//
// sled 3.6: before envelope is known (LegacyAdmission only) nothing is padded
// beyond the smallest class, 64, which every device accepts. Longer bulk
// content goes unpadded through SendAppCompressed (compressed only if that
// shrinks it): its Size is never above the plain Size, and an OriginalSize the
// device cannot take drops that message where an oversized Size would end the
// session. That is not a conformance guarantee: without envelope the client
// cannot know the message fits (LegacyAdmission checks nothing against
// envelope); it only stops the client from making the message larger than its
// content.
func frameFor(cat wireCategory, envelopeKnown bool, n int) framing {
	fits := envelopeKnown || n <= 64
	switch {
	case cat == catStream:
		return frameCompressed
	case cat == catBulk && fits:
		return frameBulk
	case cat == catBulk:
		return frameCompressed
	case cat == catControl && fits:
		return framePadded
	}
	return framePlain
}

// transmit sends one command on the admitted session, framed for its category
// (see category). Only with LegacyAdmission can the session still be
// unadmitted here: then the first call admits it, carrying the command in the
// promoting datagram.
func (c *Client) transmit(ctx context.Context, kind uint32, payload []byte, bulk bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	kind = uint32(uint8(kind)) // sled 3.1: bits 8–30 are sent as zero
	cat := category(kind, payload, bulk)
	f := frameFor(cat, c.info.set, len(payload))
	var err error
	if !c.promoted {
		// Admission is a single attempt: a failed one is not retried by the
		// next call.
		c.promoted = true
		stop := context.AfterFunc(ctx, c.closeCli)
		// The promoting message is never compressed (v1).
		if f == framePadded {
			err = c.cli.TakeControlAppPadded(kind, payload)
		} else {
			err = c.cli.TakeControlApp(kind, payload)
		}
		if !stop() {
			// The AfterFunc already ran and closed the client.
			return ctx.Err()
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("take control: %w", err)
		}
		return nil
	}
	switch f {
	case frameCompressed:
		return c.cli.SendAppCompressed(kind, payload)
	case frameBulk:
		return c.cli.SendAppBulk(kind, payload)
	case framePlain:
		return c.cli.SendApp(kind, payload)
	}
	return c.cli.SendAppPadded(kind, payload)
}

// Do runs one exchange and returns the device's ACK, with any typed response
// that preceded it.
//
// kind must be a command kind, 0x00–0x5F (spec/application.md 3.1): a kind with any
// bit above bit 7 set, a response kind (0x80 and up) or a private kind
// (0x60–0x7F, see DoPrivate) is refused with ErrInvalidKind before admission.
// How the message travels follows its kind (spec/application.md 3.5):
// PIXEL_FRAME is compressed when that shrinks it and never padded; every other
// core kind is padded and never compressed, and a wrong bulk flag for those
// kinds is overridden silently. For any other kind bulk chooses: true sends it
// as bulk content (compressed when that shrinks it, padded otherwise), false
// as control. Before DEVICE_INFO is recorded
// (LegacyAdmission), only messages of at most 64 bytes are padded; call
// DeviceInfo first to have bulk content padded.
//
// The first call admits the session with GET_DEVICE_INFO and records the
// answer before it sends the command (spec/application.md 3.4, 5.3.6): it costs one
// extra round trip, and its ctx must allow two. A bad DEVICE_INFO returns
// ErrBadDeviceInfo and the command is not sent. With Options.LegacyAdmission
// the first call carries the command in the promoting datagram instead.
// Do(ctx, v1.CmdGetDeviceInfo, ...) is a raw exchange: its answer is not
// recorded (use DeviceInfo).
//
// Admission is bounded by ctx: when ctx ends during it, including its
// DEVICE_INFO wait (a ctx deadline expiring there included), the underlying
// client is closed and is unusable afterwards. The wait for the ACK is bounded by
// the earlier of ctx's deadline and Options.ReplyTimeout. A context that is
// only cancellable, with no deadline, bounds admission but not the wait,
// which is then bounded by ReplyTimeout; a context with a deadline that is
// cancelled during the wait returns at the deadline, not early. A wait cut off
// by ctx's deadline returns context.DeadlineExceeded.
//
// After admission Do refuses, without sending: NTP_SERVER to a device without
// pts, PIXEL_FRAME to one without pixel, a malformed frame, and a frame over
// the device's frame limit (ErrExceedsEnvelope). It does not check capabilities:
// Do may probe an extension query only when the command is harmless if it takes
// effect (spec/application.md 7.1), and a device without the extension answers
// ERR_UNKNOWN_KIND. Private kinds are never probed (7.8): they go through
// DoPrivate, to a device that advertises their capability.
//
// Do keeps the last typed response before the ACK, whatever its kind, for a
// kind other than GET_STATUS and GET_DEVICE_INFO: it does not filter an
// extension query's typed response by kind. Use DoExtension with a respKind for
// an extension's queries.
//
// A refusal is not an error from Do: it comes back in Reply, and the caller
// decides (see Reply.Err).
func (c *Client) Do(ctx context.Context, kind uint32, payload []byte, bulk bool) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if err := checkKind(kind); err != nil {
		return Reply{}, err
	}
	if _, err := c.ensureAdmitted(ctx); err != nil {
		return Reply{}, err
	}
	if err := c.guardKind(kind, payload); err != nil {
		return Reply{}, err
	}
	return c.exchange(ctx, kind, payload, bulk)
}

// exchange sends one command on the admitted session and awaits its ACK.
func (c *Client) exchange(ctx context.Context, kind uint32, payload []byte, bulk bool) (Reply, error) {
	if err := c.checkEnvelope(payload); err != nil {
		return Reply{}, err
	}
	if err := c.transmit(ctx, kind, payload, bulk); err != nil {
		return Reply{}, err
	}
	return c.await(ctx, c.cli.LastTxNum(), uint8(kind), c.replyTimeout())
}

// DoPrivate runs one exchange of a private command kind (0x60–0x7F) that
// belongs to the private capability capability (spec/application.md 7.8).
// capability must begin with "x-" and be advertised in this session's
// DEVICE_INFO, else ErrNotAdvertised; kind outside 0x60–0x7F is
// ErrInvalidKind. Both name checks run before admission; whether the
// capability is advertised is checked after it. A private kind is never sent
// as a probe. bulk chooses the category as for an unknown kind in Do.
func (c *Client) DoPrivate(ctx context.Context, capability string, kind uint32, payload []byte, bulk bool) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if !strings.HasPrefix(capability, "x-") {
		return Reply{}, fmt.Errorf("%w: %q is not a private capability", ErrNotAdvertised, capability)
	}
	if kind < 0x60 || kind > 0x7F {
		return Reply{}, fmt.Errorf("%w: %#x is not a private kind", ErrInvalidKind, kind)
	}
	if _, err := c.ensureAdmitted(ctx); err != nil {
		return Reply{}, err
	}
	if err := c.requireCap(capability); err != nil {
		return Reply{}, err
	}
	return c.exchange(ctx, kind, payload, bulk)
}

// DoExtension runs one exchange of a command kind that belongs to an
// extension registered by the specification (spec/application.md 7.8, 9),
// identified by its capability. Checks, in this order:
//  1. ctx; then, before admission (nothing sent, no admission spent):
//     capability starting "x-", kind in 0x60-0x7F, kind >= 0x80, a core
//     command kind (v1.IsCoreCommand), or respKind not 0 and outside
//     0x81-0xFF: ErrInvalidKind (private extensions use DoPrivate);
//  2. admission (as any command), then the capability: requireCap's error
//     (ErrNotAdvertised; ErrDeviceInfoNotRead under LegacyAdmission, with
//     nothing sent).
//
// respKind, when non-zero, is the typed response kind the command is
// answered with: only that kind is kept (as for the core queries). When zero,
// the last typed response before the ACK is kept. bulk chooses the category
// as for an unknown kind in Do. DoExtension never probes. Reply.Kind and
// Reply.Typed carry the typed response.
func (c *Client) DoExtension(ctx context.Context, capability string, kind uint32, payload []byte, bulk bool, respKind uint32) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if strings.HasPrefix(capability, "x-") {
		return Reply{}, fmt.Errorf("%w: %q is a private capability: use DoPrivate", ErrInvalidKind, capability)
	}
	if kind >= 0x60 {
		return Reply{}, fmt.Errorf("%w: %#x is not an extension command kind", ErrInvalidKind, kind)
	}
	if v1.IsCoreCommand(kind) {
		return Reply{}, fmt.Errorf("%w: %#x is a core command kind", ErrInvalidKind, kind)
	}
	if respKind != 0 && (respKind < 0x81 || respKind > 0xFF) {
		return Reply{}, fmt.Errorf("%w: response kind %#x", ErrInvalidKind, respKind)
	}
	if _, err := c.ensureAdmitted(ctx); err != nil {
		return Reply{}, err
	}
	if err := c.requireCap(capability); err != nil {
		return Reply{}, err
	}
	if err := c.checkEnvelope(payload); err != nil {
		return Reply{}, err
	}
	if err := c.transmit(ctx, kind, payload, bulk); err != nil {
		return Reply{}, err
	}
	return c.awaitResp(ctx, c.cli.LastTxNum(), uint8(kind), respKind, c.replyTimeout())
}

// Admit admits the session if it is not yet admitted (the default admission's
// first exchange reads DEVICE_INFO); it is a no-op under LegacyAdmission. It
// is for a caller that must read Advertised before sending.
func (c *Client) Admit(ctx context.Context) error {
	_, err := c.ensureAdmitted(ctx)
	return err
}

// Advertised returns a copy of this session's latest recorded DEVICE_INFO
// fields without a round trip; ok is false until one is recorded (by
// admission, or by DeviceInfo under LegacyAdmission).
func (c *Client) Advertised() (fields []sled.DeviceInfoField, ok bool) {
	if !c.info.set {
		return nil, false
	}
	return append([]sled.DeviceInfoField(nil), c.info.fields...), true
}

// Send transmits one command and does not wait for an answer to it. It goes
// through the same admission path as Do: the first call admits the session,
// bounded by ctx, and a later Do does not admit again. By default that first
// call does wait, for the admission DEVICE_INFO only (see Do), and its ctx must
// allow two round trips. Use Send for commands the device never answers
// (NTP_SERVER). kind and bulk are treated as in Do, and it refuses what Do
// refuses after admission.
//
// Caveats:
//
//  1. Send returns once the message is queued, not delivered. After admission
//     the underlying send returns when the KCP write is queued, and Close does
//     not flush. A following Ping proves delivery, because the stream is in
//     order.
//  2. Send is not a streaming path. A Client is not safe for concurrent use,
//     so a pixel stream belongs on a v1.Client with Await.
//  3. A reply to a kind the device does answer is left unread, and the next Do
//     discards it under the foreign-ACK rule.
//  4. As with Do, a local error on the first call (for example
//     v1.ErrPayloadTooLarge) still spends the one-shot admission.
func (c *Client) Send(ctx context.Context, kind uint32, payload []byte, bulk bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkKind(kind); err != nil {
		return err
	}
	if _, err := c.ensureAdmitted(ctx); err != nil {
		return err
	}
	if err := c.guardKind(kind, payload); err != nil {
		return err
	}
	if err := c.checkEnvelope(payload); err != nil {
		return err
	}
	return c.transmit(ctx, kind, payload, bulk)
}

// await reads until the ACK for message wantNum and command origKind arrives
// (see Await), bounded by timeout and by ctx's deadline.
func (c *Client) await(ctx context.Context, wantNum uint64, origKind uint8, timeout time.Duration) (Reply, error) {
	respKind, _ := expectedResponse(origKind)
	return c.awaitResp(ctx, wantNum, origKind, respKind, timeout)
}

// awaitResp is await with the typed response kind given (see awaitKind).
func (c *Client) awaitResp(ctx context.Context, wantNum uint64, origKind uint8, respKind uint32, timeout time.Duration) (Reply, error) {
	deadline := time.Now().Add(timeout)
	fromCtx := false
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline, fromCtx = dl, true
	}
	r, err := awaitKind(c.cli, wantNum, origKind, respKind, deadline, c.logf)
	if errors.Is(err, ErrNoAnswer) {
		if fromCtx {
			return Reply{}, context.DeadlineExceeded
		}
		return Reply{}, fmt.Errorf("no answer within %s: %w", timeout, err)
	}
	return r, err
}

func (c *Client) logf(format string, a ...any) {
	if c.opts.Logf != nil {
		c.opts.Logf(format, a...)
	}
}

// exec runs one command and returns the device's refusal, if any.
func (c *Client) exec(ctx context.Context, kind uint32, payload []byte, bulk bool) error {
	r, err := c.Do(ctx, kind, payload, bulk)
	if err != nil {
		return err
	}
	return r.Err()
}

// SetBrightness sets the global brightness.
func (c *Client) SetBrightness(ctx context.Context, v uint8) error {
	return c.exec(ctx, v1.CmdSetBrightness, []byte{v}, false)
}

// SetFPS sets the target frame rate.
func (c *Client) SetFPS(ctx context.Context, fps uint8) error {
	return c.exec(ctx, v1.CmdSetFPS, []byte{fps}, false)
}

// SetMode sets the device's mode (sled.ModePixel; the other values belong to
// extensions and implementations).
func (c *Client) SetMode(ctx context.Context, mode uint8) error {
	return c.exec(ctx, v1.CmdSetMode, []byte{mode}, false)
}

// Mode reads the device's mode and whether its output is enabled (GET_MODE,
// spec/application.md 4.3). The answer is the ACK's detail; there is no typed response. An
// undefined mode is returned raw.
func (c *Client) Mode(ctx context.Context) (sled.ModeInfo, error) {
	r, err := c.Do(ctx, v1.CmdGetMode, nil, false)
	if err != nil {
		return sled.ModeInfo{}, err
	}
	if err := r.Err(); err != nil {
		return sled.ModeInfo{}, err
	}
	return sled.DecodeMode(r.Ack.Detail)
}

// Ping checks that the device answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.exec(ctx, v1.CmdPing, nil, false)
}

// On enables the output.
func (c *Client) On(ctx context.Context) error {
	return c.exec(ctx, v1.CmdOn, nil, false)
}

// Off disables the output.
func (c *Client) Off(ctx context.Context) error {
	return c.exec(ctx, v1.CmdOff, nil, false)
}

// SetNTPServer announces an NTP server to the device. NTP_SERVER is never
// answered, so it is sent with Send and not awaited; see Send for what that
// implies. It is refused unless this session's DEVICE_INFO advertises pts
// (spec/application.md 4.2).
func (c *Client) SetNTPServer(ctx context.Context, s sled.NTPServer) error {
	if _, err := c.ensureAdmitted(ctx); err != nil {
		return err
	}
	payload, err := sled.EncodeNTPServer(s)
	if err != nil {
		return err
	}
	return c.Send(ctx, v1.CmdNTPServer, payload, false)
}

// Status queries the device status.
func (c *Client) Status(ctx context.Context) (sled.Status, error) {
	r, err := c.Do(ctx, v1.CmdGetStatus, nil, false)
	if err != nil {
		return sled.Status{}, err
	}
	if err := r.Err(); err != nil {
		return sled.Status{}, err
	}
	if r.Kind != v1.RespStatus {
		return sled.Status{}, ErrNoResponsePayload
	}
	return sled.DecodeStatus(r.Typed)
}

// DeviceInfo returns the device's DEVICE_INFO and records it for this session
// (see Geometry, Advertised).
//
// When this call admitted the session, or retried a DEVICE_INFO left pending by
// a ReplyTimeout, that read serves it: one GET_DEVICE_INFO, not two. After a
// bad DEVICE_INFO at admission it returns the refused field list (when it
// decoded) with the stored ErrBadDeviceInfo. Otherwise it reads DEVICE_INFO
// again; a refused answer (non-OK ACK, no typed response, a malformed or
// out-of-range field, spec/application.md 5.3.2) returns ErrBadDeviceInfo, with the
// field list when it decoded, and leaves the earlier record as it was.
func (c *Client) DeviceInfo(ctx context.Context) ([]sled.DeviceInfoField, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	read, err := c.ensureAdmitted(ctx)
	if err != nil {
		if errors.Is(err, ErrBadDeviceInfo) {
			return append([]sled.DeviceInfoField(nil), c.badFields...), err
		}
		return nil, err
	}
	if read {
		return append([]sled.DeviceInfoField(nil), c.info.fields...), nil
	}
	r, err := c.Do(ctx, v1.CmdGetDeviceInfo, nil, false)
	if err != nil {
		return nil, err
	}
	fields, rec, err := decodeDeviceInfo(r)
	if err != nil {
		return fields, err
	}
	c.recordInfo(rec)
	return fields, nil
}

// Geometry returns this session's recorded DEVICE_INFO geometry, and whether
// DEVICE_INFO has been recorded in this session.
func (c *Client) Geometry() (sled.Geometry, bool) {
	if !c.info.set {
		return sled.Geometry{}, false
	}
	return c.info.geom, true
}
