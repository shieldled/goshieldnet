// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	"github.com/shieldled/goshieldnet/sledclient"
	"github.com/shieldled/goshieldnet/sledclient/sledclienttest"
	v1 "github.com/shieldled/goshieldnet/v1"
)

func dial(t *testing.T, dev *sledclienttest.Device, replyTimeout time.Duration) *sledclient.Client {
	t.Helper()
	return dialOpts(t, dev, sledclient.Options{ReplyTimeout: replyTimeout})
}

// dialOpts dials dev with opts and AllowSameHost.
func dialOpts(t *testing.T, dev *sledclienttest.Device, opts sledclient.Options) *sledclient.Client {
	t.Helper()
	opts.AllowSameHost = true
	c, err := sledclient.Dial(dev.Addr, dev.PSK, dev.ID, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func kinds(rs []sledclienttest.Received) []uint32 {
	out := make([]uint32, len(rs))
	for i, r := range rs {
		out[i] = r.Kind
	}
	return out
}

// extBlock is a recognisable STATUS extension block: seed, seed+1, ...
func extBlock(seed byte) [sled.StatusExtSize]byte {
	var b [sled.StatusExtSize]byte
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

func TestStatusDecodes(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Status: sled.Status{Ext: extBlock(0xa0), Brightness: 77}})
	c := dial(t, dev, 0)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ext != extBlock(0xa0) || st.Brightness != 77 {
		t.Errorf("status = %+v", st)
	}
}

// sled 3.1: bits 8–30 of a received MessageType are reserved and ignored; the
// kind is the low byte. Both halves matter: the ACK (0x00ABCD80) must complete
// the request, and the typed response (0x00ABCD81) must be kept as RespStatus.
func TestHighTypeBitsIgnored(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		Status:           sled.Status{Ext: extBlock(0x10), Brightness: 91},
		ResponseTypeBits: 0x00ABCD00,
	})
	c := dial(t, dev, 0)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ext != extBlock(0x10) || st.Brightness != 91 {
		t.Errorf("status = %+v", st)
	}
}

func TestCommandsSendExpectedPayloads(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	ctx := context.Background()

	for _, call := range []struct {
		name string
		err  error
	}{
		{"SetBrightness", c.SetBrightness(ctx, 40)},
		{"SetFPS", c.SetFPS(ctx, 30)},
		{"SetMode", c.SetMode(ctx, sled.ModePixel)},
		{"Ping", c.Ping(ctx)},
		{"On", c.On(ctx)},
		{"Off", c.Off(ctx)},
	} {
		if call.err != nil {
			t.Errorf("%s: %v", call.name, call.err)
		}
	}

	want := []sledclienttest.Received{
		{Kind: v1.CmdSetBrightness, Payload: []byte{40}},
		{Kind: v1.CmdSetFPS, Payload: []byte{30}},
		{Kind: v1.CmdSetMode, Payload: []byte{1}},
		{Kind: v1.CmdPing, Payload: nil},
		{Kind: v1.CmdOn, Payload: nil},
		{Kind: v1.CmdOff, Payload: nil},
	}
	got := dev.Received()
	if len(got) != 1+len(want) || got[0].Kind != v1.CmdGetDeviceInfo {
		t.Fatalf("device saw kinds %v, want GET_DEVICE_INFO then %d commands", kinds(got), len(want))
	}
	got = got[1:]
	for i := range want {
		if got[i].Kind != want[i].Kind || !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Errorf("command %d: got kind %#x payload %x, want kind %#x payload %x",
				i, got[i].Kind, got[i].Payload, want[i].Kind, want[i].Payload)
		}
	}
}

func TestAckRefusalReturnsAckError(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{AckFor: map[uint32]uint8{v1.CmdSetBrightness: sled.AckErrInvalidArg}})
	c := dial(t, dev, 0)
	err := c.SetBrightness(context.Background(), 40)
	var ae *sledclient.AckError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *AckError", err)
	}
	if ae.Status != sled.AckErrInvalidArg {
		t.Errorf("status = %d, want %d", ae.Status, sled.AckErrInvalidArg)
	}
	if !sledclient.IsAckError(err) {
		t.Error("IsAckError = false")
	}
}

func TestStrayAckIgnored(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{StrayAck: map[uint32]uint8{v1.CmdSetBrightness: sled.AckErrInvalidArg}})
	c := dial(t, dev, 0)
	if err := c.SetBrightness(context.Background(), 40); err != nil {
		t.Fatalf("SetBrightness = %v, want nil: the stray ACK must be skipped", err)
	}
}

// sled 3.3: correlation is by orig_message_num alone. An ACK with the right
// number and another orig_kind closes the exchange.
func TestSled33WrongKindAckCloses(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{WrongKindAck: map[uint32]uint8{v1.CmdSetBrightness: sled.AckErrInvalidArg}})
	c := dial(t, dev, 0)
	r, err := c.Do(context.Background(), v1.CmdSetBrightness, []byte{40}, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ack.OrigKind != v1.CmdSetBrightness+1 || r.Ack.Status != sled.AckErrInvalidArg {
		t.Fatalf("ACK = kind %#x status %d, want the wrong-kind ACK (kind %#x, ERR_INVALID_ARG)",
			r.Ack.OrigKind, r.Ack.Status, v1.CmdSetBrightness+1)
	}
	pingAfter(t, c) // the real ACK that follows is foreign to PING and skipped
}

func TestTypedResponseBeforeForeignAckIsDropped(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{TypedThenStrayAck: true})
	c := dial(t, dev, 0)
	_, err := c.Status(context.Background())
	if !errors.Is(err, sledclient.ErrNoResponsePayload) {
		t.Fatalf("err = %v, want ErrNoResponsePayload: a foreign ACK after RespStatus closes it", err)
	}
}

func TestStatusWithoutTypedPayload(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{NoTyped: true})
	c := dial(t, dev, 0)
	_, err := c.Status(context.Background())
	if !errors.Is(err, sledclient.ErrNoResponsePayload) {
		t.Fatalf("err = %v, want ErrNoResponsePayload", err)
	}
}

func TestReplyTimeout(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdOn: true}})
	c := dial(t, dev, 300*time.Millisecond)
	ctx := context.Background()
	if _, err := c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.On(ctx)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("err = %v, want a no-answer timeout", err)
	}
	if elapsed < 250*time.Millisecond || elapsed >= 2*time.Second {
		t.Errorf("On took %s, want about 300ms", elapsed)
	}
	rs := dev.Received()
	if len(rs) == 0 || rs[len(rs)-1].Kind != v1.CmdOn {
		t.Errorf("device saw kinds %v, want the last to be CmdOn", kinds(rs))
	}
}

func TestContextDeadlineWins(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdOn: true}})
	c := dial(t, dev, 10*time.Second)
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.On(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if elapsed < 250*time.Millisecond || elapsed >= 2*time.Second {
		t.Errorf("On took %s, want about 300ms", elapsed)
	}
}

func TestAdmissionHonoursContext(t *testing.T) {
	ip := sledclienttest.LANIPv4(t)
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	psk := bytes.Repeat([]byte{7}, 32)
	c, err := sledclient.Dial(pc.LocalAddr().String(), psk, [8]byte{1}, sledclient.Options{AllowSameHost: true, ReplyTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Status(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if elapsed >= 2*time.Second {
		t.Errorf("admission took %s, want it cut at about 300ms", elapsed)
	}
}

func TestDeviceInfoDecodes(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 8256, Strips: 2, LEDs: 100, BPP: 3, Caps: []string{"pixel"}},
	})
	c := dial(t, dev, 0)
	fields, err := c.DeviceInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g, err := sled.DecodeGeometry(fields)
	if err != nil {
		t.Fatal(err)
	}
	if g != (sled.Geometry{Envelope: 8256, Strips: 2, LEDs: 100, BPP: 3, HasLEDs: true}) {
		t.Errorf("geometry = %+v", g)
	}
	if !sled.HasCapability(fields, "pixel") {
		t.Errorf("fields %+v lack capability pixel", fields)
	}
}

func TestDeviceInfoWithoutTypedPayload(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{NoDeviceInfo: true})
	c := dial(t, dev, 0)
	_, err := c.DeviceInfo(context.Background())
	if !errors.Is(err, sledclient.ErrBadDeviceInfo) || !errors.Is(err, sledclient.ErrNoResponsePayload) {
		t.Fatalf("err = %v, want ErrBadDeviceInfo and ErrNoResponsePayload", err)
	}
}

func TestSetNTPServerDoesNotWait(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 5*time.Second)
	ctx := context.Background()
	if _, err := c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	s := sled.NTPServer{Host: "192.0.2.1", Port: 123}
	want, err := sled.EncodeNTPServer(s)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.SetNTPServer(ctx, s); err != nil {
		t.Fatalf("SetNTPServer = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("SetNTPServer took %s, want it to return without waiting", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rs := dev.Received()
		if n := len(rs); n > 0 && rs[n-1].Kind == v1.CmdNTPServer {
			if !bytes.Equal(rs[n-1].Payload, want) {
				t.Errorf("payload = %x, want %x", rs[n-1].Payload, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device saw kinds %v, want the last to be CmdNTPServer", kinds(rs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSendFirstCallAdmits(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	ctx := context.Background()
	payload, err := sled.EncodeNTPServer(sled.NTPServer{Host: "192.0.2.1", Port: 123})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, v1.CmdNTPServer, payload, false); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	if _, err := c.Status(ctx); err != nil {
		t.Fatalf("Status after Send = %v, want nil", err)
	}
	if gen, ok := dev.Server().PrimaryGen(); !ok || gen != 1 {
		t.Errorf("PrimaryGen = %d, %v, want 1, true: a second admission happened", gen, ok)
	}
}

// rawInfo encodes name/value pairs as a DEVICE_INFO payload, without checks.
func rawInfo(kv ...string) []byte {
	var b []byte
	for i := 0; i < len(kv); i += 2 {
		b = append(b, byte(len(kv[i])))
		b = append(b, kv[i]...)
		b = append(b, byte(len(kv[i+1])))
		b = append(b, kv[i+1]...)
	}
	return b
}

var defaultGeometry = sled.Geometry{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, HasLEDs: true}

// sled 3.4, 5.3.6: the controller reads DEVICE_INFO at every admission, with
// GET_DEVICE_INFO as the first command.
func TestSled536AdmissionReadsDeviceInfoFirst(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []uint32{v1.CmdGetDeviceInfo, v1.CmdPing}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

func TestSled536BadDeviceInfoRefusesCommand(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		RawDeviceInfo: rawInfo("envelope", "79", "strips", "1", "leds", "64", "bpp", "3", "pixel", ""),
	})
	c := dial(t, dev, 0)
	ctx := context.Background()
	if err := c.Ping(ctx); !errors.Is(err, sledclient.ErrBadDeviceInfo) {
		t.Fatalf("first Ping: err = %v, want ErrBadDeviceInfo", err)
	}
	if err := c.Ping(ctx); !errors.Is(err, sledclient.ErrBadDeviceInfo) {
		t.Fatalf("second Ping: err = %v, want the stored ErrBadDeviceInfo", err)
	}
	want := []uint32{v1.CmdGetDeviceInfo}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close after a refused DEVICE_INFO: %v, want nil", err)
	}
}

func TestSled536DeviceInfoValidates(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	dev.SetRawDeviceInfo(rawInfo("envelope", "1200", "strips", "1", "leds", "64", "bpp", "5", "pixel", ""))
	if _, err := c.DeviceInfo(ctx); !errors.Is(err, sledclient.ErrBadDeviceInfo) {
		t.Fatalf("DeviceInfo with bpp=5: err = %v, want ErrBadDeviceInfo", err)
	}
	if g, ok := c.Geometry(); !ok || g != defaultGeometry {
		t.Fatalf("Geometry() = %+v, %v; want the admission's %+v", g, ok, defaultGeometry)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping after a refused re-read: %v", err)
	}
}

func TestSled536LegacyAdmission(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dialOpts(t, dev, sledclient.Options{LegacyAdmission: true})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []uint32{v1.CmdPing}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
	if g, ok := c.Geometry(); ok {
		t.Fatalf("Geometry() = %+v, true; want ok == false under LegacyAdmission", g)
	}
}

func TestSled536GeometryReported(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	if g, ok := c.Geometry(); ok {
		t.Fatalf("Geometry() before any call = %+v, true", g)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g, ok := c.Geometry(); !ok || g != defaultGeometry {
		t.Fatalf("Geometry() = %+v, %v; want %+v, true", g, ok, defaultGeometry)
	}
}

func TestSled536DeviceInfoFirstCallSingleRead(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	fields, err := c.DeviceInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sled.HasCapability(fields, "pixel") {
		t.Errorf("fields %+v lack pixel", fields)
	}
	want := []uint32{v1.CmdGetDeviceInfo}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

func TestSled536DeviceInfoTimeoutRetried(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdGetDeviceInfo: true}})
	c := dial(t, dev, 300*time.Millisecond)
	ctx := context.Background()
	err := c.Ping(ctx)
	if err == nil || errors.Is(err, sledclient.ErrBadDeviceInfo) || !errors.Is(err, sledclient.ErrNoAnswer) {
		t.Fatalf("first Ping: err = %v, want a no-answer timeout", err)
	}
	dev.SetSilent(v1.CmdGetDeviceInfo, false)
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("second Ping: %v", err)
	}
	want := []uint32{v1.CmdGetDeviceInfo, v1.CmdGetDeviceInfo, v1.CmdPing}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

// With LegacyAdmission DEVICE_INFO is not read at admission, so a call that
// needs a capability is refused until DeviceInfo has succeeded.
func TestSled536LegacyNTPNeedsDeviceInfo(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dialOpts(t, dev, sledclient.Options{LegacyAdmission: true, ReplyTimeout: 2 * time.Second})
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	payload, err := sled.EncodeNTPServer(sled.NTPServer{Host: "192.0.2.1", Port: 123})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, v1.CmdNTPServer, payload, false); !errors.Is(err, sledclient.ErrDeviceInfoNotRead) {
		t.Fatalf("Do(NTP_SERVER): err = %v, want ErrDeviceInfoNotRead", err)
	}
	pingAfter(t, c)
	if got, want := kinds(dev.Received()), []uint32{v1.CmdPing, v1.CmdPing}; !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

// transport 9.5: a DEVICE_INFO retry that times out is not terminal either.
func TestSled536SecondRetryTimeoutNotTerminal(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdGetDeviceInfo: true}})
	c := dial(t, dev, 300*time.Millisecond)
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if err := c.Ping(ctx); !errors.Is(err, sledclient.ErrNoAnswer) {
			t.Fatalf("Ping %d: err = %v, want a no-answer timeout", i, err)
		}
	}
	dev.SetSilent(v1.CmdGetDeviceInfo, false)
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("third Ping: %v", err)
	}
	want := []uint32{v1.CmdGetDeviceInfo, v1.CmdGetDeviceInfo, v1.CmdGetDeviceInfo, v1.CmdPing}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

func TestSled536CancelDuringDeviceInfoWait(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{Silent: map[uint32]bool{v1.CmdGetDeviceInfo: true}})
	c := dial(t, dev, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	if err := c.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Ping: err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("first Ping took %s, want it cut at about 100ms", elapsed)
	}
	if err := c.Ping(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("second Ping: err = %v, want the stored context.Canceled", err)
	}
}

// envelopeDevice advertises envelope 1200 and really refuses more (sled 3.6).
func envelopeDevice(t *testing.T) *sledclienttest.Device {
	return sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo:      &sledclienttest.DeviceInfo{Envelope: 1200, Strips: 1, LEDs: 300, BPP: 3, Caps: []string{"pixel"}},
		EnforceEnvelope: true,
	})
}

// pingAfter checks the session survived: a Ping must succeed.
func pingAfter(t *testing.T, c *sledclient.Client) {
	t.Helper()
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping afterwards: %v", err)
	}
}

func hasKind(rs []sledclienttest.Received, kind uint32) bool {
	for _, r := range rs {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func TestSled36OversizeRefusedLocally(t *testing.T) {
	dev := envelopeDevice(t)
	c := dial(t, dev, 2*time.Second)
	_, err := c.Do(context.Background(), v1.CmdPing, make([]byte, 1185), false)
	if !errors.Is(err, sledclient.ErrExceedsEnvelope) {
		t.Fatalf("err = %v, want ErrExceedsEnvelope", err)
	}
	pingAfter(t, c)
	if got, want := kinds(dev.Received()), []uint32{v1.CmdGetDeviceInfo, v1.CmdPing}; !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v (the oversize PING must not be sent)", got, want)
	}
}

func TestSled36LargestFitSent(t *testing.T) {
	dev := envelopeDevice(t)
	c := dial(t, dev, 2*time.Second)
	r, err := c.Do(context.Background(), v1.CmdPing, make([]byte, 1184), false)
	if err != nil || r.Err() != nil {
		t.Fatalf("1184-byte PING (Size 1200): %v %v", err, r.Err())
	}
	pingAfter(t, c)
}

func TestSled36UnpaddedWhenClassTooBig(t *testing.T) {
	dev := envelopeDevice(t)
	c := dial(t, dev, 2*time.Second)
	r, err := c.Do(context.Background(), v1.CmdPing, make([]byte, 1100), false)
	if err != nil || r.Err() != nil {
		t.Fatalf("1100-byte PING: %v %v (padded to class 2048 it would desynchronise the device)", err, r.Err())
	}
	pingAfter(t, c)
}

func TestSled36BulkOversizeRefused(t *testing.T) {
	const bulkKind = 0x20 // a kind the client does not interpret; bulk sends it as bulk content
	dev := envelopeDevice(t)
	c := dial(t, dev, 2*time.Second)
	// Zeros compress well, so refusing this proves the check is on the original size.
	_, err := c.Do(context.Background(), bulkKind, make([]byte, 1185), true)
	if !errors.Is(err, sledclient.ErrExceedsEnvelope) {
		t.Fatalf("err = %v, want ErrExceedsEnvelope", err)
	}
	pingAfter(t, c)
	if hasKind(dev.Received(), bulkKind) {
		t.Fatalf("device saw kinds %v, want no kind %#x", kinds(dev.Received()), bulkKind)
	}
}

// sled 3.6: before envelope is known the first command is not padded beyond
// the smallest class.
func TestSled36LegacyFirstCommandPadCap(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo:      &sledclienttest.DeviceInfo{Envelope: 100, Strips: 1, LEDs: 8, BPP: 3, Caps: []string{"pixel"}},
		EnforceEnvelope: true,
	})
	c := dialOpts(t, dev, sledclient.Options{LegacyAdmission: true, ReplyTimeout: 2 * time.Second})
	r, err := c.Do(context.Background(), v1.CmdPing, make([]byte, 70), false)
	if err != nil || r.Err() != nil {
		t.Fatalf("first 70-byte PING: %v %v (class 128 would be Size 144 > 100)", err, r.Err())
	}
	pingAfter(t, c)
}

// sled 3.6: before envelope is known, bulk content over 64 bytes is not padded
// to a class that would exceed the device's envelope.
func TestSled36LegacyBulkPadCap(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo:      &sledclienttest.DeviceInfo{Envelope: 100, Strips: 1, LEDs: 8, BPP: 3, Caps: []string{"pixel"}},
		EnforceEnvelope: true,
		AckFor:          map[uint32]uint8{0x50: sled.AckOK}, // a non-core kind is otherwise ERR_UNKNOWN_KIND
	})
	c := dialOpts(t, dev, sledclient.Options{LegacyAdmission: true, ReplyTimeout: 2 * time.Second})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	p := make([]byte, 70)
	for i := range p {
		p[i] = byte(i*37 + 11)
	}
	r, err := c.Do(context.Background(), 0x50, p, true)
	if err != nil {
		t.Fatalf("70-byte bulk Do: %v (class 128 would be Size 144 > envelope 100)", err)
	}
	if r.Ack.Status != sled.AckOK {
		t.Fatalf("ack status = %v, want AckOK", r.Ack.Status)
	}
	pingAfter(t, c)
	if got, want := kinds(dev.Received()), []uint32{v1.CmdPing, 0x50, v1.CmdPing}; !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

// sled 3.1: bits 8–30 are sent as zero; a controller never sends a response
// kind. Both are local refusals that do not spend admission.
func checkKindRefused(t *testing.T, kind uint32) {
	t.Helper()
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	ctx := context.Background()
	if _, err := c.Do(ctx, kind, nil, false); !errors.Is(err, sledclient.ErrInvalidKind) {
		t.Fatalf("Do(%#x): err = %v, want ErrInvalidKind", kind, err)
	}
	if err := c.Send(ctx, kind, nil, false); !errors.Is(err, sledclient.ErrInvalidKind) {
		t.Fatalf("Send(%#x): err = %v, want ErrInvalidKind", kind, err)
	}
	pingAfter(t, c)
	want := []uint32{v1.CmdGetDeviceInfo, v1.CmdPing}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

func TestSled31RefusesHighBits(t *testing.T) { checkKindRefused(t, 0x00ABCD07) }

func TestSled31RefusesResponseKind(t *testing.T) { checkKindRefused(t, 0x81) }

// wantKinds pings (so everything sent before has been delivered) and checks
// the device saw exactly want, then PING.
func wantKinds(t *testing.T, c *sledclient.Client, dev *sledclienttest.Device, want ...uint32) {
	t.Helper()
	pingAfter(t, c)
	want = append(want, v1.CmdPing)
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, want) {
		t.Fatalf("device saw kinds %v, want %v", got, want)
	}
}

// sled 4.2: NTP_SERVER goes only to a device advertising pts.
func TestSled42NTPServerNeedsPTS(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: []string{"pixel"}},
	})
	c := dial(t, dev, 0)
	ctx := context.Background()
	s := sled.NTPServer{Host: "192.0.2.1", Port: 123}
	if err := c.SetNTPServer(ctx, s); !errors.Is(err, sledclient.ErrNotAdvertised) {
		t.Fatalf("SetNTPServer: err = %v, want ErrNotAdvertised", err)
	}
	payload, err := sled.EncodeNTPServer(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, v1.CmdNTPServer, payload, false); !errors.Is(err, sledclient.ErrNotAdvertised) {
		t.Fatalf("Send(NTP_SERVER): err = %v, want ErrNotAdvertised", err)
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo)
}

func pixelFrame(t *testing.T, n int) []byte {
	t.Helper()
	b, err := sled.PixelFrame(1, 0, 0, make([]byte, n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sled 1.4, 6.2: no PIXEL_FRAME to a device without pixel.
func TestSled14PixelFrameNeedsPixel(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: []string{"pts"}},
	})
	c := dial(t, dev, 0)
	if err := c.Send(context.Background(), v1.CmdPixelFrame, pixelFrame(t, 16), true); !errors.Is(err, sledclient.ErrNotAdvertised) {
		t.Fatalf("Send(PIXEL_FRAME): err = %v, want ErrNotAdvertised", err)
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo)
}

// sled 6.2: a frame is at most the frame limit.
func TestSled62PixelFrameOverLimitRefused(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 1200, Strips: 1, LEDs: 10, BPP: 3, Caps: []string{"pixel"}},
	})
	c := dial(t, dev, 0)
	ctx := context.Background()
	if err := c.Send(ctx, v1.CmdPixelFrame, pixelFrame(t, 44), true); !errors.Is(err, sledclient.ErrExceedsEnvelope) {
		t.Fatalf("44 pixel bytes, limit 40: err = %v, want ErrExceedsEnvelope", err)
	}
	if err := c.Send(ctx, v1.CmdPixelFrame, pixelFrame(t, 40), true); err != nil {
		t.Fatalf("40 pixel bytes: %v", err)
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo, v1.CmdPixelFrame)
}

// sled 7.8: a private kind goes only to a device advertising its capability.
func TestSled78PrivateKindNeedsCapability(t *testing.T) {
	ctx := context.Background()
	dev := sledclienttest.New(t, sledclienttest.Options{})
	c := dial(t, dev, 0)
	if _, err := c.Do(ctx, 0x61, nil, false); !errors.Is(err, sledclient.ErrInvalidKind) {
		t.Fatalf("Do(0x61): err = %v, want ErrInvalidKind", err)
	}
	if _, err := c.DoPrivate(ctx, "x-acme", 0x61, []byte{1}, false); !errors.Is(err, sledclient.ErrNotAdvertised) {
		t.Fatalf("DoPrivate without x-acme: err = %v, want ErrNotAdvertised", err)
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo)

	dev = sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: []string{"pixel", "x-acme"}},
		AckFor:     map[uint32]uint8{0x61: sled.AckOK}, // a non-core kind is otherwise ERR_UNKNOWN_KIND
	})
	c = dial(t, dev, 0)
	r, err := c.DoPrivate(ctx, "x-acme", 0x61, []byte{1}, false)
	if err != nil || r.Err() != nil {
		t.Fatalf("DoPrivate with x-acme: %v %v", err, r.Err())
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo, 0x61)
}

// sled 7.1: Do stays the probe path for a kind the device may not know.
func TestSled14DoIsProbe(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{}) // answers a non-core kind ERR_UNKNOWN_KIND
	c := dial(t, dev, 0)
	const probe = 0x27
	r, err := c.Do(context.Background(), probe, nil, false)
	if err != nil {
		t.Fatalf("Do(%#x): %v", probe, err)
	}
	if r.Ack.Status != sled.AckErrUnknownKind {
		t.Fatalf("status = %d, want ERR_UNKNOWN_KIND", r.Ack.Status)
	}
	wantKinds(t, c, dev, v1.CmdGetDeviceInfo, probe)
}

// sled 3.3 rule 3: an unsolicited response between the typed response and its
// ACK is skipped; it does not replace the typed response.
func TestSled33UnsolicitedBetweenTypedAndAck(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{
		Status:      sled.Status{Ext: extBlock(0x40), Brightness: 33},
		Unsolicited: map[uint32]uint32{v1.CmdGetStatus: 0xE5},
	})
	c := dial(t, dev, 0)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Ext != extBlock(0x40) || st.Brightness != 33 {
		t.Fatalf("status = %+v", st)
	}
}

func TestSled33MalformedAckSkipped(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{MalformedAckFirst: true})
	c := dial(t, dev, 0)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// sled 3.1: a controller skips a command kind it receives.
func TestSled33CommandKindSkipped(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{CommandKindFirst: true})
	c := dial(t, dev, 0)
	r, err := c.Do(context.Background(), v1.CmdPing, nil, false)
	if err != nil {
		t.Fatalf("Do(PING): %v", err)
	}
	if r.Kind != 0 {
		t.Fatalf("Reply.Kind = %#x, want 0: a command kind is not a typed response", r.Kind)
	}
}
