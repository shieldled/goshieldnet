// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	"github.com/shieldled/goshieldnet/sledclient"
	"github.com/shieldled/goshieldnet/sledclient/sledclienttest"
	v1 "github.com/shieldled/goshieldnet/v1"
)

// extInfo is a DEVICE_INFO advertising the extension capability "ext-t".
func extInfo(caps ...string) *sledclienttest.DeviceInfo {
	return &sledclienttest.DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: append([]string{"pixel", "ext-t"}, caps...)}
}

func TestDoExtensionRequiresCapability(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	ext := func(kind uint32, payload []byte) (uint32, []byte, uint8, []byte, bool) {
		calls.Add(1)
		return 0x82, []byte{1, 2, 3}, 0, nil, true
	}

	// Without the capability: refused, and the device's Extension never runs.
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: &sledclienttest.DeviceInfo{Envelope: 32768, Strips: 1, LEDs: 64, BPP: 3, Caps: []string{"pixel"}},
		Extension:  ext,
	})
	c := dial(t, dev, 0)
	if _, err := c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0); !errors.Is(err, sledclient.ErrNotAdvertised) {
		t.Fatalf("err = %v, want ErrNotAdvertised", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("Extension called %d times, want 0", n)
	}
	if got := kinds(dev.Received()); !reflect.DeepEqual(got, []uint32{v1.CmdGetDeviceInfo}) {
		t.Fatalf("device saw %v, want only GET_DEVICE_INFO", got)
	}

	// With it: the handler sees the kind and payload; the typed reply comes back.
	var mu sync.Mutex // the device's goroutine runs Extension
	var gotKind uint32
	var gotPayload []byte
	dev = sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: extInfo(),
		Extension: func(kind uint32, payload []byte) (uint32, []byte, uint8, []byte, bool) {
			mu.Lock()
			defer mu.Unlock()
			gotKind, gotPayload = kind, bytes.Clone(payload)
			return 0x82, []byte{1, 2, 3}, 0, nil, true
		},
	})
	c = dial(t, dev, 0)
	r, err := c.DoExtension(ctx, "ext-t", 0x20, []byte{9, 8}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if gotKind != 0x20 || !bytes.Equal(gotPayload, []byte{9, 8}) {
		t.Fatalf("Extension saw kind %#x payload %v", gotKind, gotPayload)
	}
	mu.Unlock()
	if r.Kind != 0x82 || !bytes.Equal(r.Typed, []byte{1, 2, 3}) {
		t.Fatalf("reply = kind %#x typed %v, want 0x82 {1,2,3}", r.Kind, r.Typed)
	}
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}

	// A refusal comes back in Reply with its detail.
	dev = sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: extInfo(),
		Extension: func(uint32, []byte) (uint32, []byte, uint8, []byte, bool) {
			return 0, nil, 3, []byte("busy"), true
		},
	})
	c = dial(t, dev, 0)
	r, err = c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ae *sledclient.AckError
	if !errors.As(r.Err(), &ae) || string(ae.Detail) != "busy" || ae.Status != 3 {
		t.Fatalf("Reply.Err() = %v, want an AckError status 3 detail busy", r.Err())
	}
}

func TestDoExtensionRefusesKinds(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	var last atomic.Uint32
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: extInfo(),
		Extension: func(kind uint32, _ []byte) (uint32, []byte, uint8, []byte, bool) {
			calls.Add(1)
			last.Store(kind)
			return 0, nil, 0, nil, true
		},
	})
	c := dial(t, dev, 0) // fresh: admission is not spent by a refusal

	refused := func(name, capability string, kind uint32, respKind uint32) {
		t.Helper()
		if _, err := c.DoExtension(ctx, capability, kind, nil, false, respKind); !errors.Is(err, sledclient.ErrInvalidKind) {
			t.Errorf("%s: err = %v, want ErrInvalidKind", name, err)
		}
	}
	for _, k := range []uint32{0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B} {
		refused("core kind", "ext-t", k, 0)
	}
	refused("private kind", "ext-t", 0x61, 0)
	refused("response kind", "ext-t", 0x81, 0)
	refused("private capability", "x-acme", 0x20, 0)
	refused("respKind below 0x81", "ext-t", 0x20, 0x10)
	refused("respKind ACK", "ext-t", 0x20, 0x80)
	refused("respKind above 0xFF", "ext-t", 0x20, 0x100)
	if got := dev.Received(); len(got) != 0 {
		t.Fatalf("device received %v after the refusals, want nothing (no admission spent)", kinds(got))
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("Extension called %d times", n)
	}

	// 0x03 is not core: it is sent when the capability is advertised.
	if _, err := c.DoExtension(ctx, "ext-t", 0x03, []byte{1}, false, 0); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || last.Load() != 0x03 {
		t.Fatalf("Extension calls %d, last kind %#x; want 1 and 0x03", calls.Load(), last.Load())
	}
}

func TestDoExtensionLegacyAdmission(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo()})
	c := dialOpts(t, dev, sledclient.Options{LegacyAdmission: true})
	if _, err := c.DoExtension(context.Background(), "ext-t", 0x20, nil, false, 0); !errors.Is(err, sledclient.ErrDeviceInfoNotRead) {
		t.Fatalf("err = %v, want ErrDeviceInfoNotRead", err)
	}
	if got := dev.Received(); len(got) != 0 {
		t.Fatalf("device received %v, want nothing", kinds(got))
	}
}

func TestDoExtensionRespKindFilters(t *testing.T) {
	ctx := context.Background()
	send83 := func(uint32, []byte) (uint32, []byte, uint8, []byte, bool) {
		return 0x83, []byte{7}, 0, nil, true
	}
	dev := sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo(), Extension: send83})
	c := dial(t, dev, 0)
	r, err := c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0x82)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != 0 || r.Typed != nil {
		t.Fatalf("respKind 0x82: reply kind %#x typed %v, want none", r.Kind, r.Typed)
	}
	r, err = c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != 0x83 || !bytes.Equal(r.Typed, []byte{7}) {
		t.Fatalf("respKind 0: reply kind %#x typed %v, want 0x83 {7}", r.Kind, r.Typed)
	}

	// An unsolicited 0x83 after the 0x82 does not replace it when 0x82 is asked for.
	dev = sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: extInfo(),
		Extension: func(uint32, []byte) (uint32, []byte, uint8, []byte, bool) {
			return 0x82, []byte{5, 6}, 0, nil, true
		},
		Unsolicited: map[uint32]uint32{0x20: 0x83},
	})
	c = dial(t, dev, 0)
	r, err = c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0x82)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != 0x82 || !bytes.Equal(r.Typed, []byte{5, 6}) {
		t.Fatalf("reply kind %#x typed %v, want 0x82 {5,6}", r.Kind, r.Typed)
	}
}

func TestAdmitThenAdvertised(t *testing.T) {
	ctx := context.Background()
	dev := sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo()})
	c := dial(t, dev, 0)
	if _, ok := c.Advertised(); ok {
		t.Fatal("Advertised() ok before admission")
	}
	if err := c.Admit(ctx); err != nil {
		t.Fatal(err)
	}
	f, ok := c.Advertised()
	if !ok || !sled.HasCapability(f, "ext-t") {
		t.Fatalf("Advertised() = %v, %v after Admit", f, ok)
	}

	// Under LegacyAdmission Admit is a no-op and sends nothing.
	dev = sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo()})
	c = dialOpts(t, dev, sledclient.Options{LegacyAdmission: true})
	if err := c.Admit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dev.Received(); len(got) != 0 {
		t.Fatalf("Admit under LegacyAdmission sent %v", kinds(got))
	}
	if _, ok := c.Advertised(); ok {
		t.Fatal("Advertised() ok before DeviceInfo under LegacyAdmission")
	}
	if _, err := c.DeviceInfo(ctx); err != nil {
		t.Fatal(err)
	}
	if f, ok := c.Advertised(); !ok || !sled.HasCapability(f, "ext-t") {
		t.Fatalf("Advertised() = %v, %v after DeviceInfo", f, ok)
	}
}

func TestAdvertisedBeforeAndAfterAdmission(t *testing.T) {
	dev := sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo()})
	c := dial(t, dev, 0)
	if f, ok := c.Advertised(); ok || f != nil {
		t.Fatalf("before admission: %v, %v", f, ok)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	f, ok := c.Advertised()
	if !ok {
		t.Fatal("not ok after admission")
	}
	want := []sled.DeviceInfoField{{Name: "envelope", Value: "32768"}, {Name: "strips", Value: "1"}, {Name: "leds", Value: "64"}, {Name: "bpp", Value: "3"}, {Name: "pixel"}, {Name: "ext-t"}}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("Advertised() = %v, want %v", f, want)
	}
	f[0].Value = "mutated"
	f[1].Name = "mutated"
	g, _ := c.Advertised()
	if !reflect.DeepEqual(g, want) {
		t.Fatalf("mutation of the returned slice is visible: %v", g)
	}
}

func TestTestDeviceExtensionPrecedence(t *testing.T) {
	ctx := context.Background()
	dev := sledclienttest.New(t, sledclienttest.Options{
		DeviceInfo: extInfo(),
		AckFor:     map[uint32]uint8{0x20: sled.AckErrOOM},
		Extension: func(uint32, []byte) (uint32, []byte, uint8, []byte, bool) {
			return 0, nil, sled.AckErrInvalidArg, nil, true
		},
	})
	c := dial(t, dev, 2*time.Second)
	r, err := c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ack.Status != sled.AckErrOOM {
		t.Fatalf("status = %d, want AckFor's %d over Extension's", r.Ack.Status, sled.AckErrOOM)
	}
	// Extension's status holds for a kind AckFor does not name.
	r, err = c.DoExtension(ctx, "ext-t", 0x21, nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ack.Status != sled.AckErrInvalidArg {
		t.Fatalf("status = %d, want Extension's %d", r.Ack.Status, sled.AckErrInvalidArg)
	}
}

func TestTestDeviceNonCoreDefaultIsUnknownKind(t *testing.T) {
	ctx := context.Background()
	for name, ext := range map[string]func(uint32, []byte) (uint32, []byte, uint8, []byte, bool){
		"Extension nil": nil,
		"not handled":   func(uint32, []byte) (uint32, []byte, uint8, []byte, bool) { return 0x82, []byte{1}, 0, nil, false },
	} {
		dev := sledclienttest.New(t, sledclienttest.Options{DeviceInfo: extInfo(), Extension: ext})
		c := dial(t, dev, 2*time.Second)
		r, err := c.DoExtension(ctx, "ext-t", 0x20, nil, false, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Ack.Status != sled.AckErrUnknownKind || r.Kind != 0 {
			t.Errorf("%s: status %d, typed kind %#x; want ERR_UNKNOWN_KIND and no typed response", name, r.Ack.Status, r.Kind)
		}
	}
}
