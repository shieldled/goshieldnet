// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sled

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNTPServerVectors(t *testing.T) {
	for _, c := range []struct {
		hex string
		n   int
		s   NTPServer
	}{
		{"0404007b0a000005", 8, NTPServer{"10.0.0.5", 123}},
		{"04041fbbc0a8010a", 8, NTPServer{"192.168.1.10", 8123}},
		{"010a007b74696d652e6c6f63616c", 14, NTPServer{"time.local", 123}},
		{"0610007bfd000000000000000000000000000001", 20, NTPServer{"fd00::1", 123}},
	} {
		want := vector(t, c.hex, c.n)
		got, err := EncodeNTPServer(c.s)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%v: encoded %x (%v), want %x", c.s, got, err, want)
		}
		dec, err := DecodeNTPServer(want)
		if err != nil || dec != c.s {
			t.Errorf("%x: decoded %v (%v), want %v", want, dec, err, c.s)
		}
	}

	first := vector(t, "0404007b0a000005", 8)
	if got, err := EncodeNTPServer(NTPServer{"::ffff:10.0.0.5", 123}); err != nil || !bytes.Equal(got, first) {
		t.Errorf("IPv4-mapped: %x (%v), want %x", got, err, first)
	}
	padded := append(append([]byte{}, first...), make([]byte, 56)...)
	if dec, err := DecodeNTPServer(padded); err != nil || dec != (NTPServer{"10.0.0.5", 123}) {
		t.Errorf("padded: %v (%v)", dec, err)
	}
	for _, name := range []string{"Ntp-1.example", strings.Repeat("a", 253)} {
		b, err := EncodeNTPServer(NTPServer{name, 123})
		if err != nil {
			t.Errorf("%q refused: %v", name, err)
			continue
		}
		if dec, err := DecodeNTPServer(b); err != nil || dec.Host != name {
			t.Errorf("%q round trip: %v (%v)", name, dec, err)
		}
	}
}

func TestNTPServerRejects(t *testing.T) {
	for _, s := range []NTPServer{
		{"", 123}, {"10.0.0.5", 0}, {"bad host", 123}, {"a_b", 123},
		{"fe80::1%eth0", 123}, {strings.Repeat("a", 254), 123},
	} {
		if b, err := EncodeNTPServer(s); err == nil {
			t.Errorf("%q port %d accepted as %x", s.Host, s.Port, b)
		}
	}

	for _, p := range [][]byte{
		nil, {0x04}, {0x04, 0x04, 0x00},
		{0x04, 0x04, 0x00, 0x7b, 0x0a, 0x00, 0x00},
	} {
		if _, err := DecodeNTPServer(p); !errors.Is(err, ErrShort) {
			t.Errorf("%x: %v, want ErrShort", p, err)
		}
	}
	long := append([]byte{0x01, 0xfe, 0x00, 0x7b}, bytes.Repeat([]byte("a"), 254)...)
	for _, p := range [][]byte{
		{0x09, 0x04, 0x00, 0x7b, 0x0a, 0x00, 0x00, 0x05},
		{0x00, 0x00, 0x00, 0x7b},
		{0x04, 0x05, 0x00, 0x7b, 0x0a, 0x00, 0x00, 0x05, 0x00},
		{0x04, 0x03, 0x00, 0x7b, 0x0a, 0x00, 0x00},
		{0x06, 0x04, 0x00, 0x7b, 0x0a, 0x00, 0x00, 0x05},
		{0x01, 0x00, 0x00, 0x7b},
		{0x04, 0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05},
		{0x01, 0x03, 0x00, 0x7b, 0x61, 0x20, 0x62},
		long,
	} {
		_, err := DecodeNTPServer(p)
		if err == nil || errors.Is(err, ErrShort) {
			t.Errorf("%x: %v, want a non-ErrShort error", p, err)
		}
	}
}
