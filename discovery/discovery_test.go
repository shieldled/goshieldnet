// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
)

func entry(service, instance, ip string) *mdns.ServiceEntry {
	return &mdns.ServiceEntry{
		Name:   instance + "." + service + ".local.",
		AddrV4: net.ParseIP(ip),
		Port:   4000,
	}
}

func TestCollectDedupesByServiceAndInstance(t *testing.T) {
	seen := map[string]bool{}
	var out []Found
	out = collect(seen, out, "_sled_l1._udp", entry("_sled_l1._udp", "a", "10.0.0.1"), false)
	out = collect(seen, out, "_sled_l1._udp", entry("_sled_l1._udp", "a", "10.0.0.1"), false)
	if len(out) != 1 {
		t.Fatalf("same instance twice on one service gave %d results, want 1", len(out))
	}
	out = collect(seen, out, "_sled_s1._udp", entry("_sled_s1._udp", "a", "10.0.0.1"), false)
	if len(out) != 2 {
		t.Fatalf("same instance on two services gave %d results, want 2", len(out))
	}
}

func TestCollectSkipsEntryWithoutIPv4(t *testing.T) {
	out := collect(map[string]bool{}, nil, "_sled_l1._udp", entry("_sled_l1._udp", "a", ""), false)
	if len(out) != 0 {
		t.Fatalf("entry without IPv4 gave %v", out)
	}
}

func TestCollectParsesTXTAndDeviceID(t *testing.T) {
	const svc = "_sled_s1._udp"
	e := entry(svc, "00000000-0000-0000-0000-a1b2c3d4e5f6", "10.0.0.7")
	e.InfoFields = []string{"label=Hall", "caps"}
	out := collect(map[string]bool{}, nil, svc, e, false)
	if len(out) != 1 {
		t.Fatalf("got %d results", len(out))
	}
	f := out[0]
	if f.Instance != "00000000-0000-0000-0000-a1b2c3d4e5f6" {
		t.Errorf("Instance = %q", f.Instance)
	}
	if want := map[string]string{"label": "Hall", "caps": ""}; !reflect.DeepEqual(f.TXT, want) {
		t.Errorf("TXT = %v, want %v", f.TXT, want)
	}
	if want := [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0, 0}; !f.HasDeviceID || f.DeviceID != want {
		t.Errorf("DeviceID = %x (has %v), want %x", f.DeviceID, f.HasDeviceID, want)
	}
	if f.Addr() != "10.0.0.7:4000" || f.Host != "10.0.0.7" {
		t.Errorf("Addr = %q Host = %q", f.Addr(), f.Host)
	}

	out = collect(map[string]bool{}, nil, svc, entry(svc, "living-room", "10.0.0.8"), false)
	if len(out) != 1 || out[0].HasDeviceID {
		t.Errorf("non-UUID instance: %+v", out)
	}
}

func TestCollectSkipsForeignService(t *testing.T) {
	const svc = "_sled_s1._udp"
	other := entry("_sled_x1._udp", "a", "10.0.0.9")
	if out := collect(map[string]bool{}, nil, svc, other, false); len(out) != 0 {
		t.Errorf("entry for another sled service gave %v", out)
	}
	cast := &mdns.ServiceEntry{Name: "Kitchen._googlecast._tcp.local.", AddrV4: net.ParseIP("10.0.0.9"), Port: 4000}
	if out := collect(map[string]bool{}, nil, svc, cast, false); len(out) != 0 {
		t.Errorf("unrelated device gave %v", out)
	}
}

func v6entry(service, instance, ip, zone string) *mdns.ServiceEntry {
	return &mdns.ServiceEntry{
		Name:         instance + "." + service + ".local.",
		AddrV6IPAddr: &net.IPAddr{IP: net.ParseIP(ip), Zone: zone},
		Port:         4000,
	}
}

// With IPv6, an AAAA-only device is listed by its address and zone.
func TestDiscoveryIPv6Listed(t *testing.T) {
	const svc = "_sled_l1._udp"
	out := collect(map[string]bool{}, nil, svc, v6entry(svc, "a", "fe80::1", "eth0"), true)
	if len(out) != 1 {
		t.Fatalf("got %v", out)
	}
	if got := out[0].Addr(); got != "[fe80::1%eth0]:4000" {
		t.Fatalf("Addr = %q, want [fe80::1%%eth0]:4000", got)
	}
	if out := collect(map[string]bool{}, nil, svc, v6entry(svc, "a", "fe80::1", "eth0"), false); len(out) != 0 {
		t.Fatalf("without IPv6 an AAAA-only entry gave %v", out)
	}
}

func TestDiscoveryIPv6LinkLocalWithoutZoneSkipped(t *testing.T) {
	const svc = "_sled_l1._udp"
	if out := collect(map[string]bool{}, nil, svc, v6entry(svc, "a", "fe80::1", ""), true); len(out) != 0 {
		t.Fatalf("a link-local address without a zone gave %v", out)
	}
	out := collect(map[string]bool{}, nil, svc, v6entry(svc, "a", "2001:db8::7", ""), true)
	if len(out) != 1 || out[0].Host != "2001:db8::7" {
		t.Fatalf("a global address without a zone: %v", out)
	}
}

func TestDiscoveryNoAddressSkipped(t *testing.T) {
	const svc = "_sled_l1._udp"
	e := &mdns.ServiceEntry{Name: "a." + svc + ".local.", Port: 4000}
	if out := collect(map[string]bool{}, nil, svc, e, true); len(out) != 0 {
		t.Fatalf("an entry with no address gave %v", out)
	}
}

func TestServicesForDefaultsAndCustom(t *testing.T) {
	got, err := servicesFor(Options{})
	if err != nil || len(got) != len(ServiceTypes) {
		t.Fatalf("default: %v %v", got, err)
	}
	mine := []string{"_acme-led._udp", "_panel_2._UDP"}
	got, err = servicesFor(Options{Services: mine})
	if err != nil || len(got) != 2 || got[0] != mine[0] || got[1] != mine[1] {
		t.Fatalf("custom: %v %v", got, err)
	}
}

func TestServicesForRejectsMalformed(t *testing.T) {
	bad := []string{
		"_sled_s1._tcp", "sled_s1._udp", "_sled_s1._udp.local", "_sled_s1._udp.local.",
		"_sled_s1._udp.", "_._udp", "_0123456789abcdef._udp", "_two words._udp",
		"_sled.s1._udp", "_sled_s1", "",
	}
	for _, s := range bad {
		if _, err := servicesFor(Options{Services: []string{"_sled_s1._udp", s}}); !errors.Is(err, ErrBadService) {
			t.Errorf("%q: err = %v, want ErrBadService", s, err)
		}
	}
	if !validService("_0123456789abcde._udp") {
		t.Error("a 15-character name was refused")
	}
}

// A malformed list fails before any query is made.
func TestDiscoverAllWithBadServiceFailsFast(t *testing.T) {
	start := time.Now()
	out, err := DiscoverAllWith(5*time.Second, Options{Services: []string{"_acme-led"}})
	if !errors.Is(err, ErrBadService) || out != nil {
		t.Fatalf("out = %v err = %v", out, err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("took %v: a query ran", time.Since(start))
	}
}

func TestCollectCustomService(t *testing.T) {
	const svc = "_acme-led._udp"
	out := collect(map[string]bool{}, nil, svc, entry(svc, "acme-1", "10.0.0.7"), false)
	if len(out) != 1 || out[0].Service != svc || out[0].Instance != "acme-1" {
		t.Errorf("custom service: %+v", out)
	}
}
