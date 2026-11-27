// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net"
	"reflect"
	"testing"

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
