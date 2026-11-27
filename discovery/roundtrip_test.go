// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
)

// A device announcing a custom service type is found when Options.Services
// names it, and not by the default browse. Skips without a multicast-capable
// interface with an IPv4 address, or when port 5353 cannot be bound.
func TestDiscoverAllWithCustomServiceRoundTrip(t *testing.T) {
	ifaces := queryInterfaces(false)
	if len(ifaces) == 0 {
		t.Skip("no multicast-capable IPv4 interface")
	}
	var ip net.IP
	addrs, _ := ifaces[0].Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ip = n.IP.To4()
			break
		}
	}
	if ip == nil {
		t.Skip("interface has no IPv4 address")
	}
	const svc = "_sntest-cust._udp"
	zone, err := mdns.NewMDNSService("roundtrip-1", svc, "", "roundtrip-host.local.", 7000, []net.IP{ip}, []string{"caps=pixel"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: zone, Iface: &ifaces[0]})
	if err != nil {
		t.Skipf("mDNS responder: %v", err)
	}
	defer srv.Shutdown()

	out, err := DiscoverAllWith(1500*time.Millisecond, Options{Services: []string{svc}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range out {
		if f.Instance == "roundtrip-1" && f.Service == svc && f.Port == 7000 && f.TXT["caps"] == "pixel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom service not found: %+v", out)
	}

	out, err = DiscoverAll(1500 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out {
		if f.Instance == "roundtrip-1" {
			t.Fatalf("default browse found the custom service: %+v", f)
		}
	}
}
