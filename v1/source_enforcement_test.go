// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

// §4.3 end to end, on the paths that actually enforce it.
//
// source_test.go covers the SourceRejected predicate in isolation, but every
// end-to-end test in this package sets skipSrcCheck (loopback is 127/8, which
// §4.3 rejects — that is the whole reason the flag exists). So nothing exercised
// Server.handlePacket's and Client.classify's real wiring of Classify: the role,
// the address they derive, and above all WHICH PREFIX SET they pass. A server
// that handed Classify a nil prefix set — or the wrong one — would pass every
// test in the tree while silently accepting the subnet-broadcast source §4.3
// exists to refuse.
func TestServerEnforcesSourceRejectionOnReceive(t *testing.T) {
	// The device's local prefix is 192.168.4.1/24, so its subnet broadcast is
	// 192.168.4.255 — the case that can only be computed from the prefix set.
	newSrv := func() (*Server, *mockConn, *Device, []byte) {
		mock := newMockConn()
		dev, deviceID := testDevice()
		dev.SetRandSource(fixedRand(0x42))
		return NewServer(dev, mock), mock, dev, deviceID
	}

	nonce := bytes.Repeat([]byte{0xAB}, 24)

	t.Run("a permitted source is answered", func(t *testing.T) {
		srv, mock, dev, deviceID := newSrv()
		defer srv.Close()
		srv.handlePacket(validINIT(dev.kReq, nonce, deviceID),
			&net.UDPAddr{IP: net.IPv4(192, 168, 4, 2), Port: 5000})
		if mock.count() != 1 {
			t.Fatalf("a valid INIT from a permitted source produced %d datagrams, want 1", mock.count())
		}
	})

	for _, tc := range []struct {
		name string
		ip   net.IP
		why  string
	}{
		{"loopback", net.IPv4(127, 0, 0, 1), "127/8"},
		{"unspecified", net.IPv4(0, 0, 0, 0), "0/8"},
		{"multicast", net.IPv4(224, 0, 0, 1), "224/4"},
		{"limited broadcast", net.IPv4(255, 255, 255, 255), "255.255.255.255"},
		// The one that pins the prefix set: 192.168.4.255 is rejectable ONLY by
		// computing the broadcast address of the device's own 192.168.4.1/24.
		// Pass Classify a nil or wrong prefix set and this source is accepted.
		{"local subnet broadcast", net.IPv4(192, 168, 4, 255), "the /24's broadcast address"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			srv, mock, dev, deviceID := newSrv()
			defer srv.Close()
			srv.handlePacket(validINIT(dev.kReq, nonce, deviceID),
				&net.UDPAddr{IP: tc.ip, Port: 5000})
			if mock.count() != 0 {
				t.Errorf("answered an INIT from %v (%s); §4.3 requires a silent drop",
					tc.ip, tc.why)
			}
		})
	}

	// §4.3 is applied BEFORE the magic test (§5 step 0), so a rejected source
	// cannot reach the envelope path either — the expensive one.
	t.Run("rejects before demux, not after", func(t *testing.T) {
		srv, mock, _, _ := newSrv()
		defer srv.Close()
		srv.handlePacket(bytes.Repeat([]byte{0x5A}, 64),
			&net.UDPAddr{IP: net.IPv4(224, 0, 0, 1), Port: 5000})
		if mock.count() != 0 {
			t.Error("a datagram from a multicast source reached a handler")
		}
		if srv.Primary() != nil {
			t.Error("a datagram from a multicast source established a session")
		}
	})
}

// The controller half of §4.3. A client classifies against the address it is
// talking to, so pointing it at a rejected address must drop everything that
// arrives — which is exactly why the loopback harnesses set skipSrcCheck.
func TestClientEnforcesSourceRejection(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("192.168.4.2/24")}
	psk := bytes.Repeat([]byte{0x11}, 32)
	deviceID := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// a well-formed RETRY, so only the source can be the reason it is dropped
	retry := EncodeRETRY(
		bytes.Repeat([]byte{0x33}, 8),  // epoch_tag
		bytes.Repeat([]byte{0x44}, 16), // cookie
		bytes.Repeat([]byte{0x55}, 8),  // admission_epoch
		deviceID,
		bytes.Repeat([]byte{0x66}, 18), // observed_source (16 addr + 2 port)
		bytes.Repeat([]byte{0x77}, 16), // retry_mac
	)

	for _, tc := range []struct {
		name   string
		device string
		want   Class
	}{
		{"a permitted device address", "192.168.4.1:32000", ClassRETRY},
		{"loopback", "127.0.0.1:32000", ClassDrop},
		{"multicast", "224.0.0.1:32000", ClassDrop},
		// Rejectable only from the client's own prefix set, as above.
		{"the local subnet broadcast", "192.168.4.255:32000", ClassDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, err := NewClient(tc.device, psk, deviceID, local)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			if got := cli.classify(retry); got != tc.want {
				t.Errorf("classify from %s = %v, want %v", tc.device, got, tc.want)
			}
		})
	}
}
