// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package sledclient

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// ErrInvalidKey is returned when a PSK is not 64 hex characters.
var ErrInvalidKey = errors.New("encryption key must be 64 hex characters (32 bytes)")

// DecodePSK decodes a 64-hex-character pre-shared key (surrounding spaces trimmed).
func DecodePSK(hexKey string) ([]byte, error) {
	psk, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(psk) != 32 {
		return nil, ErrInvalidKey
	}
	return psk, nil
}

// DecodeDeviceID decodes a 16-hex-character ShieldNet device id.
func DecodeDeviceID(hexID string) ([8]byte, error) {
	var out [8]byte
	b, err := hex.DecodeString(strings.TrimSpace(hexID))
	if err != nil || len(b) != 8 {
		return out, errors.New("device id must be 8 bytes of hex (16 characters)")
	}
	copy(out[:], b)
	return out, nil
}

// DeviceIDFromInstance derives the device id from a firmware mDNS instance
// name (the device UUID): its last 6 bytes followed by 00 00
// (as the firmware derives it). Only the canonical form is
// accepted: 36 characters, hyphens at offsets 8, 13, 18 and 23, hex digits
// everywhere else.
func DeviceIDFromInstance(instance string) ([8]byte, error) {
	errNotUUID := errors.New("sledclient: instance is not a canonical UUID")
	if len(instance) != 36 {
		return [8]byte{}, errNotUUID
	}
	var id [16]byte
	n := 0
	for i := 0; i < 36; i++ {
		c := instance[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return [8]byte{}, errNotUUID
			}
			continue
		}
		v, ok := hexVal(c)
		if !ok {
			return [8]byte{}, errNotUUID
		}
		if n%2 == 0 {
			id[n/2] = v << 4
		} else {
			id[n/2] |= v
		}
		n++
	}
	return DeviceIDFromUUID(id), nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// DeviceIDFromUUID returns the 8-byte ShieldNet device_id for a device UUID:
// the UUID's last 6 bytes followed by two zero bytes. This matches the
// firmware, whose UUID is 534c4544-<product>-8000-8000-<mac> and whose
// device_id is mac||0000.
// A google/uuid UUID is assignable to [16]byte, so callers holding one pass
// it directly.
func DeviceIDFromUUID(id [16]byte) [8]byte {
	var out [8]byte
	copy(out[:6], id[10:16])
	return out
}

// LocalPrefixes returns this host's interface prefixes, for v1's own-address rule.
func LocalPrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}
