// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package v1 implements ShieldNet v1: a mutually-authenticated, encrypted,
// replay-resistant transport for driving ShieldLED devices over UDP.
//
// The specification is spec/transport.md in the shieldnet-protocol repository,
// and this package is byte-exact with the C implementation, libshieldnet. Where
// the code and the specification disagree, the specification is right; the
// golden vectors in testdata/ are generated from it independently of both
// implementations.
//
// Two entry points:
//
//   - Client is a controller. NewClient, then TakeControlApp to admit and send
//     the first application message in one round trip, then SendApp/RecvApp.
//     Take-control is one-shot: no retry, no backoff, no automatic failover (§7).
//   - Server is the device side, used mainly for testing and emulation; the
//     device of record is the C implementation. NewDeviceFromKDev, NewServer, Serve.
//
// A controller holds the 32-octet PSK; a device is provisioned only with its own
// derived k_dev and its 8-octet device_id, so opening one device does not
// compromise the fleet (§0, §4.7).
//
// The rest of the package is the primitives the two entry points are built from,
// exported so they can be tested and vector-checked directly: the key schedule
// and MACs (this file, §0 and §4), the wire codecs (wire.go, §3), the envelope
// (envelope.go, §3.6), demultiplexing (demux.go, §5) and the replay window
// (replay.go, §8.2).
package v1

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// Label prefixes and constants from §0 and §2. Values are the byte strings the spec
// pins; changing any of them changes every downstream vector by design.
const (
	Version   = 0x01
	TypeINIT  = 0x01
	TypeRETRY = 0x02
	TypeFIN   = 0x05
	TypeADMIT = 0x06
)

// Magic is the 8-octet datagram prefix, §2.
var Magic = []byte("SLD1Z001")

// L returns uint8(len(label)) || label, US-ASCII, no terminator (§0). Labels are
// short ASCII constants, so the length always fits one octet.
func L(label string) []byte {
	out := make([]byte, 1+len(label))
	out[0] = byte(len(label))
	copy(out[1:], label)
	return out
}

// concat joins byte slices; a small helper so the derivations below read like the
// RFC's "||" notation rather than a pile of append calls.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// hkdfExtract is RFC 5869 Extract. salt=="" means 32 zero octets (§0); a nil salt
// to x/crypto's hkdf.Extract already substitutes hashLen zero octets, but we pass
// the explicit zero salt to match the C side, which does the same.
func hkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

// hkdfExpand is RFC 5869 Expand to n octets.
func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, n)
	r := hkdf.Expand(sha256.New, prk, info)
	if _, err := r.Read(out); err != nil {
		// Expand only errors when n exceeds 255*hashLen; none of our calls do.
		panic("shieldnet: hkdf expand: " + err.Error())
	}
	return out
}

// hmac128 is the leading 128 bits of HMAC-SHA-256(k, m) — the spec's HMAC/128 (§0).
func hmac128(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)[:16]
}

// hmac256 is the full HMAC-SHA-256(k, m).
func hmac256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

var zeroSalt = make([]byte, 32) // salt="" per §0

// DeriveKDev computes k_dev from the PSK and device_id (§0). Controllers hold the
// PSK and derive k_dev per device; devices are provisioned with k_dev directly.
// Both routes produce identical bytes.
func DeriveKDev(psk, deviceID []byte) []byte {
	prkPSK := hkdfExtract(zeroSalt, psk)
	defer zero(prkPSK) // §4.6: this is a PRK over the domain PSK
	return hkdfExpand(prkPSK, concat(L("shieldled/v1/device"), deviceID), 32)
}

// StaticKeys are the long-lived request/response MAC keys, derived once per k_dev
// at init (§4.1).
type StaticKeys struct {
	KReq  []byte // k_req, client→device
	KResp []byte // k_resp, device→client
}

// DeriveStatic computes k_req and k_resp from k_dev (§4.1).
func DeriveStatic(kDev []byte) StaticKeys {
	prkStatic := hkdfExtract(zeroSalt, kDev)
	defer zero(prkStatic) // §4.6: parent of k_req/k_resp
	return StaticKeys{
		KReq:  hkdfExpand(prkStatic, L("shieldled/v1/req"), 32),
		KResp: hkdfExpand(prkStatic, L("shieldled/v1/resp"), 32),
	}
}
