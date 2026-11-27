// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "golang.org/x/crypto/curve25519"

// This file covers §4.4 and §4.5: the six MACs, the transcript (context/context2),
// the X25519 agreement, and master with its four session keys plus admit_tag.
//
// Field widths (§3): client_nonce 24, device_id 8, epoch_tag 8, cookie 16,
// admission_epoch 8, e_c/e_s 32, canonical_source 18 (16-octet v6 || 2-octet port).
// type and version are one octet each.

// InitMAC = HMAC/128(k_req, L("init") || type || version || client_nonce || device_id) (§4.4).
func InitMAC(kReq []byte, clientNonce, deviceID []byte) []byte {
	return hmac128(kReq, concat(
		L("shieldled/v1/init"),
		[]byte{TypeINIT, Version},
		clientNonce, deviceID,
	))
}

// EpochTag = HMAC-SHA-256(cookie_secret, L("epoch") || cookie_epoch)[0:8] (§4.4).
// cookieEpoch is the 4-octet big-endian uint32 from §2.
func EpochTag(cookieSecret, cookieEpochBE4 []byte) []byte {
	return hmac256(cookieSecret, concat(L("shieldled/v1/epoch"), cookieEpochBE4))[:8]
}

// Cookie = HMAC/128(cookie_secret, L("cookie") || epoch_tag || canonical_source || client_nonce) (§4.4).
func Cookie(cookieSecret, epochTag, canonicalSource, clientNonce []byte) []byte {
	return hmac128(cookieSecret, concat(
		L("shieldled/v1/cookie"),
		epochTag, canonicalSource, clientNonce,
	))
}

// RetryMAC = HMAC/128(k_resp, L("retry") || type || version || client_nonce ||
// epoch_tag || cookie || admission_epoch || device_id || observed_source) (§4.4).
func RetryMAC(kResp, clientNonce, epochTag, cookie, admissionEpoch, deviceID, observedSource []byte) []byte {
	return hmac128(kResp, concat(
		L("shieldled/v1/retry"),
		[]byte{TypeRETRY, Version},
		clientNonce, epochTag, cookie, admissionEpoch, deviceID, observedSource,
	))
}

// Context = version || client_nonce || epoch_tag || cookie || admission_epoch || device_id (§4.5).
func Context(clientNonce, epochTag, cookie, admissionEpoch, deviceID []byte) []byte {
	return concat(
		[]byte{Version},
		clientNonce, epochTag, cookie, admissionEpoch, deviceID,
	)
}

// Context2 = context || e_c || e_s (§4.5).
func Context2(context, eC, eS []byte) []byte {
	return concat(context, eC, eS)
}

// ClientTag = HMAC/128(k_req, L("finish") || type || version || context || e_c) (§4.5).
func ClientTag(kReq, context, eC []byte) []byte {
	return hmac128(kReq, concat(
		L("shieldled/v1/finish"),
		[]byte{TypeFIN, Version},
		context, eC,
	))
}

// ErrZeroDH is returned by DH when the X25519 output is all zero, which §4.5
// requires both implementations to reject.
type zeroDHError struct{}

func (zeroDHError) Error() string { return "shieldnet: X25519 produced an all-zero shared secret" }

// ErrZeroDH is the sentinel for a rejected all-zero agreement (§4.5, RFC 7748).
var ErrZeroDH error = zeroDHError{}

// testHookDH, when set by a test, runs at every DH call with the peer point.
var testHookDH func(peerPublic []byte)

// DH computes X25519(own_private, peer_public) as the dh input to master, and
// rejects an all-zero shared secret per §4.5 / RFC 7748.
//
// The rejection is enforced by curve25519.X25519 itself: it returns a non-nil error
// (and a nil output) for a low-order peer point, which is exactly the input set that
// yields an all-zero secret. So the returned error for a rejected agreement is the
// library's, not ErrZeroDH — callers and vectors MUST test err != nil, not the error
// identity. The explicit loop below is defence in depth against a future library
// that returns all-zero rather than erroring; it does not fire for stdlib X25519.
// The C side (libsodium crypto_scalarmult) checks the output for all-zero and returns
// -1; both implementations therefore reject the same agreements, which the golden
// vectors pin.
func DH(ownPrivate, peerPublic []byte) ([]byte, error) {
	if testHookDH != nil {
		testHookDH(peerPublic)
	}
	out, err := curve25519.X25519(ownPrivate, peerPublic)
	if err != nil {
		return nil, err
	}
	if allZero32(out) {
		return nil, ErrZeroDH
	}
	return out, nil
}

func allZero32(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

// SessionKeys are the four keys expanded from master (§4.5).
type SessionKeys struct {
	KC2S    []byte // k_c2s
	KS2C    []byte // k_s2c
	KKcpC2S []byte // k_kcp_c2s
	KKcpS2C []byte // k_kcp_s2c
}

// Master = HKDF-Extract(salt = L("master") || context2, ikm = k_dev || dh) (§4.5).
// The salt exceeds one SHA-256 block, so Extract pre-hashes it (RFC 2104); this is
// the >64-octet path both implementations must take.
func Master(context2, kDev, dh []byte) []byte {
	salt := concat(L("shieldled/v1/master"), context2)
	ikm := concat(kDev, dh)
	defer zero(ikm) // §4.6: k_dev || dh, otherwise abandoned to the GC un-wiped
	return hkdfExtract(salt, ikm)
}

// DeriveSession expands the four session keys from master (§4.5).
func DeriveSession(master []byte) SessionKeys {
	return SessionKeys{
		KC2S:    hkdfExpand(master, L("shieldled/v1/c2s"), 32),
		KS2C:    hkdfExpand(master, L("shieldled/v1/s2c"), 32),
		KKcpC2S: hkdfExpand(master, L("shieldled/v1/kcp-c2s"), 32),
		KKcpS2C: hkdfExpand(master, L("shieldled/v1/kcp-s2c"), 32),
	}
}

// AdmitPre = HMAC/128(k_resp, L("admit-pre") || type || version || context2) (§4.5).
func AdmitPre(kResp, context2 []byte) []byte {
	return hmac128(kResp, concat(
		L("shieldled/v1/admit-pre"),
		[]byte{TypeADMIT, Version},
		context2,
	))
}

// AdmitTag = HKDF-Expand(master, L("admit"), 16) (§4.5). An Expand output, not a
// MAC, because master already commits to context2 through its salt.
func AdmitTag(master []byte) []byte {
	return hkdfExpand(master, L("shieldled/v1/admit"), 16)
}
