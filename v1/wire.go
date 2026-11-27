// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import "errors"

// This file covers §3: the four fixed-size control messages, the transport
// envelope, and §8.3 sequence reconstruction. Encoders/decoders validate length
// before any field access (§3.5) — one of §14.5b's rules.

const (
	HeaderLen   = 10  // MAGIC[8] || type[1] || version[1]
	RequestLen  = 256 // INIT and FINISH
	RetryLen    = 84  // RETRY
	AdmitLen    = 82  // ADMIT
	EnvelopeLen = 20  // seq_wire[4] || tag[16]
	KcpOverhead = 24  // the KCP segment header
)

var (
	// ErrLength is a wrong total length (§3.5); checked before any field read.
	ErrLength = errors.New("shieldnet: wrong datagram length")
	// ErrMagic is a bad MAGIC or version.
	ErrMagic = errors.New("shieldnet: bad magic or version")
	// ErrType is an unexpected type for the direction/message.
	ErrType = errors.New("shieldnet: wrong message type")
	// ErrPadding is non-zero padding in a request (§3.5).
	ErrPadding = errors.New("shieldnet: non-zero request padding")
)

func header(typ byte) []byte {
	h := make([]byte, HeaderLen)
	copy(h, Magic)
	h[8] = typ
	h[9] = Version
	return h
}

// checkHeader validates length, magic, version, and type before any field access.
func checkHeader(b []byte, want int, typ byte) error {
	if len(b) != want {
		return ErrLength
	}
	if string(b[:8]) != string(Magic) || b[9] != Version {
		return ErrMagic
	}
	if b[8] != typ {
		return ErrType
	}
	return nil
}

// mustLen panics if a field is not its fixed width. The encoders below build
// fixed-layout datagrams; a wrong-width field would silently truncate or zero-fill
// and produce a plausible-but-wrong datagram, which is exactly the divergence the
// golden vectors exist to catch — so fail loudly at construction instead.
func mustLen(name string, b []byte, n int) {
	if len(b) != n {
		panic("shieldnet: " + name + ": got " + itoa(len(b)) + " octets, want " + itoa(n))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

// INIT (§3.1): hdr10 | client_nonce24@10 | device_id8@34 | init_mac16@42 | pad198@58.

// EncodeINIT builds a 256-octet INIT. clientNonce is 24, deviceID 8, initMAC 16.
func EncodeINIT(clientNonce, deviceID, initMAC []byte) []byte {
	mustLen("client_nonce", clientNonce, 24)
	mustLen("device_id", deviceID, 8)
	mustLen("init_mac", initMAC, 16)
	b := make([]byte, RequestLen)
	copy(b, header(TypeINIT))
	copy(b[10:34], clientNonce)
	copy(b[34:42], deviceID)
	copy(b[42:58], initMAC)
	return b
}

// INITFields is a decoded INIT.
type INITFields struct {
	ClientNonce []byte
	DeviceID    []byte
	InitMAC     []byte
}

// DecodeINIT validates and parses a 256-octet INIT, rejecting non-zero padding.
func DecodeINIT(b []byte) (INITFields, error) {
	if err := checkHeader(b, RequestLen, TypeINIT); err != nil {
		return INITFields{}, err
	}
	if !allZero(b[58:]) {
		return INITFields{}, ErrPadding
	}
	return INITFields{ClientNonce: b[10:34], DeviceID: b[34:42], InitMAC: b[42:58]}, nil
}

// RETRY (§3.2): hdr10 | epoch_tag8@10 | cookie16@18 | admission_epoch8@34 |
// device_id8@42 | observed_source18@50 | retry_mac16@68.

// EncodeRETRY builds an 84-octet RETRY.
func EncodeRETRY(epochTag, cookie, admissionEpoch, deviceID, observedSource, retryMAC []byte) []byte {
	mustLen("epoch_tag", epochTag, 8)
	mustLen("cookie", cookie, 16)
	mustLen("admission_epoch", admissionEpoch, 8)
	mustLen("device_id", deviceID, 8)
	mustLen("observed_source", observedSource, 18)
	mustLen("retry_mac", retryMAC, 16)
	b := make([]byte, RetryLen)
	copy(b, header(TypeRETRY))
	copy(b[10:18], epochTag)
	copy(b[18:34], cookie)
	copy(b[34:42], admissionEpoch)
	copy(b[42:50], deviceID)
	copy(b[50:68], observedSource)
	copy(b[68:84], retryMAC)
	return b
}

// RETRYFields is a decoded RETRY.
type RETRYFields struct {
	EpochTag       []byte
	Cookie         []byte
	AdmissionEpoch []byte
	DeviceID       []byte
	ObservedSource []byte
	RetryMAC       []byte
}

// DecodeRETRY validates and parses an 84-octet RETRY.
func DecodeRETRY(b []byte) (RETRYFields, error) {
	if err := checkHeader(b, RetryLen, TypeRETRY); err != nil {
		return RETRYFields{}, err
	}
	return RETRYFields{
		EpochTag: b[10:18], Cookie: b[18:34], AdmissionEpoch: b[34:42],
		DeviceID: b[42:50], ObservedSource: b[50:68], RetryMAC: b[68:84],
	}, nil
}

// FINISH (§3.3): hdr10 | client_nonce24@10 | epoch_tag8@34 | cookie16@42 |
// admission_epoch8@58 | e_c32@66 | client_tag16@98 | pad142@114.

// EncodeFINISH builds a 256-octet FINISH.
func EncodeFINISH(clientNonce, epochTag, cookie, admissionEpoch, eC, clientTag []byte) []byte {
	mustLen("client_nonce", clientNonce, 24)
	mustLen("epoch_tag", epochTag, 8)
	mustLen("cookie", cookie, 16)
	mustLen("admission_epoch", admissionEpoch, 8)
	mustLen("e_c", eC, 32)
	mustLen("client_tag", clientTag, 16)
	b := make([]byte, RequestLen)
	copy(b, header(TypeFIN))
	copy(b[10:34], clientNonce)
	copy(b[34:42], epochTag)
	copy(b[42:58], cookie)
	copy(b[58:66], admissionEpoch)
	copy(b[66:98], eC)
	copy(b[98:114], clientTag)
	return b
}

// FINISHFields is a decoded FINISH.
type FINISHFields struct {
	ClientNonce    []byte
	EpochTag       []byte
	Cookie         []byte
	AdmissionEpoch []byte
	EC             []byte
	ClientTag      []byte
}

// DecodeFINISH validates and parses a 256-octet FINISH, rejecting non-zero padding.
func DecodeFINISH(b []byte) (FINISHFields, error) {
	if err := checkHeader(b, RequestLen, TypeFIN); err != nil {
		return FINISHFields{}, err
	}
	if !allZero(b[114:]) {
		return FINISHFields{}, ErrPadding
	}
	return FINISHFields{
		ClientNonce: b[10:34], EpochTag: b[34:42], Cookie: b[42:58],
		AdmissionEpoch: b[58:66], EC: b[66:98], ClientTag: b[98:114],
	}, nil
}

// ADMIT (§3.4): hdr10 | admission_epoch8@10 | e_s32@18 | admit_pre16@50 | admit_tag16@66.

// EncodeADMIT builds an 82-octet ADMIT.
func EncodeADMIT(admissionEpoch, eS, admitPre, admitTag []byte) []byte {
	mustLen("admission_epoch", admissionEpoch, 8)
	mustLen("e_s", eS, 32)
	mustLen("admit_pre", admitPre, 16)
	mustLen("admit_tag", admitTag, 16)
	b := make([]byte, AdmitLen)
	copy(b, header(TypeADMIT))
	copy(b[10:18], admissionEpoch)
	copy(b[18:50], eS)
	copy(b[50:66], admitPre)
	copy(b[66:82], admitTag)
	return b
}

// ADMITFields is a decoded ADMIT.
type ADMITFields struct {
	AdmissionEpoch []byte
	ES             []byte
	AdmitPre       []byte
	AdmitTag       []byte
}

// DecodeADMIT validates and parses an 82-octet ADMIT.
func DecodeADMIT(b []byte) (ADMITFields, error) {
	if err := checkHeader(b, AdmitLen, TypeADMIT); err != nil {
		return ADMITFields{}, err
	}
	return ADMITFields{
		AdmissionEpoch: b[10:18], ES: b[18:50], AdmitPre: b[50:66], AdmitTag: b[66:82],
	}, nil
}

// Reconstruct returns the 64-bit candidate sequence for a received seq_wire against
// the current high-water mark, per §8.3. The int32 boundary (d32 == 0x80000000) is
// written out longhand because a naive cast is implementation-defined in C and
// wrapping in Go, and §15 requires both to agree there. The caller applies the
// window/wrap checks; Reconstruct only produces the signed candidate.
func Reconstruct(seqWire uint32, hwm uint64) int64 {
	d32 := seqWire - uint32(hwm&0xFFFFFFFF)
	var delta int64
	if d32 < 0x80000000 {
		delta = int64(d32)
	} else {
		delta = int64(d32) - 0x100000000
	}
	return int64(hwm) + delta
}

// seqWireOf returns the low 32 bits of seq_full (§3.6).
func seqWireOf(seqFull uint64) uint32 { return uint32(seqFull & 0xFFFFFFFF) }
