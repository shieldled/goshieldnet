// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"net/netip"
)

// This file covers §5: demultiplexing an inbound datagram. Classify is a pure
// function — the RX path calls it first, and it is §4.3's ONLY enforcement point
// (§5 step 0), so no control or envelope handler repeats the source check.

// Role is which side is receiving; it decides the §5 "Direction" rule.
type Role uint8

const (
	RoleDevice Role = iota // rejects RETRY and ADMIT (client→device types only)
	RoleClient             // rejects INIT and FINISH (device→client types only)
)

// Class is the demux outcome.
type Class uint8

const (
	ClassDrop     Class = iota // silently dropped (§5); never answered (§9.3)
	ClassEnvelope              // envelope path (§8)
	ClassINIT                  // control INIT (§6.1), device only
	ClassRETRY                 // control RETRY (§6.1), client only
	ClassFINISH                // control FINISH (§6.2), device only
	ClassADMIT                 // control ADMIT (§6.2), client only
)

// Classify implements §5 for one datagram received at src (with the interface's
// local prefixes for §4.3's own-address / subnet-broadcast checks).
//
//   - §5 step 0: a source on §4.3's rejection list is dropped before anything else.
//   - §5 step 1: N ≥ HEADER_LEN and the first 8 octets == MAGIC → control path;
//     the type octet then selects the message, filtered by direction. Reserved
//     types 0x03/0x04 and anything outside 0x01–0x06, and any well-known type in
//     the wrong direction, are dropped — not reinterpreted as an envelope.
//   - §5 step 2: otherwise → envelope path (a MAGIC-colliding ciphertext is 2⁻⁶⁴
//     and simply lost; a too-short envelope is rejected later by §8, not here).
//
// Length and version of a control message are validated by its decoder (§3.5),
// not here: Classify only routes.
func Classify(role Role, src netip.Addr, local []netip.Prefix, datagram []byte) Class {
	if SourceRejected(src, local) { // §5 step 0 — §4.3's only enforcement point
		return ClassDrop
	}
	return classifyDatagram(role, datagram)
}

// classifyDatagram is §5 steps 1–2 without the source check. The source check is
// §4.3's only enforcement point and belongs in Classify; this split exists so a
// test harness on loopback (whose 127.0.0.1 source §4.3 rejects) can exercise the
// rest of the pipeline. Production always goes through Classify.
func classifyDatagram(role Role, datagram []byte) Class {
	if len(datagram) >= HeaderLen && bytes.Equal(datagram[:8], Magic) { // §5 step 1
		switch datagram[8] {
		case TypeINIT:
			if role == RoleDevice {
				return ClassINIT
			}
		case TypeRETRY:
			if role == RoleClient {
				return ClassRETRY
			}
		case TypeFIN:
			if role == RoleDevice {
				return ClassFINISH
			}
		case TypeADMIT:
			if role == RoleClient {
				return ClassADMIT
			}
		}
		return ClassDrop // wrong-direction, reserved, or out-of-range type
	}
	return ClassEnvelope // §5 step 2
}
