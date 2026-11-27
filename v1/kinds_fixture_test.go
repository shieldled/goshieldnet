// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Kinds the transport does not interpret, used as fixtures: one for a bulk
// message (compressed when that shrinks it) and one for a control message.
const (
	anyBulkKind    = 0x20 // a kind the transport does not interpret, used as a bulk fixture
	anyControlKind = 0x23
)
