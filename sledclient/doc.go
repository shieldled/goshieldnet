// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Package sledclient is the host-side client for sled devices over ShieldNet v1.
//
// It encodes the core sled commands (status, device info, brightness, frame
// rate, mode, on/off, ping, NTP server) and correlates each ACK with the
// request that caused it. goshieldnet supplies the transport (package v1) and
// the payload codecs (package sled); sledclient adds the command layer on top
// of them. Client.Do sends any public kind unchecked and is the probe path for
// a device that may lack an extension.
//
// Extensions: DoExtension runs a command of an extension registered by the
// specification, checked against the capability the device advertises, and
// DoPrivate runs one of an "x-" extension; this module implements none.
//
// A Client is not safe for concurrent use: callers must serialise calls to Do,
// Send and the typed methods built on them.
//
// Admission is one-shot, as in v1: the first call admits the session, and a
// failed admission is not retried by the next call.
package sledclient
