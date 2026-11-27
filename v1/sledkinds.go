// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

package v1

// Command and response kinds for the ShieldLED device application protocol,
// specified in shieldnet-protocol/spec/application.md, section 10.
//
// These are declared here so that a renumbering breaks the build rather than
// silently driving the wrong command at a device. They are constants only: this
// package implements the transport and the message layer, and the payloads are
// encoded by the sled package (responses, PIXEL_FRAME, NTP_SERVER) or by the
// caller (other commands).
//
// Dispatch is on the exact kind, never on a range or a bit. Command kinds the
// specification reserves for an extension are not declared here.
const (
	// The pixel data plane.
	CmdPixelFrame = 0x00

	// Device and output control.
	CmdSetBrightness = 0x01
	CmdSetFPS        = 0x02
	CmdSetMode       = 0x04
	CmdOn            = 0x05
	CmdOff           = 0x06
	CmdPing          = 0x07
	CmdGetStatus     = 0x08
	CmdGetMode       = 0x09
	CmdGetDeviceInfo = 0x0A
	CmdNTPServer     = 0x0B
)

// Response kinds (device → client).
const (
	RespAck        = 0x80
	RespStatus     = 0x81
	RespDeviceInfo = 0x84
)

// coreCommands is the one table of the core command kinds (specification
// 10.1, Part "core"). 0x03 is reserved for an extension, so it is not here.
var coreCommands = [...]uint32{
	CmdPixelFrame, CmdSetBrightness, CmdSetFPS, CmdSetMode, CmdOn, CmdOff,
	CmdPing, CmdGetStatus, CmdGetMode, CmdGetDeviceInfo, CmdNTPServer,
}

// IsCoreCommand reports whether kind is one of the 11 core command kinds. Any
// other kind below 0x80 is an extension's or unassigned.
func IsCoreCommand(kind uint32) bool {
	for _, k := range coreCommands {
		if k == kind {
			return true
		}
	}
	return false
}
