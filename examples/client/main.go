// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Command client is a complete ShieldNet v1 controller.
//
// It admits to a device, sends control messages and pixel frames, reads
// the responses, and handles the failure modes the protocol actually produces —
// a rejected frame, a desynchronised stream, a full send queue, and a dead
// session. The error handling is the point: each case has a different remedy and
// the library reports them distinctly.
//
// Run:
//
//	umask 077; echo <64 hex chars of PSK> > psk.hex   # mode 0600
//	SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -device 192.168.4.1:32000 \
//	    -device-id 0908070605040302
//
// The PSK never comes from argv, which every local user can read through ps and
// /proc/<pid>/cmdline: it is read from the mode-0600 file named by
// SHIELDNET_PSK_FILE, or else from SHIELDNET_PSK (hex) — the same as
// libshieldnet's host tools. -psk is refused.
//
// Provisioning: a device holds only its own k_dev, never the PSK (transport §0).
// -print-kdev derives it for -device-id, prints it as hex and exits; write it
// to a mode-0600 file for the device (examples/server reads SHIELDNET_KDEV_FILE):
//
//	SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -print-kdev \
//	    -device-id 0908070605040302 > kdev.hex
//
// §4.3 rejects loopback sources, so this cannot admit to a device on 127.0.0.1.
// See examples/README.md.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shieldled/goshieldnet/examples/internal/secret"
	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

func main() {
	device := flag.String("device", "", "device address host:port (required)")
	pskFlag := flag.String("psk", "", "REFUSED: a key on the command line is world-readable; "+
		"use SHIELDNET_PSK_FILE (or SHIELDNET_PSK)")
	devHex := flag.String("device-id", "", "8-byte device id, hex (required)")
	printKDev := flag.Bool("print-kdev", false,
		"print the k_dev for -device-id (hex) for provisioning a device, then exit")
	sameHost := flag.Bool("same-host-demo", false,
		"allow a device running on THIS machine: disables §4.3's own-address "+
			"rejection. Demo only — never set it in a deployment.")
	ntpFlag := flag.String("ntp", "",
		"time server to announce to a device that advertises pts: host, host:port, "+
			"an IPv6 address or [v6]:port (port defaults to 123); empty sends nothing")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: SHIELDNET_PSK_FILE=<0600 file> %s -device host:port -device-id <16 hex>\n"+
				"       SHIELDNET_PSK_FILE=<0600 file> %s -print-kdev -device-id <16 hex>\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *pskFlag != "" {
		log.Fatal(secret.RefuseArgv("psk", "SHIELDNET_PSK_FILE", "SHIELDNET_PSK"))
	}
	deviceID, err := hex.DecodeString(*devHex)
	if err != nil || len(deviceID) != 8 {
		log.Fatal("-device-id must be 8 bytes of hex (16 characters)")
	}
	if *device == "" && !*printKDev {
		log.Fatal("-device is required")
	}
	var ntpPayload []byte
	if *ntpFlag != "" {
		var err error
		if ntpPayload, err = parseNTPFlag(*ntpFlag); err != nil {
			log.Fatalf("-ntp: %v", err)
		}
	}
	// Loaded last, so no exit path above holds it.
	psk, err := secret.Load("SHIELDNET_PSK_FILE", "SHIELDNET_PSK")
	if err != nil {
		if errors.Is(err, secret.ErrNotSet) {
			log.Fatal("no PSK: set SHIELDNET_PSK_FILE (or SHIELDNET_PSK)")
		}
		log.Fatal(err)
	}

	if *printKDev {
		// The controller side of provisioning: the device gets this, never psk.
		kDev := v1.DeriveKDev(psk, deviceID)
		secret.Wipe(psk)
		fmt.Println(hex.EncodeToString(kDev))
		secret.Wipe(kDev)
		return
	}

	// A controller holds the PSK and derives k_dev for whichever device it
	// addresses (§0). local is used only to validate the client's own source.
	// §4.3 is applied by BOTH ends. A controller rejects a datagram whose source
	// is one of its own interface addresses, so a device on the same machine has
	// its RETRY refused just as the device refuses the client's INIT. Both sides
	// must opt out for a single-machine demo; loopback stays rejected regardless.
	local := localPrefixes()
	if *sameHost {
		log.Print("WARNING: -same-host-demo disables §4.3 own-address rejection")
		local = nil
	}
	// NewClient derives what it needs and keeps no reference to psk, so this
	// copy is wiped as soon as it returns.
	cli, err := v1.NewClient(*device, psk, deviceID, local)
	secret.Wipe(psk)
	if err != nil {
		log.Fatalf("new client: %v", err)
	}
	defer cli.Close()

	// Admission is ONE attempt: no retry, no backoff, no automatic failover
	// (§7.2). Retrying is the caller's decision, and deliberately so — an
	// earlier design retried with damping, and the damping turned out to be the
	// cheapest attack in the protocol, letting two controllers be driven into a
	// displacement loop.
	//
	// TakeControlAppPadded frames the first application message as the promoting
	// datagram (§8.5(c)), so admission and the first command are one round trip.
	// PING is control, so it is padded; sled 3.6 keeps the first message within
	// the smallest class, which every device accepts. Use a TakeControlApp call
	// rather than TakeControl whenever the session will speak the message
	// layer: raw Send and SendApp share one KCP stream, so a session must use one
	// or the other from its first byte.
	if err := cli.TakeControlAppPadded(v1.CmdPing, nil); err != nil {
		log.Fatalf("take control: %v", err)
	}
	log.Printf("admitted to %s", *device)
	if err := expect(cli, "PING", cli.LastTxNum()); err != nil {
		log.Fatalf("%v", err)
	}

	// Control and configuration: padded to a §13 size class, never compressed.
	// Forbidding compression stops content-dependent length leakage; padding
	// stops the message's own length identifying which command it was. Both are
	// needed, and SendAppPadded is the call that applies them.
	if err := cli.SendAppPadded(v1.CmdGetDeviceInfo, nil); err != nil {
		log.Fatalf("GET_DEVICE_INFO: %v", err)
	}
	if err := expect(cli, "GET_DEVICE_INFO", cli.LastTxNum()); err != nil {
		log.Fatalf("%v", err)
	}
	// Rule 1: a missing or invalid geometry is a protocol error, never a
	// fallback. Without it this controller cannot size a frame it knows the
	// device will accept, so it stops rather than guess.
	if geomErr != nil {
		log.Fatalf("DEVICE_INFO rejected: %v", geomErr)
	}
	if geom == nil {
		log.Fatal("no DEVICE_INFO received; cannot size frames for this device")
	}
	// Message layer 7.3 and sled 3.6: a sender respects the receiver's bound, and
	// the device's bound is its envelope. From here padding picks only a class
	// whose Size fits it.
	if err := cli.SetPeerReceiveBound(int(geom.Envelope)); err != nil {
		log.Fatalf("peer receive bound: %v", err)
	}

	// NTP_SERVER is response-free and goes only to a device that advertises pts
	// (Frame timing, rule 7): an older device would answer it ERR_UNKNOWN_KIND.
	if ntpPayload != nil {
		if !devicePTS {
			log.Print("NTP_SERVER: skipped, the device does not advertise pts")
		} else if err := cli.SendAppPadded(v1.CmdNTPServer, ntpPayload); err != nil {
			log.Fatalf("NTP_SERVER: %v", err)
		} else {
			log.Printf("NTP_SERVER: sent %s", *ntpFlag)
		}
	}

	if err := cli.SendAppPadded(v1.CmdGetStatus, nil); err != nil {
		log.Fatalf("GET_STATUS: %v", err)
	}
	if err := expect(cli, "GET_STATUS", cli.LastTxNum()); err != nil {
		log.Fatalf("%v", err)
	}

	// Pixel frames: the data plane. §13 permits compressing them and forbids
	// padding them (§14.4 — the rate cannot afford it), so SendAppCompressed is
	// the right call. LED content compresses heavily; a frame that does not is
	// sent plain automatically. PIXEL_FRAME is fire-and-forget: no response.
	//
	// Bounded by the advertised envelope, not by a constant: a payload past the
	// device's MAX_MSG_PAYLOAD is a frame it must reject, and the header/body
	// length disagreement that follows desynchronises the stream.
	// The advertised geometry is what the device can DRIVE; the envelope is
	// what it can RECEIVE, and on a small device those are not the same number.
	strips := geom.Strips
	leds := ledsPerStripThatFit(strips, geom.LEDs)
	if leds == 0 {
		log.Printf("PIXEL_FRAME: skipped, not one LED per strip x %d strips fits envelope %d",
			strips, geom.Envelope)
		log.Print("done")
		return
	}
	for i := 0; i < 3; i++ {
		frame, err := pixelFrame(int64(i), strips, leds)
		if err != nil {
			log.Fatalf("PIXEL_FRAME: %v", err)
		}
		if err := send(cli, "PIXEL_FRAME", func() error {
			return cli.SendAppCompressed(v1.CmdPixelFrame, frame)
		}); err != nil {
			log.Fatalf("PIXEL_FRAME: %v", err)
		}
		time.Sleep(33 * time.Millisecond) // ~30 fps
	}
	log.Print("sent 3 pixel frames")
	log.Print("done")
}

// geom is the device's validated DEVICE_INFO geometry, nil until it answers;
// geomErr records why an answer was rejected; devicePTS records whether it
// advertised the pts capability.
var (
	geom      *sled.Geometry
	geomErr   error
	devicePTS bool
)

// parseNTPFlag turns the -ntp value into an NTP_SERVER payload. Accepted forms:
// host, host:port, a bare IPv6 address and [v6]:port; the port defaults to 123.
func parseNTPFlag(v string) ([]byte, error) {
	s := sled.NTPServer{Host: v, Port: 123}
	if _, err := netip.ParseAddr(v); err != nil {
		if host, port, err := net.SplitHostPort(v); err == nil {
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil || p == 0 {
				return nil, fmt.Errorf("port %q is not a number from 1 to 65535", port)
			}
			s = sled.NTPServer{Host: host, Port: uint16(p)}
		}
	}
	return sled.EncodeNTPServer(s)
}

// maxPayload is the PIXEL_FRAME pixel-byte limit from the spec, envelope - 28 -
// 16: the subtrahends are the 28-byte PIXEL_FRAME header and the transport's
// 16-byte AEAD tag. DecodeGeometry guarantees envelope >= 80, so this is at
// least 36.
func maxPayload() int {
	return int(geom.Envelope) - sled.PixelFrameHeader - 16
}

// ledsPerStripThatFit reduces the advertised per-strip LED count until a whole
// PIXEL_FRAME fits inside the device's advertised envelope. It returns 0 when
// not even one LED per strip fits.
func ledsPerStripThatFit(strips, leds uint32) uint32 {
	m := maxPayload()
	if m <= 0 {
		return 0
	}
	fit := uint64(m) / (uint64(strips) * sled.PixelWireBPP)
	if fit >= uint64(leds) {
		return leds
	}
	log.Printf("PIXEL_FRAME: %d leds/strip would exceed the advertised envelope %d; sending %d",
		leds, geom.Envelope, fit)
	return uint32(fit)
}

// send wraps a write with the §9.5 failure mode a caller must handle.
func send(cli *v1.Client, what string, fn func() error) error {
	return sendOnce(cli, what, fn, true)
}

func sendOnce(cli *v1.Client, what string, fn func() error, mayReadmit bool) error {
	err := fn()
	switch {
	case err == nil:
		return nil

	case errors.Is(err, v1.ErrSendQueueFull):
		// §9.5: the send queue is at SEND_QUEUE_MAX, so the write was refused
		// rather than queued or dropped. The peer is not keeping up. For a pixel
		// stream the right response is to DROP this frame and send the newest
		// one — never to queue, which just replays stale frames on recovery.
		log.Printf("%s: send queue full, dropping", what)
		return nil

	case errors.Is(err, v1.ErrPayloadTooLarge):
		log.Printf("%s: payload exceeds MAX_MSG_PAYLOAD (%d)", what, v1.MaxMsgPayloadDefault)
		return err

	case errors.Is(err, v1.ErrSessionDead):
		// §7.2: SESSION_DEAD_MS elapsed with data outstanding. The library does
		// not re-admit on its own; recovery is an explicit TakeControl.
		//
		// Then RESEND. Returning nil after re-admitting reports success for a
		// message that was never sent, and the caller — which correlates the
		// answer by LastTxNum — would go on to wait for an ACK against the
		// promoting PING's MessageNum under the original command's name. The
		// re-admission also restarts the counters (§6.2), so the old number is
		// meaningless on the new session either way. Only once: a second dead
		// session is a dead link, not a race with a promotion.
		//
		// This path serves a sender that keeps streaming past SESSION_DEAD_MS
		// with data outstanding. This demo does not reach it: it sends three
		// frames, and expect makes every earlier reply timeout fatal after
		// replyTimeout, which is shorter than SESSION_DEAD_MS. A real sender
		// must also query GET_DEVICE_INFO again after re-admitting, as
		// shieldnet-protocol/spec/application.md 5.3.6 requires.
		if !mayReadmit {
			return err // already recovered once; a second dead session is a dead link
		}
		// The teardown that returns the client to IDLE is asynchronous;
		// SessionDead is set once it has finished.
		for i := 0; !cli.SessionDead(); i++ {
			if i >= 60 {
				return err
			}
			time.Sleep(50 * time.Millisecond)
		}
		log.Printf("%s: session dead, re-admitting", what)
		if err := cli.TakeControlAppPadded(v1.CmdPing, nil); err != nil {
			return err
		}
		// A new admission clears the peer receive bound (message layer 7.3).
		if geom != nil {
			if err := cli.SetPeerReceiveBound(int(geom.Envelope)); err != nil {
				return err
			}
		}
		return sendOnce(cli, what, fn, false)

	default:
		return err
	}
}

// expect reads until the ACK that answers the command with MessageNum wantNum.
//
// Correlation is by orig_message_num, NOT by message order: a query is answered
// with TWO messages (the typed response, then the ACK), and R2 requires an
// unrelated or unrecognised kind to be skipped without being charged against the
// exchange. Reading exactly one message per command — the obvious shape — walks
// one frame behind from the first query onward and reports every later answer
// against the wrong command.
// replyTimeout bounds one exchange. R1 lists a read timeout as an outcome a
// controller must handle, and without a deadline it is unreachable: a device that
// promotes the session and then never answers leaves RecvApp blocked forever,
// because §7.2's liveness timer only runs while data is outstanding and a fully
// acknowledged session has none.
const replyTimeout = 5 * time.Second

// ackError is a non-OK ACK for this exchange. It carries the status so a
// caller can tell an expected refusal from a failure.
type ackError struct {
	what   string
	status uint8
}

func (e *ackError) Error() string {
	return fmt.Sprintf("%s: device answered %s", e.what, sled.AckStatusName(e.status))
}

// ackResult is the outcome of the ACK that answers this exchange: a non-OK
// status is an error (Query framing: "A non-OK ACK for this command surfaces
// as an error"; the example applies the same rule to PING).
func ackResult(what string, a sled.Ack) error {
	if a.Status == sled.AckOK {
		return nil
	}
	return &ackError{what: what, status: a.Status}
}

func expect(cli *v1.Client, what string, wantNum uint64) error {
	deadline := time.Now().Add(replyTimeout)
	if err := cli.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer cli.SetReadDeadline(time.Time{})
	for {
		waiting, err := expectOne(cli, what, wantNum)
		if err != nil {
			return err
		}
		if !waiting {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: no answer within %s (R1 read timeout)", what, replyTimeout)
		}
	}
}

// expectOne reads one message. waiting is true if the exchange is still waiting
// for its ACK; err is a non-OK ACK.
func expectOne(cli *v1.Client, what string, wantNum uint64) (waiting bool, err error) {
	kind, payload, rerr := cli.RecvApp()
	switch {
	case rerr == nil:
		if kind == v1.RespAck {
			a, derr := sled.DecodeAck(payload)
			if derr != nil {
				log.Printf("%s: undecodable ACK, skipping: %v", what, derr)
				return true, nil
			}
			if a.OrigMessageNum != wantNum {
				// Someone else's answer, or a late one. R2: skip it.
				log.Printf("%s: ACK for message %d, not %d — skipping",
					what, a.OrigMessageNum, wantNum)
				return true, nil
			}
			log.Printf("%s -> %s", what, describe(kind, payload))
			return false, ackResult(what, a)
		}
		// A typed response (STATUS_RESP, DEVICE_INFO, ...). It carries no
		// orig_message_num, so it is reported and the ACK is still awaited.
		log.Printf("%s -> %s", what, describe(kind, payload))
		return true, nil

	case errors.Is(rerr, v1.ErrRejected):
		// Read in full and refused: a failed AEAD open or a §7 length violation.
		// The stream is still frame-aligned, so the session survives and reading
		// continues. Treating this as fatal would hand any host that can reach
		// the port a denial of service against an authenticated peer.
		log.Printf("%s: frame rejected, session survives: %v", what, rerr)
		return true, nil

	case errors.Is(rerr, v1.ErrReplay):
		log.Printf("%s: replayed MessageNum, ignoring: %v", what, rerr)
		return true, nil

	case errors.Is(rerr, v1.ErrDesync):
		// Some but not all of a frame was consumed. Every later read would parse
		// payload as a header, so the session must be abandoned.
		log.Fatalf("%s: stream desynchronised, session unrecoverable: %v", what, rerr)

	case errors.Is(rerr, v1.ErrSessionDead):
		log.Fatalf("%s: session dead (§7.2); recover with an explicit TakeControl", what)

	case isTimeout(rerr):
		// R1's read timeout. The deadline expiring mid-frame is "no progress": the
		// library stages the fragment and the next read resumes it, so this is
		// §1.2's first row — no message, no loss, session intact — until
		// MidFrameBudgetMS has passed since the frame's first octet; then the
		// read returns ErrDesync instead.
		log.Printf("%s: read timeout, no answer yet", what)
		return true, nil

	default:
		log.Fatalf("%s: %v", what, rerr)
	}
	return false, nil
}

// describe decodes a response payload. R2 requires an unrecognised response kind
// to be SKIPPED and reading to continue — never treated as an error — and R3
// requires trailing bytes beyond a known layout to be ignored, so every decoder
// below reads the prefix it understands.
// describe renders a response through the sled package's decoders. The
// decoding rules that matter are forward-compatibility ones (R2, R3, R6) and
// they belong in one place, not restated in every consumer — this example
// previously carried its own copy of all three layouts.
func describe(kind uint32, b []byte) string {
	switch kind {
	case v1.RespAck:
		a, err := sled.DecodeAck(b)
		if err != nil {
			return fmt.Sprintf("malformed ACK: %v", err)
		}
		return fmt.Sprintf("ACK kind=%#x status=%s orig_msgnum=%d detail=%q",
			a.OrigKind, sled.AckStatusName(a.Status), a.OrigMessageNum, a.Detail)

	case v1.RespStatus:
		st, err := sled.DecodeStatus(b)
		if err != nil {
			return fmt.Sprintf("malformed STATUS_RESP: %v", err)
		}
		return fmt.Sprintf("STATUS frames=%d commands=%d dropped=%d mode=%d "+
			"output=%v brightness=%d target_fps=%d",
			st.Frames, st.Commands, st.PixelFramesDropped, st.Mode,
			st.OutputEnabled, st.Brightness, st.TargetFPS)

	case v1.RespDeviceInfo:
		fields, err := sled.DecodeDeviceInfo(b)
		if err != nil {
			geomErr = err
			return fmt.Sprintf("malformed DEVICE_INFO: %v", err)
		}
		var parts []string
		for _, f := range fields {
			if f.IsCapability() {
				parts = append(parts, fmt.Sprintf("%q(capability)", f.Name))
				continue
			}
			parts = append(parts, fmt.Sprintf("%q=%q", f.Name, f.Value))
		}
		// Remember the geometry. envelope is on the wire precisely so a
		// controller does not have to know it out of band; sending past it is
		// what this field exists to prevent.
		//
		// DecodeGeometry applies every rule at once: all four required fields
		// present, each in its specified range, last value wins on a repeat, and
		// the capacity ceiling. A violation is a protocol error that MUST be
		// rejected, "never clamped, and never guessed at" — a guessed geometry
		// drives the wrong hardware, and a guessed envelope has this client send
		// frames the device must reject, which desynchronises the stream.
		g, gerr := sled.DecodeGeometry(fields)
		if gerr != nil {
			geomErr = gerr
			return "DEVICE_INFO REJECTED (" + gerr.Error() + "): " + strings.Join(parts, " ")
		}
		// Without pixel the geometry fields are optional (sled 5.3.3 rule 1) and
		// the device takes no pixel frames (sled 1.4); this client sends them.
		if !sled.HasCapability(fields, "pixel") {
			geomErr = errors.New("the device does not advertise pixel; this client sends pixel frames")
			return "DEVICE_INFO without pixel: " + strings.Join(parts, " ")
		}
		geom, geomErr = &g, nil
		devicePTS = sled.HasCapability(fields, "pts")
		return "DEVICE_INFO " + strings.Join(parts, " ")

	default:
		// R2: skip and keep reading; an unknown response kind is not an error.
		return fmt.Sprintf("unrecognised response kind %#x (%d bytes) — skipped per R2",
			kind, len(b))
	}
}

// pixelFrame builds a PIXEL_FRAME payload: a gradient, which is the kind of
// content the compression carve-out exists for. The wire stride is 4 bytes per
// pixel whatever the strip is, so the same encoding serves an RGB and an RGBW
// device — see sled.PixelWireBPP.
func pixelFrame(n int64, strips, leds uint32) ([]byte, error) {
	size, err := sled.FrameBytes(strips, leds)
	if err != nil {
		return nil, err
	}
	pixels := make([]byte, size)
	for i := 0; i < len(pixels); i += sled.PixelWireBPP {
		v := byte((i/sled.PixelWireBPP + int(n)) % 256)
		pixels[i], pixels[i+1], pixels[i+2], pixels[i+3] = v, byte(255-v), byte(v/2), 0
	}
	// Both timestamps 0: this example does not schedule (Frame timing, rule 6).
	return sled.PixelFrame(n, 0, 0, pixels)
}

func localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// isTimeout matches a read deadline expiring. kcp-go returns its timeouts
// through pkg/errors, whose *withStack does not itself implement net.Error, so
// this must use errors.As rather than a type assertion.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
