// Copyright (c) 2025-2026 BlackShield LDA
// SPDX-License-Identifier: Apache-2.0

// Command server is a complete ShieldNet v1 device.
//
// It admits one controller at a time (§9.1: a device holds at most one
// authenticated primary), then speaks the application message layer over that
// session: it reads framed messages, dispatches on the sled command kind, and
// answers with a padded response.
//
// It is NOT a ShieldLED device; the device of record is the C firmware built
// on libshieldnet. This answers a handful of kinds using the sled package's
// codecs (shieldnet-protocol/spec/application.md) so the example is end-to-end rather than a
// transport echo, and it shows the shape a responder takes.
//
// Run:
//
//	umask 077; echo <64 hex chars of k_dev> > kdev.hex   # mode 0600
//	SHIELDNET_KDEV_FILE=kdev.hex go run ./examples/server -listen :32000 \
//	    -device-id 0908070605040302
//
// Keys never come from argv, which every local user can read through ps and
// /proc/<pid>/cmdline. A device is provisioned with its own k_dev and never sees
// the fleet PSK (transport §0), so this reads k_dev from the mode-0600 file named
// by SHIELDNET_KDEV_FILE, or from SHIELDNET_KDEV (hex). Derive a device's k_dev
// on the controller side with
//
//	SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -print-kdev \
//	    -device-id 0908070605040302 > kdev.hex
//
// Demo convenience: if no k_dev is supplied but a PSK is (SHIELDNET_PSK_FILE or
// SHIELDNET_PSK), k_dev is derived from it with a warning. A real device must
// never hold the PSK.
//
// §4.3 rejects loopback sources, so a client on 127.0.0.1 will NOT be admitted.
// Run the two on different hosts, or see examples/README.md.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shieldled/goshieldnet/examples/internal/secret"
	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

func main() {
	listen := flag.String("listen", ":32000", "UDP address to bind")
	pskFlag := flag.String("psk", "", "REFUSED: a key on the command line is world-readable; "+
		"use SHIELDNET_KDEV_FILE (or SHIELDNET_KDEV)")
	devHex := flag.String("device-id", "", "8-byte device id, hex (required)")
	sameHost := flag.Bool("same-host-demo", false,
		"allow a controller running on THIS machine: disables §4.3's own-address "+
			"rejection. Demo only — never set it in a deployment.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: SHIELDNET_KDEV_FILE=<0600 file> %s -device-id <16 hex> [-listen addr]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *pskFlag != "" {
		log.Fatal(secret.RefuseArgv("psk", "SHIELDNET_KDEV_FILE", "SHIELDNET_KDEV"))
	}
	deviceID, err := hex.DecodeString(*devHex)
	if err != nil || len(deviceID) != 8 {
		log.Fatal("-device-id must be 8 bytes of hex (16 characters)")
	}
	kDev, err := loadKDev(deviceID)
	if err != nil {
		log.Fatal(err)
	}

	// A device is never provisioned with the PSK itself; it holds only its own
	// derived k_dev (§0), and NewDeviceFromKDev is the constructor for that.
	// cookie_secret and admission_epoch are per-boot CSPRNG draws (§4.2) and
	// must never be hard-coded: cookie_secret keys the anti-flood cookie, and a predictable
	// admission_epoch lets a captured FINISH be replayed.
	cookieSecret := make([]byte, 32)
	admissionEpoch := make([]byte, 8)
	if _, err := rand.Read(cookieSecret); err != nil {
		log.Fatalf("cookie secret: %v", err)
	}
	if _, err := rand.Read(admissionEpoch); err != nil {
		log.Fatalf("admission epoch: %v", err)
	}
	// §4.2: "random non-zero uint64 with the top 8 bits cleared". That is the
	// whole first OCTET, not just the top bit — the cleared range is what leaves
	// room for the counter to advance on every accepted FINISH without
	// overflowing, and incAdmissionEpoch fails closed if it would. Getting this
	// wrong is silent: RETRY still works and admission dies at FINISH.
	admissionEpoch[0] = 0
	if binary.BigEndian.Uint64(admissionEpoch) == 0 {
		admissionEpoch[7] = 1 // §4.2: non-zero
	}

	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}

	// local is the interface prefix set for §4.3's source-rejection test. Passing
	// the prefixes actually assigned here is what lets the device reject a
	// datagram claiming to come from its own address.
	// §4.3 rejects a datagram whose source is an address assigned to the
	// receiving interface, because a device must never accept traffic that
	// appears to come from itself. That also means a controller on the SAME host
	// is refused — its source is one of these prefixes — so a single-machine
	// demo has to opt out of that one check. Loopback stays rejected either way:
	// it is on §4.3's list unconditionally, so 127.0.0.1 never works.
	local := localPrefixes()
	if *sameHost {
		log.Print("WARNING: -same-host-demo disables §4.3 own-address rejection")
		local = nil
	}
	// NewServer re-seeds the device's cookie epoch onto the clock it ticks, so
	// whatever origin is passed here, the boot epoch_tag survives the first tick.
	// NewDeviceFromKDev copies its inputs, so the local copies are wiped at once.
	dev, err := v1.NewDeviceFromKDev(kDev, deviceID, cookieSecret, admissionEpoch,
		local, uint64(time.Now().UnixMilli()))
	secret.Wipe(kDev)
	secret.Wipe(cookieSecret)
	if err != nil {
		log.Fatalf("device: %v", err)
	}
	srv := v1.NewServer(dev, conn)

	// Serve runs the admission exchange, the envelope path and §9.2's
	// maintenance tick. It returns when the socket closes.
	go srv.Serve()
	log.Printf("device listening on %s (device_id %s)", conn.LocalAddr(), *devHex)

	// Close takes the socket down, which ends Serve; done tells the application
	// loop to stop too. Without it the loop would wait forever for a primary
	// that can no longer be admitted.
	done := make(chan struct{})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("shutting down")
		close(done)
		srv.Close()
	}()

	serve(srv, done)
}

// loadKDev returns this device's k_dev: SHIELDNET_KDEV_FILE, else
// SHIELDNET_KDEV, else — as a demo convenience only — derived from a PSK in
// SHIELDNET_PSK_FILE / SHIELDNET_PSK.
func loadKDev(deviceID []byte) ([]byte, error) {
	kDev, err := secret.Load("SHIELDNET_KDEV_FILE", "SHIELDNET_KDEV")
	if err == nil {
		return kDev, nil
	}
	if !errors.Is(err, secret.ErrNotSet) {
		return nil, err
	}
	psk, perr := secret.Load("SHIELDNET_PSK_FILE", "SHIELDNET_PSK")
	if errors.Is(perr, secret.ErrNotSet) {
		return nil, errors.New("no key: set SHIELDNET_KDEV_FILE (or SHIELDNET_KDEV) to this " +
			"device's k_dev; derive it with `go run ./examples/client -print-kdev`")
	}
	if perr != nil {
		return nil, perr
	}
	defer secret.Wipe(psk)
	log.Print("WARNING: deriving k_dev from the fleet PSK. Demo only — a real device is " +
		"provisioned with its k_dev (SHIELDNET_KDEV_FILE) and never sees the PSK")
	return v1.DeriveKDev(psk, deviceID), nil
}

// serve is the application loop: read a framed message, dispatch, answer. It
// returns once done is closed.
func serve(srv *v1.Server, done <-chan struct{}) {
	var lastConn interface{ RemoteAddr() net.Addr }
	for {
		select {
		case <-done:
			return
		default:
		}
		p := srv.Primary()
		if p == nil {
			// No controller has been admitted yet, or the last one was displaced.
			// §9.5: a session is never destroyed for inactivity, so this only
			// means "none yet" or "the previous one was replaced by a promotion".
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if lastConn != p {
			log.Printf("controller admitted: %s", p.RemoteAddr())
			lastConn = p
		}

		// A read deadline keeps this loop responsive to a session being replaced
		// and to shutdown.
		p.SetReadDeadline(time.Now().Add(time.Second))
		// RecvAppNumGen, not RecvApp: a device must echo the command's MessageNum
		// as the ACK's orig_message_num, because the sled layer correlates a
		// response to its command by that field and never by message order. The
		// generation names the session the read happened on, so a desync ends
		// THAT session and never one promoted while the read was in flight.
		kind, msgNum, payload, gen, err := srv.RecvAppNumGen()
		if err != nil {
			handleRecvError(srv, gen, err)
			continue
		}
		for _, r := range dispatch(kind, msgNum, payload) {
			// Responses are control messages: §13 forbids compressing them and
			// expects them padded to a size class.
			if err := srv.SendAppPadded(r.kind, r.payload); err != nil {
				log.Printf("send response: %v", err)
				break
			}
		}
	}
}

// handleRecvError applies message-layer §1.2, which requires a receiver to
// distinguish three outcomes and MUST NOT collapse them. gen is the generation
// of the session the failed read ran on.
func handleRecvError(srv *v1.Server, gen uint32, err error) {
	switch {
	case errors.Is(err, v1.ErrNotEstablished):
		// the session went away; wait for the next promotion

	case errors.Is(err, v1.ErrSessionClosed):
		// The session was closed or replaced while the read waited — a newer
		// promotion, or shutdown. It ended; it did not desynchronise. Do NOT
		// drop anything in response: the current primary, if any, is a
		// different session. Keep listening.
		log.Print("session ended")

	case errors.Is(err, v1.ErrRejected):
		// The frame was read in full and refused — a failed AEAD open or a §7
		// length-rule violation. The stream is still frame-aligned, so the
		// session MUST survive and reading MUST continue. This is what makes the
		// AEAD a filter rather than a fuse: otherwise one forged or corrupted
		// frame would be a denial of service against an authenticated peer.
		log.Printf("frame rejected, continuing: %v", err)

	case errors.Is(err, v1.ErrReplay):
		log.Printf("replayed MessageNum, continuing: %v", err)

	case errors.Is(err, v1.ErrDesync):
		// Some but not all of a frame was consumed and the rest is unrecoverable.
		// Every later read would parse payload bytes as a header, so §1.2's third
		// row says the session MUST be closed — and closing it is a real action,
		// not a log line: DropPrimaryIf retires this session and leaves the
		// device listening, so the controller can re-admit. It is conditional on
		// the generation because a re-admission may already have promoted a new
		// session, which DropPrimary would kill instead. A read deadline expiring
		// mid-frame arrives here only once MidFrameBudgetMS has passed since the
		// frame's first octet; before that the library stages the fragment and
		// reports a plain timeout (see rxStage), so this error means what it says.
		log.Printf("stream desynchronised, dropping session: %v", err)
		srv.DropPrimaryIf(gen)

	case isTimeout(err):
		// idle; §9.5 forbids destroying a session for inactivity

	default:
		log.Printf("read: %v", err)
	}
}

// response is one message the device owes the controller. A query answers with
// TWO: the typed response first, then the ACK — see "Query framing".
// libshieldnet's command core does exactly this (command.c sends the response,
// then send_ack), and
// a controller that waits for the ACK hangs against a device that omits it.
type response struct {
	payload []byte
	kind    uint32
}

func ack(kind uint32, msgNum uint64, status uint8, detail []byte) response {
	return response{sled.EncodeAck(sled.Ack{OrigKind: uint8(kind), Status: status,
		OrigMessageNum: msgNum, Detail: detail}), v1.RespAck}
}

// dispatch answers the handful of sled kinds this example implements, in the
// real wire format from shieldnet-protocol/spec/application.md. A real device implements the
// document in full; the point here is that what goes on the wire is the actual
// layout, not a readable stand-in — an example that invents its own encoding
// teaches the wrong thing and cannot be pointed at a real controller.
func dispatch(kind uint32, msgNum uint64, payload []byte) []response {
	switch kind {
	case v1.CmdPing:
		log.Print("PING")
		return []response{ack(kind, msgNum, sled.AckOK, nil)}

	case v1.CmdGetStatus:
		log.Print("GET_STATUS")
		return []response{{statusResp(), v1.RespStatus}, ack(kind, msgNum, sled.AckOK, nil)}

	case v1.CmdGetDeviceInfo:
		log.Print("GET_DEVICE_INFO")
		return []response{{deviceInfo(), v1.RespDeviceInfo}, ack(kind, msgNum, sled.AckOK, nil)}

	case v1.CmdGetMode:
		// §"ACK (0x80)": GET_MODE replies with an ACK whose 2-byte detail is
		// [u8 mode][u8 output_enabled].
		log.Print("GET_MODE")
		return []response{ack(kind, msgNum, sled.AckOK, []byte{modePixel, 1})}

	case v1.CmdPixelFrame:
		// Fire-and-forget: PIXEL_FRAME never produces a protocol response.
		fr, err := sled.ParsePixelFrame(payload)
		if err != nil {
			log.Printf("PIXEL_FRAME: %v, dropped", err)
			return nil
		}
		log.Printf("PIXEL_FRAME: frame %d, %d pixel bytes", fr.FrameNumber, len(fr.Pixels))
		return nil

	case v1.CmdNTPServer:
		// Fire-and-forget: never answered, also when the message is ignored.
		s, err := sled.DecodeNTPServer(payload)
		if err != nil {
			log.Printf("NTP_SERVER: %v, ignored", err)
			return nil
		}
		log.Printf("NTP_SERVER: %s port %d", s.Host, s.Port)
		return nil

	default:
		// R1: an unrecognised kind is answered ERR_UNKNOWN_KIND, not ignored — a
		// controller must be able to tell "older peer" from "unreachable". The
		// response-free kinds, PIXEL_FRAME and NTP_SERVER, are the exception, and
		// are handled above.
		log.Printf("unknown kind %#x", kind)
		return []response{ack(kind, msgNum, sled.AckErrUnknownKind, nil)}
	}
}

// ACK status codes (shieldnet-protocol/spec/application.md, sections 5.1 and 10.3).

const modePixel = 1

// ack builds an ACK (0x80):
//
//	[u8 orig_kind][u8 status][u8 rsv×2][be64 orig_message_num][be16 detail_len][detail]
//
// orig_message_num is what correlates a response to its command — §"Query
// framing" says correlation is by that field and never by message order, so a
// device MUST echo the number it was asked with.
// statusResp and deviceInfo build real payloads through the sled package rather
// than laying out bytes here. An example that carries its own copy of a wire
// layout is one more implementation to keep in sync, and one that drifts
// silently.
func statusResp() []byte {
	return sled.EncodeStatus(sled.Status{
		Frames: 1234, Commands: 56, Mode: modePixel,
		Connected: true, OutputEnabled: true,
		Brightness: 200, // the LIVE value, not a configured default
		TargetFPS:  30,  // CONFIGURED, not measured
	})
}

func deviceInfo() []byte {
	b, err := sled.EncodeDeviceInfo(1200, 1, 64, 4, []string{"pixel"})
	if err != nil {
		// Refused only for an out-of-range geometry, which is a constant here.
		panic(err)
	}
	return b
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// localPrefixes returns the prefixes assigned to this host, for §4.3's
// own-address rejection. A device that cannot enumerate them still works; it
// simply cannot reject a datagram forged from its own address.
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
