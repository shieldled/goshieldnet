# goshieldnet

[![Documentation](https://img.shields.io/badge/docs-shieldled.github.io%2Fgoshieldnet-blue.svg)](https://shieldled.github.io/goshieldnet/)
[![CI](https://github.com/shieldled/goshieldnet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shieldled/goshieldnet/actions/workflows/ci.yml)
[![Docs](https://github.com/shieldled/goshieldnet/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shieldled/goshieldnet/actions/workflows/docs.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shieldled/goshieldnet.svg)](https://pkg.go.dev/github.com/shieldled/goshieldnet)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/shieldled/goshieldnet/blob/main/LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/shieldled/goshieldnet)](https://github.com/shieldled/goshieldnet/blob/main/go.mod)

**Documentation: [shieldled.github.io/goshieldnet](https://shieldled.github.io/goshieldnet/)**, with the guides, the API
reference and the examples.

goshieldnet is the Go implementation of **ShieldNet**, the encrypted protocol
ShieldLED controllers use to drive LED devices over a network. It provides:

- a **client** for ShieldLED devices: `sledclient` connects to a device and runs
  its commands, and `discovery` finds devices on the local network;
- the **application payloads**, in both directions: `sled`;
- the **transport** underneath, in both roles: `v1`, the authenticated admission
  exchange, the encrypted envelope and the message layer, as a controller
  (`v1.Client`) and as a device (`v1.Server`).

It is pure Go, with no cgo. It interoperates on the wire with the C
implementation, [libshieldnet](https://github.com/shieldled/libshieldnet), and
both are checked against the same published test vectors rather than against
each other.

> **Building device firmware?** The device of record is the C implementation,
> libshieldnet. The Go device, `v1.Server`, is for tests, emulators and tools:
> it runs the transport, and you answer commands with the `sled` codecs.

## Documentation

- **[Examples](examples/README.md)**: two complete programs, a device and a
  controller, that talk to each other and to other ShieldNet implementations.
  Start here to see the library in use.
- **[API reference](https://shieldled.github.io/goshieldnet/api/)**: every
  public package with every exported identifier and its doc comment, generated
  from the Go source each time the documentation site is built (`mkdocs serve`
  shows it locally). The same reference is on
  [pkg.go.dev](https://pkg.go.dev/github.com/shieldled/goshieldnet), and
  `go doc ./v1` prints it in a terminal.
- **This README**: how ShieldNet works, a client and a device in a few lines
  each, the error and liveness rules, bounds, tuning and testing.
- **[Tuning](docs/tuning.md)**: measured cost, the KCP window and
  flush-interval knobs, and a sizing example for a pixel stream.
- **[Bring-up lessons](docs/bringup-lessons.md)**: porting and measurement traps
  that host tests cannot catch.
- **The protocol**: [shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol),
  which holds the normative specification (`spec/transport.md`,
  `spec/message-layer.md`, `spec/application.md`), the informative design notes
  (`design/`) and the test vectors. Where this code and those documents
  disagree, the documents are right.
- **[Changelog](https://github.com/shieldled/goshieldnet/blob/main/CHANGELOG.md)**:
  release history.

## The packages

| Package | What it is |
| --- | --- |
| `sledclient` | The client for ShieldLED devices: connect, request/ACK correlation, typed core commands (`SetBrightness`, `SetMode`, `Mode`, `Status`, ...) |
| `discovery` | Find devices over mDNS (DNS-SD) |
| `sled` | The application payloads: the three responses, PIXEL_FRAME and NTP_SERVER, in both directions |
| `v1` | The ShieldNet v1 transport and message layer: `Client` (a controller) and `Server` (a device), and the primitives they are built from |
| `sledclient/sledclienttest` | An in-process device for tests |

The **sled device application protocol** (command kinds, payload layouts) is
specified in [`spec/application.md`](https://github.com/shieldled/shieldnet-protocol/blob/main/spec/application.md). Its Go half
is the `sled` package: the three response payloads in both directions, PIXEL_FRAME
(`sled.PixelFrame`, `sled.ParsePixelFrame`, `sled.FrameTimes`) and NTP_SERVER,
the mode constant, and the raw extension block of `STATUS` (`Status.Ext`).
In `sledclient`, the first call of a session reads `DEVICE_INFO` at admission (sled 3.4, 5.3.6)
and every call keeps to what it advertises: `SetNTPServer` needs `pts`, a
pixel frame needs `pixel` and its frame limit, and no message exceeds the
device's `envelope` (`ErrExceedsEnvelope`). `sledclient.Client.Do` is the probe
path for a device that may lack an extension.

Extensions: `DoExtension` runs a command of an extension registered by the
specification, checked against the capability the device advertises, and
`DoPrivate` runs one of an `x-` extension; this module implements none.
`Admit` and `Advertised` give a caller the device's `DEVICE_INFO` fields without
a round trip.

The `discovery` package browses the sled mDNS service types. The kind constants stay in
`v1` (`v1.CmdPixelFrame`, `v1.CmdPing`, …) so a renumbering breaks the build
rather than silently driving the wrong command; `v1.IsCoreCommand` says whether a
kind is one of the core command kinds.

## How ShieldNet works, in brief

A session is built in five layers, bottom up:

1. **UDP.** Every datagram carries an 8-octet magic and a version octet, and is
   classified before any state is touched (transport §5).
2. **Admission.** Two round trips, four messages, keyed off a per-device `k_dev`
   derived from the PSK. A device is **never** provisioned with the PSK itself —
   only with `k_dev` and its `device_id` — so opening one device does not
   compromise the fleet (transport §0, §4).
3. **Envelope.** Every KCP datagram is sealed with ChaCha20-Poly1305-IETF under
   `k_kcp_c2s`/`k_kcp_s2c`, with a 256-entry replay window over the sequence
   number (transport §3.6, §8).
4. **KCP**, in stream mode — mandatory on both ends, because a message may span
   many segments and a message-mode sender is not interoperable with a bounded
   firmware receive buffer (`github.com/xtaci/kcp-go/v5`).
5. **Message layer.** A 20-byte header (the AEAD's AAD) plus an XChaCha20-
   Poly1305 payload under `k_c2s`/`k_s2c`, with a strictly-increasing per-
   direction `MessageNum`. Note this is a *different* AEAD from the envelope's,
   under different keys; the two are not interchangeable.

`v1` is payload-agnostic above that: application command codes travel in the opaque
`MessageType` field. Their values are declared in `v1` and the responses',
PIXEL_FRAME's and NTP_SERVER's payloads in `sled` (see above).

Section numbers written `§N` (transport §4.3, §13) are those of
shieldnet-protocol's transport design notes,
[`design/transport.md`](https://github.com/shieldled/shieldnet-protocol/blob/main/design/transport.md);
`transport N`, `message layer N` and `sled N` without the `§` are sections of
`spec/transport.md`, `spec/message-layer.md` and `spec/application.md`.

## Keys and identity

Two inputs, both raw bytes rather than hex:

| input | size | who holds it |
| --- | --- | --- |
| `psk` | 32 octets | **controllers only** |
| `deviceID` | 8 octets | both; unique within a PSK domain |

A controller holds the PSK and derives `k_dev` for whichever device it addresses.
A device is provisioned with `k_dev` and never sees the PSK: provisioning runs
`v1.DeriveKDev(psk, deviceID)` on the controller side (or
`go run ./examples/client -print-kdev`) and installs only the result, and the
device is built with `v1.NewDeviceFromKDev`. `v1.NewDevice`, which takes the PSK,
exists for tests and demos only. One PSK is live at a
time; there is no rotation and no generation identifier on the wire, so replacing
it is a flag day (transport §4.7).

## Quick start

Add the module to your project:

```sh
go get github.com/shieldled/goshieldnet@latest
```

Run the two examples against each other on one machine. Use the machine's LAN
address (here 192.168.1.10), never `127.0.0.1`: ShieldNet refuses loopback.
Pass `-same-host-demo` to both, because a device also refuses a controller on
its own host ([`examples/README.md`](examples/README.md) explains why):

```sh
git clone https://github.com/shieldled/goshieldnet && cd goshieldnet
umask 077
openssl rand -hex 32 > psk.hex                     # the PSK: controllers only
SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -print-kdev \
    -device-id 0908070605040302 > kdev.hex         # the device's k_dev

# the device, in one terminal (Ctrl-C stops it)
SHIELDNET_KDEV_FILE=kdev.hex go run ./examples/server -listen 192.168.1.10:32000 \
    -same-host-demo -device-id 0908070605040302

# the controller, in another, once the device logs "device listening"
SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -device 192.168.1.10:32000 \
    -same-host-demo -device-id 0908070605040302
```

The client admits, reads the device's `DEVICE_INFO` and `STATUS`, sends three
pixel frames, prints `done` and exits;
[`examples/README.md`](examples/README.md) shows the full output.

## A client

A complete program that admits to a device, sets its brightness and prints its
geometry. It reads the PSK and the device id (hex) from files, never from the
command line:

```go
// A ShieldNet client: it admits to a device, sets its brightness and prints
// its geometry.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/shieldled/goshieldnet/sledclient"
)

func main() {
	psk := readHex("psk.hex") // the PSK: controllers only
	var deviceID [8]byte
	copy(deviceID[:], readHex("device-id.hex"))

	c, err := sledclient.Dial("192.168.1.10:32000", psk, deviceID, sledclient.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The first call admits the session and reads the device's DEVICE_INFO.
	if err := c.SetBrightness(ctx, 128); err != nil {
		log.Fatal(err)
	}
	g, _ := c.Geometry()
	fmt.Printf("brightness set; %d strips x %d LEDs, %d bytes per LED\n", g.Strips, g.LEDs, g.BPP)
}

// readHex reads a hex key or id from a file, which must not be readable by others.
func readHex(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	v, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		log.Fatal(err)
	}
	return v
}
```

The device's address and id can come from discovery instead:
`discovery.DiscoverAll(2 * time.Second)` returns each device's `Addr()` and,
from its mDNS instance name, its `DeviceID`. A device on the same host as the
client needs `sledclient.Options{AllowSameHost: true}`.

`sledclient.Client` correlates each ACK with its request by the message number
alone (sled 3.3); a typed response followed by a foreign ACK is discarded, a
query keeps only its own response kind, and an undecodable ACK or a received
command kind is skipped.

The first call admits the session with `GET_DEVICE_INFO` and records the answer
(`Geometry`, `Advertised`) before sending its own command: one extra round
trip, and its context must allow two. A bad `DEVICE_INFO` is `ErrBadDeviceInfo`
and ends the session. `Options.LegacyAdmission` restores admission with the
first call's own command, for a device that does not answer `GET_DEVICE_INFO`.
After `v1.ErrDesync` the session is gone.

A refusal comes back as `*sledclient.AckError`, through `Reply.Err` or the typed
methods.

`Send` is for commands that are never answered (NTP_SERVER). It returns once the
message is queued, not once it is delivered, and it is not a streaming path.

Admission is one-shot, as in `v1`, and is bounded by the first call's context,
including its `DEVICE_INFO` wait.

`discovery.DiscoverAll` lists devices with an IPv4 address;
`discovery.DiscoverAllWith(timeout, discovery.Options{IPv6: true})` also lists
IPv6-only ones (a link-local `Found.Host` carries its `%zone`).

Discovery's answers arrive as unicast to an ephemeral port, so a host firewall
must accept inbound UDP from LAN source port 5353.

## A device

A complete device that admits one controller at a time and answers
`GET_DEVICE_INFO`, `SET_BRIGHTNESS` and `PING`; the client above runs against
it. It reads its `k_dev` (from `go run ./examples/client -print-kdev`) and its
device id from files:

```go
// A minimal ShieldNet device: it admits a controller and answers
// GET_DEVICE_INFO, SET_BRIGHTNESS and PING.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/shieldled/goshieldnet/sled"
	v1 "github.com/shieldled/goshieldnet/v1"
)

func main() {
	kDev := readHex("kdev.hex") // this device's k_dev, never the PSK
	deviceID := readHex("device-id.hex")

	// Per-boot secrets (transport §4.2): admission_epoch must be non-zero with
	// its top eight bits clear.
	cookieSecret, admissionEpoch := make([]byte, 32), make([]byte, 8)
	rand.Read(cookieSecret)
	rand.Read(admissionEpoch)
	admissionEpoch[0], admissionEpoch[7] = 0, admissionEpoch[7]|1

	// Bind one interface address, and pass its prefix for the source checks.
	conn, err := net.ListenPacket("udp", "192.168.1.10:32000")
	if err != nil {
		log.Fatal(err)
	}
	local := []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}
	dev, err := v1.NewDeviceFromKDev(kDev, deviceID, cookieSecret, admissionEpoch,
		local, uint64(time.Now().UnixMilli()))
	if err != nil {
		log.Fatal(err)
	}
	srv := v1.NewServer(dev, conn)
	go srv.Serve() // admission, the envelope and the maintenance tick
	defer srv.Close()

	for {
		kind, num, payload, _, err := srv.RecvAppNumGen()
		if errors.Is(err, v1.ErrNotEstablished) {
			time.Sleep(50 * time.Millisecond) // no controller admitted yet
			continue
		}
		if err != nil {
			log.Print(err) // a rejected or replayed message, or a session that ended
			continue
		}
		status := uint8(sled.AckOK)
		switch kind {
		case v1.CmdGetDeviceInfo: // a query: the typed response, then the ACK
			info, _ := sled.EncodeDeviceInfo(1200, 1, 64, 4, []string{"pixel"})
			srv.SendAppPadded(v1.RespDeviceInfo, info)
		case v1.CmdSetBrightness:
			log.Printf("brightness %d", payload[0])
		case v1.CmdPing:
		case v1.CmdPixelFrame, v1.CmdNTPServer:
			continue // never answered
		default:
			status = sled.AckErrUnknownKind
		}
		ack := sled.EncodeAck(sled.Ack{OrigKind: uint8(kind), Status: status, OrigMessageNum: num})
		if err := srv.SendAppPadded(v1.RespAck, ack); err != nil {
			log.Print(err)
		}
	}
}

// readHex reads a hex key or id from a file, which must not be readable by others.
func readHex(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	v, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		log.Fatal(err)
	}
	return v
}
```

`local` holds the prefixes of the interface the socket is bound to, for the
transport §4.3 source checks; `nil` turns off the own-address check, for a
controller on the same host (loopback stays refused). `v1.NewDevice`, which
takes the PSK instead of `k_dev`, exists for tests and demos only.

`cookieSecret` is 32 octets and `admissionEpoch` 8 (§4.2); `nowMS` is a
millisecond clock reading for the first cookie epoch, which `NewServer` re-seeds
onto the clock it ticks. A device holds
**at most one** authenticated primary session, and it is replaced only by a peer
that has completed admission — never by an unauthenticated datagram and never by
a timeout (transport §8.5).

The device side has the same message layer: `srv.RecvAppNum()` returns the
message type, its `MessageNum` and the payload, and `SendAppPadded` answers.
`RecvAppNum` rather than `RecvApp` because the sled layer correlates a response
to its command by `orig_message_num` and never by message order, so a responder
needs the number to build a conforming ACK. `RecvAppNumGen` also returns the
session's generation; on `ErrDesync` it has already dropped that session. Treat
`ErrSessionClosed` as "that session ended" — keep listening, drop nothing.

This Go server exists mainly for testing and emulation, and it does not implement
the sled application protocol. The device of record is the C implementation,
which also implements the §9.4 quiescing Go deliberately omits — see
[`design/transport.md`](https://github.com/shieldled/shieldnet-protocol/blob/main/design/transport.md).

## The transport directly: `v1.Client`

`sledclient` is built on `v1.Client`. Use `v1.Client` directly for a controller
that speaks its own application protocol over ShieldNet, or that chooses each
message's category itself.

```go
import v1 "github.com/shieldled/goshieldnet/v1"

cli, err := v1.NewClient("192.168.1.50:32000", psk, deviceID, local)
if err != nil { /* ... */ }
defer cli.Close()

// One admission attempt. The first application message rides the promoting
// datagram, so take-control and the first command are a single round trip.
// PING is control, so it is padded: TakeControlAppPadded.
if err := cli.TakeControlAppPadded(v1.CmdPing, nil); err != nil { /* ... */ }

// After reading DEVICE_INFO, a sled controller tells the client the device's
// bound, so nothing is padded past it (message layer 7.3, sled 3.6):
// cli.SetPeerReceiveBound(int(envelope))

// Pixel frames MAY compress and MUST NOT be padded (§13, §14.4).
if err := cli.SendAppCompressed(v1.CmdPixelFrame, framePayload); err != nil { /* ... */ }

// Bulk content — a blob uploaded whole — is LZ4-compressed if that shrinks it
// and padded otherwise (transport §13).
if err := cli.SendAppBulk(bulkKind, blob); err != nil { /* ... */ }

// Control and configuration is padded to a size class, never compressed.
if err := cli.SendAppPadded(v1.CmdSetBrightness, []byte{128}); err != nil { /* ... */ }

msgType, payload, err := cli.RecvApp()
```

`local` is the interface prefix set used to validate the client's own source
address (transport §4.3). Note that **loopback is on the rejection list**, so
`127.0.0.1` is refused by design — that is what makes group-address reflection
impossible. §4.3 also rejects a source that is an address assigned to the
receiving interface, so a controller and a device on one host are refused twice
over; [`examples/README.md`](examples/README.md) shows how to run them anyway.

**`TakeControlApp*` is one-shot: there is no retry, no backoff and no automatic
failover.** That is deliberate. An earlier design auto-retried with damping, and
the damping turned out to be the cheapest attack in the whole protocol — two
controllers could be driven into a displacement loop. Recovery from a dead
session is an explicit take-control by the caller, after `SESSION_DEAD_MS`
(transport §7.2, §9.3).

The four Send methods map onto transport §13's categories, because
only the caller knows which category a message kind is in:

| method | category | on the wire |
| --- | --- | --- |
| `SendAppPadded` | control and configuration | padded to a power-of-two class from 64 B, never compressed |
| `SendAppCompressed` | **pixel frames** | LZ4 if that shrinks it, never padded |
| `SendAppBulk` | bulk content (a blob uploaded whole) | LZ4 if that shrinks it, else padded to a class within the peer's bound |
| `SendApp` | — | verbatim; an escape hatch, not a default |

Pixel frames and bulk content share compression and differ in padding: a frame
is never padded, bulk content is padded when it does not compress.
`SendAppCompressed` is the normal path for a pixel stream:
frames are the highest-volume traffic on the link and LED content compresses well.
Compression is opt-in rather than automatic because the failure modes are not
symmetric — forgetting to compress a frame costs bandwidth, while compressing a
control message by accident is the leak §13 forbids.

`RecvApp` handles all three transparently — it decompresses when the peer sets the
flag and strips padding back to `OriginalSize`. Compression and padding are
mutually exclusive per message (§13): a padded compressed message would need three
lengths on the wire and the header carries two. A compressed message whose
`OriginalSize` exceeds the receiver's bound (`MaxAppPayload` on a `Client`, its
`MaxMsgPayload` on a `Server`) is refused with `ErrRejected` and the session
continues.

`SendAppBulk` sends bulk content: compressed when that shrinks it, else padded.
`SetPeerReceiveBound` tells the client the peer's receive bound (message layer
7.3), so no message or padding class exceeds it; it is reset at each admission.
`EndSession` ends the session and leaves the client reusable; `Close` ends the
client.

`TakeControl`, `Send` and `Recv` (raw KCP stream bytes) are deprecated: a first
message and the stream are sealed messages of the message layer (transport
10.2, 12.2). They share one KCP stream with the `*App` family, so a session must
use one or the other from its first byte — mixing them corrupts framing
permanently.

## Errors

Message layer §1.2 requires a receiver to distinguish three read outcomes and
**MUST NOT** collapse them, because the remedies differ. Test with `errors.Is`:

| sentinel | meaning | what the caller does |
| --- | --- | --- |
| `ErrRejected` | read in full, then refused — failed AEAD open or a §7 length rule | **keep reading.** The stream is still frame-aligned, and the session must survive. Treating this as fatal hands anyone who can reach the port a denial of service against an authenticated peer |
| `ErrDesync` | a partial frame was consumed | the session is over: `Client.RecvApp*` has returned the client to IDLE and `Server.RecvAppNumGen` has dropped the primary; admit again |
| `ErrReplay` | `MessageNum` at or below the high-water mark | ignore it and continue |
| `ErrSendQueueFull` | §9.5's send bound, refused rather than queued or dropped | for a pixel stream, drop the frame and send the newest — queueing replays stale frames on recovery |
| `ErrPayloadTooLarge` | above `MAX_MSG_PAYLOAD` | split it, or raise the bound |
| `ErrSessionDead` | §7.2's liveness timer fired | wait until `SessionDead()` is true, then re-admit with an explicit `TakeControlApp*` (the teardown that returns the client to IDLE runs asynchronously) |
| `ErrNotIdle` | `TakeControlApp*` while an admission or a session is in progress | wait for the admission in progress to finish, or after `ErrSessionDead` until `SessionDead()` is true, then re-admit; if a session is live, use it, or `Close` and create a new Client |
| `ErrSessionClosed` | the session was closed or replaced (a newer promotion, `DropPrimary`, `Close`) while the call waited | not a desync; do not end the current session in response |
| `ErrNotEstablished` | no session, or it was torn down locally (`Close`, or a local failure such as a PUSH_ACK timeout) | admit first; after `Close` the Client cannot be reused — create a new one |

## Liveness

§7.2 moves an established session to IDLE after `SESSION_DEAD_MS` with **no
authenticated datagram received while the client has unacknowledged data
outstanding**. The outstanding-data condition is load-bearing: a controller that
has sent nothing has nothing unacknowledged, so an idle session must survive —
tearing it down would leave the device holding an orphan it may not reclaim for
inactivity (§9.5) while the client pays a full re-admission for nothing. The
timer runs on the monotonic clock, so a wall-clock step cannot kill or prolong a
session.

`(*Client).SessionDead()` reports it, and `Send`/`Recv`/`SetReadDeadline` return `ErrSessionDead`
(a `Send`/`SendApp` blocked in a write when the session is torn down returns
`ErrSessionDead` (liveness) or `ErrNotEstablished` (a local `Close`), like a
blocked read, except that one whose 2 s send deadline expires at the same moment
may return `ErrSendQueueFull`). A read (`Recv`, `RecvApp`, `RecvAppNum`) blocked when
the session ends returns `ErrSessionDead` (liveness) or `ErrNotEstablished` (a
local `Close`, or another local teardown such as a PUSH_ACK timeout), never
`ErrDesync`. A read that ends in `ErrDesync` (a partly read message outliving its
budget included) after the liveness timer has run for `SESSION_DEAD_MS` returns
`ErrSessionDead` instead, and `SessionDead()` is true: the two can
expire together. A reader descheduled across a whole re-admission can see
`ErrNotEstablished` where `ErrSessionDead` was the cause (a new admission clears the
dead flag). The library never re-admits by itself.

## Bounds

| field | default | rule |
| --- | --- | --- |
| `SendQueueMax` | 32 KiB (§2) | caps what a session commits against a peer that stopped acknowledging (§9.5) |
| `MaxMsgPayload` | = `SendQueueMax` | §13's ceiling, and **MUST NOT** exceed `SendQueueMax`; bounds the pad-class ladder. Per architecture — an ESP32 cannot buffer what a controller can |
| `MaxAppPayload` | 1 MiB | the absolute receive-side allocation ceiling |

Both are settable on `Client` and `Server`; zero means the default, and
`MaxMsgPayload` is clamped to `SendQueueMax` and floored so a misconfiguration
bounds the peer rather than muting it.

## Tuning

```go
cli.Tuning = v1.KCPTuning{SndWnd: 128, RcvWnd: 64, NoDelay: 1, Interval: 10, Resend: 2, NC: 1}
```

`DefaultKCPTuning` is `{SndWnd: 32, RcvWnd: 8, NoDelay: 1, Interval: 20, Resend: 2, NC: 1}`.
`RcvWnd: 8` is the transport spec §11 recommendation; the other fields are this
library's defaults (pinned by `v1/doccheck_test.go`), sized so two worst-case
sessions fit an ESP32's heap. `RcvWnd` is the throughput lever and **both ends must be raised
together**; a receiver that advertises a window must be able to buffer it.

`SndWnd` is additionally clamped to `SendQueueMax / WireMTU` — 23 segments at the
defaults, not the 32 the struct says — because that is how §9.5's byte cap is
enforced in Go: kcp-go exposes no queue-depth accessor on a session, so the bound
is applied by sizing the window rather than by polling it. Raise `SendQueueMax`
to raise the effective send window.
Measured cost and a sizing worked example are in
[`docs/tuning.md`](docs/tuning.md).

## Interoperability

The key schedule, MACs, wire layouts and envelope are pinned by the golden
vectors of
[`spec/transport.md`](https://github.com/shieldled/shieldnet-protocol/blob/main/spec/transport.md)
Appendix A, and message-layer framing by those of
[`spec/message-layer.md`](https://github.com/shieldled/shieldnet-protocol/blob/main/spec/message-layer.md)
Appendix A. The canonical files live in `shieldnet-protocol/vectors/`, generated
by `gen_vectors.py` and `gen_msglayer_vectors.py` there — independent Python
implementations that read neither the Go nor the C source — so a
shared-with-itself error in either implementation is caught.
`testdata/shieldnet-v1-vectors.json` and `testdata/shieldnet-msglayer-vectors.json`
are byte-exact copies, checked by `TestVectorsMatchSpecRepo`.
libshieldnet generates its C header from the spec repository's `vectors/` itself.

Changing a domain label, the magic or the version octet changes every derived key
and breaks device interop. There is no negotiation and no compatibility mode: a
build implements exactly one version (transport §4.7).

## Testing

```sh
go vet ./...
go test ./...          # unit, golden vectors, Go↔Go interop
go test -race ./...    # concurrency
```

`TestCDeviceGoClientInterop` cmake-builds the real C device from the `host`
directory of the libshieldnet tree named by `SHIELDNET_LIB_DIR` (the absolute
path of a [libshieldnet](https://github.com/shieldled/libshieldnet) checkout)
and drives it through a full admission
with this controller; `TestGoDeviceCClientInterop` does the reverse with the C
client. Set `SN_HOST_BIN` / `SN_CLIENT_HOST_BIN` to prebuilt `sn_host` /
`sn_client_host` binaries to skip the build; otherwise they skip if
`SHIELDNET_LIB_DIR` is unset or its tree is absent (`SHIELDNET_REQUIRE_INTEROP=1` turns those skips into
failures: the missing C source for either direction, either C build failing, or
no non-loopback IPv4 address for the C client; the environment skips, no network
interfaces and no bindable port, stay skips). The host tools take the PSK from
`SHIELDNET_PSK_FILE` (a mode-0600 file) or `SHIELDNET_PSK`, never from argv —
the tests pass it in the environment.
`TestFixtureMatchesSpec` (in `sled`) checks `testdata/sled-vectors.json` against
`spec/application.md` in a `shieldnet-protocol` checkout, and
`TestVectorsMatchSpecRepo` (in `v1`) checks the two vector files in `testdata/`
byte for byte against that checkout's `vectors/`: set
`SHIELDNET_PROTOCOL_DIR` to its path (default `../../shieldnet-protocol`, resolved
from the test's package directory). Both skip if the spec is absent;
`SHIELDNET_REQUIRE_SPEC=1` turns those skips into failures. The C interop test is the only test
that proves the two implementations agree on the wire, rather than each agreeing
with the spec separately — treat a change that makes it skip as a change that
is untested.

The differential fuzzer needs the C oracle:

```sh
SHIELDNET_ORACLE=<path>/sn_oracle go test ./v1/ -run '^$' -fuzz FuzzDifferentialClassify
```

## For AI assistants and LLMs

- [`AGENTS.md`](https://github.com/shieldled/goshieldnet/blob/main/AGENTS.md) gives coding
  agents (Claude Code, Codex, Cursor, Copilot and others) the rules and entry points
  for writing code with the library or changing it. `CLAUDE.md` points Claude Code at
  it.
- The documentation site serves [`llms.txt`](https://shieldled.github.io/goshieldnet/llms.txt), an index of the
  documentation for LLMs, and [`llms-full.txt`](https://shieldled.github.io/goshieldnet/llms-full.txt), the whole
  documentation (README, examples, API reference, guides and changelog) in one Markdown file to attach to a chat. Each page is also
  served as Markdown: add `index.md` to its URL.

## Security

Report a vulnerability privately, as
[`SECURITY.md`](https://github.com/shieldled/goshieldnet/blob/main/SECURITY.md)
describes; do not open a public issue for it.

## Requirements

Pure Go, no cgo. Go 1.26.5 or newer (`go.mod`). Four direct dependencies:
`github.com/xtaci/kcp-go/v5`, `github.com/pierrec/lz4/v4`, `golang.org/x/crypto`
and `github.com/hashicorp/mdns`.

## License

Copyright (c) 2025-2026 BlackShield LDA. Licensed under the Apache License,
Version 2.0. See [`LICENSE`](https://github.com/shieldled/goshieldnet/blob/main/LICENSE)
and [`NOTICE`](https://github.com/shieldled/goshieldnet/blob/main/NOTICE).
