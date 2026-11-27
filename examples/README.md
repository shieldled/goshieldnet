# Examples

Two runnable programs that exercise the whole stack:

| | |
| --- | --- |
| [`server/`](server) | a device: admits one controller, then reads framed messages and answers them |
| [`client/`](client) | a controller: admits, sends control messages and pixel frames, handles every failure mode the protocol produces |

```
# controller: the PSK, in a file only you can read
umask 077; echo <64 hex> > psk.hex
# provisioning: derive this device's k_dev from the PSK
SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -print-kdev -device-id <16 hex> > kdev.hex

SHIELDNET_KDEV_FILE=kdev.hex go run ./examples/server -listen :32000 -device-id <16 hex>
SHIELDNET_PSK_FILE=psk.hex   go run ./examples/client -device HOST:32000 -device-id <16 hex>
```

The client's `-ntp` flag takes a time server (host, host:port, an IPv6 address or `[v6]:port`; the port defaults to 123). It is sent only to a device that advertises `pts`, and the device is free to ignore it. Empty sends nothing.

**Keys never go on the command line**, which `ps` and `/proc/<pid>/cmdline` show
to every local user; `-psk` is refused with an error saying so. As with
libshieldnet's `sn_host` / `sn_client_host`, a key comes from a file named by
`*_FILE` (64 hex chars, trailing whitespace allowed) or else from the hex
variable itself:

| program | key | file | hex |
| --- | --- | --- | --- |
| client | PSK | `SHIELDNET_PSK_FILE` | `SHIELDNET_PSK` |
| server | `k_dev` | `SHIELDNET_KDEV_FILE` | `SHIELDNET_KDEV` |

A key file readable by group or other (`mode & 077 != 0`) is refused — `chmod
600` it. The hex variable is unset once read so child processes do not inherit
it; prefer the file anyway.

The server is a device, so it takes `k_dev`, not the PSK (§0). As a demo
convenience only, if no `k_dev` is given but `SHIELDNET_PSK_FILE` /
`SHIELDNET_PSK` is, it derives `k_dev` itself and logs a warning: a real device
must never hold the PSK.

## Running them on one machine

**They will not talk over `127.0.0.1`.** Transport §4.3 rejects loopback sources
unconditionally, and it also rejects a datagram whose source is an address
assigned to the receiving interface — so a controller on the same host as its
device is refused twice over. Both ends apply the rule, so both would refuse.

`-same-host-demo` on **both** programs drops the own-address check for a
single-machine demo. Use the host's LAN address, not loopback:

```
SHIELDNET_KDEV_FILE=kdev.hex go run ./examples/server -listen 192.168.1.10:32000 \
    -same-host-demo -device-id 0908070605040302

SHIELDNET_PSK_FILE=psk.hex go run ./examples/client -device 192.168.1.10:32000 \
    -same-host-demo -device-id 0908070605040302
```

The client admits, queries the device, sends three pixel frames and exits 0.
Its output (timestamps removed; the source port varies):

```
WARNING: -same-host-demo disables §4.3 own-address rejection
admitted to 192.168.1.10:32000
PING -> ACK kind=0x7 status=OK orig_msgnum=1 detail=""
GET_DEVICE_INFO -> DEVICE_INFO "envelope"="1200" "strips"="1" "leds"="64" "bpp"="4" "pixel"(capability)
GET_DEVICE_INFO -> ACK kind=0xa status=OK orig_msgnum=2 detail=""
GET_STATUS -> STATUS frames=1234 commands=56 dropped=0 mode=1 output=true brightness=200 target_fps=30
GET_STATUS -> ACK kind=0x8 status=OK orig_msgnum=3 detail=""
sent 3 pixel frames
done
```

and the server logs each command it answers:

```
WARNING: -same-host-demo disables §4.3 own-address rejection
device listening on 192.168.1.10:32000 (device_id 0908070605040302)
controller admitted: 192.168.1.10:41378
PING
GET_DEVICE_INFO
GET_STATUS
PIXEL_FRAME: frame 0, 256 pixel bytes
PIXEL_FRAME: frame 1, 256 pixel bytes
PIXEL_FRAME: frame 2, 256 pixel bytes
```

Never set that flag in a deployment: it is one of §4.3's anti-reflection rules.
On two hosts, omit it — nothing else changes.

The client also drives other ShieldNet devices, for example libshieldnet's
[`led_device`](https://github.com/shieldled/libshieldnet/tree/main/examples)
(start it with the PSK and `-same-host` on the same machine); it then reports
that device's geometry and status instead.

## What they demonstrate

**Keys and identity.** A controller holds the PSK; a device is provisioned only
with its own derived `k_dev` and its `device_id` (§0) — the server is built with
`NewDeviceFromKDev`, and `client -print-kdev` is the provisioning step. `cookie_secret` and
`admission_epoch` are per-boot CSPRNG draws — the server example generates them
and shows §4.2's constraint, which is easy to get wrong silently: the top **eight
bits** of `admission_epoch` must be clear, not just the top bit. Get it wrong and
RETRY still works while admission dies at FINISH with nothing logged.

**One-shot admission.** `TakeControlApp` admits and sends the first application
message as the promoting datagram (§8.5(c)) — one round trip. There is no retry,
no backoff and no automatic failover (§7.2); retrying is the caller's decision,
because an earlier design's damping turned out to be the cheapest attack in the
protocol.

**The §13 categories.** The client sends each message with the call for its
category:

| category | call | on the wire |
| --- | --- | --- |
| control and configuration | `SendAppPadded` | padded to a size class, never compressed |
| pixel frames | `SendAppCompressed` | LZ4 if it shrinks, never padded |
| bulk content (not used by the examples) | `SendAppBulk` | LZ4 if it shrinks, else padded |
| — | `SendApp` | verbatim; an escape hatch |

**The failure modes**, which is most of the point. §1.2 requires a receiver to
distinguish three read outcomes and forbids collapsing them, so both examples
branch on the sentinels:

- `ErrRejected` — read in full and refused. The stream is still frame-aligned:
  **keep reading**. Treating it as fatal hands anyone who can reach the port a
  denial of service against an authenticated peer.
- `ErrDesync` — a partial frame. Every later read would parse payload as a
  header; the session is unrecoverable. The server ends it with
  `DropPrimaryIf(gen)`, using the generation `RecvAppNumGen` returned, so a
  session promoted in the meantime is not killed instead.
- `ErrSessionClosed` — the session was closed or replaced while the call
  waited. It ended; it did not desynchronise. Keep listening and drop nothing.
- `ErrReplay` — a `MessageNum` at or below the high-water mark.
- `ErrSendQueueFull` — §9.5's bound. For a pixel stream, drop the frame and send
  the newest; queueing just replays stale frames on recovery.
- `ErrSessionDead` — §7.2's liveness timer fired. Wait until
  `SessionDead()` is true, then recover with an explicit `TakeControl`.

## What they are not

The server is **not** a ShieldLED device. The device of record is the C firmware
built on [libshieldnet](https://github.com/shieldled/libshieldnet). The example
answers PING, GET_STATUS, GET_DEVICE_INFO and GET_MODE, decodes and logs
PIXEL_FRAME and NTP_SERVER (which are never answered), and answers any other
kind with `ERR_UNKNOWN_KIND`, using the `sled` codecs
(`shieldnet-protocol/spec/application.md`) so the demo is end-to-end rather than
a transport echo. A controller that needs more, such as libshieldnet's
`led_client` (it sends SET_MODE), stops at the first refused command.

Raw `Send`/`Recv` and the `SendApp` family share one KCP stream, so a session
must use one or the other from its first byte. Mixing them corrupts framing
permanently; that is why the client uses `TakeControlApp` rather than
`TakeControl`.
