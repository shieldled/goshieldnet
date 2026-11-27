# ShieldNet — transport tuning

The admission and envelope layers add negligible overhead. Session throughput
and latency are set almost entirely by **KCP window and flush-interval tuning**,
which is deliberately conservative by default (sized for an ESP32, [transport design](https://github.com/shieldled/shieldnet-protocol/blob/main/design/transport.md) §11). This
document records the measurements behind that statement and how to change the
tuning when a board needs more.

## Where the cost is (measured)

C device ([libshieldnet](https://github.com/shieldled/libshieldnet), raw ikcp) ↔ Go controller (`goshieldnet`), one host.

**Pure protocol overhead** (Go microbenchmarks, single core):

| Operation | Cost | Rate |
| --- | --- | --- |
| Envelope **Seal** (1000 B datagram) | 0.87 µs | ~1.15 GB/s |
| Envelope **Open** (1000 B datagram) | 0.84 µs | ~1.19 GB/s |
| Device **FINISH** (three HMACs, two X25519, the key derivation) | 127–134 µs (see "Timing budgets") | — (once per admission) |

The per-datagram AEAD is three orders of magnitude below a single flush interval,
so it is never the bottleneck. Admission costs three HMACs, two X25519 and the key
derivation (127–134 µs for the device's FINISH), paid once per session.

**Session-level**, same path, varying only the KCP knobs:

| Config | `rcv_wnd` | interval / tick | Throughput (round-trip echo) | Echo RTT | Per-session buffer¹ |
| --- | --- | --- | --- | --- | --- |
| **Default** | 8 | 20 ms / 15 ms | **0.33 MB/s** | 15 ms | ~11 KB |
| **Mid** (ESP32-feasible) | 64 | 10 ms / 5 ms | **5.84 MB/s** | — | ~88 KB |
| **Aggressive** (host only) | 1024 | 10 ms / 2 ms | **24.5 MB/s** | 9.6 ms | ~1.4 MB |

¹ `rcv_wnd × WIRE_MTU` (WIRE_MTU 1400). This is a *ceiling*: `ikcp_create`
allocates ~5 KB and segments enter only as authenticated data arrives (§9.5), so
the ceiling is reached by real traffic, not by a PSK-less flood.

**Reading this:** the default is window-starved on purpose. `rcv_wnd = 8` bounds a
session to ~11 KB so two worst-case sessions coexist during promotion (§8.5, §9.5)
on an ESP32-WROOM heap. That is plenty for the control plane (small LED commands);
it is genuinely too low for a **pixel-frame data plane**. Raising `rcv_wnd` from 8
to 64 — still ESP32-feasible — is an 18× throughput gain; going to 1024 (host-class
memory only) is 74×. The crypto ceiling (>1 GB/s) is never approached.

## Timing budgets (transport 4.3)

Transport 4.3 asks every implementation to state the processing times its two
admission budgets need, and every deployment to check both for its slowest
client/device pair. Neither party can signal a missed budget: a pair that
violates one fails every admission silently.

Measured with `go test ./v1 -run '^$' -bench 'BenchmarkClientADMIT|BenchmarkDeviceFINISH' -benchtime 5000x -count 3`
(Go 1.26.5, linux/amd64, Intel Core i7-14700KF, one core):

| Party | Work | Benchmark | Time |
| --- | --- | --- | --- |
| Client (`v1.Client`) | processing ADMIT: the checks, one X25519, the key derivation | `BenchmarkClientADMIT` | 57–62 µs |
| Device (`v1.Server`, the emulator) | processing FINISH: three HMACs, two X25519, the key derivation | `BenchmarkDeviceFINISH` | 127–134 µs |

**The pending-record budget.** A pending record lives `PENDING_TTL_MS` from the
moment the device installs it:

```
round-trip time + the client's processing of ADMIT
  + transmission of the first datagram                  <  PENDING_TTL_MS
```

In this library `PENDING_TTL_MS` is the constant `v1.PendingTTLMS` (5 000 ms,
`v1/device.go`), not a field: a deployment that needs more changes the device.

**The FINISH-phase budget.** The client abandons an attempt `FINISH_PHASE_MS`
after it first sends FINISH:

```
round-trip time + the device's processing of FINISH     <  FINISH_PHASE_MS
```

On the client this is the field `v1.Client.FinishPhaseMS` (zero means the
constant `v1.FinishPhaseMS`, 1 500 ms). Raise it for a slow device or a long
path; `TakeControl*` refuses a value at or above `COOKIE_EPOCH_MS`, before
anything is sent.

## The knobs

Both ends of a session **must use matching values** or KCP will misbehave.

| Knob | Effect | Default | Memory cost |
| --- | --- | --- | --- |
| `rcv_wnd` | in-flight receive window → **throughput** | 8 | `rcv_wnd × WIRE_MTU` per session |
| `snd_wnd` | send window | 32 | queue bound. **In Go it is derived, not set** — see below |
| `interval` | KCP flush period (ms) → **latency floor** | 20 | CPU / wakeups |
| tick period | maintenance-tick cadence (ms) | board-set | CPU / wakeups |
| `nodelay`, `resend`, `nc` | ARQ aggressiveness | 1, 2, 1 | — |

`interval` and the tick period together set the latency floor: a datagram waits up
to one of each before it is flushed. `WIRE_MTU` is **not** a tuning knob — it is
pinned at 1400 with no PMTU discovery (§8.4); the internal KCP MTU is always
`WIRE_MTU − ENVELOPE_LEN` = 1380.

## How to change it

### C device (libshieldnet)

`sn_kcp_tuning` (in `shieldnet/sn_device.h`) is applied to every session the device
promotes. Set it before any promotion:

```c
sn_device dev;
if (sn_device_init_kdev(&dev, k_dev, device_id, cookie_secret, admission_epoch,
                        local, n, now) != 0) { /* bad key material */ }

sn_kcp_tuning t = SN_KCP_TUNING_DEFAULT; /* {32, 8, 1, 20, 2, 1} */
t.rcv_wnd  = 64;   /* wider receive window for a pixel-frame data plane */
t.interval = 10;   /* faster flush */
sn_device_set_tuning(&dev, t);

sn_device_start_tick(&dev, 5); /* tick cadence is the last argument, in ms */
```

Size `rcv_wnd` against the board's **measured** heap, remembering §9.5's rule that
*two* sessions at their ceilings must fit (promotion creates the new KCP object
before releasing the old). `SN_KCP_TUNING_DEFAULT`'s `rcv_wnd` stays the transport spec's §11 recommendation; its other values are this library's choices, not the spec's.

**The board owns the tuning, not the library.** The library only supplies
`SN_KCP_TUNING_DEFAULT`; each board reads its own config and calls
`sn_device_set_tuning`. libshieldnet's reference host (`host/sn_host.c`) reads
its config from the environment:

| Env var | Field | Default |
| --- | --- | --- |
| `SHIELDNET_RCV_WND` | `rcv_wnd` | 8 |
| `SHIELDNET_SND_WND` | `snd_wnd` | 32 |
| `SHIELDNET_KCP_INTERVAL` | `interval` (ms) | 20 |
| `SHIELDNET_TICK_MS` | tick period (ms) | 15 |

```
SHIELDNET_RCV_WND=32 SHIELDNET_KCP_INTERVAL=10 SHIELDNET_TICK_MS=5 sn_host ...
```

The host prints its effective tuning to stderr at startup. An **ESP board** reads
the same values from Kconfig/`sdkconfig` (e.g. `CONFIG_SHIELDNET_RCV_WND`) and
makes the identical `sn_device_set_tuning` call.

### Go controller / server (`goshieldnet`)

`KCPTuning` (default `DefaultKCPTuning`) is a field on both `Client` and `Server`;
set it before `TakeControl` / before the first promotion:

```go
cli, _ := v1.NewClient(addr, psk, deviceID, local)
cli.SendQueueMax = 256 * 1024 // raise the byte cap FIRST — see below
cli.Tuning = v1.KCPTuning{SndWnd: 128, RcvWnd: 64, NoDelay: 1, Interval: 10, Resend: 2, NC: 1}
// ... cli.TakeControlAppPadded(v1.CmdPing, nil)
```

```go
srv := v1.NewServer(dev, conn)
srv.Tuning.RcvWnd = 64
srv.Tuning.Interval = 10
// ... go srv.Serve()
```

**`SndWnd` is not applied as written.** kcp-go exposes no queue-depth accessor on
a session, so §9.5's byte cap cannot be enforced by polling — it is enforced by
*sizing the send window* from it. The effective value is
`min(Tuning.SndWnd, SendQueueMax / WIRE_MTU)`, which at the default 32 KiB cap is
**23 segments**, whatever `SndWnd` says. Raising `SndWnd` alone therefore does
nothing; raise `SendQueueMax` first. With 256 KiB the ceiling becomes 187.

| Field | Default | Effect |
| --- | --- | --- |
| `SendQueueMax` | 32 KiB (§2) | caps `snd_queue + snd_buf` against a peer that stopped acknowledging, **and sets the effective `SndWnd`** |
| `MaxMsgPayload` | = `SendQueueMax` | §13's ceiling; bounds the pad-class ladder. Clamped to `SendQueueMax`, since a message padded past the queue cap could never be written |
| `FinishPhaseMS` (`Client` only) | 1 500 ms (`v1.FinishPhaseMS`) | FINISH_PHASE_MS, the cap on an admission's FINISH phase (transport 4.2, 4.3). Must exceed the round-trip time plus the device's FINISH processing, and stay below `COOKIE_EPOCH_MS` (4 000 ms). A negative value or one at or above 4 000 is an error from `TakeControl*`, before anything is sent; it is never clamped |
| `MidFrameBudgetMS` (`Client` and `Server`) | 10 000 ms (`v1.MidFrameBudgetMSDefault`) | How long a message may stay partly read, from its first octet (message layer 8). Past it the read returns `ErrDesync`; with no read deadline set, the session is closed to end the blocked read. Time between reads counts. Must exceed the time to receive a `MaxMsgPayload`-sized message on the slowest supported link — with the 256 KiB `SendQueueMax` above, a full-size message on a lossy link can take seconds, so raise the budget with `MaxMsgPayload` |

A write that would exceed the cap returns `ErrSendQueueFull` rather than blocking
or dropping — §9.5 requires an error to the caller and never a silent drop, and
writes resume once the window drains.

The Go server runs its own §9.2 maintenance tick at `TickIntervalMS` (500 ms),
started by `Serve`; there is no separate call as there is on the C side.

## Worked example: pixel-frame streaming

Requirement: **16 KB/frame at 30 fps**.

```
16 KB × 30 = 480 KB/s ≈ 0.48 MB/s ≈ 3.8 Mbit/s
```

(At 16 KB = 16,384 B it is 491 KB/s ≈ 0.49 MB/s — same ballpark.)

Against the measured rows:

| Config | Throughput | Covers 0.48 MB/s? |
| --- | --- | --- |
| Default (`rcv_wnd` 8) | 0.33 MB/s | **No** — under the requirement |
| Mid (`rcv_wnd` 64) | 5.84 MB/s | Yes, ~12× headroom |

Two caveats, both favourable:

- The benchmark rows are **round-trip echo** (each byte goes client→device→client).
  Pixel frames are **one-way** (controller → device), so the usable capacity for
  the same window is meaningfully higher than the echo figure.
- Even so, 0.48 MB/s sits right at the default's edge — no margin for a lost frame's
  retransmit. Do not run the stream at the default.

**Recommendation for this workload:** set `rcv_wnd = 32` on the device (≈ 44 KB
per-session buffer; two sessions ≈ 88 KB, ESP32-feasible). That is ~2–3 MB/s
territory — 4–6× headroom over 0.48 MB/s, so a retransmit does not starve the
stream. Drop `interval` to 10 ms as well: at 30 fps a frame period is 33 ms, and a
frame should not wait up to 20 ms just to be flushed.

```c
sn_kcp_tuning t = SN_KCP_TUNING_DEFAULT;
t.rcv_wnd  = 32;   /* ~44 KB/session; 4-6x headroom over 0.48 MB/s */
t.interval = 10;   /* one frame shouldn't wait 20 ms to flush at 30 fps */
sn_device_set_tuning(&dev, t);
sn_device_start_tick(&dev, 5);
```

**Also check `SEND_QUEUE_MAX`** (§9.5, default 32 KiB): it caps `snd_queue + snd_buf`
combined. One 16 KB frame fits under 32 KiB, but if you pipeline multiple frames the
in-flight total must stay under the cap or application writes start returning
`ErrSendQueueFull` (the bound is deliberate — §9.5 forbids dropping silently).
Size it for the number of frames you allow in flight, and remember it also sets
the effective `SndWnd` on the Go side.

## Recommendation

Keep the conservative default for the **control plane** — small commands don't need
the window, and the tiny footprint is the point. Raise `rcv_wnd` (and drop
`interval`) only on the **data-plane path** that actually streams, and only as far
as the device's heap allows with two sessions live. Because the value is now a
config field rather than hardcoded, a board can choose per its role without forking
the library.

## End-to-end result

Measured on device through the whole path — network, decrypt, dispatch, publish,
LEDs — at `target_fps = 30`:

| Strip | LEDs/strip | bpp | Wire frame | Rendered |
|---|---|---|---|---|
| WS2812 | 1024 | 3 | 8192 B | **30.4 fps**, 0 dropped |
| SK6812 | 768 | 4 | 6144 B | **30.4 fps**, 0 dropped |

Identical, because 25% fewer LEDs exactly cancels 33% more bytes per LED — both
push 24,576 bits and take the same 30.7 ms on the wire. **There is no RGBW
penalty.**

The render loop:

```
cycle 33.0 ms = 30.3 fps
  RMT transmit   29.86 ms   (97% of the 30.72 ms line rate, ±0.5 ms)
  idle headroom   3.00 ms
  swizzle+mailbox  0.01–0.11 ms
```

The transmit is at the physical limit of the LED protocol and everything else in
the loop is noise. `target_fps` is settable at runtime with `SET_FPS`; the
ceiling is the transmit, so asking for more than ~33 fps is clamped by physics
rather than rejected.

## Reproducing the numbers

From `goshieldnet`, with `SN_HOST_BIN` set to a built `sn_host`, or
`SHIELDNET_LIB_DIR` set to the absolute path of a libshieldnet checkout so the
tests build it (without either, the `TestBench*` tests skip):

```
go test ./v1/ -run TestBenchAdmission -v      # admission latency distribution
go test ./v1/ -run TestBenchRTT -v            # echo round-trip latency
go test ./v1/ -run TestBenchThroughput -v     # pipelined echo throughput
go test ./v1/ -bench BenchmarkEnvelope -run '^$' -benchmem # pure AEAD cost
go test ./v1/ -bench BenchmarkDeviceFINISH -run '^$'       # per-admission crypto
```

The C host is libshieldnet's `host/sn_host.c` (built via `host/CMakeLists.txt`).
The tuning-sweep rows above were produced by temporarily editing libshieldnet's
`configure_kcp` (`src/sn_session.c`) and the client's `Tuning`; the numbers will vary with hardware,
but the *shape* — flat crypto cost, window-bound throughput — is the point.
