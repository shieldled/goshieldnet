# What host tests cannot catch

A working guide for porting this stack to a new target and for measuring it
honestly. Every rule here was paid for once; none of them is obvious from the
code, and a green host suite proves none of them.

Companion to [`tuning.md`](tuning.md), which holds the knobs and the numbers.
This file holds the traps and the method.

---

## 1. The four conditions

A unit or loopback suite can be entirely green and still miss a whole class of
defect, because it supplies none of these:

| Condition | What only it exposes |
|---|---|
| **Real hardware** | Stack budgets, cycle costs, word size, toolchain and vendor headers. The host has megabytes of stack and 64-bit pointers |
| **Real network** | Loss, jitter, reordering, MTU, ICMP, DHCP, association. Loopback is lossless, instant and in-order |
| **Sustained duration** | Send and replay windows filling, ACK cadence, buffer wrap, retransmit timers. A ten-packet test never fills a 128-packet window |
| **Failure and retry paths** | Teardown, resource release, second-attempt state. Only reached when something actually fails |

**A green suite proves the components; only load over the real transport proves
the system.**

---

## 2. Porting: host idioms that do not hold on target

The host build is **not** a rehearsal for the target. Word size, stack size, tick
granularity and vendor headers all differ, and most of the following are invisible
to any amount of host-side testing.

- **`sizeof` on a pointer-typed local.** `uint8_t *buf` then `recvfrom(...,
  sizeof(buf), ...)` is **4** on a 32-bit target, not the buffer size. Legal C,
  `-Wall -Werror` clean, and it truncates every datagram. Prefer
  `sizeof(a->rx_buf)` or a named constant whenever the buffer is not a local array.
- **Stack budgets on a task that also does crypto.** A 2 KB receive buffer on a
  6 KB stack shared with X25519, HKDF and AEAD overflows precisely when admission
  reaches its most expensive step. Size stacks from
  `uxTaskGetStackHighWaterMark`, not guesswork, and give every task an explicit,
  documented size rather than inheriting another task's.
- **Tick granularity.** `pdMS_TO_TICKS(5)` is **0** at a 10 ms tick, and
  `vTaskDelayUntil` asserts on a zero delay — a boot loop, not a slow timer.
- **Vendor header paths.** lwIP puts `struct sockaddr_in` in `lwip/sockets.h`;
  `<netinet/in.h>` resolves on POSIX and not on target.
- **A vendored library may abort rather than return.** ikcp's `ikcp_send`
  asserts on a failed segment allocation, which turns a transient OOM into a
  panic and reboot — remotely reachable by any admitted peer that streams faster
  than the application drains. Read the failure modes of vendored code on a
  constrained target; do not assume it returns an error.

---

## 3. Ownership and concurrency

- **Sequence assignment must be atomic with the write that uses it.** A counter
  incremented outside the lock that serialises the write lets two senders take
  numbers *n* and *n+1* and emit them out of order. In this protocol that is
  nonce reuse, which is catastrophic, and the peer's strictly-increasing rule
  silently drops the loser either way.
- **A decoder that returns slices into the read buffer aliases it.** Anything
  retained across datagrams must be copied, or the next datagram overwrites the
  state you kept.
- **A retiring session must be detached before the new one is built.** An
  outgoing agent left inside a read on a session pointer that has since been
  replaced consumes the *new* stream's opening bytes, and the session desyncs on
  its first header. It presents as strictly alternating pass/fail across runs.
- **For every goroutine or task started on a success path, assert it is gone
  after the corresponding teardown.** A leaked reader on a shared socket starves
  the next attempt on the FD read lock *and* eats the datagrams that attempt
  needs — so a retry blocks forever, defeating a design that made retry the
  application's decision.

---

## 4. Configuration that is silently discarded

Two shapes, neither of which fails, warns or logs:

- **A zero-initialised vendor struct drops its non-zero defaults.** `wifi_config_t
  cfg = {0}` clears `pmf_cfg.capable`, which the vendor defaults to true; the
  device then never advertises 802.11w and an AP requiring PMF deauths it
  mid-session.
- **A setter called in the wrong order is clamped.** `ikcp_wndsize` only honours
  a receive window below 128 when stream mode is *already* set; otherwise it
  clamps upward. Every session then runs at the maximum regardless of config —
  a ~180 KB commitment on a 27 KB board — and the tuning knob is inert.

**The defence is to read the setting back off a live object and assert it**, not
to trust that the assignment took.

---

## 5. Measurement traps

These produce numbers that look authoritative and are not.

1. **A virtual clock outrunning the protocol.** A test advancing its clock 2 ms
   per iteration against a stack that emits every 10 ms spends most of its run
   idle-spinning. Step the interval to match what is being measured.
2. **Assuming instrumentation explains a bad number.** Re-measure on a clean
   image before attributing a low figure to logging. Re-measuring is right even
   when the reasoning is wrong — otherwise a real cause gets written off as an
   artifact.
3. **A number that is really a buffer size.** *If a rate divides out to a round
   buffer size over a round timeout, it is measuring backpressure, not
   bandwidth.* A sender that wrote exactly one send-window's worth of messages
   at memory speed and then blocked until its deadline is reporting
   `window ÷ time-to-deadline`.
4. **Not attributing a measurement to a side.** When both parties run in one
   process, a counting allocator hooks *both*. Growth in the sender's queue is
   not evidence about the receiver. Attribute every byte to a side before
   concluding anything.
5. **Reading a counter that cannot move.** Before a metric carries an argument,
   grep for its write site. A counter that is never incremented reads as a
   confident zero, and a live-looking neighbour makes the whole line plausible.
6. **Trusting a green test.** See §6.
7. **Reading a partial serial buffer.** A field grepped out of a truncated line
   may belong to the other party. Log the field you mean, with a label.

---

## 6. Method: the falsifiability bar

**A test that has never failed proves nothing.**

Two regression tests written during this work passed against the *unfixed* code:
one never reproduced the condition (loopback is too fast and lossless), and one
never reached the code under test at all — its half-device used the
source-checking classifier, which drops loopback, so it died at the first phase.
The runtime was exactly the first-phase timeout, and that was the tell.

**Rule: revert the fix, watch the test fail for the right reason, restore the
fix.** A duration or an error string that does not match the mechanism you think
you are testing means you are testing something else.

---

## 7. Method: layered masking

Bugs stack, and each one masks the next:

```
stack overflow during admission   → device resets
  → Wi-Fi drops on reset          → looks exactly like an AP deauthing a client
    → fix the overflow            → device stable, admission still fails
      → sizeof(pointer) == 4      → every datagram truncated
        → fix truncation          → admission completes in 367 ms
```

An environmental cause was proposed with confidence three times — a hostile AP
twice, a power brownout once — and was wrong all three times. The tells:

- **Precision is not environmental.** A disconnect at exactly 10.000 s after
  association, every time, is a timer, not interference.
- **Incoherent symptoms mean look lower.** Four unrelated deauth reasons is not
  one AP behaviour; it is a device resetting underneath.
- **Check the reset cause before theorising.** A panic, a watchdog and a brownout
  have different codes. One grep separates them.
- **Verify the sender before blaming the receiver.** Confirming the encoder
  produced exactly the expected length took thirty seconds and made a truncated
  receive unambiguous.

**Heuristic: when the environment is blamed, ask what would have to be true
locally for the same symptom, and eliminate that first.** It is cheaper to check
and it is usually the answer.

---

## 8. Diagnostics that pay off

| Technique | Use |
|---|---|
| `kill -QUIT <pid>` on a hung Go process | Full goroutine dump. Pinpoints a deadlock in one shot — one goroutine parked in `internal/poll.(*FD).readLock`, another holding it on the same fd |
| `uxTaskGetStackHighWaterMark` | Size a FreeRTOS stack from measurement rather than guesswork |
| Unconditional, source-annotated RX logging | A filtered log hides malformed traffic entirely. While diagnosing, log *every* datagram with size **and** source |
| Disconnect **reason codes** over generic messages | "WiFi disconnected" hides distinct failures; reason codes make the pattern legible |
| Differential fuzzing against a reference implementation | Millions of cases across a predicate, with the oracle built under UBSan — signed-overflow divergences between two implementations surface nowhere else |
| Cross-language golden vectors | Keeps two wire formats honest against the spec rather than against each other |

**Optimisation without an equivalence proof is a bug generator.** Every hot-path
rewrite here was proven byte-identical to the reference before landing.

---

## 9. Guardrails

1. **A CI target build**, not just a host build. Most of §2 is target-only.
2. **Grep for `sizeof` on pointer-typed locals.** The compiler will not help.
3. **Give every task an explicit, documented stack size.**
4. **Audit `= {0}` on vendor config structs** for discarded non-zero defaults.
5. **A failure-path test per resource**: for every goroutine or task started on a
   success path, assert it is gone after teardown.
6. **Keep a sustained-load test in CI** — loopback is fine — long enough to fill
   the send and replay windows. That is what catches a missing flush.
7. **Mark instrumented builds** so a benchmark cannot silently measure one.
8. **Log free heap and largest-free-block around session establishment.** On a
   constrained board, session setup is the largest single allocation event in the
   system.
9. **Read configuration back off the live object and assert it** (§4).
10. **Fail a benchmark that ends in backpressure.** A run whose sender stopped on
    a write timeout measured a window, not a rate (§5.3).

---

## 10. Open

- **Wi-Fi association instability, unexplained.** Reason 204 exactly 10 s after
  `assoc -> run`, DHCP never completing, on one network. Sidestepped by changing
  networks rather than understood. The device is stable once it has an IP.
- **Long-running fuzz campaigns.** CI runs short gates; the one real find
  reproduced in under a minute, and the next probably will not.
- **Key at rest.** A device is never provisioned with the PSK, only with its
  `k_dev` (transport §0). Whether a port keeps that rule, and protects `k_dev` in
  flash, is a property of the firmware image that no host test observes.
