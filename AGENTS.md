# AGENTS.md: goshieldnet for LLMs and coding agents

This file is for AI assistants and coding agents that build **with** this library
or change the library itself. People should start with
`README.md`, the Overview page of the documentation site. The same guidance,
with the whole documentation in one file, is on that site as `llms.txt` and
`llms-full.txt`.

## What the library is

The pure-Go implementation (no cgo) of ShieldNet, the encrypted protocol between
ShieldLED controllers and LED devices. Module `github.com/shieldled/goshieldnet`,
Go 1.26.5 or newer. Packages:

- `sledclient`: the client for ShieldLED devices (connect, request/ACK
  correlation, typed commands). Most applications need only this, with
  `discovery` (mDNS) to find devices.
- `sled`: the application payloads (responses, PIXEL_FRAME, NTP_SERVER), both
  directions.
- `v1`: the transport and message layer, as a controller (`v1.Client`) and a
  device (`v1.Server`, for tests, emulators and tools; the device of record is
  the C implementation, [libshieldnet](https://github.com/shieldled/libshieldnet)).
- `sledclient/sledclienttest`: an in-process device for tests.

## Where the facts are

- The Go doc comments document every exported identifier where it is declared.
  Entry points:
  - client: `sledclient.Dial`, `Options`, the typed methods (`Status`,
    `SetBrightness`, `SetMode`, ...), `Do` and `DoExtension`;
  - discovery: `discovery.DiscoverAll`, `DiscoverAllWith` (`Options.Services`
    for custom service types), `Found`;
  - device: `v1.NewDeviceFromKDev`, `v1.NewServer`, `(*v1.Server).Serve`,
    `RecvAppNumGen`, `SendAppPadded`, with `sled.EncodeAck` and the other
    `sled` encoders for the answers;
  - transport controller: `v1.NewClient`, `TakeControlAppPadded`,
    `SendAppPadded` / `SendAppCompressed` / `SendAppBulk`, `RecvApp`;
  - keys: `v1.DeriveKDev`.
- `README.md`: how ShieldNet works, complete client and device examples, the
  error sentinels and what to do on each, liveness, bounds, tuning and testing.
- `examples/client` and `examples/server`: complete, commented programs for the
  two roles; copy their structure, including their key handling
  (`examples/internal/secret`).
- The documentation site's API reference (`api/`, and `llms-full.txt`) is
  generated from `go doc -all` by `docs/hooks/api_reference.py`, so a doc
  comment is the documentation: keep it accurate when you change a call.
- `docs/tuning.md` (KCP windows, measured cost) and `docs/bringup-lessons.md`.
- The protocol: [shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol),
  `spec/transport.md`, `spec/message-layer.md` and `spec/application.md`. The
  `§N` numbers in the sources are those of its `design/transport.md`.

## Rules that matter

1. **A device never holds the PSK.** It is built with `v1.NewDeviceFromKDev`
   from its own `k_dev` (`v1.DeriveKDev(psk, deviceID)`, run on the controller
   side) and its `device_id`. `v1.NewDevice` takes the PSK and is for tests and
   demos only.
2. **Keys never come from the command line.** Read them from a mode-0600 file
   or the environment, as the examples do.
3. **Never use `127.0.0.1`.** Loopback sources are always refused. A controller
   and a device on one host need the LAN address and the same-host opt-outs
   (`sledclient.Options.AllowSameHost`, `local = nil` on the device, the
   examples' `-same-host-demo`), for development only.
4. **Admission is one-shot.** Nothing retries or re-admits by itself; after
   `ErrSessionDead` wait for `SessionDead()`, then admit again explicitly.
5. **Do not collapse the read errors.** `ErrRejected` and `ErrReplay`: keep
   reading. `ErrDesync`: the session is over. `ErrSessionClosed`: that session
   ended, drop nothing. See the README's Errors table.
6. **Use the send call for the message's category**: `SendAppPadded` for
   control, `SendAppCompressed` for pixel frames, `SendAppBulk` for bulk
   content. Never mix the deprecated raw `Send`/`Recv` with the `*App` calls in
   one session.
7. **A `sledclient.Client` is not safe for concurrent use**: serialise its calls.
8. **Wire compatibility is byte-exact** with libshieldnet. The vectors in
   `testdata/` are copies of shieldnet-protocol's `vectors/` (checked by
   `TestVectorsMatchSpecRepo`) and of its `spec/application.md`
   (`TestFixtureMatchesSpec`); update them from the spec, never by hand.

## Changing the library

```sh
gofmt -l .                 # must print nothing
go vet ./...
staticcheck ./...
go test ./...
go test -race ./...
```

- No behaviour changes without a test, and no cgo.
- CI also vets for Windows, macOS and 32-bit ARM (`.github/workflows/ci.yml`);
  keep platform-specific code in `_linux.go` / `_other.go` / `_windows.go` files.
- The C interop tests (`TestCDeviceGoClientInterop`,
  `TestGoDeviceCClientInterop`) run when `SHIELDNET_LIB_DIR` names a
  libshieldnet checkout; run them for any change on the wire.
- Every exported identifier has a doc comment; keep it so.
- Every new file starts with the licence header:
  `// Copyright (c) 2025-2026 BlackShield LDA` and
  `// SPDX-License-Identifier: Apache-2.0` (or the same two lines as `#`
  comments), above the package clause and below any `//go:build` line.
- Record user-visible changes in `CHANGELOG.md`.
- Documentation site: `pip install -r docs/requirements.txt`, then
  `mkdocs build --strict` (needs Go on PATH).
