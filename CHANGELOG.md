# Changelog

All notable changes to **goshieldnet** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Security workflow: a CycloneDX SBOM of the module and its dependencies on
  every change, every tag and weekly, scanned with Grype (see `SECURITY.md`).

### Changed

- Requires `golang.org/x/net` v0.62.0 and `golang.org/x/mod` v0.40.0 (and so
  `x/sync` v0.22.0 and `x/tools` v0.49.0), past GO-2026-6860, GO-2026-6866,
  GO-2026-6179 and GO-2026-6180; govulncheck found none of them reachable.
- `LICENSE` names the copyright holder and includes LZ4's licence, which
  `v1/lz4block.go` (derived from `lz4.c`) is under.

## [1.0.0] - 2026-11-27

First public release: the Go reference implementation of ShieldNet v1
([shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol) version 1).

- `v1`: the transport, both roles: admission, the encrypted session over KCP,
  the message layer (numbering, compression, padding), source checks and
  replay protection.
- `sled`: the ShieldLED application codecs (commands, responses, pixel frames,
  device information, status, frame timing).
- `sledclient`: a controller client over `v1` and `sled`;
  `sledclient/sledclienttest` an in-process test device.
- `discovery`: mDNS discovery of ShieldLED devices.
- Builds on Linux, macOS and Windows; byte-exact with the C implementation
  ([libshieldnet](https://github.com/shieldled/libshieldnet)) and checked
  against the specification's test vectors.
- Documentation site with an API reference generated from the source, runnable
  examples, `llms.txt` / `llms-full.txt`, `AGENTS.md`, `SECURITY.md` and
  `NOTICE`.

[1.0.0]: https://github.com/shieldled/goshieldnet/releases/tag/v1.0.0
