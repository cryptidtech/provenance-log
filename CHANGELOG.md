# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-13

### Summary

Synced from the BetterSign workspace `bs-provenance-log 0.7.0` crate. This is
a breaking release: the `bs-multicid` dependency was split into `multi-cid`
(for `Cid`) and `multi-vlad` (for `Vlad`), the `bs-wacc` dependency was
repointed to the standalone `wacc` crate, the `wasmtime` dependency was
upgraded to 41.0, the `thiserror` dependency was upgraded to 2.0, the
`serde_cbor` dependency was replaced with `multi-cbor`, and all `bs-*`
imports were renamed to `multi-*`. The public API surface is substantially
different from 1.0.23.

### Added

- `MultiVlad` error variant in the `Error` enum, since `Vlad` now lives in the standalone `multi-vlad` crate (was previously in `bs-multicid`).
- `EncodeIntoBuffer` impl for `Cid` in `multi-cid` and `Vlad` in `multi-vlad` (added to support the `provenance-log` encoding path).
- `dag_cbor` feature now enables `multi-cbor/tags`, `multi-cid/dag_cbor`, and `multi-vlad/dag_cbor`.
- MSRV declared as 1.85.
- `[lints.clippy]` config with `pedantic`, `nursery`, and `cargo` groups.
- Comprehensive test suite: concurrency, delegation, kvp_operations, log_creation, security, serialization, verification, property tests.

### Changed

- **Crate name**: renamed from `bs-provenance-log` to `provenance-log`. All `use bs_provenance_log::...` references now use `use provenance_log::...`.
- **`bs-multicid` split**: `use bs_multicid::{Cid, Vlad}` is now `use multi_cid::Cid` + `use multi_vlad::Vlad`. Imports split at every call site. This is a breaking change for all downstream consumers.
- **`bs-wacc` → `wacc`**: all `use bs_wacc::...` references now use `use wacc::...`. The `wacc` dependency was repointed from a git dep to the standalone crate. This is a breaking change.
- **`serde_cbor` → `multi-cbor`**: all `serde_cbor::` references now use `multi_cbor::`. The `dag_cbor` feature uses `multi-cbor/tags`. This is a breaking change.
- **`wasmtime`**: upgraded from `19.0` to `41.0`. This is a major breaking change for all callers of the VM verification API.
- **`thiserror`**: upgraded from `1.0` to `2.0`. This is a breaking change for error type consumers.
- **Dependencies**: repointed all `bs-*` workspace deps to standalone crates. `multi-cid`, `multi-vlad`, and `wacc` use path deps on the local standalone crates. `multi-codec`, `multi-hash`, `multi-key`, `multi-sig`, `multi-trait`, and `multi-util` use `package` rename to `bs-*` workspace path deps until Phases 7-9 publish Lamport/XMSS support.
- **`rand`**: kept at 0.8 (workspace version).
- **Test example file paths**: updated from `../../examples/provenance-log/wast` (workspace-relative) to `examples/provenance-log/wast` (crate-root-relative).
- **CI**: updated to run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo doc`, and an MSRV check job.

### Removed

- Old FSL license files (`LICENSE-APACHE.txt`, `LICENSE.md`, `pandoc.css`).
- Old standalone examples (`basic_log.rs`, `delegation_example.rs`, `signature_auth.rs`). These relied on workspace-level imports and need re-pointing for the standalone crate.

### Notes

- The `multi-codec`, `multi-hash`, `multi-key`, `multi-sig`, `multi-trait`, and `multi-util` dependencies currently point at the `bs-*` workspace path deps in `bettersign/crates/` via `package` rename. When Phases 7-9 of the crate extraction plan publish the Lamport and XMSS support to crates.io, the path deps will switch to the crates.io versions.

## [1.0.23] - 2026-08-11

### Notes

- Previous standalone release. Used git deps for `multicid`, `multihash`, `multikey`, `multisig`, `multitrait`, `multiutil`, `wacc`. Used `serde_cbor 0.11` and `thiserror 1.0`.

[2.0.0]: https://github.com/cryptidtech/provenance-log/releases/tag/v2.0.0
[1.0.23]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.23