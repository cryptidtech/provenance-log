# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2026-10-06

### Fixed

- `Log::verify()` now rejects any entry stored under a Cid that its content does not hash to (`LogError::EntryCidMismatch`), which closes the second half of issue #4. A decoded forged log also fails `Log::try_append` with the same error wrapped in `LogError::VerifyFailed`.

## [2.3.0] - 2026-10-06

### Added

- Entry version 2 with component lock and unlock scripts. `Version::CURRENT` is now 2, the legacy core-module version stays available as `Version::LEGACY` (1), and `Entry::Builder::with_version` pins an entry's version with `is_supported()` validation (`EntryError::InvalidVersion` otherwise). Version-2 entries run their scripts as WASM components on wacc 2.2's component path; version-1 entries keep core-module execution.
- Entry-carried script-kind gates: a version-2 entry's unlock and lock scripts must be WASM components and a version-1 entry's must be core modules. The builder rejects violations with `EntryError::WrongScriptKind { expected, actual }`; log verification rejects them per entry with `LogError::ScriptKindMismatch { seqno, expected, found }`, including the seqno-0 first-lock check. Undetectable payloads (empty scripts, `Script::Cid`) pass the gates and fail at compile time, as before.
- Component example scripts under `examples/provenance-log/scripts/`: three wit-bindgen `no_std` guest crates (`unlock`, `lock`, `first`) with a workspace `Cargo.toml`, vendored WIT copies pinned to the wacc 2.2.0 interface, and a Makefile fixture pipeline; the legacy `.wast` examples stay for the core-module path. `tests/component_scripts.rs` verifies component and mixed-version logs end to end.

### Changed

- New entries default to version 2, so builders of core-module entries must pin version 1 with `Builder::with_version(Version::LEGACY)`. Migration to version 2 is explicit: an entry chains in its predecessor's lock scripts and must replace inherited module locks through `with_locks` with component scripts. Mixed-version logs verify under the carried-script rule.
- Requirement `wacc = "2.1"` → `"2.2"`.
- The script verification limiter allows eight WASM instances per execution store (component guests instantiate three core modules, which the prior cap of two rejected).

### Notes

- A `[patch.crates-io]` block pins `wacc` to the local checkout while wacc 2.2.0 is unpublished; the block goes away once wacc 2.2.0 publishes.

## [2.2.0] - 2026-09-01

### Added

- Merkle-tree Lamport `lamport-merkle-blake3-256` at depth 1 is the default ephemeral signing key in the documented first-event flow: leaf 0 signs the vlad and leaf 1 signs the first entry, exactly consuming the two-leaf tree. `test_builder` in `src/log.rs` now demonstrates the full flow — `vlad::Builder::try_build_advance` for the stateful vlad signature, the advanced key's public half published at `/vlad/key`, and `SignView::sign_advance` in the proofs closure with tree-exhaustion assertions.
- `test_merkle_leaf_reuse_rejected_in_plog`: a depth-1 merkle key signs one entry at leaf 0; a second entry re-signing from stale state at leaf 0 must fail `log.verify()` with a leaf-reuse/rollback error from wacc's merkle enforcement.

### Changed

- Updated dependencies: `multi-codec` 1.2 → 1.3, `multi-key` 1.1 → 1.2, `multi-sig` 1.2 → 1.3, `multi-vlad` 0.1 → 0.2, `wacc` 2.0 → 2.1.
- Raised `rust-version` from 1.95 to 1.96 (required by `multi-key` 1.2 / `lamport_signature_plus` 0.5.0) and updated the CI MSRV job to 1.96.

### Notes

- Merkle-tree Lamport keys are stateful: each signature consumes a one-time leaf carried inside the signature wire data. Signers must persist the advanced key returned by `SignView::sign_advance` after every signature. Verification-side reuse is enforced by wacc 2.1 (strictly-increasing leaf indices per public key across a verification pass).

## [2.1.0] - 2026-08-18

### Summary

Updated all `multi-*` dependencies from git and `bs-*` workspace path dependencies to their published crates.io versions. Upgraded `wasmtime` from 41.0 to 47.0. Raised the MSRV from 1.85 to 1.95. Added a `slow-tests` feature to exclude long-running XMSS tests from the default `cargo test` run. Fixed three compile errors in the `EncodeIntoBuffer` implementations for `Entry`, `Log`, and `Script` that were introduced by the 2.0.0 refactor. No public API changes.

### Added

- `slow-tests` feature. When disabled (the default), the `test_xmss_index_reuse_rejected_in_plog` test is excluded from `cargo test`. Run with `cargo test --features slow-tests` to include it.

### Changed

- **Dependencies**: repointed all `multi-*` dependencies from `bs-*` workspace path deps and git deps to crates.io versions. `multi-base 1.0`, `multi-cbor 0.1`, `multi-cid 0.2`, `multi-codec 1.2`, `multi-hash 1.1`, `multi-key 1.1`, `multi-sig 1.2`, `multi-trait 1.0`, `multi-util 1.1`, `multi-vlad 0.1`, `wacc 2.0`.
- **`wasmtime`**: upgraded from 41.0 to 47.0.
- **`proptest`** (dev): upgraded from 1.4 to 1.11.
- **MSRV**: raised from 1.85 to 1.95.
- **`rand`**: removed as a regular dependency. Test code now uses the `rand_010` dev-dependency alias (`rand 0.10`).

### Fixed

- `EncodeIntoBuffer` implementations for `Entry` (`src/entry.rs:211`), `Log` (`src/log.rs:192`), and `Script` (`src/script.rs:276`) used `SIGIL.encode_into_buffer(...)`, but `multi_codec::Codec` does not implement `EncodeIntoBuffer`. Replaced with `u64::from(SIGIL).encode_into_buffer(...)`, which goes through the `From<Codec> for u64` conversion and then the `u64` `EncodeIntoBuffer` impl. The encoded output is identical to what `From<Codec> for Vec<u8>` produces.

## [2.0.0] - 2026-08-13

### Summary

Synced from the BetterSign workspace `bs-provenance-log 0.7.0` crate. This is a breaking release: the `bs-multicid` dependency was split into `multi-cid` (for `Cid`) and `multi-vlad` (for `Vlad`), the `bs-wacc` dependency was repointed to the standalone `wacc` crate, the `wasmtime` dependency was upgraded to 41.0, the `thiserror` dependency was upgraded to 2.0, the `serde_cbor` dependency was replaced with `multi-cbor`, and all `bs-*` imports were renamed to `multi-*`. The public API surface is substantially different from 1.0.23.

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

## [1.0.23] - 2024-08-27

### Fixed

- Fixed `check_signature` and updated codec handling.

## [1.0.22] - 2024-07-29

### Fixed

- Fixed stack debug output.

## [1.0.21] - 2024-07-29

### Added

- `test-log` debugging support in tests.

## [1.0.20] - 2024-07-29

### Fixed

- Cleaned up stack debugging.

## [1.0.19] - 2024-07-26

### Changed

- Updated to the new `wacc` API.

## [1.0.18] - 2024-07-23

### Fixed

- Improved debugging output.

## [1.0.17] - 2024-06-14

### Added

- `EncodedScript` type.
- Codec field on `Script`.
- `as_str` method on `Key`.
- Iterator over key-value pairs.

## [1.0.16] - 2024-06-13

### Added

- Iterator over key-value pairs.

## [1.0.15] - 2024-06-10

### Added

- `try_append` method on `Log`.

## [1.0.14] - 2024-06-10

### Added

- `from` method on `entry::Builder`.

## [1.0.13] - 2024-06-10

### Added

- `AsRef<str>` impl for `Key`.

## [1.0.12] - 2024-06-10

### Added

- `push` method on `Key`.

## [1.0.11] - 2024-06-10

### Added

- `PartialEq` impl for `Log`.

## [1.0.10] - 2024-06-10

### Added

- `Display` impl for key-value pairs.

## [1.0.9] - 2024-06-09

### Changed

- Simplified `SignFailed` error.

## [1.0.8] - 2024-06-09

### Fixed

- Fixed entry sign callback.

## [1.0.7] - 2024-06-09

### Added

- `SignError` type.

## [1.0.6] - 2024-05-10

### Changed

- Updated `multibase` dependency.

## [1.0.5] - 2024-04-24

### Added

- `pandoc.css` for rendering the README to HTML.

## [1.0.4] - 2024-04-17

### Changed

- Force lockfile refresh whenever locks change.

## [1.0.3] - 2024-04-16

### Changed

- Cleanup.

## [1.0.2] - 2024-04-15

### Added

- Next step in building the set of lock scripts in the correct order.

## [1.0.1] - 2024-04-15

### Added

- Paths to scripts.

## [0.1.15] - 2024-04-10

### Fixed

- Fixed small debug print issue.

## [0.1.14] - 2024-04-07

### Added

- Context key-path to event validation.

## [0.1.13] - 2024-04-07

### Added

- Key-path to no-op operations.

## [0.1.12] - 2024-04-07

### Changed

- Updated `wacc` dependency.

## [0.1.11] - 2024-04-06

### Added

- Updated README information.

## [1.0.0] - 2024-04-05

### Notes

- Initial 1.0 release. Lots of cleanup in preparation for delegation support.

## [0.1.9] - 2024-03-18

### Notes

- First approximation. Initial implementation of programmable cryptographic provenance logs.

[2.3.0]: https://github.com/cryptidtech/provenance-log/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/cryptidtech/provenance-log/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/cryptidtech/provenance-log/releases/tag/v2.1.0
[2.0.0]: https://github.com/cryptidtech/provenance-log/releases/tag/v2.0.0
[1.0.23]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.23
[1.0.22]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.22
[1.0.21]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.21
[1.0.20]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.20
[1.0.19]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.19
[1.0.18]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.18
[1.0.17]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.17
[1.0.16]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.16
[1.0.15]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.15
[1.0.14]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.14
[1.0.13]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.13
[1.0.12]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.12
[1.0.11]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.11
[1.0.10]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.10
[1.0.9]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.9
[1.0.8]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.8
[1.0.7]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.7
[1.0.6]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.6
[1.0.5]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.5
[1.0.4]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.4
[1.0.3]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.3
[1.0.2]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.2
[1.0.1]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.1
[1.0.0]: https://github.com/cryptidtech/provenance-log/releases/tag/v1.0.0
[0.1.15]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.15
[0.1.14]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.14
[0.1.13]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.13
[0.1.12]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.12
[0.1.11]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.11
[0.1.9]: https://github.com/cryptidtech/provenance-log/releases/tag/v0.1.9