[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)](https://cryptid.tech/)
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)](https://github.com/cryptidtech/provenance-specifications/)

[![Build Status](https://github.com/cryptidtech/provenance-log/actions/workflows/rust.yml/badge.svg)](https://github.com/cryptidtech/provenance-log/actions)
[![License](https://img.shields.io/crates/l/provenance-log?style=flat-square)](LICENSE-FSL)
[![Crates.io](https://img.shields.io/crates/v/provenance-log?style=flat-square)](https://crates.io/crates/provenance-log)
[![Documentation](https://docs.rs/provenance-log/badge.svg?style=flat-square)](https://docs.rs/provenance-log)

# provenance-log

Programmable cryptographic provenance logs. A tamper-evident, cryptographically verifiable log system for tracking state changes over time.

Each entry in the log represents a state transition that must be cryptographically authorized by the previous entry's lock scripts. Entries are linked via content-addressed hashes (CIDs). Lock and unlock scripts written in WebAssembly control state transitions. Lipmaa links provide O(log n) random access to historical entries.

## Features

- Cryptographic verification: each entry is linked via content-addressed CIDs.
- Programmable authorization: lock and unlock scripts in WASM via the `wacc` VM.
- Efficient traversal: Lipmaa links provide O(log n) random access.
- Virtual key-value store: entries contain operations that modify a virtual namespace.
- Delegation support: fine-grained authority delegation via hierarchical key paths.
- Forking support: multiple logs can share history via VLAD identifiers.
- DAG-CBOR support: the `dag_cbor` feature enables CBOR serialization with tag 42 for CIDs and VLADs.

## Install

```toml
[dependencies]
provenance-log = "2.0"
```

MSRV: Rust 1.99.

## License

Licensed under the Functional Source License, Version 1.1, Apache 2.0 Future License (`FSL-1.1-Apache-2.0`). See [`LICENSE-FSL`](LICENSE-FSL) for the full text.