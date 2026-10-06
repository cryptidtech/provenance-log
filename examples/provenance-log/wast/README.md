# Example WAST Scripts

This folder contains example lock and unlock scripts in WASM text format. The
unlock script compiles the signed message and pushes the proof on the stack to
set up for the lock script. The lock script does the standard version,
threshold signature, pubkey signature, and preimage checks.

## Legacy module fixtures

These scripts are core-module fixtures for the retained module script path:
the tests load the WAT text and wacc compiles it on the module path.

The component-based script examples live in `../scripts/`; the `Makefile`
there builds the guest crates for `wasm32-wasip2` and copies the components
into `target/components/`, where `tests/component_scripts.rs` loads them as
fixtures.
