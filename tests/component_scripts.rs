#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for component-script logs, verified end to end
//!
//! These suites exercise the log flow, not the VM internals:
//! - a full version-2 log whose genesis first lock and entry scripts are
//!   guest component fixtures verifies end to end
//! - a mixed-version log with a version-1 module-script genesis and a
//!   version-2 component-script successor verifies under the carried-script
//!   rule; the version-2 entry is locked by the v1-written module lock, and
//!   kind-based execution dispatches each script by its detected kind
//! - corrupt component bytes fail verification with a named error and poison
//!   the iterator
//! - a Vlad built from component first-lock bytes is accepted by the
//!   magic-only check of multi-vlad
//!
//! The guest components live as a standalone workspace under
//! `examples/provenance-log/scripts/`; the `Makefile` there copies the built
//! components into the crate's `target/components/` directory. Like the
//! legacy binary suites, the fixture-based tests skip when the fixtures are
//! missing (run `make -C examples/provenance-log/scripts guests`).

use multi_key::{EncodedMultikey, Multikey, Views};
use multi_trait::{EncodeIntoBuffer, TryDecodeFrom};
use multi_vlad::{vlad, Vlad};
use provenance_log::error::LogError;
use provenance_log::{entry, log, Error, Key, Op, Script, SeqNo, Value, Version};
use std::collections::BTreeMap;
use std::path::PathBuf;
use wacc::error::VmError;
use wacc::ScriptKind;

/// Loads a built guest component fixture; the guests live as a separate
/// workspace under `examples/provenance-log/scripts/` and the `Makefile`
/// there copies the components into the crate's `target/components/`
/// directory.
fn load_component(file_name: &str) -> Option<Vec<u8>> {
    let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pb.push("target/components");
    pb.push(file_name);
    std::fs::read(&pb).ok()
}

/// Helper function to load a WAST script from the examples directory
fn load_script(path: &Key, file_name: &str) -> Script {
    let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pb.push("examples/provenance-log/wast");
    pb.push(file_name);
    provenance_log::script::Builder::from_code_file(&pb)
        .with_path(path)
        .try_build()
        .unwrap()
}

/// Helper function to create a test multikey
fn create_test_key(_hint: &str) -> Multikey {
    EncodedMultikey::try_from(
        "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
    )
    .unwrap()
    .to_inner()
}

/// Helper function to create a test VLAD with a fake core-module message
fn create_test_vlad(key: &Multikey) -> Vlad {
    let wasm_bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    vlad::Builder::default()
        .with_signing_key(key)
        .with_message(&wasm_bytes)
        .try_build()
        .unwrap()
}

/// Helper function to create an update op with a public key
fn get_key_update_op(k: &str, key: &Multikey) -> Op {
    let kcv = key.conv_view().unwrap();
    let pk = kcv.to_public_key().unwrap();
    Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
}

/// Builds a proof-generation closure that signs the entry bytes with `key`
fn sign_with(
    key: Multikey,
) -> impl FnMut(&mut entry::Entry) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    move |entry| {
        let entry_bytes: Vec<u8> = entry.clone().into();
        let sv = key.sign_view().unwrap();
        let ms = sv.sign(&entry_bytes, false, None).unwrap();
        let sig: Vec<u8> = ms.into();
        Ok(BTreeMap::from([("primary".to_string(), sig)]))
    }
}

#[test]
fn test_v2_log_verifies_end_to_end() {
    let Some(first_bytes) = load_component("first.wasm") else {
        eprintln!(
            "Skipping test_v2_log_verifies_end_to_end: first.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };
    let Some(lock_bytes) = load_component("lock.wasm") else {
        eprintln!(
            "Skipping test_v2_log_verifies_end_to_end: lock.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };
    let Some(unlock_bytes) = load_component("unlock.wasm") else {
        eprintln!(
            "Skipping test_v2_log_verifies_end_to_end: unlock.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };

    let ephemeral = create_test_key("ephemeral");
    let key = create_test_key("signing_key");

    // the vlad message is the genesis first-lock component binary itself: the
    // magic-only vlad check accepts the component bytes untouched
    let vlad = vlad::Builder::default()
        .with_signing_key(&ephemeral)
        .with_message(&first_bytes)
        .try_build()
        .unwrap();

    let first_lock = Script::Bin(Key::default(), first_bytes);
    let lock = Script::Bin(Key::default(), lock_bytes);
    let unlock = Script::Bin(Key::default(), unlock_bytes);

    // the genesis entry carries component scripts and defaults to version 2
    let genesis = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &key))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();
    assert_eq!(genesis.version(), Version::CURRENT);

    // the successor entry chains from the genesis and re-signs with the
    // primary key the genesis carried lock governs
    let successor = entry::Builder::from(&genesis)
        .with_unlock(&unlock)
        .try_build(sign_with(key))
        .unwrap();
    assert_eq!(successor.version(), Version::CURRENT);

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&genesis)
        .append_entry(&successor)
        .try_build()
        .unwrap();
    // the log version derives from the entry versions
    assert_eq!(log.version, Version::CURRENT);

    let mut verified = 0;
    for result in log.verify() {
        let (check_count, verified_entry, _) =
            result.expect("the version-2 component log verifies end to end");
        assert_eq!(verified_entry.seqno().as_u64(), verified);
        // the genesis first lock succeeds on its first check; the carried
        // entry lock runs the failing recovery check first, so its primary
        // path succeeds at check count 1
        assert_eq!(check_count, usize::from(verified != 0));
        verified += 1;
    }
    assert_eq!(verified, 2, "both entries must verify");
}

#[test]
fn test_mixed_version_log_verifies() {
    let Some(lock_bytes) = load_component("lock.wasm") else {
        eprintln!(
            "Skipping test_mixed_version_log_verifies: lock.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };
    let Some(unlock_bytes) = load_component("unlock.wasm") else {
        eprintln!(
            "Skipping test_mixed_version_log_verifies: unlock.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };

    let ephemeral = create_test_key("ephemeral");
    let key = create_test_key("signing_key");
    let vlad = create_test_vlad(&ephemeral);

    // the legacy genesis keeps its core-module scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock_wast = load_script(&Key::default(), "lock.wast");
    let unlock_wast = load_script(&Key::default(), "unlock.wast");

    let genesis = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock_wast)
        .with_unlock(&unlock_wast)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &key))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();
    assert_eq!(genesis.version(), Version::LEGACY);

    // the version-2 successor must replace the inherited module scripts with
    // component scripts through an explicit with_locks
    let lock_component = Script::Bin(Key::default(), lock_bytes);
    let unlock_component = Script::Bin(Key::default(), unlock_bytes);
    let successor = entry::Builder::from(&genesis)
        .with_locks(&[lock_component])
        .with_unlock(&unlock_component)
        .try_build(sign_with(key))
        .unwrap();
    assert_eq!(successor.version(), Version::CURRENT);

    // the v2 successor is locked by the v1-written module lock of the
    // genesis: each script dispatches by its detected kind, so the module
    // lock still runs against the component-carrying entry
    assert_eq!(
        ScriptKind::detect(genesis.locks().next().unwrap().as_ref()),
        Some(ScriptKind::Module)
    );
    assert_eq!(
        ScriptKind::detect(successor.unlock().as_ref()),
        Some(ScriptKind::Component)
    );
    assert_eq!(
        ScriptKind::detect(successor.locks().next().unwrap().as_ref()),
        Some(ScriptKind::Component)
    );

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&genesis)
        .append_entry(&successor)
        .try_build()
        .unwrap();
    // the log version derives from the maximum of the entry versions
    assert_eq!(log.version, Version::CURRENT);

    let mut verified = 0;
    for result in log.verify() {
        let (check_count, verified_entry, _) =
            result.expect("the mixed-version log verifies under the carried-script rule");
        assert_eq!(verified_entry.seqno().as_u64(), verified);
        // the module lock of the legacy genesis validates the version-2
        // successor through its primary path at check count 1
        assert_eq!(check_count, usize::from(verified != 0));
        verified += 1;
    }
    assert_eq!(verified, 2, "both entries must verify");
}

#[test]
fn test_corrupt_component_bytes_fail_with_a_named_error() {
    let ephemeral = create_test_key("corrupt");
    let vlad = create_test_vlad(&ephemeral);

    // a header-valid component whose body is structurally corrupt: the
    // version byte keeps it detectable as a component, so the carried gate
    // passes, but compilation rejects the bytes
    let corrupt: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
    ];
    assert_eq!(ScriptKind::detect(&corrupt), Some(ScriptKind::Component));

    let genesis = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::Bin(Key::default(), corrupt))
        .try_build(sign_with(ephemeral))
        .unwrap();

    // the first lock is a detectable component text header: it passes the
    // carried gate and is never executed, because the corrupt unlock fails
    // at compile time first
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::Code(Key::default(), "(component)".to_string()))
        .append_entry(&genesis)
        .try_build()
        .unwrap();

    let results: Vec<_> = log.verify().collect();
    // the failed verification poisons the iterator: one result, then none
    assert_eq!(
        results.len(),
        1,
        "the failed verification must poison the iterator"
    );
    assert!(matches!(
        &results[0],
        Err(Error::Log(LogError::Wacc(wacc::Error::Vm(
            VmError::CompilationError { .. }
        ))))
    ));
}

#[test]
fn test_vlad_accepts_component_first_lock_bytes() {
    let Some(first_bytes) = load_component("first.wasm") else {
        eprintln!(
            "Skipping test_vlad_accepts_component_first_lock_bytes: first.wasm not found (run 'make -C examples/provenance-log/scripts guests')"
        );
        return;
    };
    assert_eq!(
        ScriptKind::detect(&first_bytes),
        Some(ScriptKind::Component)
    );

    let key = create_test_key("vlad");
    // the vlad message is the genesis first-lock component binary: the
    // magic-only check of multi-vlad accepts the component bytes as it does
    // any wasm-prefixed message
    let vlad = vlad::Builder::default()
        .with_signing_key(&key)
        .with_message(&first_bytes)
        .try_build()
        .unwrap();

    // the built vlad round-trips through its encoding unchanged
    let mut encoded = Vec::default();
    vlad.encode_into_buffer(&mut encoded);
    let (decoded, rest) = Vlad::try_decode_from(encoded.as_slice()).unwrap();
    assert_eq!(rest, []);
    assert_eq!(decoded, vlad);
}
