#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for entry version dispatch and carried-script-kind rules
//!
//! This test suite covers:
//! - Entry and log decoding with versions 1 and 2
//! - Unsupported entry versions at decode
//! - The builder-time script-kind gate on carried scripts
//! - The verify-time script-kind gate with the seqno-0 first-lock check
//! - Log version derivation from entries and the `try_append` recompute

use multi_cid::cid;
use multi_codec::Codec;
use multi_hash::mh;
use multi_key::{EncodedMultikey, Multikey, Views};
use multi_trait::EncodeIntoBuffer;
use multi_vlad::{vlad, Vlad};
use provenance_log::error::{EntryError, LogError};
use provenance_log::{entry, log, Entry, Error, Key, Log, Op, Script, SeqNo, Value, Version};
use std::collections::BTreeMap;
use std::path::PathBuf;
use wacc::ScriptKind;

/// The shortest wat text that detects as a core module
const MODULE_HEADER_CODE: &str = "(module)";

/// The shortest wat text that detects as a WASM component
const COMPONENT_HEADER_CODE: &str = "(component)";

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

/// Helper function to create a test VLAD
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
fn sign_with(key: Multikey) -> impl FnMut(&mut Entry) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    move |entry| {
        let entry_bytes: Vec<u8> = entry.clone().into();
        let sv = key.sign_view().unwrap();
        let ms = sv.sign(&entry_bytes, false, None).unwrap();
        let sig: Vec<u8> = ms.into();
        Ok(BTreeMap::from([("primary".to_string(), sig)]))
    }
}

/// Helper function to build a `Script::Cid` reference
fn cid_script() -> Script {
    let cid = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();
    Script::Cid(Key::default(), cid)
}

/// Re-encodes `entry` with its wire version replaced by `version`
///
/// The entry wire format is varuint(sigil) then varuint(version); the fixture
/// versions all encode as a single byte, so the patch is in-place.
fn patched_version_bytes(entry: &Entry, version: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = entry.clone().into();
    let mut sigil_prefix = Vec::default();
    u64::from(entry::SIGIL).encode_into_buffer(&mut sigil_prefix);
    let version_index = sigil_prefix.len();
    assert!(
        version < 128,
        "the fixture versions must stay single-byte varints"
    );
    bytes[version_index] = u8::try_from(version).unwrap();
    bytes
}

#[test]
fn test_version_constants() {
    assert_eq!(Version::CURRENT.as_u64(), 2);
    assert_eq!(Version::LEGACY.as_u64(), 1);
    assert!(Version::CURRENT.is_supported());
    assert!(Version::LEGACY.is_supported());
    assert!(!Version::new(3).is_supported());
    assert_eq!(entry::ENTRY_VERSION, 2);
    assert_eq!(log::LOG_VERSION, 2);
}

#[test]
fn test_entry_decode_accepts_versions_one_and_two() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);

    // version 1: a legacy entry with undetectable payloads decodes with its
    // carried version intact
    let legacy = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();
    let decoded = Entry::try_from(Vec::from(legacy).as_slice()).unwrap();
    assert_eq!(decoded.version(), Version::LEGACY);

    // version 2: a default-built entry carries the current version
    let current = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral))
        .unwrap();
    let decoded = Entry::try_from(Vec::from(current).as_slice()).unwrap();
    assert_eq!(decoded.version(), Version::CURRENT);
}

#[test]
fn test_entry_decode_rejects_unsupported_version() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let legacy = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral))
        .unwrap();

    let bytes = patched_version_bytes(&legacy, 3);
    let decoded = Entry::try_from(bytes.as_slice());
    assert!(matches!(
        decoded,
        Err(Error::Entry(EntryError::InvalidVersion(_)))
    ));
}

#[test]
fn test_log_version_derives_from_entries_and_decodes() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);

    // a log built from version-1 entries derives version 1 and decodes to it
    let legacy_entry = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();
    let legacy_log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::default())
        .append_entry(&legacy_entry)
        .try_build()
        .unwrap();
    assert_eq!(legacy_log.version, Version::LEGACY);
    let decoded = Log::try_from(Vec::from(legacy_log).as_slice()).unwrap();
    assert_eq!(decoded.version, Version::LEGACY);

    // a log built from version-2 entries derives version 2 and decodes to it
    let current_entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral))
        .unwrap();
    let current_log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::default())
        .append_entry(&current_entry)
        .try_build()
        .unwrap();
    assert_eq!(current_log.version, Version::CURRENT);
    let decoded = Log::try_from(Vec::from(current_log).as_slice()).unwrap();
    assert_eq!(decoded.version, Version::CURRENT);
}

#[test]
fn test_builder_gate_rejects_component_lock_in_legacy_entry() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let result = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .add_lock(&Script::Code(
            Key::default(),
            COMPONENT_HEADER_CODE.to_string(),
        ))
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral));
    assert!(matches!(
        result,
        Err(Error::Entry(EntryError::WrongScriptKind {
            expected: ScriptKind::Module,
            actual: Some(ScriptKind::Component),
        }))
    ));
}

#[test]
fn test_builder_gate_rejects_module_lock_in_current_entry() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let result = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&Script::Code(
            Key::default(),
            MODULE_HEADER_CODE.to_string(),
        ))
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral));
    assert!(matches!(
        result,
        Err(Error::Entry(EntryError::WrongScriptKind {
            expected: ScriptKind::Component,
            actual: Some(ScriptKind::Module),
        }))
    ));
}

#[test]
fn test_builder_gate_rejects_component_unlock_in_legacy_entry() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let result = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_unlock(&Script::Code(
            Key::default(),
            COMPONENT_HEADER_CODE.to_string(),
        ))
        .try_build(sign_with(ephemeral));
    assert!(matches!(
        result,
        Err(Error::Entry(EntryError::WrongScriptKind {
            expected: ScriptKind::Module,
            actual: Some(ScriptKind::Component),
        }))
    ));
}

#[test]
fn test_builder_gate_passes_undetectable_scripts_in_both_versions() {
    // an empty payload and a Cid reference are undetectable: the builder gate
    // passes them either way; they fail later at compile time
    for version in [Version::LEGACY, Version::CURRENT] {
        let key = create_test_key("undetectable");
        let vlad = create_test_vlad(&key);
        let result = entry::Builder::default()
            .with_version(version)
            .with_vlad(&vlad)
            .add_lock(&cid_script())
            .with_unlock(&Script::default())
            .try_build(sign_with(key));
        assert!(result.is_ok());
    }
}

#[test]
fn test_verify_gate_rejects_first_lock_kind_mismatch() {
    // a version-2 genesis carrying component scripts paired with a legacy
    // module first lock rejects at seqno 0, before any script execution
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let genesis = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&Script::Code(
            Key::default(),
            COMPONENT_HEADER_CODE.to_string(),
        ))
        .try_build(sign_with(ephemeral))
        .unwrap();

    let first_lock = load_script(&Key::default(), "first.wast");
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&genesis)
        .try_build()
        .unwrap();

    let results: Vec<_> = log.verify().collect();
    assert!(matches!(
        results.iter().find_map(|r| r.as_ref().err()),
        Some(Error::Log(LogError::ScriptKindMismatch {
            seqno: 0,
            expected: ScriptKind::Component,
            found: Some(ScriptKind::Module),
        }))
    ));
}

#[test]
fn test_verify_gate_rejects_carried_module_scripts_in_a_current_entry() {
    let ephemeral = create_test_key("ephemeral");
    let key2 = create_test_key("primary");
    let vlad = create_test_vlad(&ephemeral);
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // the genesis verifies like the legacy suites: real wast scripts run
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &ephemeral))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();

    // craft a version-2 entry whose carried scripts are still legacy module
    // scripts: built with the legacy version, then version-patched on the wire
    let carrier = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&Op::Delete("/vlad/key".try_into().unwrap()))
        .add_op(&get_key_update_op("/keys/primary", &key2))
        .try_build(sign_with(ephemeral))
        .unwrap();
    let e2 = Entry::try_from(patched_version_bytes(&carrier, 2).as_slice()).unwrap();
    assert_eq!(e2.version(), Version::CURRENT);

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    let results: Vec<_> = log.verify().collect();
    assert!(matches!(
        results.iter().find_map(|r| r.as_ref().err()),
        Some(Error::Log(LogError::ScriptKindMismatch {
            seqno: 1,
            expected: ScriptKind::Component,
            found: Some(ScriptKind::Module),
        }))
    ));
}

#[test]
fn test_builder_gate_enforces_the_versioned_migration_boundary() {
    // chaining from a legacy entry inherits its core-module locks; the
    // version-2 default then rejects those locks, so version migration is
    // explicit
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let lock = load_script(&Key::default(), "lock.wast");
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();

    let inherited = entry::Builder::from(&e1)
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral.clone()));
    assert!(matches!(
        inherited,
        Err(Error::Entry(EntryError::WrongScriptKind {
            expected: ScriptKind::Component,
            actual: Some(ScriptKind::Module),
        }))
    ));

    // with an explicit lock replacement the version-2 entry builds
    let migrated = entry::Builder::from(&e1)
        .with_locks(&[Script::Code(
            Key::default(),
            COMPONENT_HEADER_CODE.to_string(),
        )])
        .with_unlock(&Script::Code(
            Key::default(),
            COMPONENT_HEADER_CODE.to_string(),
        ))
        .try_build(sign_with(ephemeral))
        .unwrap();
    assert_eq!(migrated.version(), Version::CURRENT);

    // the mixed-version log derives its version from the entry versions
    let mixed_log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::default())
        .append_entry(&e1)
        .append_entry(&migrated)
        .try_build()
        .unwrap();
    assert_eq!(mixed_log.version, Version::CURRENT);
}

#[test]
fn test_try_append_recomputes_the_log_version() {
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &ephemeral))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/keys/primary", &ephemeral))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();

    let mut log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .try_build()
        .unwrap();
    assert_eq!(log.version, Version::LEGACY);

    // the appended entry re-verifies the full v1 chain and the recompute
    // keeps the log pinned at the maximum of its entry versions
    log.try_append(&e2).unwrap();
    assert_eq!(log.version, Version::LEGACY);
}

#[test]
fn test_try_append_fails_loudly_on_a_kind_mismatch() {
    // appending a default version-2 entry to a version-1 log fails the
    // verifier loudly: the undetectable empty payload dispatches to the
    // component path and fails at compile time
    let ephemeral = create_test_key("ephemeral");
    let vlad = create_test_vlad(&ephemeral);
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &ephemeral))
        .try_build(sign_with(ephemeral.clone()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_locks(&[])
        .with_unlock(&Script::default())
        .try_build(sign_with(ephemeral))
        .unwrap();
    assert_eq!(e2.version(), Version::CURRENT);

    let mut log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .try_build()
        .unwrap();

    assert!(log.try_append(&e2).is_err());
    // the failed append leaves the log untouched
    assert_eq!(log.head, e1.cid());
    assert_eq!(log.version, Version::LEGACY);
}
