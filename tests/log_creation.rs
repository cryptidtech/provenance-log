#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for log creation and basic operations
//!
//! This test suite covers:
//! - Creating logs with single and multiple entries
//! - Forking logs (parent-child relationships)
//! - Log builder validation
//! - Entry linking and sequencing

use multi_key::{EncodedMultikey, Multikey, Views};
use multi_vlad::{vlad, Vlad};
use provenance_log::{entry, log, Entry, Key, Op, Script, SeqNo, Value};
use std::path::PathBuf;

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

/// Helper function to create a test VLAD with unique data based on hint
fn create_test_vlad_with_hint(key: &Multikey, hint: &str) -> Vlad {
    // Minimal WASM module header + hint bytes to produce different VLADs
    let mut wasm_bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm_bytes.extend_from_slice(hint.as_bytes());
    vlad::Builder::default()
        .with_signing_key(key)
        .with_message(&wasm_bytes)
        .try_build()
        .unwrap()
}

/// Helper function to create a test VLAD
fn create_test_vlad(key: &Multikey) -> Vlad {
    create_test_vlad_with_hint(key, "default")
}

/// Helper function to create an update op with a public key
fn get_key_update_op(k: &str, key: &Multikey) -> Op {
    let kcv = key.conv_view().unwrap();
    let pk = kcv.to_public_key().unwrap();
    Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
}

#[test]
fn test_create_empty_log_fails() {
    // A log must have at least one entry
    let vlad = Vlad::default();
    let first_lock = Script::default();

    let result = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .try_build();

    assert!(result.is_err());
}

#[test]
fn test_create_log_with_single_entry() {
    let ephemeral = create_test_key("test key");
    let vlad = create_test_vlad(&ephemeral);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create an entry with operations
    let ephemeral_op = get_key_update_op("/vlad/key", &ephemeral);
    let pubkey_op = get_key_update_op("/keys/primary", &ephemeral);

    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&ephemeral_op)
        .add_op(&pubkey_op)
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ephemeral.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Create the log
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&entry)
        .try_build()
        .unwrap();

    // Verify log structure
    assert_eq!(log.vlad, vlad);
    assert_eq!(log.entries.len(), 1);
    assert_eq!(log.foot, log.head);
    assert_eq!(log.foot, entry.cid());
}

#[test]
fn test_create_log_with_multiple_entries() {
    let key1 = create_test_key("key1");
    let key2 = create_test_key("key2");
    let key3 = create_test_key("key3");
    let vlad = create_test_vlad(&key1);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create first entry
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &key1))
        .add_op(&get_key_update_op("/keys/primary", &key1))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key1.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Create second entry
    let e2 = entry::Builder::from(&e1)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&Op::Delete("/vlad/key".try_into().unwrap()))
        .add_op(&get_key_update_op("/keys/primary", &key2))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key1.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Create third entry
    let e3 = entry::Builder::from(&e2)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/keys/primary", &key3))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key2.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Create log with all entries
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .try_build()
        .unwrap();

    // Verify log structure
    assert_eq!(log.entries.len(), 3);
    assert_eq!(log.foot, e1.cid());
    assert_eq!(log.head, e3.cid());

    // Verify entries are properly linked
    assert_eq!(e2.prev(), e1.cid());
    assert_eq!(e3.prev(), e2.cid());

    // Verify entry iteration
    let entries: Vec<&Entry> = log.iter().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].seqno(), SeqNo::FIRST);
    assert_eq!(entries[1].seqno(), SeqNo::new(1));
    assert_eq!(entries[2].seqno(), SeqNo::new(2));
}

#[test]
fn test_log_append_entry() {
    let key1 = create_test_key("append1");
    let key2 = create_test_key("append2");
    let vlad = create_test_vlad(&key1);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create first entry
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &key1))
        .add_op(&get_key_update_op("/keys/primary", &key1))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key1.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Create log with first entry
    let mut log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .try_build()
        .unwrap();

    assert_eq!(log.entries.len(), 1);
    let original_head = log.head.clone();

    // Create and append second entry
    let e2 = entry::Builder::from(&e1)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/keys/primary", &key2))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key1.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    // Append the entry to the log
    log.try_append(&e2).unwrap();

    assert_eq!(log.entries.len(), 2);
    assert_eq!(log.foot, e1.cid());
    assert_eq!(log.head, e2.cid());
    assert_ne!(log.head, original_head);
}

#[test]
fn test_forking_logs() {
    let parent_key = create_test_key("parent");
    let child_key = create_test_key("child");

    // Create parent VLAD with unique data
    let parent_vlad = create_test_vlad_with_hint(&parent_key, "parent_log");

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create parent log with one entry
    let parent_entry = entry::Builder::default()
        .with_vlad(&parent_vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &parent_key))
        .add_op(&get_key_update_op("/keys/primary", &parent_key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = parent_key.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    let parent_log = log::Builder::new()
        .with_vlad(&parent_vlad)
        .with_first_lock(&first_lock)
        .append_entry(&parent_entry)
        .try_build()
        .unwrap();

    // Create child VLAD (fork reference) with unique data
    let child_vlad = create_test_vlad_with_hint(&child_key, "child_log");

    // Create child log with reference to parent
    let child_entry = entry::Builder::default()
        .with_vlad(&child_vlad)
        .with_seqno(SeqNo::FIRST)
        .with_prev(&parent_entry.cid()) // Link to parent
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &child_key))
        .add_op(&get_key_update_op("/keys/primary", &child_key))
        .add_op(&Op::Update(
            "/parent".try_into().unwrap(),
            Value::Data(parent_vlad.into()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = child_key.sign_view().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            {
                let sig: Vec<u8> = ms.into();
                Ok(std::collections::BTreeMap::from([(
                    "primary".to_string(),
                    sig,
                )]))
            }
        })
        .unwrap();

    let child_log = log::Builder::new()
        .with_vlad(&child_vlad)
        .with_first_lock(&first_lock)
        .append_entry(&child_entry)
        .try_build()
        .unwrap();

    // Verify parent and child are different logs
    assert_ne!(parent_log.vlad, child_log.vlad);
    assert_eq!(parent_log.entries.len(), 1);
    assert_eq!(child_log.entries.len(), 1);

    // Verify child references parent
    assert_eq!(child_entry.prev(), parent_entry.cid());
}

#[test]
fn test_entry_builder_validation() {
    let key = create_test_key("validation");
    let vlad = create_test_vlad(&key);

    // Missing VLAD should fail
    let result = entry::Builder::default()
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()));
    assert!(result.is_err());

    // Missing unlock script should fail
    let result = entry::Builder::default()
        .with_vlad(&vlad)
        .try_build(|_| Ok(std::collections::BTreeMap::new()));
    assert!(result.is_err());

    // Valid entry should succeed
    let result = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()));
    assert!(result.is_ok());
}

#[test]
fn test_log_builder_validation() {
    let vlad = Vlad::default();
    let first_lock = Script::default();

    // Missing VLAD should fail
    let result = log::Builder::new().with_first_lock(&first_lock).try_build();
    assert!(result.is_err());

    // Missing first lock should fail
    let result = log::Builder::new().with_vlad(&vlad).try_build();
    assert!(result.is_err());

    // Missing entries should fail (even with VLAD and first lock)
    let result = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .try_build();
    assert!(result.is_err());
}

#[test]
fn test_entry_sequence_numbers() {
    let key = create_test_key("seqno");
    let vlad = create_test_vlad(&key);
    let script = Script::default();

    // First entry should have seqno 0
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e1.seqno(), SeqNo::FIRST);

    // Next entry should have seqno 1
    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e2.seqno(), SeqNo::new(1));

    // Next entry should have seqno 2
    let e3 = entry::Builder::from(&e2)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e3.seqno(), SeqNo::new(2));
}

#[test]
fn test_entry_context_calculation() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Single operation context
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo/bar".try_into().unwrap(),
            Value::default(),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e1.context().to_string(), "/foo/");

    // Multiple operations with common branch
    let e2 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo/bar".try_into().unwrap(),
            Value::default(),
        ))
        .add_op(&Op::Update(
            "/foo/baz".try_into().unwrap(),
            Value::default(),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e2.context().to_string(), "/foo/");

    // Multiple operations with different branches
    let e3 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo/bar".try_into().unwrap(),
            Value::default(),
        ))
        .add_op(&Op::Update(
            "/baz/qux".try_into().unwrap(),
            Value::default(),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e3.context().to_string(), "/");

    // No operations should default to root
    let e4 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();
    assert_eq!(e4.context().to_string(), "/");
}
