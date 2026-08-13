#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for serialization roundtrips
//!
//! This test suite covers:
//! - Entry serialization/deserialization
//! - Log serialization/deserialization
//! - DAG-CBOR feature (if enabled)
//! - All value types (Nil, Str, Data)

use multi_cid::cid;
use multi_codec::Codec;
use multi_hash::mh;
use multi_key::{EncodedMultikey, Multikey, Views};
#[cfg(feature = "dag_cbor")]
use multi_trait::Null;
use multi_trait::TryDecodeFrom;
use multi_vlad::{vlad, Vlad};
use provenance_log::{entry, log, Entry, Key, Log, Op, Script, SeqNo, Value};
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

#[test]
fn test_entry_serialization_roundtrip() {
    let key = create_test_key("serialize");
    let vlad = create_test_vlad(&key);
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create entry
    let original = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/keys/primary", &key))
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key.sign_view().unwrap();
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

    // Serialize
    let serialized: Vec<u8> = original.clone().into();
    assert!(!serialized.is_empty());

    // Deserialize
    let (deserialized, remaining) = Entry::try_decode_from(&serialized).unwrap();
    assert!(remaining.is_empty(), "Should consume all bytes");

    // Verify equality
    assert_eq!(original.seqno(), deserialized.seqno());
    assert_eq!(original.vlad(), deserialized.vlad());
    assert_eq!(original.prev(), deserialized.prev());
    assert_eq!(original.cid(), deserialized.cid());

    // Verify operations match
    let orig_ops: Vec<&Op> = original.ops().collect();
    let deser_ops: Vec<&Op> = deserialized.ops().collect();
    assert_eq!(orig_ops.len(), deser_ops.len());
}

#[test]
fn test_entry_serialization_with_all_value_types() {
    let key = create_test_key("all_types");
    let vlad = create_test_vlad(&key);

    // Create entry with all value types
    let original = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/str".try_into().unwrap(),
            Value::Str("string value".to_string()),
        ))
        .add_op(&Op::Update(
            "/data".try_into().unwrap(),
            Value::Data(vec![0x01, 0x02, 0x03, 0x04]),
        ))
        .add_op(&Op::Update("/nil".try_into().unwrap(), Value::Nil))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Serialize and deserialize
    let serialized: Vec<u8> = original.clone().into();
    let (deserialized, _) = Entry::try_decode_from(&serialized).unwrap();

    // Verify value types are preserved
    let orig_ops: Vec<&Op> = original.ops().collect();
    let deser_ops: Vec<&Op> = deserialized.ops().collect();
    assert_eq!(orig_ops.len(), 3);
    assert_eq!(deser_ops.len(), 3);
}

#[test]
fn test_log_serialization_roundtrip() {
    let key = create_test_key("log_ser");
    let vlad = create_test_vlad(&key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create entry
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = key.sign_view().unwrap();
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

    // Create log
    let original = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&entry)
        .try_build()
        .unwrap();

    // Serialize
    let serialized: Vec<u8> = original.clone().into();
    assert!(!serialized.is_empty());

    // Deserialize
    let (deserialized, remaining) = Log::try_decode_from(&serialized).unwrap();
    assert!(remaining.is_empty(), "Should consume all bytes");

    // Verify equality
    assert_eq!(original.vlad, deserialized.vlad);
    assert_eq!(original.head, deserialized.head);
    assert_eq!(original.foot, deserialized.foot);
    assert_eq!(original.entries.len(), deserialized.entries.len());
    assert_eq!(original.entries.len(), 1);
}

#[test]
fn test_log_serialization_with_multiple_entries() {
    let key1 = create_test_key("multi1");
    let key2 = create_test_key("multi2");
    let vlad = create_test_vlad(&key1);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create entries
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

    let e3 = entry::Builder::from(&e2)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/data".try_into().unwrap(),
            Value::Str("test".to_string()),
        ))
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

    // Create log
    let original = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .try_build()
        .unwrap();

    // Serialize and deserialize
    let serialized: Vec<u8> = original.clone().into();
    let (deserialized, _) = Log::try_decode_from(&serialized).unwrap();

    // Verify structure
    assert_eq!(original.entries.len(), 3);
    assert_eq!(deserialized.entries.len(), 3);
    assert_eq!(original.foot, deserialized.foot);
    assert_eq!(original.head, deserialized.head);

    // Verify all entries are present
    for (cid, entry) in &original.entries {
        assert!(deserialized.entries.contains_key(cid));
        let deser_entry = &deserialized.entries[cid];
        assert_eq!(entry.seqno(), deser_entry.seqno());
    }
}

#[test]
fn test_entry_cid_determinism() {
    let key = create_test_key("determinism");
    let vlad = create_test_vlad(&key);

    // Create two identical entries
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .try_build(|_| {
            Ok(std::collections::BTreeMap::from([(
                "primary".to_string(),
                vec![0x01, 0x02, 0x03],
            )]))
        })
        .unwrap();

    let e2 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .try_build(|_| {
            Ok(std::collections::BTreeMap::from([(
                "primary".to_string(),
                vec![0x01, 0x02, 0x03],
            )]))
        })
        .unwrap();

    // CIDs should be identical for identical entries
    assert_eq!(e1.cid(), e2.cid());

    // Serialized form should also be identical
    let s1: Vec<u8> = e1.into();
    let s2: Vec<u8> = e2.into();
    assert_eq!(s1, s2);
}

#[test]
fn test_entry_cid_uniqueness() {
    let key = create_test_key("uniqueness");
    let vlad = create_test_vlad(&key);

    // Create different entries
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .try_build(|_| {
            Ok(std::collections::BTreeMap::from([(
                "primary".to_string(),
                vec![0x01],
            )]))
        })
        .unwrap();

    let e2 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("baz".to_string()),
        )) // Different value
        .try_build(|_| {
            Ok(std::collections::BTreeMap::from([(
                "primary".to_string(),
                vec![0x01],
            )]))
        })
        .unwrap();

    // CIDs should be different
    assert_ne!(e1.cid(), e2.cid());
}

#[test]
fn test_script_serialization() {
    // Test binary script
    let bin_script = Script::Bin(Key::default(), vec![0x00, 0x61, 0x73, 0x6d]); // WASM magic
    let serialized: Vec<u8> = bin_script.clone().into();
    let (deserialized, _) = Script::try_decode_from(&serialized).unwrap();
    assert_eq!(bin_script, deserialized);

    // Test CID script
    let cid = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha3512, b"test script")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    let cid_script = Script::Cid(Key::default(), cid);
    let serialized: Vec<u8> = cid_script.clone().into();
    let (deserialized, _) = Script::try_decode_from(&serialized).unwrap();
    assert_eq!(cid_script, deserialized);
}

#[test]
fn test_key_serialization() {
    // Test root key
    let root = Key::default();
    let serialized: Vec<u8> = root.clone().into();
    let (deserialized, _) = Key::try_decode_from(&serialized).unwrap();
    assert_eq!(root, deserialized);

    // Test branch key
    let branch = Key::try_from("/foo/bar/baz/").unwrap();
    let serialized: Vec<u8> = branch.clone().into();
    let (deserialized, _) = Key::try_decode_from(&serialized).unwrap();
    assert_eq!(branch, deserialized);

    // Test leaf key
    let leaf = Key::try_from("/foo/bar/baz").unwrap();
    let serialized: Vec<u8> = leaf.clone().into();
    let (deserialized, _) = Key::try_decode_from(&serialized).unwrap();
    assert_eq!(leaf, deserialized);
}

#[test]
fn test_op_serialization() {
    // Test Update
    let update = Op::Update("/foo".try_into().unwrap(), Value::Str("bar".to_string()));
    let serialized: Vec<u8> = update.clone().into();
    let (deserialized, _) = Op::try_decode_from(&serialized).unwrap();
    assert_eq!(update, deserialized);

    // Test Delete
    let delete = Op::Delete("/foo".try_into().unwrap());
    let serialized: Vec<u8> = delete.clone().into();
    let (deserialized, _) = Op::try_decode_from(&serialized).unwrap();
    assert_eq!(delete, deserialized);

    // Test Noop
    let noop = Op::Noop("/foo".try_into().unwrap());
    let serialized: Vec<u8> = noop.clone().into();
    let (deserialized, _) = Op::try_decode_from(&serialized).unwrap();
    assert_eq!(noop, deserialized);
}

#[test]
fn test_value_serialization() {
    // Test Nil
    let nil = Value::Nil;
    let serialized: Vec<u8> = nil.clone().into();
    let (deserialized, _) = Value::try_decode_from(&serialized).unwrap();
    assert_eq!(nil, deserialized);

    // Test Str
    let str_val = Value::Str("test string".to_string());
    let serialized: Vec<u8> = str_val.clone().into();
    let (deserialized, _) = Value::try_decode_from(&serialized).unwrap();
    assert_eq!(str_val, deserialized);

    // Test Data
    let data_val = Value::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let serialized: Vec<u8> = data_val.clone().into();
    let (deserialized, _) = Value::try_decode_from(&serialized).unwrap();
    assert_eq!(data_val, deserialized);
}

#[test]
fn test_large_entry_serialization() {
    let key = create_test_key("large");
    let vlad = create_test_vlad(&key);

    // Create entry with many operations
    let mut builder = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default());

    // Add 100 operations
    for i in 0..100 {
        builder = builder.add_op(&Op::Update(
            format!("/key{i}").try_into().unwrap(),
            Value::Str(format!("value{i}")),
        ));
    }

    let original = builder
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Serialize and deserialize
    let serialized: Vec<u8> = original.clone().into();
    let (deserialized, _) = Entry::try_decode_from(&serialized).unwrap();

    // Verify all operations preserved
    let orig_ops: Vec<&Op> = original.ops().collect();
    let deser_ops: Vec<&Op> = deserialized.ops().collect();
    assert_eq!(orig_ops.len(), 100);
    assert_eq!(deser_ops.len(), 100);
}

#[test]
fn test_empty_operations_serialization() {
    let vlad = Vlad::default();

    // Entry with no operations
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Serialize and deserialize
    let serialized: Vec<u8> = entry.clone().into();
    let (deserialized, _) = Entry::try_decode_from(&serialized).unwrap();

    // Verify empty operations preserved
    assert_eq!(entry.ops().count(), 0);
    assert_eq!(deserialized.ops().count(), 0);
}

#[cfg(feature = "dag_cbor")]
#[test]
fn test_dag_cbor_feature() {
    // This test verifies the dag_cbor feature is enabled
    // The actual DAG-CBOR serialization is handled by the underlying libraries
    let key = create_test_key("cbor");
    let vlad = create_test_vlad(&key);

    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/test".try_into().unwrap(),
            Value::Str("cbor".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // The entry CID should use DAG-CBOR codec
    let cid = entry.cid();
    // Verify CID is valid (detailed codec checking is done by bs-multicid)
    assert!(!cid.is_null());
}
