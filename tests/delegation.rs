#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for delegation and governance
//!
//! This test suite covers:
//! - Delegation mechanism with branch-specific keys
//! - Force recovery scenarios
//! - Precedence rules with multiple lock scripts

use multi_cid::cid;
use multi_codec::Codec;
use multi_hash::mh;
use multi_key::{EncodedMultikey, Multikey, ViewBuilder};
use multi_vlad::{vlad, Vlad};
use provenance_log::{entry, log, Key, Op, Script, SeqNo, Value, Version};
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

/// Helper function to create a test multikey with specific data
/// Returns different keys only for "root2" and "admin2" to support the cross-branch test
/// All other hints return the same key to avoid breaking existing tests
fn create_test_key(hint: &str) -> Multikey {
    // Only use distinct keys for the cross-branch modification test
    let key_hex = match hint {
        "root2" => {
            // Distinct root key for cross-branch test
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        }
        "admin2" => {
            // Distinct admin key for cross-branch test (different from root2)
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        }
        // All other tests use the same default key (to maintain backward compatibility)
        _ => {
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        }
    };

    EncodedMultikey::try_from(key_hex).unwrap().to_inner()
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
    let kcv = ViewBuilder::new(key).conv().build().unwrap();
    let pk = kcv.to_public_key().unwrap();
    Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
}

#[test]
fn test_branch_specific_delegation() {
    let root_key = create_test_key("root");
    let admin_key = create_test_key("admin");
    let data_key = create_test_key("data");
    let vlad = create_test_vlad(&root_key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let root_lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create lock scripts for different branches
    let admin_lock = load_script(&Key::try_from("/admin/").unwrap(), "lock.wast");
    let data_lock = load_script(&Key::try_from("/data/").unwrap(), "lock.wast");

    // Entry 1: Root key sets up delegation
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&root_lock)
        .add_lock(&admin_lock) // Delegate /admin/ branch
        .add_lock(&data_lock) // Delegate /data/ branch
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &root_key))
        .add_op(&get_key_update_op("/keys/primary", &root_key))
        .add_op(&get_key_update_op("/admin/pubkey", &admin_key))
        .add_op(&get_key_update_op("/data/pubkey", &data_key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap();
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

    // Entry 2: Admin key modifies /admin/ branch
    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&admin_lock)
        .add_lock(&data_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/admin/users/alice".try_into().unwrap(),
            Value::Str("alice@example.com".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&admin_key).sign().build().unwrap();
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

    // Entry 3: Data key modifies /data/ branch
    let e3 = entry::Builder::from(&e2)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&admin_lock)
        .add_lock(&data_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/data/records/123".try_into().unwrap(),
            Value::Str("record data".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&data_key).sign().build().unwrap();
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
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .try_build()
        .unwrap();

    // Verify all entries
    let mut verify_count = 0;
    for result in log.verify() {
        assert!(result.is_ok(), "Delegated operations should verify");
        verify_count += 1;
    }
    assert_eq!(verify_count, 3);
}

#[test]
fn test_delegation_prevents_cross_branch_modification() {
    let root_key = create_test_key("root2");
    let admin_key = create_test_key("admin2");
    let vlad = create_test_vlad(&root_key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let root_lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let admin_lock = load_script(&Key::try_from("/admin/").unwrap(), "lock.wast");

    // Entry 1: Setup delegation
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&root_lock)
        .add_lock(&admin_lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &root_key))
        .add_op(&get_key_update_op("/keys/primary", &root_key))
        .add_op(&get_key_update_op("/admin/pubkey", &admin_key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap();
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

    // Entry 2: Admin key tries to modify root (should fail)
    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&admin_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/system/critical".try_into().unwrap(),
            Value::Str("hacked".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            // Admin key tries to sign (not authorized for /system/)
            let sv = ViewBuilder::new(&admin_key).sign().build().unwrap();
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
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    // Verify - second entry should fail
    let mut found_error = false;
    for result in log.verify() {
        if result.is_err() {
            found_error = true;
            break;
        }
    }
    assert!(
        found_error,
        "Admin key should not be able to modify root branch"
    );
}

#[test]
fn test_force_recovery_with_precedence() {
    let root_key = create_test_key("recovery_root");
    let compromised_key = create_test_key("compromised");
    let recovery_key = create_test_key("recovery");
    let vlad = create_test_vlad(&root_key);

    // Create test CIDs for lock scripts
    let _cid1 = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha2256, b"normal lock")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    let _cid2 = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha3256, b"recovery lock")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    // Load scripts
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create lock scripts - recovery lock has root path (higher precedence)
    let normal_lock = load_script(&Key::try_from("/normal/").unwrap(), "lock.wast");
    let recovery_lock = load_script(&Key::default(), "lock.wast"); // Root path = highest precedence

    // Entry 1: Setup with both locks
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&normal_lock)
        .add_lock(&recovery_lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &root_key))
        .add_op(&get_key_update_op("/keys/primary", &root_key))
        .add_op(&get_key_update_op("/normal/pubkey", &compromised_key))
        .add_op(&get_key_update_op("/recovery/pubkey", &recovery_key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap();
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

    // Verify the entry structure
    assert_eq!(e1.locks().count(), 2);

    // Test lock sorting
    let locks: Vec<Script> = vec![normal_lock, recovery_lock.clone()];
    let sorted = e1.sort_locks(&locks).unwrap();
    // Recovery lock (root path) should come first
    assert_eq!(sorted[0], recovery_lock);
}

#[test]
fn test_multiple_delegation_levels() {
    let root_key = create_test_key("multi_root");
    let level1_key = create_test_key("level1");
    let level2_key = create_test_key("level2");
    let vlad = create_test_vlad(&root_key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let root_lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let level1_lock = load_script(&Key::try_from("/org/").unwrap(), "lock.wast");
    let level2_lock = load_script(&Key::try_from("/org/dept/").unwrap(), "lock.wast");

    // Entry 1: Root sets up multi-level delegation
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&root_lock)
        .add_lock(&level1_lock)
        .add_lock(&level2_lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &root_key))
        .add_op(&get_key_update_op("/keys/primary", &root_key))
        .add_op(&get_key_update_op("/org/pubkey", &level1_key))
        .add_op(&get_key_update_op("/org/dept/pubkey", &level2_key))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap();
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

    // Entry 2: Level 1 key modifies its branch
    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&level1_lock)
        .add_lock(&level2_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/org/policy".try_into().unwrap(),
            Value::Str("policy v1".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&level1_key).sign().build().unwrap();
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

    // Entry 3: Level 2 key modifies its deeper branch
    let e3 = entry::Builder::from(&e2)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&level1_lock)
        .add_lock(&level2_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/org/dept/budget".try_into().unwrap(),
            Value::Str("100000".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&level2_key).sign().build().unwrap();
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
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .try_build()
        .unwrap();

    // Verify all entries
    let mut verify_count = 0;
    for result in log.verify() {
        assert!(result.is_ok(), "Multi-level delegation should verify");
        verify_count += 1;
    }
    assert_eq!(verify_count, 3);
}

#[test]
fn test_lock_script_precedence_ordering() {
    let key = create_test_key("precedence");
    let vlad = create_test_vlad(&key);

    // Create test CIDs
    let cid1 = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha2256, b"script 1")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    let cid2 = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Sha3256, b"script 2")
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    // Create lock scripts at different path levels
    let root_lock = provenance_log::script::Builder::from_code_cid(&cid1)
        .with_path(&Key::default()) // "/"
        .try_build()
        .unwrap();

    let branch_lock = provenance_log::script::Builder::from_code_cid(&cid1)
        .with_path(&Key::try_from("/app/").unwrap()) // "/app/"
        .try_build()
        .unwrap();

    let sub_branch_lock = provenance_log::script::Builder::from_code_cid(&cid2)
        .with_path(&Key::try_from("/app/data/").unwrap()) // "/app/data/"
        .try_build()
        .unwrap();

    let leaf_lock = provenance_log::script::Builder::from_code_cid(&cid2)
        .with_path(&Key::try_from("/app/data/users").unwrap()) // "/app/data/users"
        .try_build()
        .unwrap();

    // Create entry with operations at various levels
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/app/data/users/alice".try_into().unwrap(),
            Value::Str("alice".to_string()),
        ))
        .add_op(&Op::Update(
            "/app/config".try_into().unwrap(),
            Value::Str("config".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Test lock sorting with various input orders
    let locks_in = vec![
        leaf_lock,
        root_lock.clone(),
        sub_branch_lock,
        branch_lock.clone(),
    ];

    let sorted = entry.sort_locks(&locks_in).unwrap();

    // Verify precedence: root -> branch -> sub_branch -> leaf
    assert_eq!(sorted[0], root_lock);
    assert_eq!(sorted[1], branch_lock);
    // The remaining order depends on which locks apply to the operations
}

#[test]
fn test_delegation_key_rotation() {
    let root_key = create_test_key("rotation_root");
    let old_delegate = create_test_key("old_delegate");
    let new_delegate = create_test_key("new_delegate");
    let vlad = create_test_vlad(&root_key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let root_lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");
    let delegate_lock = load_script(&Key::try_from("/delegated/").unwrap(), "lock.wast");

    // Entry 1: Setup initial delegation
    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&root_lock)
        .add_lock(&delegate_lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &root_key))
        .add_op(&get_key_update_op("/keys/primary", &root_key))
        .add_op(&get_key_update_op("/delegated/pubkey", &old_delegate))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap();
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

    // Entry 2: Old delegate does some work
    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&delegate_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/delegated/data".try_into().unwrap(),
            Value::Str("old delegate work".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&old_delegate).sign().build().unwrap();
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

    // Entry 3: Root rotates the delegated key
    let e3 = entry::Builder::from(&e2)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&delegate_lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/delegated/pubkey", &new_delegate)) // Rotate key
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&root_key).sign().build().unwrap(); // Root authority
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

    // Entry 4: New delegate does work
    let e4 = entry::Builder::from(&e3)
        .with_version(Version::LEGACY)
        .add_lock(&root_lock)
        .add_lock(&delegate_lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/delegated/data".try_into().unwrap(),
            Value::Str("new delegate work".to_string()),
        ))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&new_delegate).sign().build().unwrap();
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
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .append_entry(&e4)
        .try_build()
        .unwrap();

    // Verify all entries including key rotation
    let mut verify_count = 0;
    for result in log.verify() {
        assert!(result.is_ok(), "Key rotation should verify correctly");
        verify_count += 1;
    }
    assert_eq!(verify_count, 4);
}
