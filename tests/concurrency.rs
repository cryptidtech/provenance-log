#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for concurrency safety
//!
//! This test suite covers:
//! - Concurrent log reads with Arc
//! - Send + Sync trait bounds (compile-time)
//! - Thread-safe data structures

use multi_key::{EncodedMultikey, Multikey, Views};
use multi_trait::Null;
use multi_vlad::{vlad, Vlad};
use provenance_log::{entry, log, Entry, Key, Log, Op, Script, SeqNo, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

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
fn test_entry_is_send() {
    // Compile-time test that Entry implements Send
    fn assert_send<T: Send>() {}
    assert_send::<Entry>();
}

#[test]
fn test_entry_is_sync() {
    // Compile-time test that Entry implements Sync
    fn assert_sync<T: Sync>() {}
    assert_sync::<Entry>();
}

#[test]
fn test_log_is_send() {
    // Compile-time test that Log implements Send
    fn assert_send<T: Send>() {}
    assert_send::<Log>();
}

#[test]
fn test_log_is_sync() {
    // Compile-time test that Log implements Sync
    fn assert_sync<T: Sync>() {}
    assert_sync::<Log>();
}

#[test]
fn test_concurrent_log_reads() {
    let key = create_test_key("concurrent");
    let vlad = create_test_vlad(&key);

    // Load scripts
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    // Create a log with multiple entries
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &key))
        .add_op(&get_key_update_op("/keys/primary", &key))
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

    let e2 = entry::Builder::from(&e1)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/data".try_into().unwrap(),
            Value::Str("test".to_string()),
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

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    // Share log across threads using Arc
    let log = Arc::new(log);
    let mut handles = vec![];

    // Spawn multiple threads that read the log concurrently
    for thread_id in 0..10 {
        let log_clone = Arc::clone(&log);
        let handle = thread::spawn(move || {
            // Read log entries
            let entry_count = log_clone.iter().count();
            assert_eq!(entry_count, 2, "Thread {thread_id} should see 2 entries");

            // Access log fields
            assert!(!log_clone.head.is_null());
            assert!(!log_clone.foot.is_null());
            assert_eq!(log_clone.entries.len(), 2);

            thread_id
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    let mut results = vec![];
    for handle in handles {
        let result = handle.join().unwrap();
        results.push(result);
    }

    // Verify all threads completed successfully
    assert_eq!(results.len(), 10);
}

#[test]
fn test_concurrent_entry_cid_computation() {
    let vlad = Vlad::default();
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/test".try_into().unwrap(),
            Value::Str("data".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Share entry across threads
    let entry = Arc::new(entry);
    let mut handles = vec![];

    // Spawn threads that compute CID concurrently
    for _ in 0..10 {
        let entry_clone = Arc::clone(&entry);
        let handle = thread::spawn(move || entry_clone.cid());
        handles.push(handle);
    }

    // Collect all CIDs
    let mut cids = vec![];
    for handle in handles {
        let cid = handle.join().unwrap();
        cids.push(cid);
    }

    // All CIDs should be identical (OnceCell ensures thread-safe lazy init)
    for cid in &cids[1..] {
        assert_eq!(cids[0], *cid);
    }
}

#[test]
fn test_concurrent_log_iteration() {
    let key = create_test_key("iter_concurrent");
    let vlad = create_test_vlad(&key);

    // Create a log
    let first_lock = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let e1 = entry::Builder::default()
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

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&e1)
        .try_build()
        .unwrap();

    let log = Arc::new(log);
    let mut handles = vec![];

    // Multiple threads iterate over the log
    for thread_id in 0..5 {
        let log_clone = Arc::clone(&log);
        let handle = thread::spawn(move || {
            let mut count = 0;
            for entry in log_clone.iter() {
                assert_eq!(entry.seqno(), SeqNo::FIRST);
                count += 1;
            }
            assert_eq!(count, 1, "Thread {thread_id} should iterate over 1 entry");
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_entry_clone_is_safe() {
    let vlad = Vlad::default();
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Clone entry multiple times
    let entries: Vec<Entry> = (0..10).map(|_| entry.clone()).collect();

    // All clones should be equal
    for cloned in &entries {
        assert_eq!(entry.seqno(), cloned.seqno());
        assert_eq!(entry.cid(), cloned.cid());
    }
}

#[test]
fn test_log_clone_is_safe() {
    let vlad = Vlad::default();
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::default())
        .append_entry(&entry)
        .try_build()
        .unwrap();

    // Clone log multiple times
    let logs: Vec<Log> = (0..10).map(|_| log.clone()).collect();

    // All clones should be equal
    for cloned in &logs {
        assert_eq!(log.head, cloned.head);
        assert_eq!(log.foot, cloned.foot);
        assert_eq!(log.entries.len(), cloned.entries.len());
    }
}

#[test]
fn test_arc_entry_sharing() {
    let vlad = Vlad::default();
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .add_op(&Op::Update(
            "/shared".try_into().unwrap(),
            Value::Str("data".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let entry = Arc::new(entry);
    let mut handles = vec![];

    // Share entry reference across threads
    for _ in 0..5 {
        let entry_ref = Arc::clone(&entry);
        let handle = thread::spawn(move || {
            // Read entry data
            let seqno = entry_ref.seqno();
            let cid = entry_ref.cid();
            let ops: Vec<&Op> = entry_ref.ops().collect();

            assert_eq!(seqno, SeqNo::FIRST);
            assert!(!cid.is_null());
            assert_eq!(ops.len(), 1);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Original entry still accessible
    assert_eq!(entry.seqno(), SeqNo::FIRST);
}

#[test]
fn test_kvp_is_send() {
    // Compile-time test that Kvp implements Send
    fn assert_send<T: Send>() {}
    assert_send::<provenance_log::Kvp>();
}

#[test]
fn test_concurrent_serialization() {
    let vlad = Vlad::default();
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let entry = Arc::new(entry);
    let mut handles = vec![];

    // Multiple threads serialize the same entry
    for _ in 0..5 {
        let entry_clone = Arc::clone(&entry);
        let handle = thread::spawn(move || {
            let serialized: Vec<u8> = (*entry_clone).clone().into();
            serialized
        });
        handles.push(handle);
    }

    // All serializations should be identical
    let mut serializations = vec![];
    for handle in handles {
        let serialized = handle.join().unwrap();
        serializations.push(serialized);
    }

    for serialized in &serializations[1..] {
        assert_eq!(serializations[0], *serialized);
    }
}

#[test]
fn test_key_is_send_sync() {
    // Compile-time test
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Key>();
    assert_sync::<Key>();
}

#[test]
fn test_script_is_send_sync() {
    // Compile-time test
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Script>();
    assert_sync::<Script>();
}

#[test]
fn test_op_is_send_sync() {
    // Compile-time test
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Op>();
    assert_sync::<Op>();
}

#[test]
fn test_value_is_send_sync() {
    // Compile-time test
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Value>();
    assert_sync::<Value>();
}

#[test]
fn test_thread_local_storage_safety() {
    // Test that entries can be stored in thread-local storage
    let vlad = Vlad::default();

    thread_local! {
        static ENTRY: std::cell::RefCell<Option<Entry>> = const { std::cell::RefCell::new(None) };
    }

    let handle = thread::spawn(move || {
        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(SeqNo::FIRST)
            .with_unlock(&Script::default())
            .try_build(|_| Ok(std::collections::BTreeMap::new()))
            .unwrap();

        ENTRY.with(|e| {
            *e.borrow_mut() = Some(entry.clone());
        });

        ENTRY.with(|e| {
            let borrowed = e.borrow();
            assert!(borrowed.is_some());
            borrowed.as_ref().unwrap().seqno()
        })
    });

    let seqno = handle.join().unwrap();
    assert_eq!(seqno, SeqNo::FIRST);
}

#[test]
fn test_btreemap_concurrent_reads() {
    // Test that BTreeMap in Log is safe for concurrent reads
    let vlad = Vlad::default();
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_unlock(&Script::default())
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&Script::default())
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    let log = Arc::new(log);
    let mut handles = vec![];

    // Multiple threads read from the BTreeMap
    for _ in 0..5 {
        let log_clone = Arc::clone(&log);
        let handle = thread::spawn(move || {
            let count = log_clone.entries.len();
            let keys: Vec<_> = log_clone.entries.keys().collect();
            (count, keys.len())
        });
        handles.push(handle);
    }

    for handle in handles {
        let (count, keys_len) = handle.join().unwrap();
        assert_eq!(count, 2);
        assert_eq!(keys_len, 2);
    }
}
