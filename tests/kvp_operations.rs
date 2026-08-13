#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for key-value store operations
//!
//! This test suite covers:
//! - Update operations
//! - Delete operations
//! - Noop operations
//! - Nested branch operations
//! - Key-value state after applying entries

use multi_vlad::Vlad;
use provenance_log::{entry, Key, Kvp, Op, Script, SeqNo, Value};
use wacc::Pairs;

#[test]
fn test_update_operations() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with update operations
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .add_op(&Op::Update(
            "/baz".try_into().unwrap(),
            Value::Str("qux".to_string()),
        ))
        .add_op(&Op::Update(
            "/count".try_into().unwrap(),
            Value::Data(vec![0, 1, 2, 3]),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations to KVP
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Verify state
    assert_eq!(kvp.len(), 3);
    let items: Vec<(&Key, &Value)> = kvp.iter().collect();
    assert_eq!(items.len(), 3);

    // Verify specific values using the wacc::Pairs trait
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/foo") {
        assert_eq!(data.to_string(), "bar");
    } else {
        panic!("Expected Str value for /foo");
    }

    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/baz") {
        assert_eq!(data.to_string(), "qux");
    } else {
        panic!("Expected Str value for /baz");
    }

    if let Some(wacc::Value::Bin { hint: _, data }) = kvp.get("/count") {
        assert_eq!(data.as_ref(), &[0, 1, 2, 3]);
    } else {
        panic!("Expected Bin value for /count");
    }
}

#[test]
fn test_delete_operations() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create first entry with updates
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .add_op(&Op::Update(
            "/baz".try_into().unwrap(),
            Value::Str("qux".to_string()),
        ))
        .add_op(&Op::Update(
            "/keep".try_into().unwrap(),
            Value::Str("me".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply first entry
    let mut kvp = Kvp::default();
    kvp.set_entry(&e1).unwrap();
    kvp.apply_entry_ops(&e1).unwrap();
    assert_eq!(kvp.len(), 3);

    // Create second entry with deletes
    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .add_op(&Op::Delete("/foo".try_into().unwrap()))
        .add_op(&Op::Delete("/baz".try_into().unwrap()))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply second entry
    kvp.set_entry(&e2).unwrap();
    kvp.apply_entry_ops(&e2).unwrap();

    // Verify deletions
    assert_eq!(kvp.len(), 1);
    assert!(kvp.get("/foo").is_none());
    assert!(kvp.get("/baz").is_none());

    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/keep") {
        assert_eq!(data.to_string(), "me");
    } else {
        panic!("Expected /keep to still exist");
    }
}

#[test]
fn test_noop_operations() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with noop operations
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .add_op(&Op::Noop("/bar".try_into().unwrap()))
        .add_op(&Op::Update(
            "/baz".try_into().unwrap(),
            Value::Str("qux".to_string()),
        ))
        .add_op(&Op::Noop("/qux".try_into().unwrap()))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Verify noop doesn't affect state
    assert_eq!(kvp.len(), 2); // Only the two updates
    assert!(kvp.get("/foo").is_some());
    assert!(kvp.get("/baz").is_some());
    assert!(kvp.get("/bar").is_none()); // Noop doesn't create entries
    assert!(kvp.get("/qux").is_none());
}

#[test]
fn test_nested_branch_operations() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with nested operations
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/app/config/host".try_into().unwrap(),
            Value::Str("localhost".to_string()),
        ))
        .add_op(&Op::Update(
            "/app/config/port".try_into().unwrap(),
            Value::Str("8080".to_string()),
        ))
        .add_op(&Op::Update(
            "/app/data/users/alice".try_into().unwrap(),
            Value::Str("alice@example.com".to_string()),
        ))
        .add_op(&Op::Update(
            "/app/data/users/bob".try_into().unwrap(),
            Value::Str("bob@example.com".to_string()),
        ))
        .add_op(&Op::Update(
            "/system/version".try_into().unwrap(),
            Value::Str("1.0.0".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Verify nested structure
    assert_eq!(kvp.len(), 5);

    // Verify /app/config branch
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/app/config/host") {
        assert_eq!(data.to_string(), "localhost");
    } else {
        panic!("Expected host value");
    }

    // Verify /app/data/users branch
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/app/data/users/alice") {
        assert_eq!(data.to_string(), "alice@example.com");
    } else {
        panic!("Expected alice value");
    }

    // Verify /system branch
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/system/version") {
        assert_eq!(data.to_string(), "1.0.0");
    } else {
        panic!("Expected version value");
    }
}

#[test]
fn test_update_overwrites_existing_value() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create first entry
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/counter".try_into().unwrap(),
            Value::Str("1".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let mut kvp = Kvp::default();
    kvp.set_entry(&e1).unwrap();
    kvp.apply_entry_ops(&e1).unwrap();

    // Verify initial value
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/counter") {
        assert_eq!(data.to_string(), "1");
    } else {
        panic!("Expected initial counter value");
    }

    // Create second entry that updates the value
    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/counter".try_into().unwrap(),
            Value::Str("2".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    kvp.set_entry(&e2).unwrap();
    kvp.apply_entry_ops(&e2).unwrap();

    // Verify updated value
    assert_eq!(kvp.len(), 1); // Still only one entry
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/counter") {
        assert_eq!(data.to_string(), "2");
    } else {
        panic!("Expected updated counter value");
    }
}

#[test]
fn test_kvp_undo_functionality() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create first entry
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let mut kvp = Kvp::default();
    assert_eq!(kvp.undo_len(), 0);

    // Apply first entry
    kvp.set_entry(&e1).unwrap();
    kvp.apply_entry_ops(&e1).unwrap();
    assert_eq!(kvp.len(), 1);
    assert_eq!(kvp.undo_len(), 1);

    // Create second entry
    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/baz".try_into().unwrap(),
            Value::Str("qux".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply second entry
    kvp.set_entry(&e2).unwrap();
    kvp.apply_entry_ops(&e2).unwrap();
    assert_eq!(kvp.len(), 2);
    assert_eq!(kvp.undo_len(), 2);

    // Undo second entry
    let seqno = kvp.undo_entry().unwrap();
    assert_eq!(seqno, Some(SeqNo::FIRST));
    assert_eq!(kvp.len(), 1);
    assert_eq!(kvp.undo_len(), 1);
    assert!(kvp.get("/foo").is_some());
    assert!(kvp.get("/baz").is_none());

    // Undo first entry
    let seqno = kvp.undo_entry().unwrap();
    assert_eq!(seqno, None);
    assert_eq!(kvp.len(), 0);
    assert_eq!(kvp.undo_len(), 0);
}

#[test]
fn test_multiple_operations_on_same_key() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with multiple operations on same key
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/counter".try_into().unwrap(),
            Value::Str("1".to_string()),
        ))
        .add_op(&Op::Update(
            "/counter".try_into().unwrap(),
            Value::Str("2".to_string()),
        ))
        .add_op(&Op::Update(
            "/counter".try_into().unwrap(),
            Value::Str("3".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Last write wins
    assert_eq!(kvp.len(), 1);
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/counter") {
        assert_eq!(data.to_string(), "3");
    } else {
        panic!("Expected final counter value");
    }
}

#[test]
fn test_nil_value_handling() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with Nil value
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/foo".try_into().unwrap(),
            Value::Str("bar".to_string()),
        ))
        .add_op(&Op::Update("/nil_key".try_into().unwrap(), Value::Nil))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Verify Nil value is stored
    assert_eq!(kvp.len(), 2);
    assert!(kvp.get("/foo").is_some());

    // Nil values are converted to empty Bin when retrieved via wacc::Pairs
    if let Some(wacc::Value::Bin { hint: _, data }) = kvp.get("/nil_key") {
        assert_eq!(data.len(), 0);
    } else {
        panic!("Expected Nil value to be converted to empty Bin");
    }
}

#[test]
fn test_data_value_types() {
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entry with different data types
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/string".try_into().unwrap(),
            Value::Str("text data".to_string()),
        ))
        .add_op(&Op::Update(
            "/binary".try_into().unwrap(),
            Value::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ))
        .add_op(&Op::Update(
            "/empty_data".try_into().unwrap(),
            Value::Data(vec![]),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Apply operations
    let mut kvp = Kvp::default();
    kvp.set_entry(&entry).unwrap();
    kvp.apply_entry_ops(&entry).unwrap();

    // Verify different value types
    assert_eq!(kvp.len(), 3);

    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/string") {
        assert_eq!(data.to_string(), "text data");
    } else {
        panic!("Expected string value");
    }

    if let Some(wacc::Value::Bin { hint: _, data }) = kvp.get("/binary") {
        assert_eq!(data.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    } else {
        panic!("Expected binary value");
    }

    if let Some(wacc::Value::Bin { hint: _, data }) = kvp.get("/empty_data") {
        assert_eq!(data.len(), 0);
    } else {
        panic!("Expected empty data value");
    }
}

#[test]
fn test_kvp_state_progression() {
    let vlad = Vlad::default();
    let script = Script::default();

    let mut kvp = Kvp::default();

    // Entry 1: Initialize some values
    let e1 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/a".try_into().unwrap(),
            Value::Str("1".to_string()),
        ))
        .add_op(&Op::Update(
            "/b".try_into().unwrap(),
            Value::Str("2".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    kvp.set_entry(&e1).unwrap();
    kvp.apply_entry_ops(&e1).unwrap();
    assert_eq!(kvp.len(), 2);

    // Entry 2: Update one, delete one, add one
    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/a".try_into().unwrap(),
            Value::Str("updated".to_string()),
        ))
        .add_op(&Op::Delete("/b".try_into().unwrap()))
        .add_op(&Op::Update(
            "/c".try_into().unwrap(),
            Value::Str("3".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    kvp.set_entry(&e2).unwrap();
    kvp.apply_entry_ops(&e2).unwrap();
    assert_eq!(kvp.len(), 2); // a and c, b deleted

    // Entry 3: Add more values
    let e3 = entry::Builder::from(&e2)
        .with_unlock(&script)
        .add_op(&Op::Update(
            "/d".try_into().unwrap(),
            Value::Str("4".to_string()),
        ))
        .add_op(&Op::Update(
            "/e".try_into().unwrap(),
            Value::Str("5".to_string()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    kvp.set_entry(&e3).unwrap();
    kvp.apply_entry_ops(&e3).unwrap();
    assert_eq!(kvp.len(), 4); // a, c, d, e

    // Verify final state
    if let Some(wacc::Value::Str { hint: _, data }) = kvp.get("/a") {
        assert_eq!(data.to_string(), "updated");
    } else {
        panic!("Expected /a to be updated");
    }
    assert!(kvp.get("/b").is_none());
    assert!(kvp.get("/c").is_some());
    assert!(kvp.get("/d").is_some());
    assert!(kvp.get("/e").is_some());
}
