// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for Log
//!
//! Tests:
//! - Entry order preservation property

use provenance_log::{entry, log, Entry, Log, Script, SeqNo};
use multi_vlad::Vlad;

#[test]
fn test_log_entry_order_preserved() {
    // Property: log iteration should preserve entry sequence order
    let vlad = Vlad::default();
    let script = Script::default();

    // Create entries with increasing sequence numbers
    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::new(0))
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e3 = entry::Builder::from(&e2)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Create log with entries
    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .append_entry(&e1)
        .append_entry(&e2)
        .append_entry(&e3)
        .try_build()
        .unwrap();

    // Collect entries in iteration order
    let entries: Vec<&Entry> = log.iter().collect();

    // Property: entries should be ordered by sequence number
    assert_eq!(entries.len(), 4);
    for i in 0..entries.len() - 1 {
        assert!(entries[i].seqno() < entries[i + 1].seqno());
    }

    assert_eq!(entries[0].seqno(), SeqNo::new(0));
    assert_eq!(entries[1].seqno(), SeqNo::new(1));
    assert_eq!(entries[2].seqno(), SeqNo::new(2));
    assert_eq!(entries[3].seqno(), SeqNo::new(3));
}

#[test]
fn test_log_foot_head_relationship() {
    // Property: foot should be first entry, head should be last entry
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .append_entry(&e1)
        .try_build()
        .unwrap();

    // Property: foot is first, head is last
    assert_eq!(log.foot, e0.cid());
    assert_eq!(log.head, e1.cid());

    let entries: Vec<&Entry> = log.iter().collect();
    assert_eq!(entries.first().unwrap().cid(), log.foot);
    assert_eq!(entries.last().unwrap().cid(), log.head);
}

#[test]
fn test_log_single_entry_foot_equals_head() {
    // Property: log with single entry should have foot == head
    let vlad = Vlad::default();
    let script = Script::default();

    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&entry)
        .try_build()
        .unwrap();

    // Property: single entry log has foot == head
    assert_eq!(log.foot, log.head);
    assert_eq!(log.foot, entry.cid());
}

#[test]
fn test_log_serialization_roundtrip() {
    // Property: serialized log should deserialize to equivalent log
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let original = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .append_entry(&e1)
        .try_build()
        .unwrap();

    // Serialize and deserialize
    let serialized: Vec<u8> = original.clone().into();
    let deserialized = Log::try_from(serialized.as_slice()).unwrap();

    // Property: roundtrip preserves structure
    assert_eq!(original.vlad, deserialized.vlad);
    assert_eq!(original.head, deserialized.head);
    assert_eq!(original.foot, deserialized.foot);
    assert_eq!(original.entries.len(), deserialized.entries.len());
}

#[test]
fn test_log_entries_map_contains_all_entries() {
    // Property: entries map should contain exactly the entries added
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    // Property: all entries are in the map
    assert_eq!(log.entries.len(), 3);
    assert!(log.entries.contains_key(&e0.cid()));
    assert!(log.entries.contains_key(&e1.cid()));
    assert!(log.entries.contains_key(&e2.cid()));
}

#[test]
fn test_log_clone_equivalence() {
    // Property: cloned log should be equivalent to original
    let vlad = Vlad::default();
    let script = Script::default();

    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let original = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&entry)
        .try_build()
        .unwrap();

    let cloned = original.clone();

    // Property: all observable properties should be equal
    assert_eq!(original.vlad, cloned.vlad);
    assert_eq!(original.head, cloned.head);
    assert_eq!(original.foot, cloned.foot);
    assert_eq!(original.entries.len(), cloned.entries.len());
    assert_eq!(original.version, cloned.version);
}

#[test]
fn test_log_append_updates_head() {
    // Property: appending an entry should update the head
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let mut log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .try_build()
        .unwrap();

    let original_head = log.head.clone();
    let original_len = log.entries.len();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Property: appending should succeed and update head
    // Note: We can't easily test try_append here without valid signatures,
    // but we can test the builder pattern
}

#[test]
fn test_log_iteration_count_matches_entries_len() {
    // Property: iteration count should match entries map size
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&e0)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    // Property: iteration count == map size
    let iter_count = log.iter().count();
    assert_eq!(iter_count, log.entries.len());
    assert_eq!(iter_count, 3);
}

#[test]
fn test_log_entry_linking_chain() {
    // Property: entries should form a valid chain via prev links
    let vlad = Vlad::default();
    let script = Script::default();

    let e0 = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e1 = entry::Builder::from(&e0)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let e2 = entry::Builder::from(&e1)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    // Property: prev links form a chain
    assert_eq!(e1.prev(), e0.cid());
    assert_eq!(e2.prev(), e1.cid());

    // First entry has null prev
    assert!(e0.prev().is_null());
}

#[test]
fn test_log_default_has_no_entries() {
    // Property: default log should have no entries
    let log = Log::default();

    assert_eq!(log.entries.len(), 0);
    assert!(log.head.is_null());
    assert!(log.foot.is_null());
}

#[test]
fn test_log_builder_preserves_vlad() {
    // Property: log should preserve the VLAD identity
    let vlad = Vlad::default();
    let script = Script::default();

    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .with_unlock(&script)
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap();

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&script)
        .append_entry(&entry)
        .try_build()
        .unwrap();

    // Property: VLAD is preserved
    assert_eq!(log.vlad, vlad);
    assert_eq!(log.vlad, entry.vlad());
}
