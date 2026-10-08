#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the alleged-Cid confirmation in `Log::verify()`
//!
//! `Log::entries` stores each entry under the Cid that its content hashes to.
//! `Log::verify()` re-derives the Cid from the entry content and must reject
//! any log whose stored key does not match it. The decode paths insert map
//! keys unchecked, so these tests model that input: they forge a map key on
//! an otherwise honest two-entry log and assert the rejection, the iterator
//! poisoning, and the round-trip behavior.

use multi_cid::{cid, Cid};
use multi_codec::Codec;
use multi_hash::mh;
use multi_key::{EncodedMultikey, Multikey, ViewBuilder};
use multi_vlad::{vlad, Vlad};
use provenance_log::error::LogError;
use provenance_log::{entry, log, Entry, Error, Key, Log, Op, Script, SeqNo, Value, Version};
use std::collections::BTreeMap;
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
///
/// The fixed key material is returned for every hint, so the ephemeral key
/// also signs the second entry's proof
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
    let kcv = ViewBuilder::new(key).conv().build().unwrap();
    let pk = kcv.to_public_key().unwrap();
    Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
}

/// A Cid that no entry content in these fixtures hashes to
fn bogus_cid(hint: &[u8]) -> Cid {
    cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::DagCbor)
        .with_hash(
            &mh::Builder::new_from_bytes(Codec::Blake3, hint)
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap()
}

/// An honest two-entry chain
///
/// `e1` publishes the primary public key at `/keys/primary`, and the second
/// entry points at `e1.cid()` and gets signed by that primary key
fn build_chain() -> (Script, Vlad, Entry, Entry) {
    let ephemeral = create_test_key("ephemeral");
    let primary = create_test_key("primary");
    let vlad = create_test_vlad(&ephemeral);
    let first = load_script(&Key::default(), "first.wast");
    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    let e1 = entry::Builder::default()
        .with_version(Version::LEGACY)
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/vlad/key", &ephemeral))
        .add_op(&get_key_update_op("/keys/primary", &primary))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&ephemeral).sign().build().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
        })
        .unwrap();

    // `Builder::from(&e1)` sets seqno 1, prev = `e1.cid()`, and the inherited
    // lock set; the legacy version keeps the core-module script kind
    let e2 = entry::Builder::from(&e1)
        .with_version(Version::LEGACY)
        .with_prev(&e1.cid())
        .with_unlock(&unlock)
        .add_op(&get_key_update_op("/keys/primary", &primary))
        .try_build(|e| {
            let ev: Vec<u8> = e.clone().into();
            let sv = ViewBuilder::new(&primary).sign().build().unwrap();
            let ms = sv.sign(&ev, false, None).unwrap();
            Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
        })
        .unwrap();

    (first, vlad, e1, e2)
}

/// A `Log` assembled directly, bypassing the builder walk, with arbitrary
/// keys for the two entries. `foot` and `head` are metadata the verifier
/// ignores, mirroring a hostile serialized log
fn log_with_keys(first: &Script, vlad: &Vlad, key1: Cid, e1: &Entry, key2: Cid, e2: &Entry) -> Log {
    Log {
        version: Version::CURRENT,
        vlad: vlad.clone(),
        first_lock: first.clone(),
        foot: key1.clone(),
        head: key2.clone(),
        entries: BTreeMap::from([(key1, e1.clone()), (key2, e2.clone())]),
    }
}

/// The genesis entry is keyed under a Cid its content does not hash to. The
/// check must reject it before any script runs, yield exactly one result,
/// and match `LogError::EntryCidMismatch`
#[test]
fn test_verify_rejects_mismatched_entry_key() {
    let (first, vlad, e1, e2) = build_chain();
    let fake = bogus_cid(b"bogus key for the genesis entry");
    let log = log_with_keys(&first, &vlad, fake, &e1, e2.cid(), &e2);

    let results: Vec<_> = log.verify().collect();
    assert_eq!(
        results.len(),
        1,
        "the failed verification must poison the iterator"
    );
    assert!(matches!(
        &results[0],
        Err(Error::Log(LogError::EntryCidMismatch))
    ));
}

/// The second entry is keyed under a Cid its content does not hash to. The
/// first entry must verify, and the mismatch at index 1 must fail and poison
#[test]
fn test_verify_rejects_mismatched_key_on_non_genesis_entry() {
    let (first, vlad, e1, e2) = build_chain();
    let fake = bogus_cid(b"bogus key for the second entry");
    let log = log_with_keys(&first, &vlad, e1.cid(), &e1, fake, &e2);

    let results: Vec<_> = log.verify().collect();
    assert_eq!(
        results.len(),
        2,
        "index 0 verifies, index 1 fails and poisons the iterator"
    );
    assert!(results[0].is_ok());
    assert!(matches!(
        &results[1],
        Err(Error::Log(LogError::EntryCidMismatch))
    ));
}

/// An honest log keys every entry by its content Cid and verifies cleanly
#[test]
fn test_verify_accepts_consistent_keys() {
    let (first, vlad, e1, e2) = build_chain();
    let honest = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();

    // every map key equals the Cid recomputed from the entry content
    for (key, chain_entry) in &honest.entries {
        assert_eq!(key, &chain_entry.cid());
    }

    for result in honest.verify() {
        assert!(
            result.is_ok(),
            "an honest log must verify: {:?}",
            result.err()
        );
    }
}

/// The binary decode path inserts keys unchecked, so the forged key survives
/// an encode-decode round trip and the decoded log fails verification. An
/// honest log round-trips and still verifies
#[test]
fn test_verify_rejects_mismatched_key_after_roundtrip() {
    let (first, vlad, e1, e2) = build_chain();

    let fake = bogus_cid(b"bogus key that survives a round trip");
    let forged = log_with_keys(&first, &vlad, fake, &e1, e2.cid(), &e2);
    let bytes: Vec<u8> = forged.into();
    let decoded = Log::try_from(bytes.as_slice()).unwrap();
    let results: Vec<_> = decoded.verify().collect();
    assert_eq!(
        results.len(),
        1,
        "the failed verification must poison the iterator"
    );
    assert!(matches!(
        &results[0],
        Err(Error::Log(LogError::EntryCidMismatch))
    ));

    let honest = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first)
        .append_entry(&e1)
        .append_entry(&e2)
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = honest.into();
    let decoded = Log::try_from(bytes.as_slice()).unwrap();
    for result in decoded.verify() {
        assert!(
            result.is_ok(),
            "an honest round trip must verify: {:?}",
            result.err()
        );
    }
}
