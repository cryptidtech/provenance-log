// SPDX-License-Identifier: Apache-2.0
//! Performance benchmarks for bs-provenance-log

use criterion::{criterion_group, criterion_main, Criterion};
use multi_key::EncodedMultikey;
use multi_trait::EncodeIntoBuffer;
use multi_vlad::vlad;
use provenance_log::{entry, log, Entry, Key, Log, Op, Script, SeqNo, Value};
use std::hint::black_box;
use std::path::PathBuf;

/// Minimal valid WASM module: magic (4 B) + version 1 (4 B). Used as the
/// VLAD first-lock script payload for benchmark fixtures.
const TEST_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

fn load_script(path: &Key, file_name: &str) -> Script {
    let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pb.push("../..");
    pb.push("examples");
    pb.push("provenance-log");
    pb.push("wast");
    pb.push(file_name);
    provenance_log::script::Builder::from_code_file(&pb)
        .with_path(path)
        .try_build()
        .unwrap()
}

fn create_test_entry() -> Entry {
    let ephemeral = EncodedMultikey::try_from(
        "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
    )
    .unwrap();

    let vlad = vlad::Builder::default()
        .with_signing_key(&ephemeral)
        .with_message(TEST_WASM)
        .try_build()
        .unwrap();

    let lock = load_script(&Key::default(), "lock.wast");
    let unlock = load_script(&Key::default(), "unlock.wast");

    entry::Builder::default()
        .with_vlad(&vlad)
        .with_seqno(SeqNo::FIRST)
        .add_lock(&lock)
        .with_unlock(&unlock)
        .add_op(&Op::Update(
            "/test".try_into().unwrap(),
            Value::Str("value".into()),
        ))
        .try_build(|_| Ok(std::collections::BTreeMap::new()))
        .unwrap()
}

fn create_test_log() -> Log {
    let entry = create_test_entry();
    let vlad = entry.vlad();
    let first_lock = entry.locks().next().unwrap().clone();
    log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock)
        .append_entry(&entry)
        .try_build()
        .unwrap()
}

fn bench_entry_creation(c: &mut Criterion) {
    c.bench_function("entry creation", |b| {
        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();

        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(TEST_WASM)
            .try_build()
            .unwrap();

        b.iter(|| {
            entry::Builder::default()
                .with_vlad(black_box(&vlad))
                .with_seqno(black_box(SeqNo::FIRST))
                .try_build(|_| Ok(std::collections::BTreeMap::new()))
                .unwrap()
        });
    });
}

fn bench_entry_cid_computation(c: &mut Criterion) {
    let entry = create_test_entry();

    c.bench_function("cid computation (cached)", |b| {
        b.iter(|| black_box(entry.cid()));
    });
}

fn bench_entry_cid_first_computation(c: &mut Criterion) {
    c.bench_function("cid computation (first time)", |b| {
        b.iter_batched(
            create_test_entry,
            |entry| black_box(entry.cid()),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_entry_serialization(c: &mut Criterion) {
    let entry = create_test_entry();

    c.bench_function("entry serialization", |b| {
        b.iter(|| {
            let mut v = Vec::new();
            black_box(&entry).encode_into_buffer(&mut v);
        });
    });
}

fn bench_log_serialization(c: &mut Criterion) {
    let log = create_test_log();

    c.bench_function("log serialization", |b| {
        b.iter(|| {
            let mut v = Vec::new();
            black_box(&log).encode_into_buffer(&mut v);
        });
    });
}

fn bench_lock_script_sorting(c: &mut Criterion) {
    let entry = create_test_entry();
    let lock = load_script(&Key::default(), "lock.wast");
    let locks = vec![lock.clone(), lock.clone(), lock.clone(), lock];

    c.bench_function("lock script sorting", |b| {
        b.iter(|| entry.sort_locks(black_box(&locks)).unwrap());
    });
}

criterion_group!(
    benches,
    bench_entry_creation,
    bench_entry_cid_computation,
    bench_entry_cid_first_computation,
    bench_entry_serialization,
    bench_log_serialization,
    bench_lock_script_sorting
);
criterion_main!(benches);
