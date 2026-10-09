// SPDX-License-Identifier: Apache-2.0
//! Stored-entry Cid byte compatibility across the multi-hash 1.1 → 2.0 builder migration
//!
//! `Entry::cid()` hashes the encoded entry bytes with Blake3 and caches the
//! result. multi-hash 1.1 built a multihash from a whole byte slice; 2.0
//! streams bytes through `Builder::update`, and for the extendable-output
//! codecs, Blake3 included, it requires an explicit digest length. Stored
//! entries carry Cids produced by the 1.x path with a 32 byte Blake3 digest,
//! and re-deriving those Cids on the 2.0 path must reproduce those bytes.

use multi_trait::EncodeInto;
use provenance_log::Entry;

/// Cid bytes of the deterministic `Entry::default()`
///
/// Captured under the multi-hash 1.1.2 / multi-key 2.1.0 / multi-cid 0.2.0
/// resolver state that computed the original `Entry::cid()`: Cidv1 (`0x01`),
/// `DagCbor` target (`0x71`), Blake3 (`0x1e`), digest length 32 (`0x20`), then
/// the 32 digest bytes. The cached Cid path must keep reproducing these exact
/// bytes so that the Cids of entries stored before the migration still match
/// the entries' content.
const STORED_ENTRY_CID_BYTES: [u8; 36] = [
    0x01, 0x71, 0x1e, 0x20, 0xe0, 0x9d, 0x0c, 0x1a, 0x23, 0x3a, 0x9a, 0x76, 0x8f, 0x1c, 0x20, 0x81,
    0x98, 0x87, 0x24, 0xa4, 0x89, 0x13, 0x40, 0x62, 0xd2, 0x31, 0xf5, 0x18, 0x94, 0x1d, 0xaf, 0x89,
    0x84, 0x02, 0x81, 0x8e,
];

#[test]
fn stored_entry_cid_byte_compatibility() {
    let entry = Entry::default();
    let bytes = entry.cid().encode_into();

    assert_eq!(
        bytes,
        STORED_ENTRY_CID_BYTES,
        "the cached Entry::cid() path must preserve the exact bytes a stored entry's Cid carried before the multi-hash 2.0 migration"
    );
}
