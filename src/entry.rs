// SPDX-License-Identifier: FSL-1.1
use crate::{error::EntryError, Error, Key, Op, Script, SeqNo, Value, Version};
use core::fmt;
use multi_base::Base;
use multi_cid::{cid, Cid, EncodedCid};
use multi_codec::Codec;
use multi_hash::mh;
use multi_trait::{EncodeInto, EncodeIntoBuffer, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use multi_vlad::Vlad;
use once_cell::sync::OnceCell;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    convert::From,
};
use wacc::ScriptKind;

/// the multicodec sigil for a provenance entry
pub const SIGIL: Codec = Codec::ProvenanceLogEntry;

/// the current version of provenance entries this supports
pub const ENTRY_VERSION: u64 = 2;

/// the list of keys for the fields in an entry
///
/// Note: individual proofs are accessed via dynamic `/proofs/<name>` paths,
/// not through this static list.
pub const ENTRY_FIELDS: &[&str] = &[
    "/entry/",
    "/entry/version",
    "/entry/vlad",
    "/entry/prev",
    "/entry/lipmaa",
    "/entry/seqno",
    "/entry/ops",
    "/entry/unlock",
];

/// the script kind that an entry version demands for the scripts it carries:
/// version 1 demands core-module scripts and version 2 demands WASM components
pub(crate) const fn required_script_kind(version: Version) -> ScriptKind {
    if version.as_u64() >= 2 {
        ScriptKind::Component
    } else {
        ScriptKind::Module
    }
}

/// Returns the `(expected, Some(actual))` kind pair for the first carried
/// script whose detected kind contradicts the kind the entry's version demands.
///
/// An entry's unlock script and its own lock scripts must carry the script
/// kind that its version demands. Undetectable payloads (empty payloads,
/// `Script::Cid`) pass, keeping their compile-time failure behavior; the
/// detected kind of a `Script::Cid` reference resolves at execution time.
pub(crate) fn carried_script_violation(
    version: Version,
    script: &Script,
) -> Option<(ScriptKind, Option<ScriptKind>)> {
    let required = required_script_kind(version);
    match ScriptKind::detect(script.as_ref()) {
        Some(actual) if actual != required => Some((required, Some(actual))),
        _ => None,
    }
}

/// a base encoded provenance entry
pub type EncodedEntry = BaseEncoded<Entry>;

/// An Entry represents a single state change in a provenance log
///
/// Each entry contains:
/// - **Operations** (`ops`): State mutations (create, update, delete) on the virtual key-value namespace
/// - **Lock Scripts** (`locks`): WebAssembly scripts that authorize future entries
/// - **Unlock Script** (`unlock`): A WebAssembly script that proves authorization from the previous entry
/// - **Proof** (`proof`): Cryptographic proof data (signatures, ZK proofs, hash preimages) used by scripts
/// - **Links**: Content-addressed references to previous entries and Lipmaa back-links
///
/// # Verification Process
///
/// When an entry is verified:
/// 1. The unlock script executes, setting up stack state and proving authorization
/// 2. The previous entry's lock scripts execute, checking the unlock script's proof
/// 3. If verification succeeds, the entry's operations are applied to the key-value store
/// 4. The entry's lock scripts become the authorization for the next entry
///
/// # Thread Safety
///
/// `Entry` is `Send + Sync`. The internal `cached_cid` field uses `OnceCell` for thread-safe
/// lazy initialization of the computed CID.
///
/// # Builder Pattern
///
/// Entries should be constructed using the [`Builder`] pattern, which ensures all required
/// fields are present and handles proof generation:
///
/// ```rust,no_run
/// use provenance_log::{Entry, entry, SeqNo, Script, Op, Key, Value};
/// use multi_vlad::Vlad;
///
/// let vlad = Vlad::default();
/// let entry = entry::Builder::default()
///     .with_vlad(&vlad)
///     .with_seqno(SeqNo::FIRST)
///     .with_unlock(&Script::default())
///     .add_op(&Op::Update(
///         Key::try_from("/data").unwrap(),
///         Value::Str("value".into())
///     ))
///     .try_build(|entry| {
///         // Generate named proofs (signatures, etc.) from the entry
///         Ok(std::collections::BTreeMap::new())
///     })
///     .unwrap();
/// ```
///
/// # Examples
///
/// Accessing entry data:
///
/// ```rust,no_run
/// # use provenance_log::{Entry, SeqNo};
/// # let entry = Entry::default();
/// // Get the sequence number
/// let seqno: SeqNo = entry.seqno();
///
/// // Get the CID of this entry
/// let cid = entry.cid();
///
/// // Iterate over operations
/// for op in entry.ops() {
///     println!("Operation: {:?}", op);
/// }
///
/// // Get the entry's branch context (longest common key prefix)
/// let context = entry.context();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Entry {
    /// the entry version
    pub(crate) version: Version,
    /// long lived address for this provenance log
    pub(crate) vlad: Vlad,
    /// link to the previous entry
    pub(crate) prev: Cid,
    /// lipmaa link provides O(log n) traversal between entries
    pub(crate) lipmaa: Cid,
    /// sequence numbering of entries
    pub(crate) seqno: SeqNo,
    /// operations on the namespace in this entry
    pub(crate) ops: Vec<Op>,
    /// the lock scripts associated with keys
    pub(crate) locks: Vec<Script>,
    /// the script that unlocks this entry, must include all fields except itself
    pub(crate) unlock: Script,
    /// named proofs that this entry is valid. each proof is a named cryptographic
    /// proof (digital signature, zkp, hash preimage, etc.) referenced by the
    /// unlock script and required by the lock script in the previous Entry.
    /// this data is generated using the Entry Builder by passing a closure to
    /// the `try_build` function that gets called with the complete serialized
    /// Entry to generate this data.
    pub(crate) proofs: BTreeMap<String, Vec<u8>>,
    /// Cached CID to avoid recomputation (not serialized)
    pub(crate) cached_cid: OnceCell<Cid>,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seqno.cmp(&other.seqno)
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CodecInfo for Entry {
    /// Return that we are a ProvenanceEntry object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the same
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Entry {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl wacc::Pairs for Entry {
    fn get(&self, key: &str) -> Option<wacc::Value> {
        let key = match Key::try_from(key) {
            Ok(key) => key,
            Err(_) => return None,
        };
        match self.get_value(&key) {
            Some(value) => match value {
                Value::Data(data) => Some(wacc::Value::Bin {
                    hint: key.to_string(),
                    data: data.into(),
                }),
                Value::Str(s) => Some(wacc::Value::Str {
                    hint: key.to_string(),
                    data: s.into(),
                }),
                Value::Nil => None,
            },
            None => None,
        }
    }

    fn put(&mut self, _key: &str, _value: &wacc::Value) -> Option<wacc::Value> {
        None
    }
}

impl From<Entry> for Vec<u8> {
    fn from(val: Entry) -> Self {
        let mut v = Vec::default();
        val.encode_into_buffer(&mut v);
        v
    }
}

impl EncodeIntoBuffer for Entry {
    fn encode_into_buffer(&self, v: &mut Vec<u8>) {
        // add in the entry sigil
        u64::from(SIGIL).encode_into_buffer(v);
        // add in the version
        Varuint(self.version.as_u64()).encode_into_buffer(v);
        // add in the vlad
        self.vlad.encode_into_buffer(v);
        // add in the prev link
        self.prev.encode_into_buffer(v);
        // add in the lipmaa link
        self.lipmaa.encode_into_buffer(v);
        // add in the seqno
        Varuint(self.seqno.as_u64()).encode_into_buffer(v);
        // add in the number of ops
        Varuint(self.ops.len()).encode_into_buffer(v);
        // add in the ops
        self.ops.iter().for_each(|op| op.encode_into_buffer(v));
        // first add the number of keys
        Varuint(self.locks.len()).encode_into_buffer(v);
        // add in the locks
        self.locks
            .iter()
            .for_each(|script| script.encode_into_buffer(v));
        // add in the unlock script
        self.unlock.encode_into_buffer(v);
        // add in the proofs map
        Varuint(self.proofs.len()).encode_into_buffer(v);
        for (name, sig_bytes) in &self.proofs {
            name.len().encode_into_buffer(v);
            v.extend_from_slice(name.as_bytes());
            sig_bytes.len().encode_into_buffer(v);
            v.extend_from_slice(sig_bytes);
        }
    }
}

impl EncodeInto for Entry {
    fn encode_into(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode_into_buffer(&mut buffer);
        buffer
    }
}

impl<'a> TryFrom<&'a [u8]> for Entry {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (pe, _) = Self::try_decode_from(bytes)?;
        Ok(pe)
    }
}

impl<'a> TryDecodeFrom<'a> for Entry {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(EntryError::MissingSigil.into());
        }
        // decode the version
        let (version, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let version = Version::new(version.to_inner());
        if !version.is_supported() {
            return Err(EntryError::InvalidVersion(1).into());
        }
        // decode the vlad
        let (vlad, ptr) = Vlad::try_decode_from(ptr)?;
        // decode the prev cid
        let (prev, ptr) = Cid::try_decode_from(ptr)?;
        // decode the lipmaa cid
        let (lipmaa, ptr) = Cid::try_decode_from(ptr)?;
        // decode the seqno
        let (seqno, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let seqno = SeqNo::new(seqno.to_inner());
        // decode the number of ops
        let (num_ops, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        if *num_ops > crate::limits::MAX_OPS_PER_ENTRY {
            return Err(EntryError::TooManyOps(*num_ops, crate::limits::MAX_OPS_PER_ENTRY).into());
        }
        // decode the ops
        let (ops, ptr) = if *num_ops == 0 {
            (Vec::default(), ptr)
        } else {
            let mut ops = Vec::with_capacity(*num_ops);
            let mut p = ptr;
            for _ in 0..*num_ops {
                let (op, ptr) = Op::try_decode_from(p)?;
                ops.push(op);
                p = ptr;
            }
            (ops, p)
        };
        // decode the number of lock scripts
        let (num_locks, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        if *num_locks > crate::limits::MAX_LOCKS_PER_ENTRY {
            return Err(
                EntryError::TooManyLocks(*num_locks, crate::limits::MAX_LOCKS_PER_ENTRY).into(),
            );
        }
        // decode the ops
        let (locks, ptr) = if *num_locks == 0 {
            (Vec::default(), ptr)
        } else {
            let mut locks = Vec::with_capacity(*num_locks);
            let mut p = ptr;
            for _ in 0..*num_locks {
                let (lock, ptr) = Script::try_decode_from(p)?;
                locks.push(lock);
                p = ptr;
            }
            (locks, p)
        };
        // decode the unlock script
        let (unlock, ptr) = Script::try_decode_from(ptr)?;
        // decode the proofs map
        let (num_proofs, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        if *num_proofs > crate::limits::MAX_PROOFS_PER_ENTRY {
            return Err(EntryError::TooManyProofs(
                *num_proofs,
                crate::limits::MAX_PROOFS_PER_ENTRY,
            )
            .into());
        }
        let (proofs, ptr) = {
            let mut proofs = BTreeMap::new();
            let mut p = ptr;
            for _ in 0..*num_proofs {
                let (name_bytes, ptr) = Varbytes::try_decode_from(p)?;
                let name = String::from_utf8(name_bytes.to_inner())?;
                if name.is_empty() {
                    return Err(EntryError::InvalidProofName.into());
                }
                let (proof_bytes, ptr) = Varbytes::try_decode_from(ptr)?;
                let proof = proof_bytes.to_inner();
                if proof.len() > crate::limits::MAX_PROOF_SIZE {
                    return Err(EntryError::ProofTooLarge(
                        proof.len(),
                        crate::limits::MAX_PROOF_SIZE,
                    )
                    .into());
                }
                proofs.insert(name, proof);
                p = ptr;
            }
            (proofs, p)
        };

        Ok((
            Self {
                version,
                vlad,
                prev,
                lipmaa,
                seqno,
                ops,
                locks,
                unlock,
                proofs,
                cached_cid: OnceCell::new(),
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - #{}\n\t{}\n\t{}",
            SIGIL,
            self.seqno,
            EncodedCid::new(Base::Base32Lower, self.cid()),
            EncodedCid::new(Base::Base32Lower, self.prev())
        )
    }
}

impl Default for Entry {
    fn default() -> Self {
        Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(SeqNo::FIRST)
            .with_unlock(&Script::default())
            .try_build(|_| Ok(BTreeMap::new()))
            .expect("hardcoded default entry components are valid")
    }
}

struct Iter<'a> {
    iter: std::slice::Iter<'static, &'static str>,
    entry: &'a Entry,
}

impl Iterator for Iter<'_> {
    type Item = (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(k) => {
                let key = match Key::try_from(*k) {
                    Ok(key) => key,
                    Err(_) => return None,
                };
                self.entry.get_value(&key).map(|value| (key, value))
            }
            None => None,
        }
    }
}

impl Entry {
    /// get an iterator over the keys and values
    pub fn iter(&self) -> impl Iterator<Item = (Key, Value)> + '_ {
        Iter {
            iter: ENTRY_FIELDS.iter(),
            entry: self,
        }
    }

    /// get the Entry's values by Key
    pub fn get_value(&self, key: &Key) -> Option<Value> {
        match key.as_str() {
            "/entry/" => {
                let mut e = self.clone();
                e.proofs = BTreeMap::new();
                Some(Value::Data(e.into()))
            }
            "/entry/version" => Some(Value::Data(Varuint(self.version.as_u64()).into())),
            "/entry/vlad" => Some(Value::Data(self.vlad.clone().into())),
            "/entry/prev" => Some(Value::Data(self.prev.clone().into())),
            "/entry/lipmaa" => Some(Value::Data(self.lipmaa.clone().into())),
            "/entry/seqno" => Some(Value::Data(Varuint(self.seqno.as_u64()).into())),
            "/entry/ops" => {
                let mut v = Vec::new();
                v.append(&mut Varuint(self.ops.len()).into());
                self.ops
                    .iter()
                    .for_each(|op| v.append(&mut op.clone().into()));
                Some(Value::Data(v))
            }
            // Deferred: make this accessible via an iterator
            //"/entry/locks" => Some(Value::Data(self.locks.clone().into())),
            "/entry/unlock" => Some(Value::Data(self.unlock.clone().into())),
            key if key.starts_with("/proofs/") => {
                let name = &key["/proofs/".len()..];
                self.proofs.get(name).map(|v| Value::Data(v.clone()))
            }
            _ => None,
        }
    }

    /// Get the cid of the previous entry if there is one
    pub fn prev(&self) -> Cid {
        self.prev.clone()
    }

    /// Get the version of the entry
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get the sequence number of the entry
    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    /// Get the vlad for the whole p.log
    pub fn vlad(&self) -> Vlad {
        self.vlad.clone()
    }

    /// get an iterator over the operations in the entry
    pub fn ops(&self) -> impl Iterator<Item = &Op> {
        self.ops.iter()
    }

    /// get an iterator over the lock scripts
    pub fn locks(&self) -> impl Iterator<Item = &Script> {
        self.locks.iter()
    }

    /// get the unlock script that proves who authored this entry
    pub fn unlock(&self) -> &Script {
        &self.unlock
    }

    /// get the cid of this entry
    pub fn cid(&self) -> Cid {
        self.cached_cid
            .get_or_init(|| {
                let mut v = Vec::new();
                self.encode_into_buffer(&mut v);
                let mut hash_builder = mh::Builder::new(Codec::Blake3)
                    .expect("Blake3 is a hashing codec, a builder for it should always be created");
                hash_builder.update(v.as_slice());
                // Blake3 is an extendable-output codec in multi-hash 2.0 and requires an
                // explicit digest length. Every stored entry hashed Blake3 to 32 bytes
                // under multi-hash 1.1, so pinning 32 keeps the Cid bytes of stored
                // entries byte-for-byte stable across the builder shape change.
                hash_builder.output_len(32);
                cid::Builder::new(Codec::Cidv1)
                    .with_target_codec(Codec::DagCbor)
                    .with_hash(
                        &hash_builder
                            .try_build()
                            .expect("a Blake3 multihash with a 32 byte digest should always build"),
                    )
                    .try_build()
                    .expect("CID building should never fail with valid hash and codec")
            })
            .clone()
    }

    /// get the longest common branch context from the ops
    pub fn context(&self) -> Key {
        if self.ops.is_empty() {
            Key::default()
        } else {
            // get the first branch - safe because we checked is_empty() above
            let mut ctx = self
                .ops
                .first()
                .expect("ops vector should not be empty after is_empty() check")
                .clone()
                .path()
                .branch();

            // got through the rest looking for the shortest one
            for k in self.ops.iter() {
                ctx = k.path().branch().longest_common_branch(&ctx);
            }
            ctx
        }
    }

    /// go through the lock script from the previous entry and sort them in order of execution for
    /// validating this Entry. This goes through the mutation operations in this Event, looking at
    /// at the path for each op and building the valid set of lock scripts that govern all of teh
    /// branches and leaves that are modified in the set of mutation operations.
    pub fn sort_locks(&self, locks: &[Script]) -> Result<Vec<Script>, Error> {
        let locks_in = locks.to_owned();
        let mut locks_set: HashSet<Script> = HashSet::new();

        let mut ops = match self.ops.len() {
            0 => vec![Op::Noop(Key::try_from("/")?)],
            _ => self.ops.clone(),
        };

        if locks_in != self.locks {
            ops.push(Op::Noop(Key::try_from("/")?));
        }

        // Build set of applicable locks (O(ops × locks) instead of O(ops × locks × tmp))
        for op in &ops {
            for lock in &locks_in {
                if lock.path().parent_of(&op.path()) {
                    locks_set.insert(lock.clone());
                }
            }
        }

        // Preserve original order while filtering
        let mut locks_out: Vec<Script> = locks_in
            .into_iter()
            .filter(|lock| locks_set.contains(lock))
            .collect();

        locks_out.sort();
        Ok(locks_out)
    }
}

/// Builder for Entry objects
///
/// The `Builder` pattern ensures all required fields are present before constructing an `Entry`.
/// It also handles the proof generation process, allowing you to sign or otherwise prove the
/// entry's contents.
///
/// # Required Fields
///
/// - **vlad**: The log's VLAD identifier (set via `with_vlad`)
/// - **unlock**: The unlock script (set via `with_unlock`)
/// - **seqno**: Sequence number (optional, defaults to 0)
///
/// # Proof Generation
///
/// The `try_build` method takes a closure that receives a mutable reference to the entry
/// (with all fields except `proof` populated) and must return a `Vec<u8>` containing the
/// proof data:
///
/// ```rust,no_run
/// # use provenance_log::{entry, SeqNo, Script};
/// # use multi_vlad::Vlad;
/// # use multi_key::Multikey;
/// let vlad = Vlad::default();
/// let signing_key = Multikey::default(); // Your signing key
///
/// let entry = entry::Builder::default()
///     .with_vlad(&vlad)
///     .with_seqno(SeqNo::FIRST)
///     .with_unlock(&Script::default())
///     .try_build(|entry| {
///         // Serialize the entry
///         let entry_bytes: Vec<u8> = entry.clone().into();
///
///         // Sign it and return named proofs
///         // let signature = signing_key.sign(&entry_bytes)?;
///         Ok(std::collections::BTreeMap::new()) // Return named proofs
///     })
///     .unwrap();
/// ```
///
/// # Chaining Entries
///
/// To build a subsequent entry, use `Builder::from(&previous_entry)`:
///
/// ```rust,no_run
/// # use provenance_log::{Entry, entry, Script};
/// # let previous_entry = Entry::default();
/// let next_entry = entry::Builder::from(&previous_entry)
///     .with_unlock(&Script::default())
///     .try_build(|_| Ok(std::collections::BTreeMap::new()))
///     .unwrap();
/// ```
#[derive(Clone)]
pub struct Builder {
    version: Version,
    vlad: Option<Vlad>,
    prev: Option<Cid>,
    lipmaa: Option<Cid>,
    seqno: Option<SeqNo>,
    ops: Vec<Op>,
    locks: Vec<Script>,
    unlock: Option<Script>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            version: Version::CURRENT,
            vlad: None,
            prev: None,
            lipmaa: None,
            seqno: None,
            ops: Vec::default(),
            locks: Vec::default(),
            unlock: None,
        }
    }
}

// this initializes a builder for the next entry after this one
impl From<&Entry> for Builder {
    fn from(entry: &Entry) -> Self {
        Self {
            version: Version::CURRENT,
            vlad: Some(entry.vlad()),
            prev: Some(entry.cid()),
            lipmaa: None,
            seqno: Some(entry.seqno().next()),
            ops: Vec::default(),
            locks: entry.locks.clone(),
            unlock: None,
        }
    }
}

impl Builder {
    /// Set the version
    ///
    /// The version demands the script kind the entry carries: version 2
    /// (`Version::CURRENT`) demands WASM components and version 1
    /// (`Version::LEGACY`) demands core modules. [`Self::try_build`] rejects
    /// unsupported versions and detectable script-kind mismatches.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Set the Vlad
    pub fn with_vlad(mut self, vlad: &Vlad) -> Self {
        self.vlad = Some(vlad.clone());
        self
    }

    /// Set the prev Cid
    pub fn with_prev(mut self, cid: &Cid) -> Self {
        self.prev = Some(cid.clone());
        self
    }

    /// Set the sequence number
    pub fn with_seqno(mut self, seqno: SeqNo) -> Self {
        self.seqno = Some(seqno);
        self
    }

    /// Set the lipmaa Cid
    pub fn with_lipmaa(mut self, lipmaa: &Cid) -> Self {
        self.lipmaa = Some(lipmaa.clone());
        self
    }

    /// Set the ops
    pub fn with_ops(mut self, ops: &[Op]) -> Self {
        ops.clone_into(&mut self.ops);
        self
    }

    /// Add an op
    pub fn add_op(mut self, op: &Op) -> Self {
        self.ops.push(op.clone());
        self
    }

    /// Set the lock scripts
    pub fn with_locks(mut self, locks: &[Script]) -> Self {
        locks.clone_into(&mut self.locks);
        self
    }

    /// Set the lock script
    pub fn add_lock(mut self, script: &Script) -> Self {
        self.locks.push(script.clone());
        self
    }

    /// Set the unlock script
    pub fn with_unlock(mut self, unlock: &Script) -> Self {
        self.unlock = Some(unlock.clone());
        self
    }

    /// Build the Entry from the provided data and then call the `gen_proofs`
    /// closure to generate named proofs (signatures, ZK proofs, etc.)
    pub fn try_build<F>(&self, mut gen_proofs: F) -> Result<Entry, Error>
    where
        F: FnMut(&mut Entry) -> Result<BTreeMap<String, Vec<u8>>, Error>,
    {
        let version = self.version;
        if !version.is_supported() {
            return Err(EntryError::InvalidVersion(version.as_u64() as usize).into());
        }
        let vlad = self.vlad.clone().ok_or(EntryError::MissingVlad)?;
        let prev = self.prev.clone().unwrap_or_else(Cid::null);
        let seqno = self.seqno.unwrap_or(SeqNo::FIRST);
        let lipmaa = if seqno.is_lipmaa() {
            self.lipmaa.clone().ok_or(EntryError::MissingLipmaaLink)?
        } else {
            Cid::null()
        };
        let unlock = self.unlock.clone().ok_or(EntryError::MissingUnlockScript)?;

        // first construct an entry with every field except the proofs
        let mut entry = Entry {
            version,
            vlad,
            prev,
            seqno,
            lipmaa,
            ops: self.ops.clone(),
            locks: self.locks.clone(),
            unlock,
            proofs: BTreeMap::new(),
            cached_cid: OnceCell::new(),
        };

        // an entry carries the script kind its version demands: reject the
        // unlock script and every lock script whose detected kind mismatches;
        // undetectable payloads pass and fail later, exactly as today
        let mut scripts = std::iter::once(&entry.unlock).chain(entry.locks.iter());
        if let Some((expected, actual)) =
            scripts.find_map(|script| carried_script_violation(version, script))
        {
            return Err(EntryError::WrongScriptKind { expected, actual }.into());
        }

        // call the gen_proofs closure to create and store the proof data
        entry.proofs = gen_proofs(&mut entry)?;

        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{script, Value};
    use multi_key::EncodedMultikey;
    use multi_vlad::vlad;

    #[test]
    fn test_builder() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        assert_eq!(entry.seqno(), SeqNo::FIRST);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }

    #[test]
    fn test_builder_next() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        assert_eq!(entry.seqno(), SeqNo::FIRST);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        let entry2 = Builder::from(&entry)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();
        assert_eq!(entry2.seqno(), SeqNo::new(1));
        for op in entry2.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry2.context()), "/".to_string());
    }

    #[test]
    fn test_entry_iter() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        assert_eq!(entry.seqno(), SeqNo::FIRST);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        for (key, _value) in entry.iter() {
            assert!(ENTRY_FIELDS.contains(&key.as_str()));
        }
    }

    #[test]
    fn test_sort_locks_change_lock_order() {
        let vlad = Vlad::default();
        let script = Script::default();
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice");
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let mut hash_builder = mh::Builder::new(Codec::Sha3256)
            .expect("SHA3-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"move every zig");
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let locks_in1: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        // these are the same as above just in a different order which is significant
        let locks_in2: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_locks(&locks_in2) // same locks, different order
            .with_ops(&ops)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        // sorting/filtering the locks from the previous event. in this case they are the same
        // locks but in a different order.
        let locks_out = entry.sort_locks(&locks_in1).unwrap();
        assert_eq!(
            locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap()
        );
    }

    #[test]
    fn test_sort_locks_no_ops() {
        let vlad = Vlad::default();
        let script = Script::default();
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice");
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let mut hash_builder = mh::Builder::new(Codec::Sha3256)
            .expect("SHA3-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"move every zig");
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_ops(&ops)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(
            locks_out,
            vec![script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),]
        );
    }

    #[test]
    fn test_sort_locks() {
        let vlad = Vlad::default();
        let script = Script::default();
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice");
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let mut hash_builder = mh::Builder::new(Codec::Sha3256)
            .expect("SHA3-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"move every zig");
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_ops(&ops)
            .try_build(|_| Ok(BTreeMap::new()))
            .unwrap();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(
            locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
        );
        assert_eq!(
            locks_out[1],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap()
        );
        assert_eq!(
            locks_out[2],
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
        );

        assert_eq!(
            locks_out[3],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        );
    }
    #[test]
    fn test_preimage() {
        // Create a signing key for the VLAD
        let signing_key = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        ).unwrap().to_inner();
        let wasm_bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        let vlad = vlad::Builder::default()
            .with_signing_key(&signing_key)
            .with_message(&wasm_bytes)
            .try_build()
            .unwrap();

        // build a cid for Script::Cid
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let script = Script::Cid(Key::default(), cid);
        let op = Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into()));
        let entry = Builder::default()
            .with_vlad(&vlad)
            .add_lock(&script)
            .with_unlock(&script)
            .add_op(&op)
            .try_build(|e| {
                let vlad_bytes: Vec<u8> = e.vlad.clone().into();
                let mut proofs = BTreeMap::new();
                proofs.insert("primary".to_string(), vlad_bytes);
                Ok(proofs)
            })
            .unwrap();

        assert_eq!(entry.seqno(), SeqNo::FIRST);
        for op in entry.ops() {
            assert_eq!(
                Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into())),
                op.clone()
            );
        }
        // The proof is the VLAD bytes (used as preimage for Script::Cid verification)
        let vlad_bytes: Vec<u8> = vlad.clone().into();
        assert_eq!(entry.proofs.get("primary").unwrap(), &vlad_bytes);
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }
}

/*
in wild's embrace, hearts find their rest,
nature's gifts, for the loving, are best.
in every leaf, in each bird's song,
the wilderness, where souls belong.
*/
