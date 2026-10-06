// SPDX-License-Identifier: FSL-1.1
//
//! # WACC VM Execution Limits
//!
//! The provenance log verification process executes WASM scripts (lock/unlock) using
//! the wacc VM with the following security limits configured:
//!
//! ## StoreLimits (Memory & Resource Constraints)
//! - **Memory Size**: 64 KB (1 << 16) - Limits linear memory size to prevent memory exhaustion
//! - **Instances**: 8 - Maximum number of WASM instances (component guests
//!   from the wit-bindgen recipe embed three core modules, so instantiation
//!   creates three core instances and needs headroom)
//! - **Memories**: 1 - Maximum number of WASM linear memories
//! - **Tables**: 0 (default) - WASM table count (not explicitly set)
//!
//! These limits are applied to both unlock and lock script execution contexts;
//! see the two `StoreLimitsBuilder` uses in `VerifyIter::next`.
//!
//! ## Fuel Limits (Instruction Counting)
//! The wacc VM uses Wasmtime's fuel-based execution limiting, which provides instruction-level
//! control over script execution to prevent infinite loops and DoS attacks. Fuel limits are
//! configured when building the VM instance via `vm::Builder::new()`, which defaults to:
//!
//! - **Production Default**: 1,000,000 fuel units (FuelAmount::DEFAULT)
//! - **Development Mode**: 10,000,000 fuel units (10× default)
//! - **Strict Mode**: 100,000 fuel units (for untrusted code)
//!
//! Each WASM instruction consumes fuel, and execution is interrupted if fuel is exhausted.
//! The fuel mechanism is always enabled for security via `Config::consume_fuel(true)` in
//! the wacc VM builder.
//!
//! ## Security Considerations
//! - StoreLimits protect against memory exhaustion attacks
//! - Fuel limits protect against infinite loops and excessive computation
//! - Combined, these limits ensure script execution cannot DoS the verification process
//! - Timeout limits are NOT directly configurable in StoreLimitsBuilder (as they're handled
//!   by fuel consumption)
//! - For more details on security configuration, see `wacc::SecurityLimits`
//!
use crate::{
    entry::{self, carried_script_violation, required_script_kind},
    error::LogError,
    Entry, Error, Kvp, Script, Stk, Version,
};
use core::fmt;
use multi_base::Base;
use multi_cid::Cid;
use multi_codec::Codec;
use multi_trait::{EncodeInto, EncodeIntoBuffer, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, EncodingInfo, Varuint};
use multi_vlad::Vlad;
use std::collections::BTreeMap;
use wacc::ScriptKind;
use wacc::{prelude::StoreLimitsBuilder, types::ContextPath, vm};
use wasmtime::AsContextMut;

/// the multicodec provenance log codec
pub const SIGIL: Codec = Codec::ProvenanceLog;

/// the current version of provenance entries this supports
pub const LOG_VERSION: u64 = 2;

/// a base encoded provenance log
pub type EncodedLog = BaseEncoded<Log>;

/// the log entries type
pub type Entries = BTreeMap<Cid, Entry>;

/// A cryptographically verifiable provenance log
///
/// A `Log` is a tamper-evident, append-only data structure composed of linked [`Entry`] objects.
/// Each entry represents a state transition that must be cryptographically authorized by the
/// previous entry's lock scripts.
///
/// # Structure
///
/// - **VLAD**: Verifiable Log Address - a stable identifier for the log
/// - **Entries**: Content-addressed entry objects stored in a `BTreeMap<Cid, Entry>`
/// - **Head/Foot**: CIDs of the most recent and first entries
/// - **First Lock**: The initial lock script that authorizes the first entry
///
/// # Linking
///
/// Entries are linked via:
/// - **Prev links**: Each entry points to its immediate predecessor
/// - **Lipmaa links**: Skip-list style links providing O(log n) traversal
///
/// # Verification Process
///
/// Call [`verify()`](Self::verify) to validate the entire log:
///
/// 1. For each entry, execute its unlock script
/// 2. Execute applicable lock scripts from the previous entry
/// 3. If all scripts succeed, apply the entry's operations to the virtual key-value store
/// 4. Continue with the next entry
///
/// ```rust,no_run
/// # use provenance_log::Log;
/// # let log = Log::default();
/// for result in log.verify() {
///     match result {
///         Ok((check_count, entry, kvp)) => {
///             println!("Entry {} verified", entry.seqno());
///         }
///         Err(e) => {
///             eprintln!("Verification failed: {}", e);
///             break;
///         }
///     }
/// }
/// ```
///
/// # Builder Pattern
///
/// Use [`Builder`] to construct logs:
///
/// ```rust,no_run
/// use provenance_log::{Log, log, Entry, Script};
/// use multi_vlad::Vlad;
///
/// # let vlad = Vlad::default();
/// # let first_lock = Script::default();
/// # let entry = Entry::default();
/// let log = log::Builder::new()
///     .with_vlad(&vlad)
///     .with_first_lock(&first_lock)
///     .append_entry(&entry)
///     .try_build()
///     .unwrap();
/// ```
///
/// # Common Operations
///
/// ```rust,no_run
/// # use provenance_log::Log;
/// # let mut log = Log::default();
/// # let entry = provenance_log::Entry::default();
/// // Iterate over entries in chronological order
/// for entry in log.iter() {
///     println!("Entry #{}: {:?}", entry.seqno(), entry.cid());
/// }
///
/// // Append a new entry with verification
/// log.try_append(&entry).unwrap();
/// ```
///
/// # Thread Safety
///
/// `Log` is `Send + Sync` as all fields are thread-safe.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The version of this log format
    pub version: Version,
    /// Every log has a vlad identifier
    pub vlad: Vlad,
    /// The lock script for the first entry
    pub first_lock: Script,
    /// The first entry in the log
    pub foot: Cid,
    /// The latest entry in the log
    pub head: Cid,
    /// Entry objects are stored in a hashmap indexed by their Cid
    pub entries: Entries,
}

impl CodecInfo for Log {
    /// Return that we are a Log object
    fn preferred_codec() -> Codec {
        entry::SIGIL
    }

    /// Return that we are a Log
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Log {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Log> for Vec<u8> {
    fn from(val: Log) -> Self {
        let mut v = Vec::default();
        val.encode_into_buffer(&mut v);
        v
    }
}

impl EncodeIntoBuffer for Log {
    fn encode_into_buffer(&self, v: &mut Vec<u8>) {
        // add in the provenance log sigil
        u64::from(SIGIL).encode_into_buffer(v);
        // add in the version
        Varuint(self.version.as_u64()).encode_into_buffer(v);
        // add in the vlad
        self.vlad.encode_into_buffer(v);
        // add in the lock script for the first entry
        self.first_lock.encode_into_buffer(v);
        // add in the foot cid
        self.foot.encode_into_buffer(v);
        // add in the head cid
        self.head.encode_into_buffer(v);
        // add in the entry count
        Varuint(self.entries.len()).encode_into_buffer(v);
        // add in the entries
        self.entries.iter().for_each(|(cid, entry)| {
            cid.encode_into_buffer(v);
            entry.encode_into_buffer(v);
        });
    }
}

impl EncodeInto for Log {
    fn encode_into(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode_into_buffer(&mut buffer);
        buffer
    }
}

impl<'a> TryFrom<&'a [u8]> for Log {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (pl, _) = Self::try_decode_from(bytes)?;
        Ok(pl)
    }
}

impl<'a> TryDecodeFrom<'a> for Log {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(LogError::MissingSigil.into());
        }
        // decode the version
        let (version, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let version = Version::new(version.to_inner());
        // decode the vlad
        let (vlad, ptr) = Vlad::try_decode_from(ptr)?;
        // decode the lock script for the first entry
        let (first_lock, ptr) = Script::try_decode_from(ptr)?;
        // decode the foot cid
        let (foot, ptr) = Cid::try_decode_from(ptr)?;
        // decode the head cid if there is one
        let (head, ptr) = Cid::try_decode_from(ptr)?;
        // decode the number of entries
        let (num_entries, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        if *num_entries > crate::limits::MAX_ENTRIES_PER_LOG {
            return Err(
                LogError::TooManyEntries(*num_entries, crate::limits::MAX_ENTRIES_PER_LOG).into(),
            );
        }
        // decode the entries
        let (entries, ptr) = if *num_entries == 0 {
            (Entries::default(), ptr)
        } else {
            let mut entries = Entries::new();
            let mut p = ptr;
            for _ in 0..*num_entries {
                let (cid, ptr) = Cid::try_decode_from(p)?;
                let (entry, ptr) = Entry::try_decode_from(ptr)?;
                if entries.insert(cid.clone(), entry).is_some() {
                    return Err(LogError::DuplicateEntry(cid).into());
                }
                p = ptr;
            }
            (entries, p)
        };
        Ok((
            Self {
                version,
                vlad,
                first_lock,
                foot,
                head,
                entries,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Log {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {:?} - {:?} - {:?} - Entries: {}",
            self.codec(),
            self.version,
            self.vlad,
            self.head,
            self.foot,
            self.entries.len()
        )
    }
}

struct EntryIter<'a> {
    entries: Vec<&'a Entry>,
    current: usize,
}

/// A built script ready to execute, on either execution model.
///
/// Verification dispatches on the script kind detected in the payload bytes:
/// a core module runs through [`vm::Instance`] and a WASM component through
/// [`vm::ComponentInstance`]. Both hold the same [`vm::Context`] store, so
/// stack reads work identically through [`Self::store`].
enum ScriptVm {
    Module(vm::Instance),
    Component(vm::ComponentInstance),
}

impl ScriptVm {
    /// Builds the script payload on the execution model that its detected
    /// kind demands. Undetectable payloads (empty payloads, `Script::Cid`
    /// references) fall back to the kind the owning entry's version demands,
    /// which preserves their compile-time failure behavior.
    fn build(
        bytes: &[u8],
        entry_version: Version,
        context: vm::Context,
    ) -> Result<Self, wacc::Error> {
        let component_path = match ScriptKind::detect(bytes) {
            Some(ScriptKind::Component) => true,
            Some(ScriptKind::Module) => false,
            None => required_script_kind(entry_version) == ScriptKind::Component,
        };
        let builder = vm::Builder::new().with_context(context);
        if component_path {
            Ok(Self::Component(
                builder.with_component_bytes(bytes).try_build_component()?,
            ))
        } else {
            Ok(Self::Module(builder.with_bytes(bytes).try_build()?))
        }
    }

    /// Runs the script's export entry point; non-zero results mean success.
    fn run(&mut self, fname: &str) -> Result<bool, wacc::Error> {
        match self {
            Self::Module(instance) => instance.run(fname),
            Self::Component(component) => component.run(fname),
        }
    }

    /// Mutable context over the script's virtual machine store, the same
    /// borrow the module path takes to read the stacks
    fn store_context_mut(&mut self) -> wasmtime::StoreContextMut<'_, vm::Context> {
        match self {
            Self::Module(instance) => instance.store.as_context_mut(),
            Self::Component(component) => component.store.as_context_mut(),
        }
    }
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = &'a Entry;

    fn next(&mut self) -> Option<Self::Item> {
        match self.entries.get(self.current) {
            Some(e) => {
                self.current += 1;
                Some(e)
            }
            None => None,
        }
    }
}

struct VerifyIter<'a> {
    entries: Vec<&'a Entry>,
    seqno: usize,
    prev_seqno: usize,
    /// CID of the previously-validated entry (null for the genesis check).
    /// The current entry's prev link must match this exactly — a null prev
    /// link mid-chain is a splice and must fail verification.
    prev_cid: Cid,
    kvp: Kvp<'a>,
    lock_scripts: Vec<Script>,
    error: Option<Error>,
    /// Enforces XMSS leaf-index monotonicity across this verification pass;
    /// installed for the lifetime of the iterator (thread-local, RAII).
    xmss_enforcement: vm::XmssEnforcement,
}

impl<'a> Iterator for VerifyIter<'a> {
    type Item = Result<(usize, Entry, Kvp<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        //println!("iter::next({})", self.seqno);
        let entry = *self.entries.get(self.seqno)?;

        // the first entry processed MUST be a true
        // genesis — sequence number 0 with a null prev link. The iterator
        // walks entries sorted by seqno and seeds `first_lock`; without this
        // guard, a log whose real genesis was stripped (truncation/splice)
        // would verify against `first_lock` as if a later surviving entry
        // were the genesis. A valid genesis always satisfies this, so honest
        // logs are unaffected.
        if self.seqno == 0 && (entry.seqno.as_u64() != 0 || !entry.prev().is_null()) {
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed {
                    msg: "first entry is not a valid genesis (seqno != 0 or prev not null)"
                        .to_string(),
                    seqno: Some(entry.seqno.as_u64()),
                    entry_cid: Some(entry.cid()),
                }
                .into(),
            );
            return Some(Err(self
                .error
                .take()
                .expect("error should be Some as it was just set above")));
        }

        // this is the check count if successful
        let mut count = 0;

        // set up the stacks
        let pstack = Stk::default();
        let rstack = Stk::default();

        // check the seqno meet the criteria
        if self.seqno > 0 && self.seqno != self.prev_seqno + 1 {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error state
            self.error = Some(LogError::InvalidSeqno.into());
            if let Some(error) = self.error.take() {
                return Some(Err(error));
            }
            return None;
        }

        // HIGH-1: Validate prev link points to actual previous entry's CID.
        // `prev_cid` is seeded null: at seqno 0 the genesis guard already
        // required a null prev (matching the seed), and at seqno > 0 a null
        // prev link mid-chain is a splice that must fail verification.
        if entry.prev() != self.prev_cid {
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed {
                    msg: format!(
                        "Entry prev link does not match previous entry CID (seqno {})",
                        entry.seqno
                    ),
                    seqno: Some(entry.seqno.as_u64()),
                    entry_cid: Some(entry.cid()),
                }
                .into(),
            );
            return Some(Err(self
                .error
                .take()
                .expect("error should be Some as it was just set above")));
        }

        // CRIT-2: Validate Lipmaa link if this entry should have one
        if entry.seqno.is_lipmaa() {
            let expected_lipmaa_seqno = entry.seqno.lipmaa();

            // Find the entry at the expected Lipmaa target sequence number
            let lipmaa_target_entry = self
                .entries
                .iter()
                .find(|e| e.seqno == expected_lipmaa_seqno);

            if let Some(target_entry) = lipmaa_target_entry {
                // Verify the Lipmaa link points to the correct entry's CID
                if entry.lipmaa != target_entry.cid() {
                    self.seqno = self.entries.len();
                    self.error = Some(
                        LogError::InvalidLipmaaLink {
                            seqno: entry.seqno.as_u64(),
                            expected_target: expected_lipmaa_seqno.as_u64(),
                            actual_cid: None,
                        }
                        .into(),
                    );
                    return Some(Err(self
                        .error
                        .take()
                        .expect("error should be Some as it was just set above")));
                }
            } else {
                // Lipmaa target entry doesn't exist in log
                self.seqno = self.entries.len();
                self.error = Some(
                    LogError::VerifyFailed {
                        msg: format!(
                            "Lipmaa target entry at seqno {} not found in log",
                            expected_lipmaa_seqno
                        ),
                        seqno: Some(entry.seqno.as_u64()),
                        entry_cid: Some(entry.cid()),
                    }
                    .into(),
                );
                return Some(Err(self
                    .error
                    .take()
                    .expect("error should be Some as it was just set above")));
            }
        }

        // an entry, the log's first lock at seqno 0, and the entry's own
        // version must agree on the script kind: version 2 entries carry
        // WASM components and version 1 entries carry core modules.
        // Mismatches reject loudly; undetectable payloads pass and fail
        // later at compile time.
        let incoming = self.lock_scripts.iter().filter(|_| self.seqno == 0);
        let mut scripts = std::iter::once(&entry.unlock)
            .chain(entry.locks.iter())
            .chain(incoming);
        if let Some((expected, found)) =
            scripts.find_map(|script| carried_script_violation(entry.version, script))
        {
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::ScriptKindMismatch {
                    seqno: entry.seqno.as_u64(),
                    expected,
                    found,
                }
                .into(),
            );
            return Some(Err(self
                .error
                .take()
                .expect("error should be Some as it was just set above")));
        }

        // 'unlock:
        // Extract pstack values after unlock to use in lock scripts
        log::warn!(
            "VerifyIter seqno={} proof_count={} proof_keys={:?}",
            self.seqno,
            entry.proofs.len(),
            entry.proofs.keys().collect::<Vec<_>>()
        );
        let (mut result, pstack_values) = {
            // run the unlock script using the entry as the kvp to get the
            // stack in the vm::Context set up.
            let unlock_ctx = vm::Context {
                current: Box::new(entry.clone()), // limit the available data to just the entry
                proposed: Box::new(entry.clone()), // limit the available data to just the entry
                pstack: Box::new(pstack),
                rstack: Box::new(rstack),
                check_count: 0.into(),
                write_idx: 0,
                context: ContextPath::new(entry.context().to_string()),
                log: Vec::default(),
                limiter: StoreLimitsBuilder::new()
                    .memory_size(1 << 16)
                    .instances(8)
                    .memories(1)
                    .build(),
            };

            let mut instance =
                match ScriptVm::build(entry.unlock.as_ref(), entry.version, unlock_ctx) {
                    Ok(instance) => instance,
                    Err(e) => {
                        // set our index out of range
                        self.seqno = self.entries.len();
                        self.error = Some(LogError::Wacc(e).into());
                        return Some(Err(self
                            .error
                            .take()
                            .expect("error should be Some as it was just set above")));
                    }
                };
            //print!("running unlock script from seqno: {}...", self.seqno);

            // run the unlock script — check both the return value and any runtime error
            let unlock_ok = match instance.run("for_great_justice") {
                Ok(b) => b,
                Err(e) => {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self
                        .error
                        .take()
                        .expect("error should be Some as it was just set above")));
                }
            };

            // Extract pstack values from the store after unlock script runs
            let values = {
                let mut ctx = instance.store_context_mut();
                let context = ctx.data_mut();
                let mut values = Vec::new();
                for i in 0..context.pstack.len() {
                    if let Some(val) = context.pstack.peek(context.pstack.len() - 1 - i) {
                        values.push(val);
                    }
                }
                values
            };

            (unlock_ok, values)
        };

        /*
        println!("values:");
        println!("{:?}", pstack.clone());
        println!("return:");
        println!("{:?}", rstack.clone());
        */

        if !result {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed {
                    msg: "unlock script failed".to_string(),
                    seqno: Some(entry.seqno.as_u64()),
                    entry_cid: Some(entry.cid()),
                }
                .into(),
            );
            return Some(Err(self
                .error
                .take()
                .expect("error should be Some as it was just set above")));
        }

        /*
        // set the entry to look into for proof and message values
        if let Some(e) = self.kvp.set_entry(entry).err() {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(LogError::KvpSetEntryFailed {
                msg: e.to_string(),
                entry_cid: Some(entry.cid()),
            }.into());
            return Some(Err(self.error.take().unwrap()));
        }
        */

        // if this is the first entry, then we need to apply the
        // mutation ops
        if self.seqno == 0 {
            //println!("applying kvp ops for seqno 0");
            if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(
                    LogError::UpdateKvpFailed {
                        msg: e.to_string(),
                        seqno: Some(entry.seqno.as_u64()),
                        entry_cid: Some(entry.cid()),
                    }
                    .into(),
                );
                return Some(Err(self
                    .error
                    .take()
                    .expect("error should be Some as it was just set above")));
            }
        }

        // 'lock:
        result = false;
        let mut lock_fail_reason: Option<String> = None;

        // build the set of lock scripts to run in order from root to longest branch to leaf
        let locks = match entry.sort_locks(&self.lock_scripts) {
            Ok(l) => l,
            Err(e) => {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(e);
                return Some(Err(self
                    .error
                    .take()
                    .expect("error should be Some as it was just set above")));
            }
        };

        // run each of the lock scripts
        for lock in locks {
            let lock_result = {
                // Create context with owned data
                let lock_ctx = vm::Context {
                    current: Box::new(self.kvp.without_entry()),
                    proposed: Box::new(entry.clone()),
                    pstack: Box::new(Stk::from_values(pstack_values.clone())),
                    rstack: Box::new(Stk::default()),
                    check_count: 0.into(),
                    write_idx: 0,
                    context: ContextPath::new(entry.context().to_string()), // set the branch path for branch()
                    log: Vec::default(),
                    limiter: StoreLimitsBuilder::new()
                        .memory_size(1 << 16)
                        .instances(8)
                        .memories(1)
                        .build(),
                };

                let mut instance = match ScriptVm::build(lock.as_ref(), entry.version, lock_ctx) {
                    Ok(instance) => instance,
                    Err(e) => {
                        // set our index out of range
                        self.seqno = self.entries.len();
                        self.error = Some(LogError::Wacc(e).into());
                        return Some(Err(self
                            .error
                            .take()
                            .expect("error should be Some as it was just set above")));
                    }
                };
                //print!("running lock script from seqno: {}...", self.seqno);

                // run the unlock script
                if let Some(e) = instance.run("move_every_zig").err() {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self
                        .error
                        .take()
                        .expect("error should be Some as it was just set above")));
                }

                //println!("SUCCEEDED!");

                // Extract the result from the instance's store
                let mut ctx = instance.store_context_mut();
                let context = ctx.data_mut();
                context.rstack.top()
            };

            // break out of this loop as soon as a lock script succeeds
            if let Some(v) = lock_result {
                match v {
                    vm::Value::Success(c) => {
                        count = c;
                        result = true;
                        break;
                    }
                    vm::Value::Failure(ref reason) => {
                        lock_fail_reason = Some(reason.clone());
                        result = false;
                    }
                    _ => result = false,
                }
            }
        }

        if result {
            // if the entry verifies, apply it's mutataions to the kvp
            // the 0th entry has already been applied at this point so no
            // need to do it here
            if self.seqno > 0 {
                if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(
                        LogError::UpdateKvpFailed {
                            msg: e.to_string(),
                            seqno: Some(entry.seqno.as_u64()),
                            entry_cid: Some(entry.cid()),
                        }
                        .into(),
                    );
                    return Some(Err(self
                        .error
                        .take()
                        .expect("error should be Some as it was just set above")));
                }
            }
            // the entry validated: commit any XMSS leaf indices it consumed so
            // later entries must use strictly greater indices for the same key
            self.xmss_enforcement.commit_entry();
            // update the lock script to validate the next entry
            self.lock_scripts.clone_from(&entry.locks);
            // update the seqno and the expected prev link for the next entry
            self.prev_seqno = self.seqno;
            self.prev_cid = entry.cid();
            self.seqno += 1;
        } else {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed {
                    msg: lock_fail_reason.map_or_else(
                        || "lock script failed".to_string(),
                        |r| format!("lock script failed: {r}"),
                    ),
                    seqno: Some(entry.seqno.as_u64()),
                    entry_cid: Some(entry.cid()),
                }
                .into(),
            );
            return Some(Err(self
                .error
                .take()
                .expect("error should be Some as it was just set above")));
        }

        // return the check count, validated entry, and kvp state
        Some(Ok((count, entry.clone(), self.kvp.clone())))
    }
}

impl Log {
    /// get an iterator over the entries in from head to foot
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        // get a list of Entry references, sort them by seqno
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort();
        EntryIter {
            entries,
            current: 0,
        }
    }

    /// Verifies all entries in the log
    pub fn verify(&self) -> impl Iterator<Item = Result<(usize, Entry, Kvp<'_>), Error>> {
        // get a list of Entry objects, sort them by seqno
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort();
        VerifyIter {
            entries,
            seqno: 0,
            prev_seqno: 0,
            prev_cid: Cid::null(),
            kvp: Kvp::default(),
            lock_scripts: vec![self.first_lock.clone()],
            error: None,
            xmss_enforcement: vm::XmssEnforcement::install(),
        }
    }

    /// Try to add an entry to the p.log
    pub fn try_append(&mut self, entry: &Entry) -> Result<(), Error> {
        let cid = entry.cid();
        let mut plog = self.clone();
        plog.entries.insert(cid.clone(), entry.clone());
        let vi = plog.verify();
        for ret in vi {
            if let Some(e) = ret.err() {
                return Err(LogError::VerifyFailed {
                    msg: e.to_string(),
                    seqno: None,
                    entry_cid: Some(cid.clone()),
                }
                .into());
            }
        }
        self.entries.insert(cid.clone(), entry.clone());
        self.head = cid;
        // the log version derives from the entry versions: the maximum of the
        // carried entries; appending never lowers the version
        self.version = self
            .entries
            .values()
            .map(|entry| entry.version.as_u64())
            .max()
            .map_or(self.version, Version::new);
        Ok(())
    }
}

/// Builder for Log objects
#[derive(Clone, Default)]
pub struct Builder {
    version: Version,
    vlad: Option<Vlad>,
    first_lock: Option<Script>,
    foot: Option<Cid>,
    head: Option<Cid>,
    entries: Entries,
}

impl Builder {
    /// build new with version
    pub fn new() -> Self {
        Self {
            version: Version::CURRENT,
            ..Default::default()
        }
    }

    /// Set the Vlad
    pub fn with_vlad(mut self, vlad: &Vlad) -> Self {
        self.vlad = Some(vlad.clone());
        self
    }

    /// Set the lock script for the first Entry
    pub fn with_first_lock(mut self, script: &Script) -> Self {
        self.first_lock = Some(script.clone());
        self
    }

    /// Set the foot Cid
    pub fn with_foot(mut self, cid: &Cid) -> Self {
        self.foot = Some(cid.clone());
        self
    }

    /// Set the head Cid
    pub fn with_head(mut self, cid: &Cid) -> Self {
        self.head = Some(cid.clone());
        self
    }

    /// Set the passed in entries to the existin entries
    pub fn with_entries(mut self, entries: &Entries) -> Self {
        self.entries.append(&mut entries.clone());
        self
    }

    /// Add an entry at the head of the log and adjust the head and possibly
    /// the foot if this is the only entry
    pub fn append_entry(mut self, entry: &Entry) -> Self {
        let cid = entry.cid();
        self.head = Some(cid.clone());
        // update the foot if this is the first entry
        if self.entries.is_empty() {
            self.foot = Some(cid.clone());
        }
        self.entries.insert(cid.clone(), entry.clone());
        self
    }

    /// Try to build the Log
    pub fn try_build(&self) -> Result<Log, Error> {
        let vlad = self.vlad.clone().ok_or(LogError::MissingVlad)?;
        let first_lock = self
            .first_lock
            .clone()
            .ok_or(LogError::MissingFirstEntryLockScript)?;
        let foot = self.foot.clone().ok_or(LogError::MissingFoot)?;
        let head = self.head.clone().ok_or(LogError::MissingHead)?;
        let entries = self.entries.clone();
        if entries.is_empty() {
            return Err(LogError::MissingEntries.into());
        } else {
            // start at the head and walk the prev links to the foot to ensure
            // they are all connected
            let mut c = head.clone();
            let f = foot.clone();
            while c != f {
                if let Some(entry) = entries.get(&c) {
                    if c != entry.cid() {
                        return Err(LogError::EntryCidMismatch.into());
                    }
                    c = entry.prev();
                    if c.is_null() {
                        return Err(LogError::BrokenEntryLinks.into());
                    }
                } else {
                    return Err(LogError::BrokenPrevLink.into());
                }
            }
        }
        // the log version derives from the entry versions: the maximum of the
        // carried entries, falling back to the builder's version when there
        // are no entries
        let version = entries
            .values()
            .map(|entry| entry.version.as_u64())
            .max()
            .map_or(self.version, Version::new);
        Ok(Log {
            version,
            vlad,
            first_lock,
            foot,
            head,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Key, Op, SeqNo, Value};
    use multi_hash::mh;
    use multi_key::{EncodedMultikey, Multikey, Views};
    use multi_vlad::vlad;
    use std::path::PathBuf;

    fn load_script(path: &Key, file_name: &str) -> Script {
        // CARGO_MANIFEST_DIR points to crates/provenance-log
        // Need to go up to workspace root, then into examples/provenance-log/wast
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("examples/provenance-log/wast");
        pb.push(file_name);
        crate::script::Builder::from_code_file(&pb)
            .with_path(path)
            .try_build()
            .unwrap()
    }

    fn get_key_update_op(k: &str, key: &Multikey) -> Op {
        let kcv = key.conv_view().unwrap();
        let pk = kcv.to_public_key().unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
    }

    fn get_hash_update_op(k: &str, preimage: &str) -> Op {
        let mh = mh::Builder::new_from_bytes(Codec::Sha3512, preimage.as_bytes())
            .unwrap()
            .try_build()
            .unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(mh.into()))
    }

    #[test]
    fn test_default() {
        let log = Log::default();
        assert_eq!(Vlad::default(), log.vlad);
        assert_eq!(log.iter().next(), None);
    }

    #[test]
    fn test_builder() {
        // the ephemeral key is a merkle-tree Lamport key (the recommended
        // default) at depth 1: leaf 0 signs the vlad, leaf 1 signs the first
        // entry, exhausting the tree
        let ephemeral = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rand_010::rng(),
        )
        .unwrap()
        .try_build()
        .unwrap();
        let key = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();

        // build a vlad with the stateful ephemeral key, capturing the advanced
        // key state (leaf 0 consumed)
        let (vlad, advanced) = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build_advance()
            .unwrap();

        // the vlad signature is a merkle-Lamport signature at depth 1
        assert_eq!(vlad.multisig().depth(), Some(1));

        // load the entry scripts
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        // the verifier needs the ephemeral tree-root public key at /vlad/key;
        // the advanced key has the same public half as the original
        let vlad_key_op = get_key_update_op("/vlad/key", &advanced);
        let pubkey_op = get_key_update_op("/keys/primary", &key);

        let entry = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&vlad_key_op)
            .add_op(&pubkey_op)
            .try_build(|e| {
                // get the serialized version of the entry (with empty proof)
                let ev: Vec<u8> = e.clone().into();
                // sign with the advanced stateful key: leaf 1 is consumed
                let sv = advanced.sign_view().unwrap();
                let (ms, advanced2) = sv.sign_advance(&ev, false, None).unwrap();
                // leaf 1 was the last leaf; the tree is now exhausted
                let mv = advanced2.merkle_state_view().unwrap();
                assert_eq!(mv.next_index().unwrap(), 2);
                assert_eq!(mv.remaining_signatures().unwrap(), 0);
                // store the signature as proof
                let sig: Vec<u8> = ms.into();
                Ok(BTreeMap::from([("primary".to_string(), sig)]))
            })
            .unwrap();

        // load the first lock script
        let first = load_script(&Key::default(), "first.wast");

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&entry)
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert!(!log.foot.is_null());
        assert!(!log.head.is_null());
        assert_eq!(log.foot, log.head);
        assert_eq!(Some(entry), log.iter().next().cloned());
        let verify_iter = log.verify();
        for ret in verify_iter {
            if let Some(e) = ret.err() {
                panic!("verify failed: {e}");
            }
        }
    }

    #[test]
    #[cfg(feature = "slow-tests")]
    fn test_xmss_index_reuse_rejected_in_plog() {
        use multi_key::mk;

        let mut rng = rand_010::rng();
        // ephemeral ed25519 key signs the vlad and the foot entry
        let ephemeral = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        // a single XMSS-SHA2_10_256 key signs the following entries; because the
        // stateless sign view does not advance the stored key, every signature it
        // produces consumes leaf index 0 — i.e. the second one is a reuse.
        let xmss = mk::Builder::new_from_random_bytes(Codec::XmssSha210256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build()
            .unwrap();

        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        let first = load_script(&Key::default(), "first.wast");

        let vlad_key_op = get_key_update_op("/vlad/key", &ephemeral);
        let xmss_primary_op = get_key_update_op("/keys/primary", &xmss);

        // foot: registers the XMSS public key as /keys/primary, self-signed by
        // the ephemeral key (validated by first.wast)
        let e1 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::FIRST)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&vlad_key_op)
            .add_op(&xmss_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = ephemeral
                    .sign_view()
                    .unwrap()
                    .sign(&ev, false, None)
                    .unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // seqno 1: signed by the XMSS key at leaf index 0 (valid), keeps
        // /keys/primary = XMSS pub so the same key validates the next entry
        let e2 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(1))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&xmss_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = xmss.sign_view().unwrap().sign(&ev, false, None).unwrap();
                assert_eq!(ms.sig_index(), Some(0));
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // a log of the foot + one valid XMSS entry must verify cleanly
        let good_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .try_build()
            .unwrap();
        for ret in good_log.verify() {
            assert!(ret.is_ok(), "valid XMSS log should verify: {:?}", ret.err());
        }

        // seqno 2: signed by the SAME XMSS key, which again consumes leaf index 0
        // — a reuse that simulates restoring the key from an old snapshot
        let e3 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(2))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .add_op(&xmss_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = xmss.sign_view().unwrap().sign(&ev, false, None).unwrap();
                assert_eq!(ms.sig_index(), Some(0)); // reused index
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        let reuse_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .append_entry(&e3)
            .try_build()
            .unwrap();

        // verification must fail on the reusing entry
        let results: Vec<_> = reuse_log.verify().collect();
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("XMSS index reuse must be rejected by plog verification");
        let msg = err.to_string();
        assert!(
            msg.contains("reused") || msg.contains("rolled back"),
            "expected an XMSS index-reuse error, got: {msg}"
        );
    }

    #[test]
    fn test_lamport_one_time_reuse_rejected_in_plog() {
        use multi_key::mk;

        let mut rng = rand_010::rng();
        let ephemeral = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        // a single Lamport key signs two entries; the second use must be rejected
        let lamport = mk::Builder::new_from_random_bytes(Codec::LamportSha3256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build()
            .unwrap();

        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        let first = load_script(&Key::default(), "first.wast");

        let vlad_key_op = get_key_update_op("/vlad/key", &ephemeral);
        let lamport_primary_op = get_key_update_op("/keys/primary", &lamport);

        // foot: registers the Lamport public key as /keys/primary
        let e1 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::FIRST)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&vlad_key_op)
            .add_op(&lamport_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = ephemeral
                    .sign_view()
                    .unwrap()
                    .sign(&ev, false, None)
                    .unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // seqno 1: first (valid) use of the Lamport key, keeps /keys/primary
        let e2 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(1))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&lamport_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = lamport.sign_view().unwrap().sign(&ev, false, None).unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // foot + one valid Lamport entry must verify cleanly
        let good_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .try_build()
            .unwrap();
        for ret in good_log.verify() {
            assert!(
                ret.is_ok(),
                "valid Lamport log should verify: {:?}",
                ret.err()
            );
        }

        // seqno 2: SECOND use of the same Lamport key — a one-time-key reuse
        let e3 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(2))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .add_op(&lamport_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = lamport.sign_view().unwrap().sign(&ev, false, None).unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        let reuse_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .append_entry(&e3)
            .try_build()
            .unwrap();

        let results: Vec<_> = reuse_log.verify().collect();
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("Lamport one-time-key reuse must be rejected by plog verification");
        assert!(
            err.to_string().contains("reused"),
            "expected a Lamport reuse error, got: {err}"
        );
    }

    #[test]
    fn test_merkle_leaf_reuse_rejected_in_plog() {
        use multi_key::mk;

        let mut rng = rand_010::rng();
        // a stateless ephemeral key signs the vlad and the foot entry
        let ephemeral = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        // a depth-1 merkle key holds exactly two one-time leaves; the primary
        // key published at /keys/primary signs entries with it
        let merkle = mk::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();

        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build()
            .unwrap();

        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        let first = load_script(&Key::default(), "first.wast");

        let vlad_key_op = get_key_update_op("/vlad/key", &ephemeral);
        let merkle_primary_op = get_key_update_op("/keys/primary", &merkle);

        // foot: registers the merkle public key as /keys/primary
        let e1 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::FIRST)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&vlad_key_op)
            .add_op(&merkle_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = ephemeral
                    .sign_view()
                    .unwrap()
                    .sign(&ev, false, None)
                    .unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // seqno 1: leaf 0 signs the entry
        let e2 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(1))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&merkle_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let (ms, advanced) = merkle
                    .sign_view()
                    .unwrap()
                    .sign_advance(&ev, false, None)
                    .unwrap();
                // leaf 0 consumed; the advanced state would be persisted here.
                // A real signer would advance; this test intentionally keeps
                // using the stale original state below to attempt reuse.
                let mv = advanced.merkle_state_view().unwrap();
                assert_eq!(mv.next_index().unwrap(), 1);
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // foot + one valid merkle entry must verify cleanly
        let good_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .try_build()
            .unwrap();
        for ret in good_log.verify() {
            assert!(
                ret.is_ok(),
                "valid merkle log should verify: {:?}",
                ret.err()
            );
        }

        // seqno 2: leaf 0 AGAIN — the tree only holds leaves 0 and 1, and leaf
        // 0 was already consumed by the previous entry. Signing with stale
        // state (the original key) produces a leaf-0 signature, which wacc
        // must reject as reused/rolled back.
        let e3 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(2))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .add_op(&merkle_primary_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = merkle
                    .sign_view()
                    .unwrap()
                    .sign_advance(&ev, false, None)
                    .unwrap()
                    .0;
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        let reuse_log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1)
            .append_entry(&e2)
            .append_entry(&e3)
            .try_build()
            .unwrap();

        let results: Vec<_> = reuse_log.verify().collect();
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("merkle-Lamport leaf reuse must be rejected by plog verification");
        let msg = err.to_string();
        assert!(
            msg.contains("reused") || msg.contains("rolled back"),
            "expected a merkle leaf-reuse error, got: {msg}"
        );
    }

    #[test]
    fn test_entry_iterator() {
        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();
        let key1 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();
        let key2 = EncodedMultikey::try_from(
            "fba2480260874657374206b65790101203f4c94407de791e53b4df12ef1d5534d1b19ff2ccfccba4ccc4722b6e5e8ea07"
        )
        .unwrap();
        let key3 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120518e3ea918b1168d29ca7e75b0ca84be1ad6edf593a47828894a5f1b94a83bd4"
        )
        .unwrap();

        // create a vlad
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build()
            .unwrap();

        let vlad_key_op = get_key_update_op("/vlad/key", &ephemeral);
        let pubkey1_op = get_key_update_op("/keys/primary", &key1);
        let pubkey2_op = get_key_update_op("/keys/primary", &key2);
        let pubkey3_op = get_key_update_op("/keys/primary", &key3);
        let preimage1_op = get_hash_update_op("/hash", "for great justice");
        let preimage2_op = get_hash_update_op("/hash", "move every zig");

        // load the entry scripts
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");

        // create the first, self-signed Entry object
        let e1 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::FIRST)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .add_op(&vlad_key_op) // "/vlad/key"
            .add_op(&pubkey1_op) // "/keys/primary"
            .add_op(&preimage1_op) // "/preimage"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = ephemeral.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                let sig: Vec<u8> = ms.into();
                Ok(BTreeMap::from([("primary".to_string(), sig)]))
            })
            .unwrap();

        //println!("{:?}", e1);
        let e2 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(1))
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&Op::Delete("/vlad/key".try_into().unwrap())) // "/vlad/key"
            .add_op(&pubkey2_op) // "/keys/primary"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key1.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                let sig: Vec<u8> = ms.into();
                Ok(BTreeMap::from([("primary".to_string(), sig)]))
            })
            .unwrap();

        //println!("{:?}", e2);
        let e3 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(2))
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key2.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                let sig: Vec<u8> = ms.into();
                Ok(BTreeMap::from([("primary".to_string(), sig)]))
            })
            .unwrap();

        //println!("{:?}", e3);
        let e4 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(3))
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e3.cid())
            .add_op(&pubkey3_op) // "/keys/primary"
            .add_op(&preimage2_op) // "/preimage"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key2.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                let sig: Vec<u8> = ms.into();
                Ok(BTreeMap::from([("primary".to_string(), sig)]))
            })
            .unwrap();
        //println!("{:?}", e4);

        // load the first lock script
        let first = load_script(&Key::default(), "first.wast");

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1) // foot
            .append_entry(&e2)
            .append_entry(&e3)
            .append_entry(&e4) // head
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert_eq!(4, log.entries.len());
        let mut iter = log.iter();
        assert_eq!(Some(&e1), iter.next());
        assert_eq!(Some(&e2), iter.next());
        assert_eq!(Some(&e3), iter.next());
        assert_eq!(Some(&e4), iter.next());
        assert_eq!(None, iter.next());
        let verify_iter = log.verify();
        for ret in verify_iter {
            match ret {
                Ok((c, _, _)) => {
                    println!("check count: {c}");
                }
                Err(e) => {
                    println!("verify failed: {e}");
                    panic!();
                }
            }
        }
    }

    #[test]
    fn test_mid_log_null_prev_link_rejected() {
        use multi_key::Views as _;

        let mut rng = rand_010::rng();
        // stateless keys keep the merkle guard out of the picture; the probe
        // targets the prev-link check alone
        let ephemeral = multi_key::mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let primary = multi_key::mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_message(&[0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
            .try_build()
            .unwrap();

        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        let first = load_script(&Key::default(), "first.wast");

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
                let ms = ephemeral
                    .sign_view()
                    .unwrap()
                    .sign(&ev, false, None)
                    .unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // e2 omits with_prev(): its prev link stays null while seqno is 1 —
        // a spliced chain that VerifyIter must reject
        let e2 = entry::Builder::default()
            .with_version(Version::LEGACY)
            .with_vlad(&vlad)
            .with_seqno(SeqNo::new(1))
            .add_lock(&lock)
            .with_unlock(&unlock)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let ms = primary.sign_view().unwrap().sign(&ev, false, None).unwrap();
                Ok(BTreeMap::from([("primary".to_string(), ms.into())]))
            })
            .unwrap();

        // build the Log directly (fields are public) so Log::try_build's
        // prev-chain walk does not reject it first; this models an
        // attacker-supplied serialized log
        let log = Log {
            version: Version::CURRENT,
            vlad: vlad.clone(),
            first_lock: first,
            foot: e1.cid(),
            head: e2.cid(),
            entries: BTreeMap::from([(e1.cid(), e1.clone()), (e2.cid(), e2.clone())]),
        };

        let results: Vec<_> = log.verify().collect();
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("a mid-log entry with a null prev link must fail verification");
        assert!(
            err.to_string().contains("prev link does not match"),
            "expected a prev-link error, got: {err}"
        );
    }
}

/*
the gifts of wilderness are given
—in no small measure or part—
to those who call it livin'
having outside inside their heart
*/
