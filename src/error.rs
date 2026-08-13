// SPDX-License-Identifier: FSL-1.1
//! Error types for provenance log operations
//!
//! This module defines all error types that can occur during provenance log operations.
//! Errors are organized by the component that generates them and include contextual
//! information to aid in debugging and recovery.

/// Top-level error type for all provenance log operations
///
/// This enum wraps more specific error types and provides transparent error propagation
/// via the `thiserror` crate. All errors implement `std::error::Error` and can be
/// converted to and from their specific types.
///
/// # Error Recovery
///
/// Many errors indicate problems that can be fixed:
///
/// - [`EntryError::MissingVlad`]: Ensure you call `with_vlad()` on the builder
/// - [`LogError::VerifyFailed`]: Check that scripts and proofs are correct
/// - [`KeyError::PathTooLong`]: Use shorter key paths or increase limits
///
/// See individual error variant documentation for specific recovery suggestions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Entry error
    #[error(transparent)]
    Entry(#[from] EntryError),
    /// Key error
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Kvp error
    #[error(transparent)]
    Kvp(#[from] KvpError),
    /// ProvenanceLog error
    #[error(transparent)]
    Log(#[from] LogError),
    /// Operation error
    #[error(transparent)]
    Op(#[from] OpError),
    /// Script error
    #[error(transparent)]
    Script(#[from] ScriptError),
    /// Operation error
    #[error(transparent)]
    Value(#[from] ValueError),

    /// Multi-cid error
    #[error(transparent)]
    Multicid(#[from] multi_cid::Error),
    /// Multi-vlad error
    #[error(transparent)]
    Multivlad(#[from] multi_vlad::Error),
    /// Multicodec Error
    #[error(transparent)]
    Multicodec(#[from] multi_codec::Error),
    /// Multihash Error
    #[error(transparent)]
    Multihash(#[from] multi_hash::Error),
    /// Multitrait Error
    #[error(transparent)]
    Multitrait(#[from] multi_trait::Error),
    /// Multiutil Error
    #[error(transparent)]
    Multiutil(#[from] multi_util::Error),

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Errors specific to Entry operations
///
/// These errors occur during entry construction, serialization, or validation.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// Missing entry sigil during deserialization
    ///
    /// **Recovery**: Ensure you're decoding valid entry bytes with the correct codec prefix.
    #[error("missing provenance entry sigil")]
    MissingSigil,

    /// Entry version is not supported
    ///
    /// **Recovery**: Check that the entry was created with a compatible version of this library.
    #[error("Invalid provenance entry version {0}")]
    InvalidVersion(usize),

    /// VLAD identifier not provided to builder
    ///
    /// **Recovery**: Call `builder.with_vlad(&vlad)` before building.
    #[error("missing vlad")]
    MissingVlad,
    /// Missing libpmaa
    #[error("missing lipmaa link")]
    MissingLipmaaLink,
    /// Missing lock script
    #[error("missing lock script")]
    MissingLockScript,
    /// Missing unlock script
    #[error("missing unlock script")]
    MissingUnlockScript,
    /// Proof generator error
    #[error("proof generation failed: {source}")]
    ProofGenerationFailed {
        /// The underlying formatting error
        #[source]
        source: std::fmt::Error,
    },
    /// Entries are read-only
    #[error("Entry objects are read-only")]
    ReadOnly,
    /// Signing the entry failed
    #[error("signing the entry failed: {msg}")]
    SignFailed {
        /// Error message describing the signing failure
        msg: String,
        /// The sequence number of the entry that failed to sign, if known
        seqno: Option<u64>,
    },
    /// Too many operations in entry
    #[error("entry has {0} operations, maximum allowed is {1}")]
    TooManyOps(usize, usize),
    /// Too many lock scripts in entry
    #[error("entry has {0} lock scripts, maximum allowed is {1}")]
    TooManyLocks(usize, usize),
    /// Proof size exceeds limit
    #[error("proof size {0} bytes exceeds maximum {1} bytes")]
    ProofTooLarge(usize, usize),
    /// Invalid proof name (empty)
    #[error("invalid proof name: proof names must not be empty")]
    InvalidProofName,
    /// Too many proofs in entry
    #[error("entry has {0} proofs, maximum allowed is {1}")]
    TooManyProofs(usize, usize),
}

impl From<std::fmt::Error> for EntryError {
    fn from(source: std::fmt::Error) -> Self {
        Self::ProofGenerationFailed { source }
    }
}

/// Key errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// Empty key string
    #[error("the key string is empty")]
    EmptyKey,
    /// Missing root key separator
    #[error("key string doesn't begin with the separator: {0}")]
    MissingRootSeparator(String),
    /// Key is not a branch
    #[error("key is not a branch")]
    NotABranch,
    /// Key path too long
    #[error("key path length {0} exceeds maximum {1}")]
    PathTooLong(usize, usize),
    /// Key path too deep
    #[error("key path depth {0} exceeds maximum {1}")]
    PathTooDeep(usize, usize),
}

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KvpError {
    /// Sequence number must be zero
    #[error("seqno must be zero")]
    NonZeroSeqNo,
    /// Invalid sequence number
    #[error("invalid seqno")]
    InvalidSeqNo,
    /// Empty undo stack
    #[error("empty undo stack")]
    EmptyUndoStack,
    /// No Entry Attributes on the undo stack
    #[error("no entry attributes on undo stack")]
    NoEntryAttributes,
    /// Failed to insert kvp
    #[error("kvp insert failed")]
    FailedInsert,
}

/// ProvenanceLog Errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LogError {
    /// Wacc Error
    #[error(transparent)]
    Wacc(#[from] wacc::Error),
    /// Missing sigil
    #[error("missing provenance log sigil")]
    MissingSigil,
    /// Missing vlad
    #[error("missing vlad")]
    MissingVlad,
    /// Missing foot
    #[error("missing foot")]
    MissingFoot,
    /// Missing head
    #[error("missing head")]
    MissingHead,
    /// Missing entries
    #[error("missing entries")]
    MissingEntries,
    /// Broken entry links
    #[error("broken entry links")]
    BrokenEntryLinks,
    /// Broken prev link
    #[error("broken prev link")]
    BrokenPrevLink,
    /// Entry cid mismatch
    #[error("entry cid mismatch")]
    EntryCidMismatch,
    /// Invalid seqno
    #[error("invalid seqno")]
    InvalidSeqno,
    /// Duplicate log entry
    #[error("duplicate log entry")]
    DuplicateEntry(multi_cid::Cid),
    /// Missing lock script for the first entry
    #[error("Missing lock script for the first entry")]
    MissingFirstEntryLockScript,
    /// Verify failed
    #[error("log verify failed: {msg}")]
    VerifyFailed {
        /// Error message describing the verification failure
        msg: String,
        /// The sequence number of the entry that failed verification, if known
        seqno: Option<u64>,
        /// The CID of the entry that failed verification, if known
        entry_cid: Option<multi_cid::Cid>,
    },
    /// Updating kvp failed
    #[error("updating kvp failed: {msg}")]
    UpdateKvpFailed {
        /// Error message describing the KVP update failure
        msg: String,
        /// The sequence number of the entry being processed when update failed, if known
        seqno: Option<u64>,
        /// The CID of the entry being processed when update failed, if known
        entry_cid: Option<multi_cid::Cid>,
    },
    /// Kvp set entry failed
    #[error("kvp set entry failed: {msg}")]
    KvpSetEntryFailed {
        /// Error message describing the KVP set entry failure
        msg: String,
        /// The CID of the entry that failed to be set in the KVP, if known
        entry_cid: Option<multi_cid::Cid>,
    },
    /// Too many entries in log
    #[error("log has {0} entries, maximum allowed is {1}")]
    TooManyEntries(usize, usize),
    /// Invalid Lipmaa link
    ///
    /// This error occurs when an entry's Lipmaa link doesn't point to the correct
    /// entry as calculated by the Lipmaa algorithm. This prevents log traversal attacks.
    ///
    /// # Security
    ///
    /// Lipmaa links provide O(log n) traversal of the log. Invalid links could:
    /// - Break traversal efficiency
    /// - Enable log forgery
    /// - Cause infinite loops in traversal code
    ///
    /// # Recovery
    ///
    /// Ensure entry Lipmaa links are calculated correctly using the Lipmaa algorithm.
    #[error("invalid lipmaa link at seqno {seqno}: expected link to seqno {expected_target}, but found CID mismatch")]
    InvalidLipmaaLink {
        /// The sequence number of the entry with invalid Lipmaa link
        seqno: u64,
        /// The expected Lipmaa target sequence number
        expected_target: u64,
        /// The actual CID the entry's Lipmaa field points to
        #[source]
        actual_cid: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpError {
    /// Invalid operation id
    #[error("invalid operation id {0}")]
    InvalidOperationId(u8),
    /// Invalid operation name
    #[error("invalid operation name {0}")]
    InvalidOperationName(String),
}

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// Missing sigil
    #[error("missing provenance entry sigil")]
    MissingSigil,
    /// Invalid script type id
    #[error("invalid script type id {0}")]
    InvalidScriptId(u8),
    /// Invalid script type name
    #[error("invalid script type name {0}")]
    InvalidScriptName(String),
    /// Missing script code
    #[error("missing script code")]
    MissingCode,
    /// Missing path
    #[error("missing path")]
    MissingPath,
    /// Failed to load script
    #[error("failed to load script: {msg}")]
    LoadingFailed {
        /// Error message describing the loading failure
        msg: String,
        /// The file path that failed to load, if known
        path: Option<String>,
    },
    /// Build failed
    #[error("building script failed")]
    BuildFailed,
    /// invalid wasm script magic value
    #[error("invalid wasm script")]
    InvalidScriptMagic,
    /// Script file too large
    #[error("script file size {0} bytes exceeds maximum {1} bytes")]
    ScriptFileTooLarge(usize, usize),
}

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValueError {
    /// Invalid value type id
    #[error("invalid value type id {0}")]
    InvalidValueId(u8),
    /// Invalid value type name
    #[error("invalid value type name {0}")]
    InvalidValueName(String),
}
