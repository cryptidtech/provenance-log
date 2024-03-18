// SPDX-License-Identifier: FSL-1.1
/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Entry error
    #[error(transparent)]
    Entry(#[from] EntryError),
    /// ProvenanceLog error
    #[error(transparent)]
    Log(#[from] LogError),
    /// Operation error
    #[error(transparent)]
    Op(#[from] OpError),
    /// Pairs error
    #[error(transparent)]
    Pairs(#[from] PairsError),
    /// Script error
    #[error(transparent)]
    Script(#[from] ScriptError),
    /// Operation error
    #[error(transparent)]
    Value(#[from] ValueError),

    /// Multicid error
    #[error(transparent)]
    Multicid(#[from] multicid::Error),
    /// Multicodec Error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// Multihash Error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// Multitrait Error
    #[error(transparent)]
    Multitrait(#[from] multitrait::Error),
    /// Multiutil Error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// ProvenanceLog Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
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
    DuplicateEntry(multicid::Cid),
    /// Missing lock script for the first entry
    #[error("Missing lock script for the first entry")]
    MissingFirstEntryLockScript,
    /// Verify failed
    #[error("Log verify failed {0}")]
    VerifyFailed(String),
}

/// ProvenanceEntry Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// Missing sigil
    #[error("missing provenance entry sigil")]
    MissingSigil,
    /// Invalid version
    #[error("Invalid provenance entry version {0}")]
    InvalidVersion(usize),
    /// Missing vlad
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
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] std::fmt::Error),
    /// Entries are read-only
    #[error("Entry objects are read-only")]
    ReadOnly,
}

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairsError {
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

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// Invalid script type id
    #[error("invalid script type id {0}")]
    InvalidScriptId(u8),
    /// Invalid script type name
    #[error("invalid script type name {0}")]
    InvalidScriptName(String),
    /// Missing script code
    #[error("missing script code")]
    MissingCode,
    /// Failed to load script
    #[error("failed to load script: {0}")]
    LoadingFailed(String),
    /// Build failed
    #[error("building script failed")]
    BuildFailed,
    /// invalid wasm script magic value
    #[error("invalid wasm script")]
    InvalidScriptMagic,
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
pub enum ValueError {
    /// Invalid value type id
    #[error("invalid value type id {0}")]
    InvalidValueId(u8),
    /// Invalid value type name
    #[error("invalid value type name {0}")]
    InvalidValueName(String),
}
