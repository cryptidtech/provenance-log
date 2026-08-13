// SPDX-License-Identifier: FSL-1.1
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::use_self,
    clippy::uninlined_format_args,
    clippy::manual_string_new,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::should_panic_without_expect,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::elidable_lifetime_names,
    clippy::explicit_iter_loop,
    clippy::too_long_first_doc_paragraph,
    clippy::return_self_not_must_use,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::needless_else,
    clippy::needless_for_each,
    clippy::redundant_else,
    clippy::struct_field_names,
    clippy::collection_is_never_read
)]
//! # provenance-log - Programmable Cryptographic Provenance Logs
//!
//! This crate provides a tamper-evident, cryptographically verifiable log system for tracking
//! state changes over time. Each entry in the log represents a state transition that must be
//! cryptographically authorized by the previous entry's lock scripts.
//!
//! ## Features
//!
//! - **Cryptographic Verification**: Each entry is linked via content-addressed hashes (CIDs)
//! - **Programmable Authorization**: Lock and unlock scripts written in WebAssembly control state transitions
//! - **Efficient Traversal**: Lipmaa links provide O(log n) random access to historical entries
//! - **Virtual Key-Value Store**: Entries contain operations that modify a virtual namespace
//! - **Delegation Support**: Fine-grained authority delegation via hierarchical key paths
//! - **Forking Support**: Multiple logs can share history via VLAD identifiers
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use provenance_log::{Entry, Log, Script, Op, Key, Value, SeqNo};
//! use multi_vlad::Vlad;
//!
//! // Create a VLAD (Verifiable Log Address) for your log
//! let vlad = Vlad::default();
//!
//! // Create a lock script that authorizes the first entry
//! let first_lock = Script::default();
//!
//! // Build the first entry
//! let entry = provenance_log::entry::Builder::default()
//!     .with_vlad(&vlad)
//!     .with_seqno(SeqNo::FIRST)
//!     .with_unlock(&Script::default())
//!     .add_op(&Op::Update(
//!         Key::try_from("/data").unwrap(),
//!         Value::Str("hello".into())
//!     ))
//!     .try_build(|_| Ok(std::collections::BTreeMap::new()))
//!     .unwrap();
//!
//! // Build a log containing the entry
//! let log = provenance_log::log::Builder::new()
//!     .with_vlad(&vlad)
//!     .with_first_lock(&first_lock)
//!     .append_entry(&entry)
//!     .try_build()
//!     .unwrap();
//!
//! // Verify all entries in the log
//! for result in log.verify() {
//!     match result {
//!         Ok((check_count, entry, kvp)) => {
//!             println!("Entry #{} verified with {} checks", entry.seqno(), check_count);
//!         }
//!         Err(e) => {
//!             eprintln!("Verification failed: {}", e);
//!             break;
//!         }
//!     }
//! }
//! ```
//!
//! ## Security
//!
//! This crate implements several security measures:
//!
//! - **Resource Limits**: Configurable limits on entry count, operations per entry, and proof sizes
//! - **Script Execution Limits**: WebAssembly scripts run with fuel limits and memory constraints
//! - **Input Validation**: All key paths, operation counts, and data sizes are validated
//!
//! See the [`limits`] module for specific resource constraints.
//!
//! ## Thread Safety
//!
//! All public types in this crate are `Send` and `Sync` where their underlying data structures
//! permit. `Entry` and `Log` types can be safely shared across threads.
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Resource limits for security
pub mod limits {
    /// Maximum number of operations permitted per entry
    pub const MAX_OPS_PER_ENTRY: usize = 1000;

    /// Maximum number of lock scripts permitted per entry
    pub const MAX_LOCKS_PER_ENTRY: usize = 100;

    /// Maximum number of entries permitted per log
    pub const MAX_ENTRIES_PER_LOG: usize = 1_000_000;

    /// Maximum proof size in bytes per proof (10 MB)
    pub const MAX_PROOF_SIZE: usize = 10 * 1024 * 1024;

    /// Maximum number of named proofs per entry
    pub const MAX_PROOFS_PER_ENTRY: usize = 16;

    /// Maximum script size in bytes when loading from file (5 MB)
    pub const MAX_SCRIPT_FILE_SIZE: usize = 5 * 1024 * 1024;

    /// Maximum key path length in characters
    pub const MAX_KEY_PATH_LENGTH: usize = 1024;

    /// Maximum key path depth (number of separators)
    pub const MAX_KEY_PATH_DEPTH: usize = 32;
}

/// Provenance log entry related functions
pub mod entry;
pub use entry::{EncodedEntry, Entry};

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Key-path used in the Kvp
pub mod key;
pub use key::Key;

/// Lipmaa numbering for sequence numbers
pub mod lipmaa;
pub use lipmaa::Lipmaa;

/// Provenance log related functions
pub mod log;
pub use log::{EncodedLog, Log};

/// Ops for the plog virtual namespace
pub mod op;
pub use op::{Op, OpId};

/// The virtual key-value pair store
pub mod pairs;
pub use pairs::Kvp;

/// Script related functions
pub mod script;
pub use script::{EncodedScript, Script, ScriptId};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// The parameter and return value stack type
pub mod stack;
pub use stack::Stk;

/// Entry Value related functions
pub mod value;
pub use value::{Value, ValueId};

/// Type-safe wrappers
pub mod types;
pub use types::{SeqNo, Version};

/// Prelude module for convenient imports
///
/// This module re-exports all commonly used types and traits from this crate,
/// along with essential dependencies from the `bs-*` ecosystem.
///
/// # Usage
///
/// ```rust
/// use provenance_log::prelude::*;
///
/// // Now you have access to all major types:
/// // Entry, Log, Key, Value, Op, Script, SeqNo, Version
/// // Plus encoding utilities: Base, Codec, BaseEncoded
/// ```
pub mod prelude {
    pub use super::*;
    /// Re-exports from multi-base for encoding support
    pub use multi_base::Base;
    /// Re-exports from multi-codec for codec support
    pub use multi_codec::Codec;
    /// Re-exports from multi-util for base encoding utilities
    pub use multi_util::BaseEncoded;
}
