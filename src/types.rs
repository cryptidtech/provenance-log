// SPDX-License-Identifier: FSL-1.1
//! Type-safe wrappers for provenance log primitives
//!
//! This module provides newtype wrappers around primitive types to ensure type safety
//! and prevent accidental misuse of raw integers as sequence numbers or versions.

use crate::Lipmaa;
use std::fmt;

/// Sequence number newtype for type safety
///
/// A `SeqNo` represents the position of an entry within a provenance log. Sequence numbers
/// start at 0 and increment by 1 for each new entry. They provide temporal ordering and
/// are used to coordinate Lipmaa link calculations for efficient log traversal.
///
/// # Thread Safety
///
/// `SeqNo` is `Send + Sync` as it contains only a `u64`.
///
/// # Examples
///
/// ```
/// use provenance_log::SeqNo;
///
/// let first = SeqNo::FIRST;
/// assert_eq!(first.as_u64(), 0);
///
/// let second = first.next();
/// assert_eq!(second.as_u64(), 1);
///
/// // Check if a sequence number is a Lipmaa link point
/// if second.is_lipmaa() {
///     println!("This entry should have a Lipmaa back-link");
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SeqNo(u64);

impl SeqNo {
    /// Create a new sequence number
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw u64 value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get the next sequence number
    pub const fn next(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Check if this sequence number is a Lipmaa link point
    pub fn is_lipmaa(&self) -> bool {
        self.0.is_lipmaa()
    }

    /// Calculate the Lipmaa link target for this sequence number
    ///
    /// Returns the sequence number this entry should link back to via its Lipmaa link.
    /// For entries where `is_lipmaa()` is false, this still returns a valid number
    /// but the entry doesn't need to store a Lipmaa link.
    pub fn lipmaa(&self) -> Self {
        Self(self.0.lipmaa())
    }

    /// The first sequence number (0)
    pub const FIRST: Self = Self(0);
}

impl From<u64> for SeqNo {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SeqNo> for u64 {
    fn from(seqno: SeqNo) -> Self {
        seqno.0
    }
}

impl fmt::Display for SeqNo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Entry/Log version newtype for type safety
///
/// A `Version` tracks the format version of entries and logs to enable future upgrades
/// and backward compatibility checks. The current version is 1.
///
/// # Thread Safety
///
/// `Version` is `Send + Sync` as it contains only a `u64`.
///
/// # Examples
///
/// ```
/// use provenance_log::Version;
///
/// let current = Version::CURRENT;
/// assert_eq!(current.as_u64(), 1);
/// assert!(current.is_supported());
///
/// // Check if a version is supported
/// let future_version = Version::new(99);
/// assert!(!future_version.is_supported());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(u64);

impl Version {
    /// The current supported version
    pub const CURRENT: Self = Self(1);

    /// Create a new version
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw u64 value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Check if this version is supported
    pub const fn is_supported(&self) -> bool {
        self.0 <= Self::CURRENT.0
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl From<u64> for Version {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Version> for u64 {
    fn from(version: Version) -> Self {
        version.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
