#![allow(clippy::needless_collect, clippy::unnecessary_wraps, clippy::too_many_lines, clippy::match_same_arms)]
// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for provenance-log
//!
//! This module contains property-based tests using proptest.

#[cfg(test)]
mod entry_props;

#[cfg(test)]
mod key_props;

#[cfg(test)]
mod log_props;
