// SPDX-License-Identifier: FSL-1.1

//#[cfg(feature = "rhai")]
mod rhai;
//#[cfg(not(feature = "rhai"))]
//mod wsm;

use crate::{entry, error::LogError, Entry, Error, Kvp, Lipmaa, Script};
use core::fmt;
use multibase::Base;
use multicid::{Cid, Vlad};
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varuint};
use std::collections::BTreeMap;

/// the multicodec provenance log codec
pub const SIGIL: Codec = Codec::ProvenanceLog;

/// the current version of provenance entries this supports
pub const LOG_VERSION: u64 = 1;

/// a base encoded provenance log
pub type EncodedLog = BaseEncoded<Log>;

/// the log entries type
pub type Entries = BTreeMap<Cid, Entry>;

/// A Provenance Log
///
/// It's is made up of a series of Entry objects that are linked
/// together using content addressing links. Entry object also has a lipmaa
/// linking structure for efficient O(log n) traversal between any two Entry
/// object in the Log.
#[derive(Clone, Default, PartialEq)]
pub struct Log {
    /// The version of this log format
    pub version: u64,
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
        // add in the provenance log sigil
        v.append(&mut SIGIL.into());
        // add in the version
        v.append(&mut Varuint(val.version).into());
        // add in the vlad
        v.append(&mut val.vlad.clone().into());
        // add in the lock script for the first entry
        v.append(&mut val.first_lock.clone().into());
        // add in the foot cid
        v.append(&mut val.foot.clone().into());
        // add in the head cid
        v.append(&mut val.head.clone().into());
        // add in the entry count
        v.append(&mut Varuint(val.entries.len()).into());
        // add in the entries
        val.entries.iter().for_each(|(cid, entry)| {
            v.append(&mut cid.clone().into());
            v.append(&mut entry.clone().into());
        });
        v
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
        let version = version.to_inner();
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
        // decode the entries
        let (entries, ptr) = match *num_entries {
            0 => (Entries::default(), ptr),
            _ => {
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
            }
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
    kvp: Kvp<'a>,
    lock_scripts: Vec<Script>,
    error: Option<Error>,
}

impl Log {
    /// Returns the Entries with the given seqno
    pub fn seqno(&self, seqno: u64) -> Result<&Entry, Error> {
        self.entries
            .values()
            .find(|entry| entry.seqno() == seqno)
            .ok_or(LogError::InvalidSeqno.into())
    }

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
            kvp: Kvp::default(),
            lock_scripts: vec![self.first_lock.clone()],
            error: None,
        }
    }

    /// Try to add an entry to the p.log
    pub fn try_append(&mut self, mut entry: Entry) -> Result<(), Error> {
        let cid = entry.cid();
        let mut plog = self.clone();
        plog.entries.insert(cid.clone(), entry.clone());
        let vi = plog.verify();
        for ret in vi {
            if let Some(e) = ret.err() {
                return Err(LogError::VerifyFailed(e.to_string()).into());
            }
        }
        // check current entry for lipmaa longhop, and set lipmaa if needed
        let curr_seqno = entry.seqno();
        if curr_seqno.is_lipmaa() {
            let lipmaa = curr_seqno.lipmaa();
            let longhop_entry = plog.seqno(lipmaa)?;
            entry.lipmaa = longhop_entry.cid();
        }
        self.entries.insert(cid, entry);
        Ok(())
    }
}

/// Builder for Log objects
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct Builder {
    version: u64,
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
            version: LOG_VERSION,
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
        let version = self.version;
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
