// SPDX-License-Identifier: FSL-1.1
use crate::{entry, error::LogError, Entry, Error, Kvp, Script, Stk};
use core::fmt;
use multibase::Base;
use multicid::{Cid, Vlad};
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varuint};
use std::collections::BTreeMap;
use wacc::{prelude::StoreLimitsBuilder, vm};

/// the multicodec provenance log codec
pub const SIGIL: Codec = Codec::ProvenanceLog;

/// the current version of provenance entries this supports
pub const LOG_VERSION: u64 = 1;

/// a base encoded provenance log
pub type EncodedLog = BaseEncoded<Log>;

/// the log entries type
pub type Entries = BTreeMap<Cid, Entry>;

/// A Provenance Log is made up of a series of Entry objects that are linked
/// together using content addressing links. Entry object also has a lipmaa
/// linking structure for efficient O(log n) traversal between any two Entry
/// object in the Log.
#[derive(Clone, Default)]
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

impl Into<Vec<u8>> for Log {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the provenance log sigil
        v.append(&mut SIGIL.into());
        // add in the version
        v.append(&mut Varuint(self.version).into());
        // add in the vlad
        v.append(&mut self.vlad.clone().into());
        // add in the lock script for the first entry
        v.append(&mut self.first_lock.clone().into());
        // add in the foot cid
        v.append(&mut self.foot.clone().into());
        // add in the head cid
        v.append(&mut self.head.clone().into());
        // add in the entry count
        v.append(&mut Varuint(self.entries.len()).into());
        // add in the entries
        self.entries.iter().for_each(|(cid, entry)| {
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
    current: Option<usize>,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = &'a Entry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.current {
            if current < self.entries.len() {
                self.current = Some(current + 1);
                Some(self.entries[current])
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Log {
    /// get an iterator over the entries in from head to foot
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        // get a list of Entry references
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        // sort them by seqno
        entries.sort();

        let current = if entries.len() > 0 { Some(0) } else { None };

        EntryIter {
            entries: entries.clone(),
            current,
        }
    }

    /// Verifies all entries in the log
    pub fn verify(&self) -> Result<(), Error> {
        let mut kvp = Kvp::default();
        let mut seqno: Option<u64> = None;
        let mut lock = self.first_lock.clone();
        for entry in self.iter() {
            let mut pstack = Stk::default();
            let mut rstack = Stk::default();

            // check the seqno meet the criteria
            if let Some(s) = seqno {
                if entry.seqno() == s + 1 {
                    seqno = Some(entry.seqno());
                } else {
                    return Err(LogError::InvalidSeqno.into());
                }
            } else {
                seqno = Some(entry.seqno());
            }

            // 'unlock:
            let result = {
                // run the unlock script using the entry as the kvp to get the
                // stack in the vm::Context set up.
                let unlock_ctx = vm::Context {
                    pairs: entry,
                    pstack: &mut pstack,
                    rstack: &mut rstack,
                    check_count: 0,
                    log: Vec::default(),
                    limiter: StoreLimitsBuilder::new()
                        .memory_size(1 << 16)
                        .instances(2)
                        .memories(1)
                        .build(),
                };

                let mut instance = vm::Builder::new()
                    .with_context(unlock_ctx)
                    .with_bytes(entry.unlock.clone())
                    .try_build()
                    .map_err(|e| LogError::Wacc(e))?;

                // run the unlock script
                instance
                    .run("for_great_justice")
                    .map_err(|e| LogError::Wacc(e))?
            };

            if !result {
                return Err(LogError::VerifyFailed(format!("unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}", rstack, pstack)).into());
            }

            // set the entry to look into for proof and message values
            kvp.set_entry(entry)?;

            // if this is the first entry, then we also need to apply the
            // mutation ops
            if entry.seqno() == 0 {
                kvp.apply_entry_ops(entry)?;
            }

            // 'lock:
            let result = {
                let lock_ctx = vm::Context {
                    pairs: &kvp,
                    pstack: &mut pstack,
                    rstack: &mut rstack,
                    check_count: 0,
                    log: Vec::default(),
                    limiter: StoreLimitsBuilder::new()
                        .memory_size(1 << 16)
                        .instances(2)
                        .memories(1)
                        .build(),
                };

                let mut instance = vm::Builder::new()
                    .with_context(lock_ctx)
                    .with_bytes(lock.clone())
                    .try_build()
                    .map_err(|e| LogError::Wacc(e))?;

                // run the unlock script
                instance
                    .run("move_every_zig")
                    .map_err(|e| LogError::Wacc(e))?
            };

            if result == true {
                // if the entry verifies, apply it's mutataions to the kvp
                // the 0th entry has already been applied at this point so no
                // need to do it here
                if entry.seqno() > 0 {
                    kvp.apply_entry_ops(entry)?;
                }
                // update the lock script to validate the next entry
                lock = entry.lock.clone();
            } else {
                return Err(LogError::VerifyFailed(format!("unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}", rstack, pstack)).into());
            }
        }
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
        if self.entries.len() == 0 {
            self.foot = Some(cid.clone());
        }
        self.entries.insert(cid.clone(), entry.clone());
        self
    }

    /// Try to build the Log
    pub fn try_build(&self) -> Result<Log, Error> {
        let version = self.version;
        let vlad = self.vlad.clone().ok_or_else(|| LogError::MissingVlad)?;
        let first_lock = self
            .first_lock
            .clone()
            .ok_or_else(|| LogError::MissingFirstEntryLockScript)?;
        let foot = self.foot.clone().ok_or_else(|| LogError::MissingFoot)?;
        let head = self.head.clone().ok_or_else(|| LogError::MissingHead)?;
        let entries = self.entries.clone();
        if entries.len() == 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{entry, Op, Script, Value};
    use multicid::{cid, vlad};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::{mk, EncodedMultikey, Multikey, Views};
    use std::path::PathBuf;

    fn load_script(file_name: &str) -> Script {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("examples");
        pb.push("wast");
        pb.push(file_name);
        crate::script::Builder::from_code_file(&pb)
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
        let ephemeral = EncodedMultikey::try_from(
            "zF3WX3Dwnv7jv2nPfYL6e2XaLdNyaiwkPyzEtgw65d872KYG22jezzuYPtrds8WSJ3Sv8SCA",
        )
        .unwrap();
        let key = mk::EncodedMultikey::try_from(
            "zF3WX3Dwnv7jv2nPfYL6e2XaLdNyfeuKuXMPzh4bk7jXP5cmP5woZkUvVz8GGpAEQtqEK1yx",
        )
        .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        // build a vlad from the cid
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        // load the entry scripts
        let lock = load_script("lock.wast");
        let unlock = load_script("unlock.wast");
        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey_op = get_key_update_op("/pubkey", &key);

        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .with_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&ephemeral_op)
            .add_op(&pubkey_op)
            .try_build(|e| {
                // get the serialized version of the entry (with empty proof)
                let ev: Vec<u8> = e.clone().into();
                // get the signing view on the multikey
                let sv = ephemeral.sign_view().unwrap();
                // generate the signature over the event
                let ms = sv.sign(&ev, false, None).unwrap();
                // store the signature as proof
                e.proof = ms.into();
                Ok(())
            })
            .unwrap();

        // load the first lock script
        let first = load_script("first.wast");

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
        assert!(log.verify().is_ok());
    }

    #[test]
    fn test_entry_iterator() {
        let ephemeral = EncodedMultikey::try_from(
            "zF3WX3Dwnv7jv2nPfYL6e2XaLdNyaiwkPyzEtgw65d872KYG22jezzuYPtrds8WSJ3Sv8SCA",
        )
        .unwrap();
        let key1 = mk::EncodedMultikey::try_from(
            "zF3WX3Dwnv7jv2nPfYL6e2XaLdNyfeuKuXMPzh4bk7jXP5cmP5woZkUvVz8GGpAEQtqEK1yx",
        )
        .unwrap();
        let key2 = mk::EncodedMultikey::try_from(
            "zVCYiTqf3RfiqqE4RxExy9wNL5MoFGzSGgBNqQRAMhX6t43UCRx3kxBL5Lf47tifh",
        )
        .unwrap();
        let key3 = mk::EncodedMultikey::try_from(
            "zVCf3r3QpMWktTrCdJyRyAoCLd5sYWabKFMoj242TdbX2mvsEDnFWnSDznbZcSYLE",
        )
        .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        // create a vlad
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey1_op = get_key_update_op("/pubkey", &key1);
        let pubkey2_op = get_key_update_op("/pubkey", &key2);
        let pubkey3_op = get_key_update_op("/pubkey", &key3);
        let preimage1_op = get_hash_update_op("/hash", "for great justice");
        let preimage2_op = get_hash_update_op("/hash", "move every zig");

        // load the entry scripts
        let lock = load_script("lock.wast");
        let unlock = load_script("unlock.wast");

        // create the first, self-signed Entry object
        let e1 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(0)
            .with_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&ephemeral_op)
            .add_op(&pubkey1_op)
            .add_op(&preimage1_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = ephemeral.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                e.proof = ms.into();
                Ok(())
            })
            .unwrap();

        //println!("{:?}", e1);
        let e2 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(1)
            .with_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&Op::Delete("/ephemeral".try_into().unwrap()))
            .add_op(&pubkey2_op)
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key1.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                e.proof = ms.into();
                Ok(())
            })
            .unwrap();

        //println!("{:?}", e2);
        let e3 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(2)
            .with_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key2.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                e.proof = ms.into();
                Ok(())
            })
            .unwrap();

        //println!("{:?}", e3);
        let e4 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(3)
            .with_lock(&lock)
            .with_unlock(&unlock)
            .with_prev(&e3.cid())
            .add_op(&pubkey3_op)
            .add_op(&preimage2_op)
            .try_build(|e| {
                e.proof = "for great justice".as_bytes().to_vec();
                Ok(())
            })
            .unwrap();
        //println!("{:?}", e4);

        // load the first lock script
        let first = load_script("first.wast");

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
        match log.verify() {
            Ok(_) => println!("log.verify() worked!!"),
            Err(e) => {
                println!("verify failed: {}", e.to_string());
                panic!()
            }
        }
    }
}

/*
the gifts of wilderness are given
—in no small measure or part—
to those who call it livin'
having outside inside their heart
*/
