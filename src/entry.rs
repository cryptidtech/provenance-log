// SPDX-License-Identifier: FSL-1.1
use crate::{error::EntryError, Error, Key, Lipmaa, Op, Script};
use core::fmt;
use multibase::Base;
use multicid::{cid, Cid, EncodedCid, Vlad};
use multicodec::Codec;
use multihash::mh;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use std::cmp::Ordering;

/// the multicodec sigil for a provenance entry
pub const SIGIL: Codec = Codec::ProvenanceLogEntry;

/// the current version of provenance entries this supports
pub const ENTRY_VERSION: u64 = 1;

/// a base encoded provenance entry
pub type EncodedEntry = BaseEncoded<Entry>;

/// An Entry represents a single state change associated with a key/value pair
/// in a provenance log.
#[derive(Clone, Eq, PartialEq)]
pub struct Entry {
    /// the entry version
    pub(crate) version: u64,
    /// long lived address for this provenance log
    pub(crate) vlad: Vlad,
    /// link to the previous entry
    pub(crate) prev: Cid,
    /// lipmaa link provides O(log n) traversal between entries
    pub(crate) lipmaa: Cid,
    /// sequence numbering of entries
    pub(crate) seqno: u64,
    /// operations on the namespace in this entry
    pub(crate) ops: Vec<Op>,
    /// the lock scripts associated with keys
    pub(crate) locks: Vec<Script>,
    /// the script that unlocks this entry, must include all fields except itself
    pub(crate) unlock: Script,
    /// the proof that this entry is valid, this can be a digital signature of
    /// some kind or a zkp or hash preimage. it is the proof data referenced by
    /// the unlock script and required by the lock script in the previous
    /// Entry. this data is generated using the Entry Builder by passing a
    /// closure to the `try_build` function that gets called with the complete
    /// serialized Entry to generate this data.
    pub(crate) proof: Vec<u8>,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.seqno == other.seqno {
            Ordering::Equal
        } else if self.seqno < other.seqno {
            Ordering::Less
        } else {
            Ordering::Greater
        }
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
        let value = match key {
            "/entry/" => {
                let mut e = self.clone();
                e.proof = Vec::default();
                Some(wacc::Value::Bin(e.into()))
            }
            "/entry/version" => Some(wacc::Value::Bin(Varuint(self.version).into())),
            "/entry/vlad" => Some(wacc::Value::Bin(self.vlad.clone().into())),
            "/entry/prev" => Some(wacc::Value::Bin(self.prev.clone().into())),
            "/entry/lipmaa" => Some(wacc::Value::Bin(self.lipmaa.clone().into())),
            "/entry/seqno" => Some(wacc::Value::Bin(Varuint(self.seqno).into())),
            "/entry/ops" => {
                let mut v = Vec::new();
                v.append(&mut Varuint(self.ops.len()).into());
                self.ops
                    .iter()
                    .for_each(|op| v.append(&mut op.clone().into()));
                Some(wacc::Value::Bin(v))
            }
            // TODO: make this accessible via an iterator
            //"/entry/locks" => Some(wacc::Value::Bin(self.locks.clone().into())),
            "/entry/unlock" => Some(wacc::Value::Bin(self.unlock.clone().into())),
            "/entry/proof" => Some(wacc::Value::Bin(self.proof.clone())),
            _ => None,
        };
        value
    }

    fn put(&mut self, _key: &str, _value: &wacc::Value) -> Option<wacc::Value> {
        None
    }
}

impl Into<Vec<u8>> for Entry {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the entry sigil
        v.append(&mut SIGIL.into());
        // add in the version
        v.append(&mut Varuint(self.version).into());
        // add in the vlad
        v.append(&mut self.vlad.clone().into());
        // add in the prev link
        v.append(&mut self.prev.clone().into());
        // add in the lipmaa link
        v.append(&mut self.lipmaa.clone().into());
        // add in the seqno
        v.append(&mut Varuint(self.seqno).into());
        // add in the number of ops
        v.append(&mut Varuint(self.ops.len()).into());
        // add in the ops
        self.ops
            .iter()
            .for_each(|op| v.append(&mut op.clone().into()));
        // first add the number of keys
        v.append(&mut Varuint(self.locks.len()).into());
        // add in the locks
        self.locks
            .iter()
            .for_each(|script| v.append(&mut script.clone().into()));
        // add in the unlock script
        v.append(&mut self.unlock.clone().into());
        // add in the proof
        v.append(&mut Varbytes(self.proof.clone()).into());
        v
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
        let version = version.to_inner();
        if version != ENTRY_VERSION {
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
        let seqno = seqno.to_inner();
        // decode the number of ops
        let (num_ops, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the ops
        let (ops, ptr) = match *num_ops {
            0 => (Vec::default(), ptr),
            _ => {
                let mut ops = Vec::with_capacity(*num_ops);
                let mut p = ptr;
                for _ in 0..*num_ops {
                    let (op, ptr) = Op::try_decode_from(p)?;
                    ops.push(op);
                    p = ptr;
                }
                (ops, p)
            }
        };
        // decode the number of lock scripts
        let (num_locks, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the ops
        let (locks, ptr) = match *num_locks {
            0 => (Vec::default(), ptr),
            _ => {
                let mut locks = Vec::with_capacity(*num_locks);
                let mut p = ptr;
                for _ in 0..*num_locks {
                    let (lock, ptr) = Script::try_decode_from(p)?;
                    locks.push(lock);
                    p = ptr;
                }
                (locks, p)
            }
        };
        // decode the unlock script
        let (unlock, ptr) = Script::try_decode_from(ptr)?;
        // decode the proof
        let (proof, ptr) = Varbytes::try_decode_from(ptr)?;
        let proof = proof.to_inner();

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
                proof,
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
            .with_seqno(0)
            .with_unlock(&Script::default())
            .try_build(|_| Ok(()))
            .unwrap()
    }
}

impl Entry {
    /// Get the cid of the previous entry if there is one
    pub fn prev(&self) -> Cid {
        self.prev.clone()
    }

    /// Get the sequence number of the entry
    pub fn seqno(&self) -> u64 {
        self.seqno
    }

    /// get an iterator over the operations in the entry
    pub fn ops(&self) -> impl Iterator<Item = &Op> {
        self.ops.iter()
    }

    /// get an iterator over the lock scripts 
    pub fn locks(&self) -> impl Iterator<Item = &Script> {
        self.locks.iter()
    }

    /// get the cid of this entry
    pub fn cid(&self) -> Cid {
        let v: Vec<u8> = self.clone().into();
        cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, v.as_slice())
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap()
    }

    /// get the longest common branch context from the ops
    pub fn context(&self) -> Key {
        if self.ops.len() == 0 {
            Key::default()
        } else {
            // get the first branch
            let mut ctx = self.ops.first().unwrap().clone().key().branch();

            // got through the rest looking for the shortest one
            for k in self.ops.iter() {
                ctx = k.key().branch().longest_common_branch(&ctx);
            }
            ctx
        }
    }
}

/// Builder for Entry objects
#[derive(Clone)]
pub struct Builder {
    version: u64,
    vlad: Option<Vlad>,
    prev: Option<Cid>,
    lipmaa: Option<Cid>,
    seqno: Option<u64>,
    ops: Vec<Op>,
    locks: Vec<Script>,
    unlock: Option<Script>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            version: ENTRY_VERSION,
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

impl Builder {
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
    pub fn with_seqno(mut self, seqno: u64) -> Self {
        self.seqno = Some(seqno);
        self
    }

    /// Set the lipmaa Cid
    pub fn with_lipmaa(mut self, lipmaa: &Cid) -> Self {
        self.lipmaa = Some(lipmaa.clone());
        self
    }

    /// Set the ops
    pub fn with_ops(mut self, ops: &Vec<Op>) -> Self {
        self.ops = ops.clone();
        self
    }

    /// Add an op
    pub fn add_op(mut self, op: &Op) -> Self {
        self.ops.push(op.clone());
        self
    }

    /// Set the lock scripts
    pub fn with_locks(mut self, locks: &Vec<Script>) -> Self {
        self.locks = locks.clone();
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

    /// Build the Entry from the provided data and then call the `gen_proof`
    /// closure to generate a lock script and proof
    pub fn try_build<F>(&self, mut gen_proof: F) -> Result<Entry, Error>
    where
        F: FnMut(&mut Entry) -> Result<(), Error>,
    {
        let version = self.version;
        let vlad = self.vlad.clone().ok_or(EntryError::MissingVlad)?;
        let prev = self.prev.clone().unwrap_or_else(|| Cid::null());
        let seqno = self.seqno.unwrap_or_default();
        let lipmaa = if seqno.is_lipmaa() {
            self.lipmaa.clone().ok_or(EntryError::MissingLipmaaLink)?
        } else {
            Cid::null()
        };
        let unlock = self.unlock.clone().ok_or(EntryError::MissingUnlockScript)?;

        // first construct an entry with every field except the proof
        let mut entry = Entry {
            version,
            vlad,
            prev,
            seqno,
            lipmaa,
            ops: self.ops.clone(),
            locks: self.locks.clone(),
            unlock,
            proof: Vec::default(),
        };

        // call the gen_proof closure to create and store the proof data
        gen_proof(&mut entry)?;

        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;
    use multicid::vlad;
    use multikey::nonce;

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
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }

    #[test]
    fn test_preimage() {
        // build a nonce
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
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
                let mut b = Vec::default();
                b.append(&mut e.vlad.clone().into());
                e.proof = b;
                Ok(())
            })
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(
                Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into())),
                op.clone()
            );
        }
        assert_eq!(entry.proof, hex::decode("073b20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }
}

/*
in wild's embrace, hearts find their rest,
nature's gifts, for the loving, are best.
in every leaf, in each bird's song,
the wilderness, where souls belong.
*/
