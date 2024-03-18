// SPDX-License-Identifier: FSL-1.1
use crate::{error::EntryError, Error, Lipmaa, Op, Script, Value};
use core::fmt;
use multibase::Base;
use multicid::{cid, Cid, EncodedCid, Vlad};
use multicodec::Codec;
use multihash::mh;
use multitrait::TryDecodeFrom;
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
    pub(crate) prev: Option<Cid>,
    /// lipmaa link provides O(log n) traversal between entries
    pub(crate) lipmaa: Option<Cid>,
    /// sequence numbering of entries
    pub(crate) seqno: u64,
    /// operations on the namespace in this entry
    pub(crate) ops: Vec<Op>,
    /// the script locking the next entry
    pub(crate) lock: Script,
    /// the script that unlocks this entry, must include all fields except itself
    pub(crate) unlock: Script,
    /// the proof that this entry is valid, this can be a digital signature of
    /// some kind or a zkp or hash preimage. it is the proof data referenced by
    /// the unlock script and required by the lock script in the previous
    /// Entry. this data is generated using the Entry Builder by passing a
    /// closure to the `try_build` function that gets called with the complete
    /// Entry and the proof `Codec` to generate this data.
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

impl wacc::Pairs<Value> for Entry {
    type Error = Error;

    fn get(&self, key: &str) -> Option<Value> {
        let value = match key {
            "entry" => {
                let mut e = self.clone();
                e.proof = Vec::default();
                Some(Value::Data(e.into()))
            }
            "version" => Some(Value::Data(Varuint(self.version).into())),
            "vlad" => Some(Value::Data(self.vlad.clone().into())),
            "prev" => {
                if let Some(prev) = &self.prev {
                    Some(Value::Data(Varbytes(prev.clone().into()).into()))
                } else {
                    Some(Value::Data(Varbytes::default().into()))
                }
            }
            "lipmaa" => {
                if let Some(lipmaa) = &self.lipmaa {
                    Some(Value::Data(Varbytes(lipmaa.clone().into()).into()))
                } else {
                    Some(Value::Data(Varbytes::default().into()))
                }
            }
            "seqno" => Some(Value::Data(Varuint(self.seqno).into())),
            "ops" => {
                let mut v = Vec::new();
                v.append(&mut Varuint(self.ops.len()).into());
                self.ops
                    .iter()
                    .for_each(|op| v.append(&mut op.clone().into()));
                Some(Value::Data(v))
            }
            "lock" => Some(Value::Data(self.lock.clone().into())),
            "unlock" => Some(Value::Data(self.unlock.clone().into())),
            "proof" => Some(Value::Data(self.proof.clone())),
            _ => None,
        };
        //println!("entry get: {} => {:?}", key, value);
        value
    }
    fn put(&mut self, _key: &str, _value: &Value) -> Result<Value, Self::Error> {
        Err(EntryError::ReadOnly.into())
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
        if let Some(prev) = self.prev {
            // encodes the length of the encoded cid as a varuint followed by
            // the cid data itself
            v.append(&mut Varbytes(prev.clone().into()).into());
        } else {
            // encodes zero-length varbytes
            v.append(&mut Varbytes::default().into());
        }
        // add in the lipmaa link
        if let Some(lipmaa) = self.lipmaa {
            // encodes the length of the encoded cid as a varuint followed by
            // the cid data itself
            v.append(&mut Varbytes(lipmaa.clone().into()).into());
        } else {
            // encodes a zero-length varbytes
            v.append(&mut Varbytes::default().into());
        }
        // add in the seqno
        v.append(&mut Varuint(self.seqno).into());
        // add in the number of ops
        v.append(&mut Varuint(self.ops.len()).into());
        // add in the ops
        self.ops
            .iter()
            .for_each(|op| v.append(&mut op.clone().into()));
        // add in the lock script
        v.append(&mut self.lock.clone().into());
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
        // decode the prev cid if there is one
        let (opt, ptr) = Varbytes::try_decode_from(ptr)?;
        let prev = if opt.len() > 0 {
            Some(Cid::try_from(opt.as_slice())?)
        } else {
            None
        };
        // decode the lipmaa cid if there is one
        let (opt, ptr) = Varbytes::try_decode_from(ptr)?;
        let lipmaa = if opt.len() > 0 {
            Some(Cid::try_from(opt.as_slice())?)
        } else {
            None
        };
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
        // decode the lock script
        let (lock, ptr) = Script::try_decode_from(ptr)?;
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
                lock,
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
            EncodedCid::new(Base::Base32Lower, self.prev.clone().unwrap_or_default())
        )
    }
}

impl Default for Entry {
    fn default() -> Self {
        Builder::new()
            .with_vlad(&Vlad::default())
            .with_seqno(0)
            .with_lock(&Script::default())
            .with_unlock(&Script::default())
            .try_build(|_| Ok(()))
            .unwrap()
    }
}

impl Entry {
    /// Get the cid of the previous entry if there is one
    pub fn prev(&self) -> Option<Cid> {
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

    /// get the cid of this entry
    pub fn cid(&self) -> Cid {
        let v: Vec<u8> = self.clone().into();
        cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Raw)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, v.as_slice())
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap()
    }
}

/// Builder for Entry objects
#[derive(Clone, Default)]
pub struct Builder {
    version: u64,
    vlad: Option<Vlad>,
    prev: Option<Cid>,
    lipmaa: Option<Cid>,
    seqno: Option<u64>,
    ops: Option<Vec<Op>>,
    lock: Option<Script>,
    unlock: Option<Script>,
}

impl Builder {
    /// build new with version
    pub fn new() -> Self {
        Self {
            version: ENTRY_VERSION,
            ..Default::default()
        }
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
        self.ops = Some(ops.clone());
        self
    }

    /// Add an op
    pub fn add_op(mut self, op: &Op) -> Self {
        let ops = match self.ops {
            Some(mut ops) => {
                ops.push(op.clone());
                ops
            }
            None => {
                let mut ops = Vec::default();
                ops.push(op.clone());
                ops
            }
        };
        self.ops = Some(ops);
        self
    }

    /// Set the lock script
    pub fn with_lock(mut self, lock: &Script) -> Self {
        self.lock = Some(lock.clone());
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
        let vlad = self.vlad.clone().ok_or_else(|| EntryError::MissingVlad)?;
        let prev = self.prev.clone();
        let seqno = self.seqno.unwrap_or_default();
        let lipmaa = match &self.lipmaa {
            Some(lipmaa) => Some(lipmaa.clone()),
            None => {
                if seqno.is_lipmaa() {
                    return Err(EntryError::MissingLipmaaLink.into());
                } else {
                    None
                }
            }
        };
        let ops = self.ops.clone().unwrap_or_default();
        let lock = self.lock.clone().ok_or(EntryError::MissingLockScript)?;
        let unlock = self.unlock.clone().ok_or(EntryError::MissingUnlockScript)?;

        // first construct an entry with every field except the proof
        let mut entry = Entry {
            version,
            vlad,
            prev,
            seqno,
            lipmaa,
            ops,
            lock,
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
    use multicid::{cid, vlad};
    use multihash::mh;
    use multikey::nonce;

    #[test]
    fn test_builder() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::Noop;
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_lock(&script)
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
            assert_eq!(Op::Noop, op.clone());
        }
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

        let script = Script::Cid(cid);
        let op = Op::Update("move".into(), Value::Str("zig!".into()));
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_lock(&script)
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
                Op::Update("move".into(), Value::Str("zig!".into())),
                op.clone()
            );
        }
        assert_eq!(entry.proof, hex::decode("073b20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
    }
}

/*
in wild's embrace, hearts find their rest,
nature's gifts, for the loving, are best.
in every leaf, in each bird's song,
the wilderness, where souls belong.
*/
