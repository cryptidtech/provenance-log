// SPDX-License-Identifier: FSL-1.1
use crate::{entry::SIGIL, Entry, Op, Script};
use core::fmt;
use multicid::{Cid, Vlad};
use multicodec::Codec;
use multiutil::Varbytes;
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Entry`]
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] = &[
            "version", "vlad", "prev", "lipmaa", "seqno", "ops", "lock", "unlock", "proof",
        ];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Vlad,
            Prev,
            Lipmaa,
            Seqno,
            Ops,
            Lock,
            Unlock,
            Proof,
        }

        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = Entry;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Entry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut version = None;
                let mut vlad = None;
                let mut prev = None;
                let mut lipmaa = None;
                let mut seqno = None;
                let mut ops = None;
                let mut lock = None;
                let mut unlock = None;
                let mut proof = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Version => {
                            if version.is_some() {
                                return Err(Error::duplicate_field("version"));
                            }
                            let v: u64 = map.next_value()?;
                            version = Some(v);
                        }
                        Field::Vlad => {
                            if vlad.is_some() {
                                return Err(Error::duplicate_field("vlad"));
                            }
                            let v: Vlad = map.next_value()?;
                            vlad = Some(v);
                        }
                        Field::Prev => {
                            if prev.is_some() {
                                return Err(Error::duplicate_field("prev"));
                            }
                            let c: Cid = map.next_value()?;
                            prev = Some(c);
                        }
                        Field::Lipmaa => {
                            if lipmaa.is_some() {
                                return Err(Error::duplicate_field("lipmaa"));
                            }
                            let c: Cid = map.next_value()?;
                            lipmaa = Some(c);
                        }
                        Field::Seqno => {
                            if seqno.is_some() {
                                return Err(Error::duplicate_field("seqno"));
                            }
                            let v: u64 = map.next_value()?;
                            seqno = Some(v);
                        }
                        Field::Ops => {
                            if ops.is_some() {
                                return Err(Error::duplicate_field("ops"));
                            }
                            let o: Vec<Op> = map.next_value()?;
                            ops = Some(o);
                        }
                        Field::Lock => {
                            if lock.is_some() {
                                return Err(Error::duplicate_field("lock"));
                            }
                            let s: Script = map.next_value()?;
                            lock = Some(s);
                        }
                        Field::Unlock => {
                            if unlock.is_some() {
                                return Err(Error::duplicate_field("unlock"));
                            }
                            let s: Script = map.next_value()?;
                            unlock = Some(s);
                        }
                        Field::Proof => {
                            if proof.is_some() {
                                return Err(Error::duplicate_field("proof"));
                            }
                            let v: Varbytes = map.next_value()?;
                            proof = Some(v.to_inner());
                        }
                    }
                }
                let version = version.ok_or_else(|| Error::missing_field("version"))?;
                let vlad = vlad.ok_or_else(|| Error::missing_field("vlad"))?;
                let seqno = seqno.ok_or_else(|| Error::missing_field("seqno"))?;
                let ops = ops.ok_or_else(|| Error::missing_field("ops"))?;
                let lock = lock.ok_or_else(|| Error::missing_field("lock"))?;
                let unlock = unlock.ok_or_else(|| Error::missing_field("unlock"))?;
                let proof = proof.ok_or_else(|| Error::missing_field("proof"))?;
                Ok(Self::Value {
                    version,
                    vlad,
                    prev,
                    lipmaa,
                    seqno,
                    ops,
                    lock,
                    unlock,
                    proof,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, EntryVisitor)
        } else {
            let (sigil, version, vlad, prev, lipmaa, seqno, ops, lock, unlock, proof): (
                Codec,
                u64,
                Vlad,
                Varbytes,
                Varbytes,
                u64,
                Vec<Op>,
                Script,
                Script,
                Varbytes,
            ) = Deserialize::deserialize(deserializer)?;

            if sigil != SIGIL {
                return Err(Error::custom("deserialized sigil is not an Entry sigil"));
            }
            let prev = {
                let p = prev.to_inner();
                match p.len() {
                    0 => None,
                    _ => Some(Cid::try_from(p.as_slice()).map_err(Error::custom)?),
                }
            };
            let lipmaa = {
                let l = lipmaa.to_inner();
                match l.len() {
                    0 => None,
                    _ => Some(Cid::try_from(l.as_slice()).map_err(Error::custom)?),
                }
            };
            let proof = proof.to_inner();

            Ok(Self {
                version,
                vlad,
                prev,
                lipmaa,
                seqno,
                ops,
                lock,
                unlock,
                proof,
            })
        }
    }
}
