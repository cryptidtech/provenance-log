// SPDX-License-Identifier: FSL-1.1
use crate::{script::SIGIL, Script, ScriptId};
use multi_trait::EncodeIntoBuffer;
use multi_util::{EncodingInfo, Varbytes};
use serde::ser::{self, SerializeTupleVariant};

/// Serialize instance of [`crate::ScriptId`]
impl ser::Serialize for ScriptId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            Varbytes::new(self.clone().into()).serialize(serializer)
        }
    }
}

/// Serialize instance of [`crate::Script`]
impl ser::Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Bin(p, b) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        u32::from(ScriptId::Bin.code()),
                        ScriptId::Bin.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&Varbytes::encoded_new(self.encoding(), b.clone()))?;
                    ss.end()
                }
                Self::Code(p, s) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        u32::from(ScriptId::Code.code()),
                        ScriptId::Code.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&s)?;
                    ss.end()
                }
                Self::Cid(p, cid) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        u32::from(ScriptId::Cid.code()),
                        ScriptId::Cid.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&cid)?;
                    ss.end()
                }
            }
        } else {
            let mut v = Vec::new();
            self.encode_into_buffer(&mut v);
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
