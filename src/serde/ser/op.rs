// SPDX-License-Identifier: FSL-1.1
use crate::{Op, OpId};
use multi_trait::EncodeIntoBuffer;
use multi_util::Varbytes;
use serde::ser::{self, SerializeTupleVariant};

/// Serialize instance of [`crate::OpId`]
impl ser::Serialize for OpId {
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

/// Serialize instance of [`crate::Op`]
impl ser::Serialize for Op {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Noop(key) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        u32::from(OpId::Noop.code()),
                        OpId::Noop.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.end()
                }
                Self::Delete(key) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        u32::from(OpId::Delete.code()),
                        OpId::Delete.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.end()
                }
                Self::Update(key, value) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        u32::from(OpId::Update.code()),
                        OpId::Update.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.serialize_field(&value)?;
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
