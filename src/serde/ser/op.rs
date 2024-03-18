// SPDX-License-Identifier: FSL-1.1
use crate::{Op, OpId, Value};
use multiutil::Varbytes;
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
            Varbytes(self.clone().into()).serialize(serializer)
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
                Self::Noop => serializer.serialize_unit_variant(
                    "op",
                    OpId::Noop.code() as u32,
                    OpId::Noop.as_str(),
                ),
                Self::Delete(key) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        OpId::Delete.code() as u32,
                        OpId::Delete.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.end()
                }
                Self::Update(key, value) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        OpId::Update.code() as u32,
                        OpId::Update.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.serialize_field(&value)?;
                    ss.end()
                }
            }
        } else {
            // regardless of the enum variant, we serialize a tuple of
            // (OpId, Varbytes, Value) and a Value serializes as a (ValueId, Varbytes)
            match self {
                Self::Noop => {
                    (OpId::from(self), Varbytes::default(), Value::default()).serialize(serializer)
                }
                Self::Delete(key) => (
                    OpId::from(self),
                    Varbytes(key.as_bytes().to_vec()),
                    Value::default(),
                )
                    .serialize(serializer),
                Self::Update(key, value) => {
                    (OpId::from(self), Varbytes(key.as_bytes().to_vec()), value)
                        .serialize(serializer)
                }
            }
        }
    }
}
