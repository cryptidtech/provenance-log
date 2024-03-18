// SPDX-License-Identifier: FSL-1.1
use crate::{Script, ScriptId};
use core::fmt;
use multicid::Cid;
use multiutil::{EncodedVarbytes, Varbytes};
use serde::{
    de::{EnumAccess, Error, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::ScriptId`]
impl<'de> Deserialize<'de> for ScriptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(ScriptId::try_from(s).map_err(Error::custom)?)
        } else {
            let id: Varbytes = Deserialize::deserialize(deserializer)?;
            Ok(ScriptId::try_from(id.to_inner().as_slice()).map_err(Error::custom)?)
        }
    }
}

/// Deserialize instance of [`crate::Script`]
impl<'de> Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &'static [&'static str] = &["bin", "code", "cid"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Variant {
            Bin,
            Code,
            Cid,
        }

        struct BinVisitor;

        impl<'de> Visitor<'de> for BinVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Bin(b)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let s: &str = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("bin"))?;
                let v = EncodedVarbytes::try_from(s).map_err(Error::custom)?;
                Ok(Script::Bin(v.to_inner().to_vec()))
            }
        }

        struct CodeVisitor;

        impl<'de> Visitor<'de> for CodeVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Code(s)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let s: String = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("code"))?;
                Ok(Script::Code(s))
            }
        }

        struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Update(key, value)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let cid: Cid = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("cid"))?;
                Ok(Script::Cid(cid))
            }
        }

        struct ScriptVisitor;

        impl<'de> Visitor<'de> for ScriptVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script")
            }

            fn visit_enum<V>(self, e: V) -> Result<Self::Value, V::Error>
            where
                V: EnumAccess<'de>,
            {
                match e.variant()? {
                    (Variant::Bin, v) => Ok(v.tuple_variant(1, BinVisitor)?),
                    (Variant::Code, v) => Ok(v.tuple_variant(1, CodeVisitor)?),
                    (Variant::Cid, v) => Ok(v.tuple_variant(1, CidVisitor)?),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_enum("script", VARIANTS, ScriptVisitor)
        } else {
            let (id, bytes): (ScriptId, Varbytes) = Deserialize::deserialize(deserializer)?;
            match id {
                ScriptId::Bin => Ok(Script::Bin(bytes.to_inner())),
                ScriptId::Code => {
                    let code = String::from_utf8(bytes.to_inner()).map_err(Error::custom)?;
                    Ok(Script::Code(code))
                }
                ScriptId::Cid => {
                    let cid = Cid::try_from(bytes.to_inner().as_slice()).map_err(Error::custom)?;
                    Ok(Script::Cid(cid))
                }
            }
        }
    }
}
