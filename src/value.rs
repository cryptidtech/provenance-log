// SPDX-License-Identifier: FSL-1.1
use crate::{error::ValueError, Error};
use core::fmt;
use multi_base::Base;
use multi_trait::{EncodeInto, EncodeIntoBuffer, TryDecodeFrom};
use multi_util::{EncodingInfo, Varbytes};

/// the identifiers for the operations performed on the namespace in each entry
#[repr(u8)]
#[derive(Clone, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum ValueId {
    /// nil value
    #[default]
    Nil,
    /// printable string value
    Str,
    /// binary data value
    Data,
}

impl ValueId {
    /// Get the numerical code for the operation id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// convert the operation id to a str
    pub fn as_str(&self) -> &str {
        match self {
            Self::Nil => "nil",
            Self::Str => "str",
            Self::Data => "data",
        }
    }
}

impl From<ValueId> for u8 {
    fn from(val: ValueId) -> Self {
        val as u8
    }
}

impl From<&Value> for ValueId {
    fn from(op: &Value) -> Self {
        match op {
            Value::Nil => Self::Nil,
            Value::Str(_) => Self::Str,
            Value::Data(_) => Self::Data,
        }
    }
}

impl TryFrom<u8> for ValueId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::Nil),
            1 => Ok(Self::Str),
            2 => Ok(Self::Data),
            _ => Err(ValueError::InvalidValueId(c).into()),
        }
    }
}

impl From<ValueId> for Vec<u8> {
    fn from(val: ValueId) -> Self {
        let v: u8 = val.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for ValueId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for ValueId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for ValueId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "nil" => Ok(Self::Nil),
            "str" => Ok(Self::Str),
            "data" => Ok(Self::Data),
            _ => Err(ValueError::InvalidValueName(s.to_string()).into()),
        }
    }
}

impl fmt::Debug for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ('{}')", self.as_str(), self.code())
    }
}

/// Values stored in the virtual namespace
///
/// A `Value` represents data stored at a leaf key in the provenance log's virtual key-value store.
/// Values can be:
///
/// - **Nil**: Absence of a value (used for deletion or initialization)
/// - **Str**: UTF-8 encoded text data
/// - **Data**: Raw binary data (signatures, hashes, serialized structures, etc.)
///
/// # Examples
///
/// ```
/// use provenance_log::Value;
///
/// // String value
/// let text = Value::Str("Hello, world!".into());
///
/// // Binary data value
/// let data = Value::Data(vec![0x01, 0x02, 0x03]);
///
/// // Nil value
/// let nil = Value::Nil;
///
/// // Access underlying bytes
/// let bytes: &[u8] = text.as_ref();
/// ```
///
/// # Thread Safety
///
/// `Value` is `Send + Sync` as it contains only `String` and `Vec<u8>`.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Value {
    /// An empty value
    #[default]
    Nil,
    /// A printable string value
    Str(String),
    /// A binary blob value
    Data(Vec<u8>),
}

impl EncodingInfo for Value {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl AsRef<[u8]> for Value {
    fn as_ref(&self) -> &[u8] {
        match self {
            Value::Nil => &[],
            Value::Str(s) => s.as_ref(),
            Value::Data(b) => b.as_ref(),
        }
    }
}

impl From<Value> for Vec<u8> {
    fn from(val: Value) -> Self {
        let mut v = Vec::default();
        val.encode_into_buffer(&mut v);
        v
    }
}

impl EncodeIntoBuffer for Value {
    fn encode_into_buffer(&self, output: &mut Vec<u8>) {
        // add in the operation
        u8::from(ValueId::from(self)).encode_into_buffer(output);
        match self {
            Value::Nil => {}
            Value::Str(s) => {
                // add in the string
                s.len().encode_into_buffer(output);
                output.extend_from_slice(s.as_bytes());
            }
            Value::Data(b) => {
                // add in the data
                b.len().encode_into_buffer(output);
                output.extend_from_slice(b);
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Value {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (op, _) = Self::try_decode_from(bytes)?;
        Ok(op)
    }
}

impl<'a> TryDecodeFrom<'a> for Value {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the value id
        let (id, ptr) = ValueId::try_decode_from(bytes)?;
        let (v, ptr) = match id {
            ValueId::Nil => (Self::Nil, ptr),
            ValueId::Str => {
                let (s, ptr) = Varbytes::try_decode_from(ptr)?;
                let s = String::from_utf8(s.to_inner())?;
                (Self::Str(s), ptr)
            }
            ValueId::Data => {
                let (b, ptr) = Varbytes::try_decode_from(ptr)?;
                (Self::Data(b.to_inner()), ptr)
            }
        };
        Ok((v, ptr))
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let id = ValueId::from(self);
        match self {
            Self::Nil => write!(f, "{:?}", id),
            Self::Str(s) => write!(f, "{:?} - \"{}\"", id, s),
            Self::Data(b) => write!(f, "{:?} - {:x?}", id, b.clone()),
        }
    }
}
