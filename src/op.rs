// SPDX-License-Identifier: FSL-1.1
use crate::{error::OpError, Error, Value};
use core::fmt;
use multitrait::{EncodeInto, TryDecodeFrom};
use multiutil::Varbytes;

/// the identifiers for the operations performed on the namespace in each entry
#[repr(u8)]
#[derive(Clone, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum OpId {
    /// noop, no operation
    #[default]
    Noop,
    /// delete the associated key from the key-value store
    Delete,
    /// update/create the associated key with the associated value
    Update,
}

impl OpId {
    /// Get the numerical code for the operation id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// convert the operation id to a str
    pub fn as_str(&self) -> &str {
        match self {
            Self::Noop => "noop",
            Self::Delete => "delete",
            Self::Update => "update",
        }
    }
}

impl Into<u8> for OpId {
    fn into(self) -> u8 {
        self as u8
    }
}

impl From<&Op> for OpId {
    fn from(op: &Op) -> Self {
        match op {
            Op::Noop => Self::Noop,
            Op::Delete(_) => Self::Delete,
            Op::Update(_, _) => Self::Update,
        }
    }
}

impl TryFrom<u8> for OpId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::Noop),
            1 => Ok(Self::Delete),
            2 => Ok(Self::Update),
            _ => Err(OpError::InvalidOperationId(c).into()),
        }
    }
}

impl Into<Vec<u8>> for OpId {
    fn into(self) -> Vec<u8> {
        let v: u8 = self.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for OpId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for OpId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for OpId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "noop" => Ok(Self::Noop),
            "delete" => Ok(Self::Delete),
            "update" => Ok(Self::Update),
            _ => Err(OpError::InvalidOperationName(s.to_string()).into()),
        }
    }
}

impl fmt::Debug for OpId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ('{}')", self.as_str(), self.code())
    }
}

/// the operations performed on the namespace in each entry
#[derive(Clone, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum Op {
    /// no operation
    #[default]
    Noop,
    /// delete the value associated with the key
    Delete(String),
    /// update/create the key value pair
    Update(String, Value),
}

impl Into<Vec<u8>> for Op {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the operation
        v.append(&mut OpId::from(&self).into());
        match self {
            Self::Noop => v,
            Self::Delete(key) => {
                // add in the key string
                v.append(&mut Varbytes(key.as_bytes().to_vec()).into());
                v
            }
            Self::Update(key, value) => {
                // add in the key string
                v.append(&mut Varbytes(key.as_bytes().to_vec()).into());
                // add in the value data
                v.append(&mut value.clone().into());
                v
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Op {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (op, _) = Self::try_decode_from(bytes)?;
        Ok(op)
    }
}

impl<'a> TryDecodeFrom<'a> for Op {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the operation id
        let (id, ptr) = OpId::try_decode_from(bytes)?;
        let (v, ptr) = match id {
            OpId::Noop => (Self::Noop, ptr),
            OpId::Delete => {
                let (key, ptr) = Varbytes::try_decode_from(ptr)?;
                let key = String::from_utf8(key.to_inner())?;
                (Self::Delete(key), ptr)
            }
            OpId::Update => {
                let (key, ptr) = Varbytes::try_decode_from(ptr)?;
                let key = String::from_utf8(key.to_inner())?;
                let (value, ptr) = Value::try_decode_from(ptr)?;
                (Self::Update(key, value), ptr)
            }
        };
        Ok((v, ptr))
    }
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let id = OpId::from(self);
        match self {
            Self::Noop => write!(f, "{:?}", id),
            Self::Delete(key) => write!(f, "{:?} - {}", id, key),
            Self::Update(key, value) => write!(f, "{:?} - {} => {:?}", id, key, value),
        }
    }
}
