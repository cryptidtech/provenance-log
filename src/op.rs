// SPDX-License-Identifier: FSL-1.1
use crate::{error::OpError, Error, Key, Value};
use core::fmt;
use multi_trait::{EncodeInto, EncodeIntoBuffer, TryDecodeFrom};

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

impl From<OpId> for u8 {
    fn from(val: OpId) -> Self {
        val as u8
    }
}

impl From<&Op> for OpId {
    fn from(op: &Op) -> Self {
        match op {
            Op::Noop(_) => Self::Noop,
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

impl From<OpId> for Vec<u8> {
    fn from(val: OpId) -> Self {
        let v: u8 = val.into();
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

/// Operations performed on the virtual namespace
///
/// Each entry in a provenance log contains zero or more operations that modify the virtual
/// key-value store. Operations are applied in order and affect authorization decisions.
///
/// # Operation Types
///
/// - **Noop**: No operation; used to trigger lock script evaluation without modifying state
/// - **Delete**: Remove a key-value pair from the namespace
/// - **Update**: Create or modify a key-value pair (idempotent)
///
/// # Authorization
///
/// Operations trigger lock script evaluation based on their key paths. A lock script at `/users/`
/// will be evaluated for operations on `/users/alice`, `/users/bob/email`, etc.
///
/// # Examples
///
/// ```
/// use provenance_log::{Op, Key, Value};
///
/// // Update a value
/// let update = Op::Update(
///     Key::try_from("/config/timeout").unwrap(),
///     Value::Data(vec![0, 0, 0, 60]) // 60 seconds
/// );
///
/// // Delete a value
/// let delete = Op::Delete(Key::try_from("/temp/session").unwrap());
///
/// // Noop to trigger authorization check without changing state
/// let noop = Op::Noop(Key::try_from("/admin/").unwrap());
///
/// // Get the key from any operation
/// assert_eq!(update.path().to_string(), "/config/timeout");
/// ```
///
/// # Thread Safety
///
/// `Op` is `Send + Sync` as it contains only `Key` and `Value`.
#[derive(Clone, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum Op {
    /// no operation
    Noop(Key),
    /// delete the value associated with the key
    Delete(Key),
    /// update/create the key value pair
    Update(Key, Value),
}

impl Op {
    /// get the key in the op
    pub fn path(&self) -> Key {
        match self {
            Self::Noop(p) => p.clone(),
            Self::Delete(p) => p.clone(),
            Self::Update(p, _) => p.clone(),
        }
    }
}

impl Default for Op {
    fn default() -> Self {
        Op::Noop(Key::default())
    }
}

impl From<Op> for Vec<u8> {
    fn from(val: Op) -> Self {
        let mut v = Vec::default();
        val.encode_into_buffer(&mut v);
        v
    }
}

impl EncodeIntoBuffer for Op {
    fn encode_into_buffer(&self, output: &mut Vec<u8>) {
        // add in the operation
        u8::from(OpId::from(self)).encode_into_buffer(output);
        match self {
            Op::Noop(key) => {
                // add in the key string
                key.encode_into_buffer(output);
            }
            Op::Delete(key) => {
                // add in the key string
                key.encode_into_buffer(output);
            }
            Op::Update(key, value) => {
                // add in the key string
                key.encode_into_buffer(output);
                // add in the value data
                value.encode_into_buffer(output);
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
            OpId::Noop => {
                let (key, ptr) = Key::try_decode_from(ptr)?;
                (Self::Noop(key), ptr)
            }
            OpId::Delete => {
                let (key, ptr) = Key::try_decode_from(ptr)?;
                (Self::Delete(key), ptr)
            }
            OpId::Update => {
                let (key, ptr) = Key::try_decode_from(ptr)?;
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
            Self::Noop(key) => write!(f, "{:?} - {}", id, key),
            Self::Delete(key) => write!(f, "{:?} - {}", id, key),
            Self::Update(key, value) => write!(f, "{:?} - {} => {:?}", id, key, value),
        }
    }
}
