// SPDX-License-Identifier: FSL-1.1
use crate::{error::ScriptError, Error};
use core::fmt;
use multibase::Base;
use multicid::Cid;
use multitrait::{EncodeInto, TryDecodeFrom};
use multiutil::{EncodingInfo, Varbytes};
use std::path::PathBuf;

/// the identifiers for the operations performed on the namespace in each entry
#[repr(u8)]
#[derive(Clone, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum ScriptId {
    /// compiled binary script
    #[default]
    Bin,
    /// uncompiled script code
    Code,
    /// a cid referencing the script data
    Cid,
}

impl ScriptId {
    /// Get the numerical code for the operation id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// convert the operation id to a str
    pub fn as_str(&self) -> &str {
        match self {
            Self::Bin => "bin",
            Self::Code => "code",
            Self::Cid => "cid",
        }
    }
}

impl Into<u8> for ScriptId {
    fn into(self) -> u8 {
        self as u8
    }
}

impl From<&Script> for ScriptId {
    fn from(op: &Script) -> Self {
        match op {
            Script::Bin(_) => Self::Bin,
            Script::Code(_) => Self::Code,
            Script::Cid(_) => Self::Cid,
        }
    }
}

impl TryFrom<u8> for ScriptId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::Bin),
            1 => Ok(Self::Code),
            2 => Ok(Self::Cid),
            _ => Err(ScriptError::InvalidScriptId(c).into()),
        }
    }
}

impl Into<Vec<u8>> for ScriptId {
    fn into(self) -> Vec<u8> {
        let v: u8 = self.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for ScriptId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for ScriptId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for ScriptId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "bin" => Ok(Self::Bin),
            "code" => Ok(Self::Code),
            "cid" => Ok(Self::Cid),
            _ => Err(ScriptError::InvalidScriptName(s.to_string()).into()),
        }
    }
}

impl fmt::Debug for ScriptId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ('{}')", self.as_str(), self.code())
    }
}

/// A Script is either a printable string or a binary blob. These are the values
/// stored in the virtual namespace of the log.
#[derive(Clone, Eq, PartialEq)]
pub enum Script {
    /// An empty value
    Bin(Vec<u8>),
    /// A printable string value
    Code(String),
    /// A binary blob value
    Cid(Cid),
}

impl EncodingInfo for Script {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::Bin(Vec::default())
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bin(v) => v.as_ref(),
            Self::Code(s) => s.as_bytes(),
            Self::Cid(_) => &[],
        }
    }
}

impl Into<Vec<u8>> for Script {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the operation
        v.append(&mut ScriptId::from(&self).into());
        match self {
            Self::Bin(b) => {
                // add in the compiled binary script
                v.append(&mut Varbytes(b.clone()).into());
                v
            }
            Self::Code(s) => {
                // add in the uncompiled script
                v.append(&mut Varbytes(s.as_bytes().to_vec()).into());
                v
            }
            Self::Cid(c) => {
                // add in the cid
                v.append(&mut c.clone().into());
                v
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Script {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (op, _) = Self::try_decode_from(bytes)?;
        Ok(op)
    }
}

impl<'a> TryDecodeFrom<'a> for Script {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the value id
        let (id, ptr) = ScriptId::try_decode_from(bytes)?;
        let (v, ptr) = match id {
            ScriptId::Bin => {
                let (b, ptr) = Varbytes::try_decode_from(ptr)?;
                (Self::Bin(b.to_inner()), ptr)
            }
            ScriptId::Code => {
                let (s, ptr) = Varbytes::try_decode_from(ptr)?;
                let s = String::from_utf8(s.to_inner())?;
                (Self::Code(s), ptr)
            }
            ScriptId::Cid => {
                let (c, ptr) = Cid::try_decode_from(ptr)?;
                (Self::Cid(c), ptr)
            }
        };
        Ok((v, ptr))
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let id = ScriptId::from(self);
        match self {
            Self::Bin(b) => write!(f, "{:?} - {:?}", id, Varbytes(b.clone())),
            Self::Code(s) => write!(f, "{:?} -\n{}", id, s),
            Self::Cid(c) => write!(f, "{:?} - {:?}", id, c),
        }
    }
}

/// Builder for Scripts that helps create them from files and Cid's
#[derive(Clone, Default)]
pub struct Builder {
    bin: Option<PathBuf>,
    code: Option<PathBuf>,
    cid: Option<Cid>,
}

impl Builder {
    /// create a builder from the contents of a compile binary file
    pub fn from_bin_file(pb: &PathBuf) -> Self {
        Self {
            bin: Some(pb.to_owned()),
            ..Default::default()
        }
    }

    /// create a builder from the contents of uncompiled script code
    pub fn from_code_file(pb: &PathBuf) -> Self {
        Self {
            code: Some(pb.to_owned()),
            ..Default::default()
        }
    }

    /// create a builder from the contents of uncompiled script code
    pub fn from_code_cid(cid: &Cid) -> Self {
        Self {
            cid: Some(cid.clone()),
            ..Default::default()
        }
    }

    /// Tries to build a Script from the collected data
    pub fn try_build(&self) -> Result<Script, Error> {
        if let Some(b) = &self.bin {
            let b = std::fs::read(b).map_err(|e| ScriptError::LoadingFailed(e.to_string()))?;
            if b.len() < 4 {
                Err(ScriptError::MissingCode.into())
            } else if b[0] == 0x00 && b[1] == 0x61 && b[2] == 0x73 && b[3] == 0x6d {
                Ok(Script::Bin(b))
            } else {
                Err(ScriptError::InvalidScriptMagic.into())
            }
        } else if let Some(c) = &self.code {
            let c = std::fs::read(c).map_err(|e| ScriptError::LoadingFailed(e.to_string()))?;
            Ok(Script::Code(String::from_utf8(c)?))
        } else if let Some(cid) = &self.cid {
            // TODO: this is where we could handle resolving the Cid into either code or binary
            // script data. for now we're just going to pass it along for later processing
            Ok(Script::Cid(cid.clone()))
        } else {
            Err(ScriptError::BuildFailed.into())
        }
    }
}
