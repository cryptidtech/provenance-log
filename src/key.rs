// SPDX-License-Identifier: FSL-1.1
use crate::{error::KeyError, Error};
use std::fmt;
use multibase::Base;
use multitrait::TryDecodeFrom;
use multiutil::{EncodingInfo, Varbytes};


/// the separator for the parts of a key
pub const KEY_SEPARATOR: char = '/';

/// The keys used to reference values in a Pairs storage. These form a path of namespaces
/// each part separated by the separator "/" and they come in two flavors: branch or leaf
/// A branch is a key-path that ends with the separator: "/foo/bar/baz/"
/// A leaf is a key-path that does not end with the separator: "/foo/bar/baz"
/// Branches identify a namespace full of leaves and a leaf identifies a single value
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key {
    parts: Vec<String>
}

impl Key {
    /// true if this key is a branch
    pub fn is_branch(&self) -> bool {
        self.parts.last().unwrap().len() == 0
    }

    /// true if this key is a leaf
    pub fn is_leaf(&self) -> bool {
        self.parts.last().unwrap().len() > 0
    }

    /// returns the number of parts in the key
    pub fn len(&self) -> usize {
        match self.parts.len() {
            0 => 0,
            len => {
                if self.is_branch() {
                    len - 2
                } else {
                    len - 1
                }
            }
        }
    }

    /// returns the branch part of the key
    pub fn branch(&self) -> Self {
        if self.is_branch() || self.len() == 0 {
            self.clone()
        } else {
            let mut p = self.parts.clone();
            let _ = p.pop();
            p.push("".to_string());
            Self {
                parts: p
            }
        }
    }

    /// returns the longest common branch between this and the other Key
    pub fn longest_common_branch(&self, rhs: &Key) -> Self {
        let lhs = self.branch();
        let rhs = rhs.branch();
        let mut v = Vec::default();
        let mut itr = lhs.parts.iter().zip(rhs.parts.iter());
        while let Some((l, r)) = itr.next() {
            if l == r {
                v.push(l.clone());
            } else {
                break;
            }
        }

        match v.len() {
            0 => {
                v.push("".to_string());
                v.push("".to_string());
            }
            1 => {
                v.push("".to_string());
            }
            _ => {
                if v.last() != Some(&"".to_string()) {
                    v.push("".to_string());
                }
            }
        }

        Self { parts: v }
    }
}

impl Default for Key {
    fn default() -> Self {
        Key {
            parts: vec!["".to_string(), "".to_string()]
        }
    }
}

impl EncodingInfo for Key {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // convert the path to a string and encode it as varbytes
        v.append(&mut Varbytes(self.to_string().as_bytes().to_vec()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Key {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (key, _) = Self::try_decode_from(bytes)?;
        Ok(key)
    }
}

impl<'a> TryDecodeFrom<'a> for Key {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (s, ptr) = Varbytes::try_decode_from(bytes)?;
        let s = String::from_utf8(s.to_inner())?;
        let k = Self::try_from(s)?;
        Ok((k, ptr))
    }
}

impl TryFrom<&str> for Key {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Key::try_from(s.to_string())
    }
}

impl TryFrom<String> for Key {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() == 0 {
            return Err(KeyError::EmptyKey.into());
        }
        let filtered = {
            let mut prev = KEY_SEPARATOR;
            let mut filtered = String::default();
            for (i, c) in s.chars().enumerate() {
                match i {
                    0 => {
                        if c != KEY_SEPARATOR {
                            return Err(KeyError::MissingRootSeparator(s).into());
                        }
                        filtered.push(c);
                    }
                    // eliminate runs of the separator char '///' becomes '/'
                    _ if c == KEY_SEPARATOR => {
                        if c != prev {
                            filtered.push(c);
                            prev = c;
                        }
                    }
                    _ => {
                        filtered.push(c);
                        prev = c;
                    }
                }
            }
            filtered
        };
        Ok(Key {
            parts: filtered.split(KEY_SEPARATOR).map(|s| s.to_string()).collect()
        })
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.parts.join(&KEY_SEPARATOR.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_empty_key() {
        Key::try_from("").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_bad_key() {
        Key::try_from("foo/bar").unwrap();
    }

    #[test]
    fn test_default() {
        let k = Key::default();
        assert!(k.is_branch());
        assert!(!k.is_leaf());
        assert_eq!(0, k.len());
        assert_eq!(format!("{}", k), "/".to_string());
    }

    #[test]
    fn test_branch() {
        let k = Key::try_from("/foo/bar/baz/").unwrap();
        assert!(k.is_branch());
        assert!(!k.is_leaf());
        assert_eq!(3, k.len());
        assert_eq!(format!("{}", k), "/foo/bar/baz/".to_string());
        assert_eq!(format!("{}", k.branch()), "/foo/bar/baz/".to_string());
        assert_eq!(3, k.branch().len());
    }

    #[test]
    fn test_leaf() {
        let k = Key::try_from("/foo/bar/baz").unwrap();
        assert!(!k.is_branch());
        assert!(k.is_leaf());
        assert_eq!(3, k.len());
        assert_eq!(format!("{}", k), "/foo/bar/baz".to_string());
        assert_eq!(format!("{}", k.branch()), "/foo/bar/".to_string());
        assert_eq!(2, k.branch().len());
    }

    #[test]
    fn longest_branch_one() {
        let l = Key::try_from("/foo/bar/baz").unwrap();
        let r = Key::try_from("/foo/bar").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(1, mk.len());
        assert_eq!(format!("{}", mk), "/foo/".to_string());
    }

    #[test]
    fn longest_branch_two() {
        let l = Key::try_from("/foo/bar/baz").unwrap();
        let r = Key::try_from("/blah/boo").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_three() {
        let l = Key::try_from("/").unwrap();
        let r = Key::try_from("/blah/boo").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_four() {
        let l = Key::try_from("/").unwrap();
        let r = Key::try_from("/").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_five() {
        let l = Key::try_from("/foo/bar/baz/blah/").unwrap();
        let r = Key::try_from("/foo/bar/baz/blah/").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(4, mk.len());
        assert_eq!(format!("{}", mk), "/foo/bar/baz/blah/".to_string());
    }
}
