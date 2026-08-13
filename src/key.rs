// SPDX-License-Identifier: FSL-1.1
use crate::{error::KeyError, Error};
use multi_base::Base;
use multi_trait::{EncodeIntoBuffer, TryDecodeFrom};
use multi_util::{EncodingInfo, Varbytes};
use std::fmt;

/// the separator for the parts of a key
pub const KEY_SEPARATOR: char = '/';

/// Hierarchical key paths for the virtual namespace
///
/// Keys are slash-separated paths similar to filesystem paths or URLs. They come in two flavors:
///
/// - **Branch** (namespace): Ends with `/` → `/foo/bar/`
/// - **Leaf** (value): No trailing `/` → `/foo/bar/baz`
///
/// Branches identify namespaces that can contain other branches and leaves. Leaves identify
/// individual values. This distinction is critical for authorization: lock scripts can be
/// associated with branches to control all operations within that namespace.
///
/// # Path Structure
///
/// - All paths must start with `/`
/// - Parts are separated by `/`
/// - Multiple consecutive `/` are collapsed to a single `/`
/// - Maximum path length: 1024 characters
/// - Maximum depth: 32 levels
///
/// # Examples
///
/// ```
/// use provenance_log::Key;
///
/// // A branch (namespace)
/// let branch = Key::try_from("/users/alice/").unwrap();
/// assert!(branch.is_branch());
/// assert!(!branch.is_leaf());
/// assert_eq!(branch.len(), 2);
///
/// // A leaf (value)
/// let leaf = Key::try_from("/users/alice/email").unwrap();
/// assert!(leaf.is_leaf());
/// assert!(!leaf.is_branch());
/// assert_eq!(leaf.len(), 3);
///
/// // Get the branch part of a leaf
/// let parent = leaf.branch();
/// assert_eq!(parent.to_string(), "/users/alice/");
///
/// // Check parent-child relationships
/// assert!(branch.parent_of(&leaf));
/// ```
///
/// # Thread Safety
///
/// `Key` is `Send + Sync` as it contains only owned `String` and `Vec<String>`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key {
    parts: Vec<String>,
    s: String, // holds the "rendered" string so we can return a &str
}

impl Key {
    /// true if this key is a branch
    pub fn is_branch(&self) -> bool {
        self.parts
            .last()
            .expect("Key should always have at least one part from construction")
            .is_empty()
    }

    /// true if this key is a leaf
    pub fn is_leaf(&self) -> bool {
        !self
            .parts
            .last()
            .expect("Key should always have at least one part from construction")
            .is_empty()
    }

    /// add a key-path to us
    pub fn push<S: AsRef<str>>(&mut self, s: S) -> Result<(), Error> {
        if !self.is_branch() {
            return Err(KeyError::NotABranch.into());
        }
        let moar = Self::try_from(s.as_ref())?;
        let _ = self.parts.pop();
        self.parts.append(&mut moar.parts[1..].to_vec());
        self.s = self.parts.join(&KEY_SEPARATOR.to_string());
        Ok(())
    }

    /// true if this path is a branch and the passed in path is achild of it
    /// treu if this path is a leaf and the passed in path is the same path
    pub fn parent_of(&self, other: &Self) -> bool {
        //println!("\t{} is a {}", self, if self.is_leaf() { "leaf" } else { "branch" });
        if self.is_leaf() {
            self == other
        } else {
            let mut self_parts = Vec::default();
            let mut itr = self.parts.iter();
            itr.next(); // skip the first ""
            for p in itr {
                self_parts.push("/".to_string());
                if !p.is_empty() {
                    self_parts.push(p.clone());
                }
            }

            let mut other_parts = Vec::default();
            let mut itr = other.parts.iter();
            itr.next(); // skip the first ""
            for p in itr {
                other_parts.push("/".to_string());
                if !p.is_empty() {
                    other_parts.push(p.clone());
                }
            }

            //println!("\t{:?} {} with {:?}", other_parts, if other_parts.starts_with(&self_parts) { "starts" } else { "does not start" }, self_parts);
            other_parts.starts_with(&self_parts)
        }
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

    /// return if the key has zero length
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// returns the branch part of the key
    pub fn branch(&self) -> Self {
        if self.is_branch() || self.is_empty() {
            self.clone()
        } else {
            let mut parts = self.parts.clone();
            let _ = parts.pop();
            parts.push("".to_string());
            let s = parts.join(&KEY_SEPARATOR.to_string());
            Self { parts, s }
        }
    }

    /// returns the longest common branch between this and the other Key
    pub fn longest_common_branch(&self, rhs: &Key) -> Self {
        let lhs = self.branch();
        let rhs = rhs.branch();
        let mut parts = Vec::default();
        let itr = lhs.parts.iter().zip(rhs.parts.iter());
        for (l, r) in itr {
            if l == r {
                parts.push(l.clone());
            } else {
                break;
            }
        }

        match parts.len() {
            0 => {
                parts.push("".to_string());
                parts.push("".to_string());
            }
            1 => {
                parts.push("".to_string());
            }
            _ => {
                if parts.last() != Some(&"".to_string()) {
                    parts.push("".to_string());
                }
            }
        }

        let s = parts.join(&KEY_SEPARATOR.to_string());
        Self { parts, s }
    }

    /// return the key as a &str
    pub fn as_str(&self) -> &str {
        self.s.as_str()
    }
}

impl Default for Key {
    fn default() -> Self {
        let parts = vec!["".to_string(), "".to_string()];
        let s = parts.join(&KEY_SEPARATOR.to_string());
        Self { parts, s }
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

impl From<Key> for Vec<u8> {
    fn from(val: Key) -> Self {
        let mut v = Vec::default();
        val.encode_into_buffer(&mut v);
        v
    }
}

impl EncodeIntoBuffer for Key {
    fn encode_into_buffer(&self, output: &mut Vec<u8>) {
        self.s.len().encode_into_buffer(output);
        output.extend_from_slice(self.s.as_bytes());
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
        Self::try_from(s.to_string())
    }
}

impl TryFrom<String> for Key {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(KeyError::EmptyKey.into());
        }

        // Check path length
        if s.len() > crate::limits::MAX_KEY_PATH_LENGTH {
            return Err(KeyError::PathTooLong(s.len(), crate::limits::MAX_KEY_PATH_LENGTH).into());
        }

        // Check path depth (count separators)
        let depth = s.matches('/').count();
        if depth > crate::limits::MAX_KEY_PATH_DEPTH {
            return Err(KeyError::PathTooDeep(depth, crate::limits::MAX_KEY_PATH_DEPTH).into());
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
        let parts = filtered
            .split(KEY_SEPARATOR)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let s = parts.join(&KEY_SEPARATOR.to_string());
        Ok(Self { parts, s })
    }
}

impl AsRef<str> for Key {
    fn as_ref(&self) -> &str {
        self.s.as_str()
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

    #[test]
    fn sort_keys() {
        let mut v: Vec<Key> = vec![
            Key::try_from("/bar/").unwrap(),
            Key::try_from("/").unwrap(),
            Key::try_from("/bar/").unwrap(),
            Key::try_from("/foo").unwrap(),
        ];
        v.sort();
        for k in v {
            println!("{}", k);
        }
    }

    #[test]
    #[should_panic]
    fn push_to_leaf() {
        let mut l = Key::try_from("/foo/bar/baz").unwrap();
        l.push("/blah").unwrap();
    }

    #[test]
    #[should_panic]
    fn push_invalid_key() {
        let mut k = Key::try_from("/foo/bar/").unwrap();
        k.push("baz").unwrap();
    }

    #[test]
    fn push_leaf() {
        let mut b = Key::try_from("/foo/bar/").unwrap();
        b.push("/baz").unwrap();
        assert!(b.is_leaf());
        assert_eq!(format!("{}", b), "/foo/bar/baz".to_string());
    }

    #[test]
    fn push_branch() {
        let mut b = Key::try_from("/foo/bar/").unwrap();
        b.push("/baz/").unwrap();
        assert!(b.is_branch());
        assert_eq!(format!("{}", b), "/foo/bar/baz/".to_string());
    }

    #[test]
    fn test_as_ref() {
        let b = Key::try_from("/foo/bar").unwrap();
        assert_eq!(b.as_ref(), "/foo/bar");
    }
}
