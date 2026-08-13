// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for Key
//!
//! Tests:
//! - Branch always ends with '/' property
//! - parent_of transitivity property

use provenance_log::Key;

#[test]
fn test_branch_always_ends_with_slash() {
    // Property: Key::branch() should always return a key ending with '/'
    let test_cases = vec![
        "/",
        "/foo",
        "/foo/",
        "/foo/bar",
        "/foo/bar/",
        "/foo/bar/baz",
        "/a/b/c/d/e/f",
    ];

    for case in test_cases {
        let key = Key::try_from(case).unwrap();
        let branch = key.branch();

        // Property: branch should always end with separator
        assert!(branch.is_branch());
        assert!(branch.to_string().ends_with('/'));
    }
}

#[test]
fn test_leaf_becomes_branch_when_branched() {
    // Property: calling branch() on a leaf should give its parent branch
    let test_cases = vec![
        ("/foo", "/"),
        ("/foo/bar", "/foo/"),
        ("/a/b/c", "/a/b/"),
    ];

    for (leaf, expected_branch) in test_cases {
        let key = Key::try_from(leaf).unwrap();
        assert!(key.is_leaf());

        let branch = key.branch();
        assert!(branch.is_branch());
        assert_eq!(branch.to_string(), expected_branch);
    }
}

#[test]
fn test_branch_is_idempotent() {
    // Property: calling branch() on a branch should return itself
    let test_cases = vec!["/", "/foo/", "/foo/bar/", "/a/b/c/d/"];

    for case in test_cases {
        let key = Key::try_from(case).unwrap();
        assert!(key.is_branch());

        let branch = key.branch();
        assert_eq!(key, branch);
    }
}

#[test]
fn test_parent_of_reflexive_for_leaves() {
    // Property: a leaf is parent_of itself
    let test_cases = vec!["/foo", "/foo/bar", "/a/b/c"];

    for case in test_cases {
        let key = Key::try_from(case).unwrap();
        assert!(key.is_leaf());

        // Property: leaf.parent_of(leaf) should be true
        assert!(key.parent_of(&key));
    }
}

#[test]
fn test_parent_of_transitivity() {
    // Property: if A is parent of B and B is parent of C, then A is parent of C
    let root = Key::try_from("/").unwrap();
    let foo = Key::try_from("/foo/").unwrap();
    let bar = Key::try_from("/foo/bar/").unwrap();
    let baz = Key::try_from("/foo/bar/baz").unwrap();

    // Verify the chain
    assert!(root.parent_of(&foo));
    assert!(foo.parent_of(&bar));
    assert!(bar.parent_of(&baz));

    // Property: transitivity
    assert!(root.parent_of(&bar));
    assert!(root.parent_of(&baz));
    assert!(foo.parent_of(&baz));
}

#[test]
fn test_parent_of_antisymmetry() {
    // Property: if A is parent of B and A != B, then B is not parent of A
    let parent = Key::try_from("/foo/").unwrap();
    let child = Key::try_from("/foo/bar").unwrap();

    assert!(parent.parent_of(&child));
    assert!(!child.parent_of(&parent));
}

#[test]
fn test_root_is_parent_of_everything() {
    // Property: root "/" is parent of all keys
    let root = Key::try_from("/").unwrap();
    let test_cases = vec![
        "/",
        "/foo",
        "/foo/",
        "/foo/bar",
        "/foo/bar/",
        "/a/b/c/d/e",
    ];

    for case in test_cases {
        let key = Key::try_from(case).unwrap();
        // Property: root is parent of everything
        assert!(root.parent_of(&key));
    }
}

#[test]
fn test_longest_common_branch_is_commutative() {
    // Property: longest_common_branch(A, B) == longest_common_branch(B, A)
    let test_pairs = vec![
        ("/foo/bar", "/foo/baz"),
        ("/a/b/c", "/a/b/d"),
        ("/x/y", "/z/w"),
        ("/", "/foo"),
    ];

    for (a_str, b_str) in test_pairs {
        let a = Key::try_from(a_str).unwrap();
        let b = Key::try_from(b_str).unwrap();

        let lcb_ab = a.longest_common_branch(&b);
        let lcb_ba = b.longest_common_branch(&a);

        // Property: should be commutative
        assert_eq!(lcb_ab, lcb_ba);
    }
}

#[test]
fn test_longest_common_branch_with_self() {
    // Property: longest_common_branch(A, A) should give A's branch
    let test_cases = vec!["/foo", "/foo/", "/foo/bar", "/a/b/c/"];

    for case in test_cases {
        let key = Key::try_from(case).unwrap();
        let lcb = key.longest_common_branch(&key);

        // Property: LCB with self is own branch
        assert_eq!(lcb, key.branch());
    }
}

#[test]
fn test_longest_common_branch_is_branch() {
    // Property: result of longest_common_branch is always a branch
    let test_pairs = vec![
        ("/foo/bar", "/foo/baz"),
        ("/a/b/c", "/x/y/z"),
        ("/", "/anything"),
    ];

    for (a_str, b_str) in test_pairs {
        let a = Key::try_from(a_str).unwrap();
        let b = Key::try_from(b_str).unwrap();

        let lcb = a.longest_common_branch(&b);

        // Property: result is always a branch
        assert!(lcb.is_branch());
    }
}

#[test]
fn test_key_len_counts_segments() {
    // Property: key length counts path segments (not including separators)
    let test_cases = vec![
        ("/", 0),
        ("/foo", 1),
        ("/foo/", 1),
        ("/foo/bar", 2),
        ("/foo/bar/", 2),
        ("/a/b/c", 3),
        ("/a/b/c/", 3),
    ];

    for (key_str, expected_len) in test_cases {
        let key = Key::try_from(key_str).unwrap();
        // Property: length matches segment count
        assert_eq!(key.len(), expected_len, "Key '{}' should have length {}", key_str, expected_len);
    }
}

#[test]
fn test_key_serialization_roundtrip() {
    // Property: serialized key should deserialize to equivalent key
    let test_cases = vec![
        "/",
        "/foo",
        "/foo/",
        "/foo/bar/baz",
        "/a/b/c/d/e/",
    ];

    for case in test_cases {
        let original = Key::try_from(case).unwrap();
        let serialized: Vec<u8> = original.clone().into();
        let deserialized = Key::try_from(serialized.as_slice()).unwrap();

        // Property: roundtrip preserves key
        assert_eq!(original, deserialized);
        assert_eq!(original.to_string(), deserialized.to_string());
    }
}

#[test]
fn test_key_push_preserves_branch_property() {
    // Property: pushing to a branch keeps it valid
    let mut branch = Key::try_from("/foo/").unwrap();
    assert!(branch.is_branch());

    // Push a leaf
    branch.push("/bar").unwrap();
    assert!(branch.is_leaf());
    assert_eq!(branch.to_string(), "/foo/bar");

    // Start with a branch again
    let mut branch2 = Key::try_from("/foo/").unwrap();
    branch2.push("/bar/").unwrap();
    assert!(branch2.is_branch());
    assert_eq!(branch2.to_string(), "/foo/bar/");
}

#[test]
fn test_key_push_to_leaf_fails() {
    // Property: cannot push to a leaf key
    let mut leaf = Key::try_from("/foo").unwrap();
    assert!(leaf.is_leaf());

    let result = leaf.push("/bar");
    // Property: should fail
    assert!(result.is_err());
}

#[test]
fn test_key_ordering_consistent() {
    // Property: key ordering should be consistent with string ordering
    let keys = vec![
        Key::try_from("/").unwrap(),
        Key::try_from("/a").unwrap(),
        Key::try_from("/a/").unwrap(),
        Key::try_from("/b").unwrap(),
        Key::try_from("/b/c").unwrap(),
    ];

    // Check that keys are ordered
    for i in 0..keys.len() - 1 {
        // Property: ordering is consistent
        assert!(keys[i] <= keys[i + 1]);
    }
}

#[test]
fn test_key_equality_ignores_redundant_separators() {
    // Property: keys with redundant separators should be normalized
    let k1 = Key::try_from("/foo/bar").unwrap();
    let k2 = Key::try_from("/foo//bar").unwrap();  // Double separator
    let k3 = Key::try_from("/foo///bar").unwrap();  // Triple separator

    // Property: normalized keys should be equal
    assert_eq!(k1, k2);
    assert_eq!(k2, k3);
    assert_eq!(k1.to_string(), k2.to_string());
}

#[test]
fn test_key_default_is_root() {
    // Property: default key is root "/"
    let default = Key::default();
    assert!(default.is_branch());
    assert_eq!(default.len(), 0);
    assert_eq!(default.to_string(), "/");
}
