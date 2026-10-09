// SPDX-License-Identifier: FSL-1.1
//! Serde (de)serialization for provenance log types
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{entry, Key, Op, Script, Value};
    use multi_cid::cid;
    use multi_codec::Codec;
    use multi_hash::mh;
    use multi_key::EncodedMultikey;
    use multi_vlad::vlad;
    use serde_test::{assert_tokens, Configure, Token};
    use std::collections::BTreeMap;

    #[test]
    fn test_value_default_compact() {
        let v = Value::default();
        assert_tokens(&v.compact(), &[Token::BorrowedBytes(&[0])]);
    }

    #[test]
    fn test_value_default_readable() {
        let v = Value::default();
        assert_tokens(
            &v.readable(),
            &[Token::UnitVariant {
                name: "value",
                variant: "nil",
            }],
        );
    }

    #[test]
    fn test_value_default_json() {
        let v = Value::default();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"nil\"".to_string());
        assert_eq!(v, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_value_default_cbor() {
        let v = Value::default();
        let b = multi_cbor::to_vec(&v).unwrap();
        assert_eq!(b, vec![65, 0]);
        assert_eq!(v, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_value_str_compact() {
        let v = Value::Str("move zig!".into());
        assert_tokens(
            &v.compact(),
            &[Token::BorrowedBytes(&[
                1, 9, 109, 111, 118, 101, 32, 122, 105, 103, 33,
            ])],
        );
    }

    #[test]
    fn test_value_str_readable() {
        let v = Value::Str("move zig!".into());
        assert_tokens(
            &v.readable(),
            &[
                Token::TupleVariant {
                    name: "value",
                    variant: "str",
                    len: 1,
                },
                Token::BorrowedStr("move zig!"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_value_str_json() {
        let v = Value::Str("move zig!".into());
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "{\"str\":[\"move zig!\"]}".to_string());
        assert_eq!(v, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_value_str_cbor() {
        let v = Value::Str("move zig!".into());
        let b = multi_cbor::to_vec(&v).unwrap();
        assert_eq!(b, vec![75, 1, 9, 109, 111, 118, 101, 32, 122, 105, 103, 33]);
        assert_eq!(v, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_default_compact() {
        let o = Op::default();
        assert_tokens(&o.compact(), &[Token::BorrowedBytes(&[0, 1, 47])]);
    }

    #[test]
    fn test_op_default_readable() {
        let o = Op::default();
        assert_tokens(
            &o.readable(),
            &[
                Token::TupleVariant {
                    name: "op",
                    variant: "noop",
                    len: 1,
                },
                Token::BorrowedStr("/"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_op_default_json() {
        let o = Op::default();
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"noop\":[\"/\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_default_cbor() {
        let o = Op::default();
        let b = multi_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![67, 0, 1, 47]);
        assert_eq!(o, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_delete_compact() {
        let o = Op::Delete("/zig".try_into().unwrap());
        assert_tokens(
            &o.compact(),
            &[Token::BorrowedBytes(&[1, 4, 47, 122, 105, 103])],
        );
    }

    #[test]
    fn test_op_delete_readable() {
        let o = Op::Delete("/zig".try_into().unwrap());
        assert_tokens(
            &o.readable(),
            &[
                Token::TupleVariant {
                    name: "op",
                    variant: "delete",
                    len: 1,
                },
                Token::BorrowedStr("/zig"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_op_delete_json() {
        let o = Op::Delete("/zig".try_into().unwrap());
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"delete\":[\"/zig\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::Str("zig".into()));
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(
            s,
            "{\"update\":[\"/move\",{\"str\":[\"zig\"]}]}".to_string()
        );
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_data_value_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::Data(vec![1]));
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(
            s,
            "{\"update\":[\"/move\",{\"data\":[\"f0101\"]}]}".to_string()
        );
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_default_value_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::default());
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"update\":[\"/move\",\"nil\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }
    #[test]
    fn test_op_delete_cbor() {
        let o = Op::Delete("/zig".try_into().unwrap());
        let b = multi_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![70, 1, 4, 47, 122, 105, 103]);
        assert_eq!(o, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_default_compact() {
        let s = Script::default();
        assert_tokens(
            &s.compact(),
            &[Token::BorrowedBytes(&[138, 36, 0, 1, 47, 0])],
        );
    }

    #[test]
    fn test_script_default_readable() {
        let s = Script::default();
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant {
                    name: "provenance-log-script",
                    variant: "bin",
                    len: 2,
                },
                Token::BorrowedStr("/"),
                Token::BorrowedStr("f00"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_default_json() {
        let t = Script::default();
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"bin\":[\"/\",\"f00\"]}".to_string());
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_default_cbor() {
        let s = Script::default();
        let b = multi_cbor::to_vec(&s).unwrap();
        assert_eq!(b, vec![70, 138, 36, 0, 1, 47, 0]);
        assert_eq!(s, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv0_compact() {
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v0 = cid::Builder::default()
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        assert_tokens(
            &s.compact(),
            &[Token::BorrowedBytes(&[
                138, 36, 2, 1, 47, 18, 32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130, 36, 114,
                228, 122, 105, 111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100, 238, 164,
                30, 126,
            ])],
        );
    }

    #[test]
    fn test_script_cidv0_readable() {
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v0 = cid::Builder::default()
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant {
                    name: "provenance-log-script",
                    variant: "cid",
                    len: 2,
                },
                Token::BorrowedStr("/"),
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(0),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-pb"),
                Token::BorrowedStr("hash"),
                Token::Struct {
                    name: "multihash",
                    len: 2,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha2-256"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr(
                    "f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e",
                ),
                Token::StructEnd,
                Token::StructEnd,
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv0_json() {
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v0 = cid::Builder::default()
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let t = Script::Cid(Key::default(), v0);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"cid\":[\"/\",{\"version\":0,\"encoding\":\"dag-pb\",\"hash\":{\"codec\":\"sha2-256\",\"hash\":\"f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e\"}}]}");
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv0_cbor() {
        let mut hash_builder = mh::Builder::new(Codec::Sha2256)
            .expect("SHA2-256 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v0 = cid::Builder::default()
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        let b = multi_cbor::to_vec(&s).unwrap();
        assert_eq!(
            b,
            vec![
                88, 39, 138, 36, 2, 1, 47, 18, 32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130,
                36, 114, 228, 122, 105, 111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100,
                238, 164, 30, 126
            ]
        );
        assert_eq!(s, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv1_compact() {
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v1);
        assert_tokens(
            &s.compact(),
            &[Token::BorrowedBytes(&[
                138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142,
                78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73,
                82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122,
                61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190,
            ])],
        );
    }

    #[test]
    fn test_script_cidv1_readable() {
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v1);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant { name: "provenance-log-script", variant: "cid", len: 2, },
                Token::BorrowedStr("/"),
                Token::Struct { name: "cid", len: 3, },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-cbor"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha3-512"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
                Token::StructEnd,
                Token::StructEnd,
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv1_json() {
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let t = Script::Cid(Key::default(), v1);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s,
            "{\"cid\":[\"/\",{\"version\":1,\"encoding\":\"dag-cbor\",\"hash\":{\"codec\":\"sha3-512\",\"hash\":\"f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be\"}}]}"
        );
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv1_cbor() {
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v1);
        let b = multi_cbor::to_vec(&s).unwrap();
        assert_eq!(
            b,
            vec![
                88, 73, 138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107,
                142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134,
                97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230,
                227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1,
                190
            ]
        );
        assert_eq!(s, multi_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_preimage_entry_serde_compact() {
        // Create a signing key for the VLAD
        let signing_key = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        ).unwrap().to_inner();
        let wasm_bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        let vlad = vlad::Builder::default()
            .with_signing_key(&signing_key)
            .with_message(&wasm_bytes)
            .try_build()
            .unwrap();

        // build a cid for Script::Cid
        let mut hash_builder = mh::Builder::new(Codec::Sha3512)
            .expect("SHA3-512 is a hashing codec, a builder for it should always be created");
        hash_builder.update(b"for great justice, move every zig!");
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&hash_builder.try_build().unwrap())
            .try_build()
            .unwrap();

        let script = Script::Cid(Key::default(), cid);
        let op = Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into()));
        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .add_lock(&script)
            .with_unlock(&script)
            .add_op(&op)
            .try_build(|e| {
                let vlad_bytes: Vec<u8> = e.vlad.clone().into();
                Ok(BTreeMap::from([("primary".to_string(), vlad_bytes)]))
            })
            .unwrap();

        /*
        let v: Vec<u8> = entry.clone().into();
        print!("BLAH: ");
        for b in &v {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */

        // Verify compact serde roundtrip (serialize then deserialize)
        let serialized: Vec<u8> = entry.clone().into();
        let deserialized = crate::Entry::try_from(serialized.as_slice()).unwrap();
        assert_eq!(entry, deserialized);
    }
}
