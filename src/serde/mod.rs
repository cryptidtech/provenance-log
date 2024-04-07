// SPDX-License-Identifier: FSL-1.1
//! Serde (de)serialization for provenance log types
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Op, Script, Value};
    use multicid::cid;
    use multicodec::Codec;
    use multihash::mh;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_value_default_compact() {
        let v = Value::default();
        assert_tokens(
            &v.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[0]),
                Token::TupleEnd,
            ],
        );
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
        let b = serde_cbor::to_vec(&v).unwrap();
        assert_eq!(b, hex::decode("824201004100").unwrap());
        assert_eq!(v, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_value_str_compact() {
        let v = Value::Str("move zig!".into());
        assert_tokens(
            &v.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 1]),
                Token::BorrowedBytes(&[9, 109, 111, 118, 101, 32, 122, 105, 103, 33]),
                Token::TupleEnd,
            ],
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
        let b = serde_cbor::to_vec(&v).unwrap();
        assert_eq!(b, hex::decode("824201014a096d6f7665207a696721").unwrap());
        assert_eq!(v, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_default_compact() {
        let o = Op::default();
        assert_tokens(
            &o.compact(),
            &[
                Token::Tuple { len: 3 },       // noop tuple
                Token::BorrowedBytes(&[1, 0]), // varuint 1 byte, value 0 "noop"
                Token::BorrowedBytes(&[2, 1, 47]),    // varbytes len as varuint, 0
                Token::Tuple { len: 2 },       // value tuple
                Token::BorrowedBytes(&[1, 0]), // varuint 1 byte, value 0 "nil"
                Token::BorrowedBytes(&[0]),    // varbytes len as varuint, 0
                Token::TupleEnd,               // end of value tuple
                Token::TupleEnd,               // end of op tuple
            ],
        );
    }

    #[test]
    fn test_op_default_readable() {
        let o = Op::default();
        assert_tokens(
            &o.readable(),
            &[
                Token::TupleVariant { name: "op", variant: "noop", len: 1 },
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
        let b = serde_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![131, 66, 1, 0, 67, 2, 1, 47, 130, 66, 1, 0, 65, 0]);
        assert_eq!(o, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_delete_compact() {
        let o = Op::Delete("/zig".try_into().unwrap());
        assert_tokens(
            &o.compact(),
            &[
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[1, 1]),
                Token::BorrowedBytes(&[5, 4, 47, 122, 105, 103]),
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[0]),
                Token::TupleEnd,
                Token::TupleEnd,
            ],
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
        assert_eq!(s, "{\"update\":[\"/move\",{\"str\":[\"zig\"]}]}".to_string());
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
        let b = serde_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![131, 66, 1, 1, 70, 5, 4, 47, 122, 105, 103, 130, 66, 1, 0, 65, 0]);
        assert_eq!(o, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_default_compact() {
        let s = Script::default();
        assert_tokens(
            &s.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[0]),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_script_default_readable() {
        let s = Script::default();
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant {
                    name: "script",
                    variant: "bin",
                    len: 1,
                },
                Token::BorrowedStr("f00"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_default_json() {
        let t = Script::default();
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"bin\":[\"f00\"]}".to_string());
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_default_cbor() {
        let s = Script::default();
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, hex::decode("824201004100").unwrap());
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv0_compact() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v0);
        assert_tokens(
            &s.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 2]),
                Token::BorrowedBytes(&[
                    34, 18, 32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130, 36, 114, 228, 122,
                    105, 111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100, 238, 164, 30,
                    126,
                ]),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv0_readable() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v0);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant { name: "script", variant: "cid", len: 1, },
                Token::Struct { name: "cid", len: 3, },
                Token::BorrowedStr("version"),
                Token::U64(0),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-pb"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha2-256"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e"),
                Token::StructEnd,
                Token::StructEnd,
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv0_json() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let t = Script::Cid(v0);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"cid\":[{\"version\":0,\"encoding\":\"dag-pb\",\"hash\":{\"codec\":\"sha2-256\",\"hash\":\"f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e\"}}]}");
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv0_cbor() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v0);
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, hex::decode("824201025823221220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e").unwrap());
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv1_compact() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v1);
        assert_tokens(
            &s.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 2]),
                Token::BorrowedBytes(&[
                    68, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181,
                    120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106,
                    30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61,
                    234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190,
                ]),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv1_readable() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v1);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant { name: "script", variant: "cid", len: 1, },
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
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let t = Script::Cid(v1);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"cid\":[{\"version\":1,\"encoding\":\"dag-cbor\",\"hash\":{\"codec\":\"sha3-512\",\"hash\":\"f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be\"}}]}");
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv1_cbor() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(v1);
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, hex::decode("82420102584544017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }
}
