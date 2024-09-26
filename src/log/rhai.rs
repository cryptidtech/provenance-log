use crate::{Key, LogValue};

use super::*;
use comrade_core::{ComradeBuilder, Current, Pairs, Proposed, Value};
use tracing::{debug, info, trace};

/// Kvp is the virtual key-value pair storage system that builds up the state
/// encoded in provenance logs as time series of verifiable state changes.
#[derive(Clone, Debug, Default)]
pub struct OwnedKvp {
    /// the key-value pair store itself
    kvp: BTreeMap<Key, LogValue>,
    /// the entry so we can expose it as part of the key-value store
    entry: Option<Entry>,
}

impl OwnedKvp {
    /// create a new OwnedKvp instance
    pub fn new(kvp: Kvp) -> Self {
        Self {
            kvp: kvp.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            entry: None,
        }
    }
}

impl Pairs for OwnedKvp {
    fn get(&self, key: &str) -> Option<Value> {
        let k = match Key::try_from(key) {
            Ok(k) => k,
            _ => return None,
        };
        match self.kvp.get(&k) {
            Some(ref v) => match v {
                LogValue::Nil => Some(Value::Bin {
                    hint: key.to_string(),
                    data: Vec::default(),
                }),
                LogValue::Str(ref s) => Some(Value::Str {
                    hint: key.to_string(),
                    data: s.clone(),
                }),
                LogValue::Data(ref v) => Some(Value::Bin {
                    hint: key.to_string(),
                    data: v.clone(),
                }),
            },
            None => {
                if let Some(entry) = &self.entry {
                    entry.get(key)
                } else {
                    None
                }
            }
        }
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        let k = match Key::try_from(key) {
            Ok(k) => k,
            _ => return None,
        };
        let v = match value {
            Value::Str {
                hint: _,
                data: ref s,
            } => LogValue::Str(s.clone()),
            Value::Bin {
                hint: _,
                data: ref v,
            } => LogValue::Data(v.clone()),
            _ => return None,
        };
        match self.kvp.insert(k, v) {
            Some(LogValue::Nil) => Some(Value::Bin {
                hint: key.to_string(),
                data: Vec::default(),
            }),
            Some(LogValue::Str(s)) => Some(Value::Str {
                hint: key.to_string(),
                data: s,
            }),
            Some(LogValue::Data(v)) => Some(Value::Bin {
                hint: key.to_string(),
                data: v,
            }),
            None => None,
        }
    }
}
impl<'a> Iterator for VerifyIter<'a> {
    type Item = Result<(usize, Entry, Kvp<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = match self.entries.get(self.seqno) {
            Some(e) => *e,
            None => return None,
        };

        // this is the check count if successful
        let mut count = 0;

        // check the seqno meet the criteria
        if self.seqno > 0 && self.seqno != self.prev_seqno + 1 {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error state
            self.error = Some(LogError::InvalidSeqno.into());
            return Some(Err(self.error.clone().unwrap()));
        }

        // unlock:
        let Script::Code(_, ref unlock) = entry.unlock else {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error state
            self.error = Some(LogError::WrongScriptFormat.into());
            return Some(Err(self.error.clone().unwrap()));
        };

        // if this is the first entry, then we need to apply the
        // mutation ops
        if self.seqno == 0 {
            //println!("applying kvp ops for seqno 0");
            if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(LogError::UpdateKvpFailed(e.to_string()).into());
                return Some(Err(self.error.clone().unwrap()));
            }
        }

        // take a copy of self.kvp and turn into Kvp<'static> somehow
        let kvp_copy = OwnedKvp::new(self.kvp.clone());

        let Ok(unlocked) = ComradeBuilder::new(unlock, Current(kvp_copy), Proposed(entry.clone()))
            .with_domain(entry.context().as_str())
            .try_unlock()
        else {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error stat
            self.error = Some(LogError::Anyhow("Failed to run unlock script".to_string()).into());
            return Some(Err(self.error.clone().unwrap()));
        };

        // 'lock:

        // build the set of lock scripts to run in order from root to longest branch to leaf
        let locks = entry
            .sort_locks(&self.lock_scripts)
            .map_err(|e| {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(e);
                self.error.clone().unwrap()
            })
            .ok()?;

        let mut results = false;

        // run each of the lock scripts
        for lock in locks {
            let Script::Code(_, lock) = lock else {
                // set our index out of range
                self.seqno = self.entries.len();
                // set the error state
                self.error = Some(LogError::WrongScriptFormat.into());
                return Some(Err(self.error.clone().unwrap()));
            };

            match unlocked.try_lock(lock) {
                Ok(Some(Value::Success(ct))) => {
                    count = ct;
                    results = true;
                    break;
                }
                Err(e) => {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Anyhow(e).into());
                    return Some(Err(self.error.clone().unwrap()));
                }
                _ => continue,
            }
        }

        if !results {
            // set the error state
            self.error = Some(
                LogError::VerifyFailed(format!("entry {} failed to verify", self.seqno)).into(),
            );
            // set our index out of range
            self.seqno = self.entries.len();
            return Some(Err(self.error.clone().unwrap()));
        }

        // if the entry verifies, apply it's mutataions to the kvp
        // the 0th entry has already been applied at this point so no
        // need to do it here
        if self.seqno > 0 {
            if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(LogError::UpdateKvpFailed(e.to_string()).into());
                return Some(Err(self.error.clone().unwrap()));
            }
        }
        // update the lock script to validate the next entry
        self.lock_scripts.clone_from(&entry.locks);
        // update the seqno
        self.prev_seqno = self.seqno;
        self.seqno += 1;
        // return the check count, validated entry, and kvp state
        Some(Ok((count, entry.clone(), self.kvp.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Key, LogValue, Op};
    use multicid::{cid, vlad};
    use multihash::mh;
    use multikey::{EncodedMultikey, Multikey, Views};
    use tracing_subscriber::{fmt, EnvFilter};

    fn first_lock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
                check_signature("/ephemeral", "/entry/")
            "#
            .to_string(),
        )
    }

    fn lock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
                check_signature("/recovery", "/entry/") ||
                check_signature("/pubkey", "/entry/") ||
                check_preimage("/hash")
            "#
            .to_string(),
        )
    }

    fn unlock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
push("/entry/");
push("/entry/proof");
"#
            .to_string(),
        )
    }

    fn init_logger() {
        let subscriber = fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    fn get_key_update_op(k: &str, key: &Multikey) -> Op {
        let kcv = key.conv_view().unwrap();
        let pk = kcv.to_public_key().unwrap();
        Op::Update(k.try_into().unwrap(), LogValue::Data(pk.into()))
    }

    fn get_hash_update_op(k: &str, preimage: &str) -> Op {
        let mh = mh::Builder::new_from_bytes(Codec::Sha3512, preimage.as_bytes())
            .unwrap()
            .try_build()
            .unwrap();
        Op::Update(k.try_into().unwrap(), LogValue::Data(mh.into()))
    }

    #[test]
    fn test_default() {
        let log = Log::default();
        assert_eq!(Vlad::default(), log.vlad);
        assert_eq!(log.iter().next(), None);
    }

    #[test]
    fn test_builder() {
        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();
        let key = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        // build a vlad from the cid
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        // load the entry scripts
        let unlock = unlock_script();
        let lock = lock_script();

        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey_op = get_key_update_op("/pubkey", &key);

        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&ephemeral_op)
            .add_op(&pubkey_op)
            .try_build(|e| {
                // get the serialized version of the entry (with empty proof)
                let ev: Vec<u8> = e.clone().into();
                // get the signing view on the multikey
                let sv = ephemeral.sign_view().unwrap();
                // generate the signature over the event
                let ms = sv.sign(&ev, false, None).unwrap();
                // store the signature as proof
                Ok(ms.into())
            })
            .unwrap();

        // load the first lock script
        let first = first_lock_script();

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&entry)
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert!(!log.foot.is_null());
        assert!(!log.head.is_null());
        assert_eq!(log.foot, log.head);
        assert_eq!(Some(entry), log.iter().next().cloned());
        let verify_iter = log.verify();
        for ret in verify_iter {
            if let Some(e) = ret.err() {
                println!("verify failed: {}", e);
            }
        }
    }

    #[test]
    fn test_entry_iterator() {
        init_logger();

        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();
        let key1 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();
        let key2 = EncodedMultikey::try_from(
            "fba2480260874657374206b65790101203f4c94407de791e53b4df12ef1d5534d1b19ff2ccfccba4ccc4722b6e5e8ea07"
        )
        .unwrap();
        let key3 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120518e3ea918b1168d29ca7e75b0ca84be1ad6edf593a47828894a5f1b94a83bd4"
        )
        .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        // create a vlad
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey1_op = get_key_update_op("/pubkey", &key1);
        let pubkey2_op = get_key_update_op("/pubkey", &key2);
        let pubkey3_op = get_key_update_op("/pubkey", &key3);
        let preimage1_op = get_hash_update_op("/hash", "for great justice");
        let preimage2_op = get_hash_update_op("/hash", "move every zig");

        // load the entry scripts
        let unlock = unlock_script();
        let lock = lock_script();

        tracing::info!("unlock: {:?}", unlock);

        // create the first, self-signed Entry object
        let e1 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(0)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .add_op(&ephemeral_op) // "/ephemeral"
            .add_op(&pubkey1_op) // "/pubkey"
            .add_op(&preimage1_op) // "/preimage"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = ephemeral.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e1);
        let e2 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(1)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&Op::Delete("/ephemeral".try_into().unwrap())) // "/ephemeral"
            .add_op(&pubkey2_op) // "/pubkey"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key1.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e2);
        let e3 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(2)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key2.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e3);
        let e4 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(3)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e3.cid())
            .add_op(&pubkey3_op) // "/pubkey"
            .add_op(&preimage2_op) // "/preimage"
            .try_build(|_| Ok(b"for great justice".to_vec()))
            .unwrap();
        //println!("{:?}", e4);

        // load the first lock script
        let first = first_lock_script();

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1) // foot
            .append_entry(&e2)
            .append_entry(&e3)
            .append_entry(&e4) // head
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert_eq!(4, log.entries.len());
        let mut iter = log.iter();
        assert_eq!(Some(&e1), iter.next());
        assert_eq!(Some(&e2), iter.next());
        assert_eq!(Some(&e3), iter.next());
        assert_eq!(Some(&e4), iter.next());
        assert_eq!(None, iter.next());
        let verify_iter = log.verify();
        for ret in verify_iter {
            match ret {
                Ok((c, _, _)) => {
                    println!("check count: {}", c);
                }
                Err(e) => {
                    println!("verify failed: {}", e);
                    panic!();
                }
            }
        }
    }
}
