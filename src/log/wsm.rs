use super::*;

use wacc::{prelude::StoreLimitsBuilder, vm, Stack};

impl<'a> Iterator for VerifyIter<'a> {
    type Item = Result<(usize, Entry, Kvp<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        //println!("iter::next({})", self.seqno);
        let entry = match self.entries.get(self.seqno) {
            Some(e) => *e,
            None => return None,
        };

        // this is the check count if successful
        let mut count = 0;

        // set up the stacks
        let mut pstack = Stk::default();
        let mut rstack = Stk::default();

        // check the seqno meet the criteria
        if self.seqno > 0 && self.seqno != self.prev_seqno + 1 {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error state
            self.error = Some(LogError::InvalidSeqno.into());
            return Some(Err(self.error.clone().unwrap()));
        }

        // 'unlock:
        let mut result = {
            // run the unlock script using the entry as the kvp to get the
            // stack in the vm::Context set up.
            let unlock_ctx = vm::Context {
                current: entry,  // limit the available data to just the entry
                proposed: entry, // limit the available data to just the entry
                pstack: &mut pstack,
                rstack: &mut rstack,
                check_count: 0,
                write_idx: 0,
                context: entry.context().to_string(),
                log: Vec::default(),
                limiter: StoreLimitsBuilder::new()
                    .memory_size(1 << 16)
                    .instances(2)
                    .memories(1)
                    .build(),
            };

            let mut instance = match vm::Builder::new()
                .with_context(unlock_ctx)
                .with_bytes(entry.unlock.clone())
                .try_build()
            {
                Ok(i) => i,
                Err(e) => {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self.error.clone().unwrap()));
                }
            };
            //print!("running unlock script from seqno: {}...", self.seqno);

            // run the unlock script
            if let Some(e) = instance.run("for_great_justice").err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(LogError::Wacc(e).into());
                return Some(Err(self.error.clone().unwrap()));
            }

            //println!("SUCCEEDED!");

            true
        };

        /*
        println!("values:");
        println!("{:?}", pstack.clone());
        println!("return:");
        println!("{:?}", rstack.clone());
        */

        if !result {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed(format!(
                    "unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}",
                    rstack, pstack
                ))
                .into(),
            );
            return Some(Err(self.error.clone().unwrap()));
        }

        /*
        // set the entry to look into for proof and message values
        if let Some(e) = self.kvp.set_entry(entry).err() {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(LogError::KvpSetEntryFailed(e.to_string()).into());
            return Some(Err(self.error.clone().unwrap()));
        }
        */

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

        // 'lock:
        result = false;

        // build the set of lock scripts to run in order from root to longest branch to leaf
        let locks = match entry.sort_locks(&self.lock_scripts) {
            Ok(l) => l,
            Err(e) => {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(e);
                return Some(Err(self.error.clone().unwrap()));
            }
        };

        // run each of the lock scripts
        for lock in locks {
            // NOTE: clone the kvp and stacks each time
            let lock_kvp = self.kvp.clone();
            let mut lock_pstack = pstack.clone();
            let mut lock_rstack = rstack.clone();

            {
                let lock_ctx = vm::Context {
                    current: &lock_kvp,
                    proposed: entry,
                    pstack: &mut lock_pstack,
                    rstack: &mut lock_rstack,
                    check_count: 0,
                    write_idx: 0,
                    context: entry.context().to_string(), // set the branch path for branch()
                    log: Vec::default(),
                    limiter: StoreLimitsBuilder::new()
                        .memory_size(1 << 16)
                        .instances(2)
                        .memories(1)
                        .build(),
                };

                let mut instance = match vm::Builder::new()
                    .with_context(lock_ctx)
                    .with_bytes(lock.clone())
                    .try_build()
                {
                    Ok(i) => i,
                    Err(e) => {
                        // set our index out of range
                        self.seqno = self.entries.len();
                        self.error = Some(LogError::Wacc(e).into());
                        return Some(Err(self.error.clone().unwrap()));
                    }
                };
                //print!("running lock script from seqno: {}...", self.seqno);

                // run the unlock script
                if let Some(e) = instance.run("move_every_zig").err() {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self.error.clone().unwrap()));
                }

                //println!("SUCCEEDED!");
            }

            // break out of this loop as soon as a lock script succeeds
            if let Some(v) = lock_rstack.top() {
                match v {
                    vm::Value::Success(c) => {
                        count = c;
                        result = true;
                        break;
                    }
                    _ => result = false,
                }
            }
        }

        if result {
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
        } else {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed(format!(
                    "unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}",
                    rstack, pstack
                ))
                .into(),
            );
            return Some(Err(self.error.clone().unwrap()));
        }

        // return the check count, validated entry, and kvp state
        Some(Ok((count, entry.clone(), self.kvp.clone())))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Key, Op, Value};
    use multicid::{cid, vlad};
    use multihash::mh;
    use multikey::{EncodedMultikey, Multikey, Views};
    use std::path::PathBuf;

    fn load_script(path: &Key, file_name: &str) -> Script {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("examples");
        pb.push("wast");
        pb.push(file_name);
        crate::script::Builder::from_code_file(&pb)
            .with_path(path)
            .try_build()
            .unwrap()
    }

    fn get_key_update_op(k: &str, key: &Multikey) -> Op {
        let kcv = key.conv_view().unwrap();
        let pk = kcv.to_public_key().unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
    }

    fn get_hash_update_op(k: &str, preimage: &str) -> Op {
        let mh = mh::Builder::new_from_bytes(Codec::Sha3512, preimage.as_bytes())
            .unwrap()
            .try_build()
            .unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(mh.into()))
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
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
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
        let first = load_script(&Key::default(), "first.wast");

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
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");

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
        let first = load_script(&Key::default(), "first.wast");

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

/*
the gifts of wilderness are given
—in no small measure or part—
to those who call it livin'
having outside inside their heart
*/
