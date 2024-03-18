// SPDX-License-Identifier: FSL-1.1
use crate::{log::SIGIL, Entry, Log};
use multicid::Cid;
use multiutil::Varbytes;
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Log`]
impl ser::Serialize for Log {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 4)?;
            ss.serialize_field("vlad", &self.vlad)?;
            ss.serialize_field("first_lock", &self.first_lock)?;
            if let Some(foot) = &self.foot {
                ss.serialize_field("foot", foot)?;
            }
            if let Some(head) = &self.head {
                ss.serialize_field("head", head)?;
            }
            ss.end()
        } else {
            let foot = if let Some(foot) = &self.foot {
                Varbytes(foot.clone().into())
            } else {
                Varbytes::default()
            };
            let head = if let Some(head) = &self.head {
                Varbytes(head.clone().into())
            } else {
                Varbytes::default()
            };
            let entries: Vec<(Cid, Entry)> = self
                .entries
                .iter()
                .map(|(cid, entry)| (cid.clone(), entry.clone()))
                .collect();
            (
                SIGIL,
                self.version,
                self.vlad.clone(),
                self.first_lock.clone(),
                foot,
                head,
                entries,
            )
                .serialize(serializer)
        }
    }
}
