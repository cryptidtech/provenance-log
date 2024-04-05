// SPDX-License-Identifier: FSL-1.1
use crate::{log::SIGIL, Entry, Log};
use multicid::Cid;
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
            ss.serialize_field("foot", &self.foot)?;
            ss.serialize_field("head", &self.head)?;
            ss.end()
        } else {
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
                self.foot.clone(),
                self.head.clone(),
                entries,
            )
                .serialize(serializer)
        }
    }
}
