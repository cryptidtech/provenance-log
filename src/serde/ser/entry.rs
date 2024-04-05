// SPDX-License-Identifier: FSL-1.1
use crate::{entry::SIGIL, Entry};
use multiutil::{EncodingInfo, Varbytes};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Entry`]
impl ser::Serialize for Entry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 9)?;
            ss.serialize_field("version", &self.version)?;
            ss.serialize_field("vlad", &self.vlad)?;
            ss.serialize_field("prev", &self.prev)?;
            ss.serialize_field("lipmaa", &self.lipmaa)?;
            ss.serialize_field("seqno", &self.seqno)?;
            ss.serialize_field("ops", &self.ops)?;
            ss.serialize_field("lock", &self.lock)?;
            ss.serialize_field("unlock", &self.unlock)?;
            ss.serialize_field(
                "proof",
                &Varbytes::encoded_new(self.encoding(), self.proof.clone()),
            )?;
            ss.end()
        } else {
            (
                SIGIL,
                self.version,
                self.vlad.clone(),
                self.prev.clone(),
                self.lipmaa.clone(),
                self.seqno,
                self.ops.clone(),
                self.lock.clone(),
                self.unlock.clone(),
                Varbytes(self.proof.clone()),
            )
            .serialize(serializer)
        }
    }
}
