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
            let num_fields = 7
                + if self.prev.is_some() { 1 } else { 0 }
                + if self.lipmaa.is_some() { 1 } else { 0 };
            let mut ss = serializer.serialize_struct(SIGIL.as_str(), num_fields)?;
            ss.serialize_field("version", &self.version)?;
            ss.serialize_field("vlad", &self.vlad)?;
            if let Some(prev) = &self.prev {
                ss.serialize_field("prev", prev)?;
            }
            if let Some(lipmaa) = &self.lipmaa {
                ss.serialize_field("lipmaa", lipmaa)?;
            }
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
            let prev = if let Some(prev) = &self.prev {
                Varbytes(prev.clone().into())
            } else {
                Varbytes::default()
            };
            let lipmaa = if let Some(lipmaa) = &self.lipmaa {
                Varbytes(lipmaa.clone().into())
            } else {
                Varbytes::default()
            };
            let proof = Varbytes(self.proof.clone());

            (
                SIGIL,
                self.version,
                self.vlad.clone(),
                prev,
                lipmaa,
                self.seqno,
                self.ops.clone(),
                self.lock.clone(),
                self.unlock.clone(),
                proof,
            )
                .serialize(serializer)
        }
    }
}
