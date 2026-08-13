// SPDX-License-Identifier: FSL-1.1
use crate::{entry::SIGIL, Entry};
use multi_trait::EncodeIntoBuffer;
use multi_util::EncodingInfo;
use serde::ser::{self, SerializeMap, SerializeStruct};

/// Serialize instance of [`crate::Entry`]
impl ser::Serialize for Entry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 9)?;
            ss.serialize_field("version", &self.version.as_u64())?;
            ss.serialize_field("vlad", &self.vlad)?;
            ss.serialize_field("prev", &self.prev)?;
            ss.serialize_field("lipmaa", &self.lipmaa)?;
            ss.serialize_field("seqno", &self.seqno.as_u64())?;
            ss.serialize_field("ops", &self.ops)?;
            ss.serialize_field("locks", &self.locks)?;
            ss.serialize_field("unlock", &self.unlock)?;
            ss.serialize_field("proofs", &ProofsHelper(&self.proofs, self.encoding()))?;
            ss.end()
        } else {
            let mut v = Vec::new();
            self.encode_into_buffer(&mut v);
            serializer.serialize_bytes(v.as_slice())
        }
    }
}

/// Helper to serialize proofs BTreeMap with encoded varbytes values
struct ProofsHelper<'a>(
    &'a std::collections::BTreeMap<String, Vec<u8>>,
    multi_base::Base,
);

impl ser::Serialize for ProofsHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, bytes) in self.0 {
            map.serialize_entry(
                name,
                &multi_util::Varbytes::encoded_new(self.1, bytes.clone()),
            )?;
        }
        map.end()
    }
}
