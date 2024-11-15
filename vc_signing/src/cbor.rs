use crate::{VerifiableCredential, VerifiablePresentation};
use serde::{de::DeserializeOwned, Serialize};

impl VerifiablePresentation {
    /// Serializes a verifiable structure into cbor
    pub fn serialize_cbor(&self) -> Result<Vec<u8>, String>
    where
        Self: Serialize,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }
    /// Deserializes cbor into a verifiable structure
    pub fn deserialize_cbor(reader: Vec<u8>) -> Result<Self, String>
    where
        Self: DeserializeOwned + Sized,
    {
        ciborium::from_reader(reader.as_slice()).map_err(|e| e.to_string())
    }
}

impl VerifiableCredential {
    /// Serializes a verifiable structure into cbor
    pub fn serialize_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>>
    where
        Self: Serialize,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }
    /// Deserializes cbor into a verifiable structure
    pub fn deserialize_cbor(reader: Vec<u8>) -> Result<Self, String>
    where
        Self: DeserializeOwned + Sized,
    {
        ciborium::from_reader(reader.as_slice()).map_err(|e| e.to_string())
    }
}
