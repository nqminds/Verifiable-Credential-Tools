#[cfg(feature = "protobuf")]
use crate::protobuf;
use crate::{Proof, VerifiableCredential, VerifiablePresentation};
use chrono::Utc;
#[cfg(feature = "protobuf")]
use prost::Message;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{from_value, to_string, Value};
use std::fmt::Write;

pub trait VerifiableFunctions {
    fn get_proof(&mut self) -> Result<Proof, String>;
    fn set_proof(&mut self, proof: Proof);
    /// Signs a verifiable structure with the given private key
    fn sign(mut self, private_key: &[u8]) -> Result<Self, String>
    where
        Self: Serialize + Sized,
    {
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let proof_value = private_key.sign(to_string(&self).map_err(|e| e.to_string())?.as_bytes());
        self.set_proof(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            cryptosuite: "eddsa-rdfc-2022".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: proof_value.as_ref().to_vec(),
        });
        Ok(self)
    }
    /// Verifies a verifiable structure was signed by the owner of the given public key
    fn verify(&self, public_key: &[u8]) -> Result<(), String>
    where
        Self: Serialize + Clone,
    {
        let mut clone = self.clone();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key);
        let proof_value = clone.get_proof()?.proof_value;
        public_key
            .verify(
                to_string(&clone).map_err(|e| e.to_string())?.as_bytes(),
                &proof_value,
            )
            .map_err(|e| e.to_string())
    }
    #[cfg(feature = "cbor")]
    /// Serializes a verifiable structure into cbor
    fn serialize_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>>
    where
        Self: Serialize,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }
    #[cfg(feature = "cbor")]
    /// Deserializes cbor into a verifiable structure
    fn deserialize_cbor(reader: Vec<u8>) -> Result<Self, String>
    where
        Self: DeserializeOwned + Sized,
    {
        ciborium::from_reader(reader.as_slice()).map_err(|e| e.to_string())
    }
    #[cfg(feature = "protobuf")]
    fn serialize_protobuf(self) -> Vec<u8>;
    #[cfg(feature = "protobuf")]
    fn deserialize_protobuf(reader: Vec<u8>) -> Result<Self, prost::DecodeError>
    where
        Self: Sized;
}

impl VerifiableFunctions for VerifiablePresentation {
    fn get_proof(&mut self) -> Result<Proof, String> {
        self.proof.take().ok_or("VP is unsigned".to_string())
    }
    fn set_proof(&mut self, proof: Proof) {
        self.proof = Some(proof);
    }
    #[cfg(feature = "protobuf")]
    /// Serializes a verifiable presentation structure into protobuf
    fn serialize_protobuf(self) -> Vec<u8> {
        Into::<protobuf::verifiable_credentials::VerifiablePresentation>::into(self).encode_to_vec()
    }
    #[cfg(feature = "protobuf")]
    /// Deserializes protobuf into a verifiable presentation structure
    fn deserialize_protobuf(reader: Vec<u8>) -> Result<Self, prost::DecodeError> {
        Ok(Into::<VerifiablePresentation>::into(
            protobuf::verifiable_credentials::VerifiablePresentation::decode(reader.as_slice())?,
        ))
    }
}

impl VerifiableFunctions for VerifiableCredential {
    fn get_proof(&mut self) -> Result<Proof, String> {
        self.proof.take().ok_or("VC is unsigned".to_string())
    }
    fn set_proof(&mut self, proof: Proof) {
        self.proof = Some(proof);
    }
    #[cfg(feature = "protobuf")]
    /// Serializes a verifiable credential structure into protobuf
    fn serialize_protobuf(self) -> Vec<u8> {
        Into::<protobuf::verifiable_credentials::VerifiableCredential>::into(self).encode_to_vec()
    }
    #[cfg(feature = "protobuf")]
    /// Deserializes protobuf into a verifiable credential structure
    fn deserialize_protobuf(reader: Vec<u8>) -> Result<Self, prost::DecodeError> {
        Ok(Into::<VerifiableCredential>::into(
            protobuf::verifiable_credentials::VerifiableCredential::decode(reader.as_slice())?,
        ))
    }
}

impl VerifiablePresentation {
    /// Creates a verifiable presentation structure from a json value
    pub fn new(verifiable_presentation: Value) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        from_value::<Self>(verifiable_presentation).map_err(|e| e.to_string())
    }
}

impl VerifiableCredential {
    /// Creates a verifiable credential structure from a json value
    pub fn new(verifiable_credential: Value, schema: Value) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        let schema = from_value::<Self>(schema).map_err(|e| e.to_string())?;
        let verifiable_credential =
            from_value::<Self>(verifiable_credential).map_err(|e| e.to_string())?;
        let mut scope = valico::json_schema::Scope::new();
        let schema = scope
            .compile_and_return(schema.credential_subject, true)
            .map_err(|e| e.to_string())?;
        let result = schema.validate(&verifiable_credential.credential_subject);
        if !result.is_valid() {
            return Err(result.errors.iter().fold(String::new(), |mut output, e| {
                match e.get_detail() {
                    Some(detail) => writeln!(output, "{}: {}", e.get_path(), detail).unwrap(),
                    None => writeln!(output, "{}", e.get_path()).unwrap(),
                }
                output
            }));
        }
        Ok(verifiable_credential)
    }
}
