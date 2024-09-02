use crate::{Proof, VerifiableCredential, VerifiablePresentation};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{from_value, to_string, Value};
use std::fmt::Write;

pub trait ProofTrait {
    fn get_proof(&mut self) -> Result<Proof, String>;
    fn set_proof(&mut self, proof: Proof) -> Result<(), String>;
}

impl ProofTrait for VerifiablePresentation {
    fn get_proof(&mut self) -> Result<Proof, String> {
        self.proof.take().ok_or("VP is unsigned".to_string())
    }
    fn set_proof(&mut self, proof: Proof) -> Result<(), String> {
        self.proof = Some(proof);
        Ok(())
    }
}

impl ProofTrait for VerifiableCredential {
    fn get_proof(&mut self) -> Result<Proof, String> {
        self.proof.take().ok_or("VC is unsigned".to_string())
    }
    fn set_proof(&mut self, proof: Proof) -> Result<(), String> {
        self.proof = Some(proof);
        Ok(())
    }
}

pub trait CryptoTrait: ProofTrait {
    fn sign(mut self, private_key: &[u8]) -> Result<Self, String>
    where
        Self: Serialize + Sized,
    {
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let jws = private_key.sign(to_string(&self).map_err(|e| e.to_string())?.as_bytes());
        let proof = Proof {
            proof_type: "JsonWebSignature2020".to_string(),
            jws: BASE64_STANDARD.encode(jws.as_ref()),
            proof_purpose: "assertionMethod".to_string(),
            created: Utc::now(),
        };
        self.set_proof(proof)?;
        Ok(self)
    }
    fn verify(&self, public_key: &[u8]) -> Result<(), String>
    where
        Self: Serialize + Clone,
    {
        let mut clone = self.clone();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key);
        let jws = clone.get_proof()?.jws;
        public_key
            .verify(
                to_string(&clone).map_err(|e| e.to_string())?.as_bytes(),
                BASE64_STANDARD
                    .decode(jws)
                    .map_err(|e| e.to_string())?
                    .as_slice(),
            )
            .map_err(|e| e.to_string())
    }
}

impl CryptoTrait for VerifiablePresentation {}
impl CryptoTrait for VerifiableCredential {}

impl VerifiablePresentation {
    pub fn new(verifiable_presentation: Value) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        from_value::<Self>(verifiable_presentation).map_err(|e| e.to_string())
    }
}
impl VerifiableCredential {
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

pub fn gen_keys() -> Result<(Vec<u8>, Vec<u8>), String> {
    let private_key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|e| e.to_string())?;
    Ok((
        private_key.as_ref().to_vec(),
        Ed25519KeyPair::from_pkcs8(private_key.as_ref())
            .map_err(|e| e.to_string())?
            .public_key()
            .as_ref()
            .to_vec(),
    ))
}
