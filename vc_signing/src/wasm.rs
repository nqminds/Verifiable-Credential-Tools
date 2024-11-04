use crate::{Proof, VerifiableCredential, VerifiablePresentation};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::Serializer;
use serde_json::to_string;
use std::fmt::Write;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
impl VerifiablePresentation {
    #[wasm_bindgen(constructor)]
    /// Creates a VerifiablePresentation struct from a JavaScript object
    pub fn new(verifiable_presentation: JsValue) -> Result<VerifiablePresentation, String> {
        serde_wasm_bindgen::from_value::<VerifiablePresentation>(verifiable_presentation)
            .map_err(|e| e.to_string())
    }
    /// Signs a VerifiablePresentation with the given private key
    pub fn sign(mut self, private_key: &[u8]) -> Result<VerifiablePresentation, String> {
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let proof_value = private_key.sign(to_string(&self).map_err(|e| e.to_string())?.as_bytes());
        self.proof = Some(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            cryptosuite: "eddsa-rdfc-2022".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: BASE64_STANDARD.encode(proof_value.as_ref()),
        });
        Ok(self)
    }
    /// Verifies a VerifiablePresentation was signed by the owner of the given public key
    pub fn verify(&self, public_key: &[u8]) -> Result<(), String> {
        let mut clone = self.clone();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key);
        let proof_value = clone.proof.take().ok_or("VC is unsigned")?.proof_value;
        public_key
            .verify(
                to_string(&clone).map_err(|e| e.to_string())?.as_bytes(),
                BASE64_STANDARD
                    .decode(proof_value)
                    .map_err(|e| e.to_string())?
                    .as_slice(),
            )
            .map_err(|e| e.to_string())
    }
    /// Creates a JavaScript object from a VerifiablePresentation
    pub fn to_object(&self) -> Result<JsValue, String> {
        serde_wasm_bindgen::Serializer::json_compatible()
            .serialize_newtype_struct("", self)
            .map_err(|e| e.to_string())
    }
}

#[wasm_bindgen]
impl VerifiableCredential {
    #[wasm_bindgen(constructor)]
    /// Creates a VerifiableCredential struct from a JavaScript object
    pub fn new(
        verifiable_credential: JsValue,
        schema: JsValue,
    ) -> Result<VerifiableCredential, String> {
        let schema = serde_wasm_bindgen::from_value::<VerifiableCredential>(schema)
            .map_err(|e| e.to_string())?;
        let verifiable_credential =
            serde_wasm_bindgen::from_value::<VerifiableCredential>(verifiable_credential)
                .map_err(|e| e.to_string())?;
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
    /// Signs a VerifiableCredential with the given private key
    pub fn sign(mut self, private_key: &[u8]) -> Result<VerifiableCredential, String> {
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let proof_value = private_key.sign(to_string(&self).map_err(|e| e.to_string())?.as_bytes());
        self.proof = Some(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            cryptosuite: "eddsa-rdfc-2022".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: BASE64_STANDARD.encode(proof_value.as_ref()),
        });
        Ok(self)
    }
    /// Verifies a VerifiableCredential was signed by the owner of the given public key
    pub fn verify(&self, public_key: &[u8]) -> Result<(), String> {
        let mut clone = self.clone();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key);
        let proof_value = clone.proof.take().ok_or("VC is unsigned")?.proof_value;
        public_key
            .verify(
                to_string(&clone).map_err(|e| e.to_string())?.as_bytes(),
                BASE64_STANDARD
                    .decode(proof_value)
                    .map_err(|e| e.to_string())?
                    .as_slice(),
            )
            .map_err(|e| e.to_string())
    }
    /// Creates a JavaScript object from a VerifiableCredential
    pub fn to_object(&self) -> Result<JsValue, String> {
        serde_wasm_bindgen::Serializer::json_compatible()
            .serialize_newtype_struct("", self)
            .map_err(|e| e.to_string())
    }
}
