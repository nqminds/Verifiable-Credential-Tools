use crate::{Proof, VerifiableCredential};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;
#[cfg(target_family = "wasm")]
use serde::Serializer;
use serde_json::to_string;
#[cfg(not(target_family = "wasm"))]
use serde_json::{from_value, Value};
#[cfg(target_family = "wasm")]
use serde_wasm_bindgen::from_value;
#[cfg(target_family = "wasm")]
use wasm_bindgen::{prelude::wasm_bindgen, JsError, JsValue};

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifiableCredential {
    #[cfg(not(target_family = "wasm"))]
    /// Creates a verifiable credential structure from a json value
    pub fn new(verifiable_credential: Value, schema: Value) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        let schema = from_value::<Self>(schema).map_err(|e| e.to_string())?;
        let verifiable_credential =
            from_value::<Self>(verifiable_credential).map_err(|e| e.to_string())?;
        let validator =
            jsonschema::validator_for(&schema.credential_subject).map_err(|e| e.to_string())?;
        let errors: Vec<_> = validator
            .iter_errors(&verifiable_credential.credential_subject)
            .collect();
        match errors.is_empty() {
            true => Ok(verifiable_credential),
            false => {
                let errors: Vec<_> = errors
                    .iter()
                    .map(|e| format!("Schema validation error: {} At: {}", e, e.instance_path))
                    .collect();
                Err(errors.join("\n"))
            }
        }
    }
    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(constructor)]
    pub fn new(verifiable_credential: JsValue, schema: JsValue) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        let schema = from_value::<Self>(schema).map_err(|e| e.to_string())?;
        let verifiable_credential =
            from_value::<Self>(verifiable_credential).map_err(|e| e.to_string())?;
        let validator =
            jsonschema::validator_for(&schema.credential_subject).map_err(|e| e.to_string())?;
        let errors: Vec<_> = validator
            .iter_errors(&verifiable_credential.credential_subject)
            .collect();
        match errors.is_empty() {
            true => Ok(verifiable_credential),
            false => {
                let errors: Vec<_> = errors
                    .iter()
                    .map(|e| format!("Schema validation error: {} At: {}", e, e.instance_path))
                    .collect();
                Err(errors.join("\n"))
            }
        }
    }
    /// Signs a VerifiableCredential with the given private key
    pub fn sign(mut self, private_key: &[u8]) -> Result<Self, String>
    where
        Self: Serialize + Sized,
    {
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
    pub fn verify(&self, public_key: &[u8]) -> Result<(), String>
    where
        Self: Serialize + Clone,
    {
        let mut clone = self.clone();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key);
        let proof = BASE64_STANDARD
            .decode(clone.proof.take().ok_or("VP is unsigned")?.proof_value)
            .map_err(|e| e.to_string())?;
        public_key
            .verify(
                to_string(&clone).map_err(|e| e.to_string())?.as_bytes(),
                &proof,
            )
            .map_err(|_| "Failed to verify".into())
    }
    #[cfg(target_family = "wasm")]
    pub fn to_object(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::Serializer::json_compatible().serialize_newtype_struct("", self)?)
    }
}
