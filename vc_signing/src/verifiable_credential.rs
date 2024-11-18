use crate::{Proof, VerifiableCredential};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::to_string;
#[cfg(not(target_family = "wasm"))]
use {
    crate::{CredentialSchema, SchemaEnum, TypeEnum},
    serde_json::{from_value, json, Value},
    url::Url,
    uuid::Uuid,
};
#[cfg(target_family = "wasm")]
use {
    serde::Serializer,
    serde_wasm_bindgen::from_value,
    wasm_bindgen::{prelude::wasm_bindgen, JsError, JsValue},
};

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifiableCredential {
    #[cfg(not(target_family = "wasm"))]
    /// Creates a VerifiableCredential structure from a json value
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
    #[cfg(not(target_family = "wasm"))]
    /// Creates a VerifiableCredential structure from json raw subject & schema with random UUIDs
    pub fn create(subject: Value, schema: Value) -> Result<Self, String> {
        let create = |input| {
            Ok::<Value, String>(json!({
                "@context": vec![Url::parse("https://www.w3.org/ns/credentials/v2").map_err(|e| e.to_string())?],
                "id": Some(Url::parse(&format!("urn:uuid:{}", Uuid::new_v4())).map_err(|e| e.to_string())?),
                "type": TypeEnum::Single("VerifiableCredential".to_string()),
                "issuer": Url::parse(&format!("urn:uuid:{}", Uuid::new_v4())).map_err(|e| e.to_string())?,
                "credentialSchema": SchemaEnum::Single(CredentialSchema {
                    id: Url::parse(&format!("urn:uuid:{}", Uuid::new_v4())).map_err(|e| e.to_string())?,
                    credential_type: "Example".to_string(),
                }),
                "credentialSubject": input
            }))
        };
        Self::new(create(subject)?, create(schema)?)
    }
    #[cfg(target_family = "wasm")]
    /// Converts a VerifiableCredential to a JavaScript object
    pub fn to_object(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::Serializer::json_compatible().serialize_newtype_struct("", self)?)
    }
}
