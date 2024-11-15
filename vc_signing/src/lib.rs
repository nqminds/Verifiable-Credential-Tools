use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "cbor")]
mod cbor;
#[cfg(feature = "protobuf")]
mod protobuf;
mod verifiable_credential;
mod verifiable_presentation;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct VerifiablePresentation {
    id: Option<Url>,
    #[serde(rename = "type")]
    vp_type: TypeEnum,
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: VerifiableCredentialEnum,
    holder: Option<Url>,
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum VerifiableCredentialEnum {
    Single(VerifiableCredential),
    Multiple(Vec<VerifiableCredential>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    context: Vec<Url>,
    id: Option<Url>,
    #[serde(rename = "type")]
    vc_type: TypeEnum,
    name: Option<String>,
    description: Option<String>,
    issuer: Url,
    #[serde(rename = "validFrom")]
    valid_from: Option<DateTime<Utc>>,
    #[serde(rename = "validUntil")]
    valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "credentialStatus")]
    credential_status: Option<StatusEnum>,
    #[serde(rename = "credentialSchema")]
    credential_schema: SchemaEnum,
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum TypeEnum {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum StatusEnum {
    Single(CredentialStatus),
    Multiple(Vec<CredentialStatus>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct CredentialStatus {
    id: Option<Url>,
    #[serde(rename = "type")]
    status_type: TypeEnum,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum SchemaEnum {
    Single(CredentialSchema),
    Multiple(Vec<CredentialSchema>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct CredentialSchema {
    id: Url,
    #[serde(rename = "type")]
    credential_type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    created: DateTime<Utc>,
    cryptosuite: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    #[serde(rename = "proofValue")]
    proof_value: String,
}

#[cfg(not(target_family = "wasm"))]
pub struct SignatureKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct SignatureKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl SignatureKeyPair {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Result<Self, String> {
        let key_pair = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| "Error generating key pair")?;
        let public_key = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
            .map_err(|_| "Error generating key pair")?
            .public_key()
            .as_ref()
            .to_vec();
        let private_key = key_pair.as_ref().to_vec();
        Ok(Self {
            private_key,
            public_key,
        })
    }
    #[cfg(target_family = "wasm")]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    #[cfg(target_family = "wasm")]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}
