use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{to_string, Value};
use std::fmt::Write;
use url::Url;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[wasm_bindgen]
pub struct VerifiablePresentation {
    id: Option<Url>,
    #[serde(rename = "type")]
    vp_type: TypeEnum,
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: VerifiableCredentialEnum,
    holder: Option<Url>,
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum VerifiableCredentialEnum {
    Single(VerifiableCredential),
    Multiple(Vec<VerifiableCredential>),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[wasm_bindgen]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum TypeEnum {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum StatusEnum {
    Single(CredentialStatus),
    Multiple(Vec<CredentialStatus>),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CredentialStatus {
    id: Option<Url>,
    #[serde(rename = "type")]
    status_type: TypeEnum,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum SchemaEnum {
    Single(CredentialSchema),
    Multiple(Vec<CredentialSchema>),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CredentialSchema {
    id: Url,
    #[serde(rename = "type")]
    credential_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    pub cryptosuite: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

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

#[wasm_bindgen]
pub struct KeyPairStruct {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPairStruct {
    /// Returns the private key contained in the struct
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
    /// Returns the public key contained in the struct
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[wasm_bindgen]
/// Generates a structure containing a PKCS#8 ED25519 public private key pair
pub fn gen_keys() -> Result<KeyPairStruct, String> {
    let private_key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|e| e.to_string())?
        .as_ref()
        .to_vec();
    let public_key = Ed25519KeyPair::from_pkcs8(&private_key)
        .map_err(|e| e.to_string())?
        .public_key()
        .as_ref()
        .to_vec();
    Ok(KeyPairStruct {
        private_key,
        public_key,
    })
}
