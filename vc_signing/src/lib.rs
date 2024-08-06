use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string, Value};
use url::Url;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize)]
struct VerifiableCredential {
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

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum TypeEnum {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StatusEnum {
    Single(CredentialStatus),
    Multiple(Vec<CredentialStatus>),
}

#[derive(Serialize, Deserialize)]
struct CredentialStatus {
    id: Option<Url>,
    #[serde(rename = "type")]
    status_type: TypeEnum,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum SchemaEnum {
    Single(CredentialSchema),
    Multiple(Vec<CredentialSchema>),
}

#[derive(Serialize, Deserialize)]
struct CredentialSchema {
    id: Url,
    #[serde(rename = "type")]
    credential_type: String,
}

#[derive(Serialize, Deserialize)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    jws: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    created: DateTime<Utc>,
}

#[wasm_bindgen]
pub fn sign(
    private_key: &[u8],
    verifiable_credential: &str,
    _schema: &str, // TODO validate schema
) -> Result<String, String> {
    let random = ring::rand::SystemRandom::new();
    let private_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, &random)
            .map_err(|e| e.to_string())?;
    let mut vc: VerifiableCredential =
        from_str(verifiable_credential).map_err(|e| e.to_string())?;
    let jws = private_key
        .sign(
            &random,
            to_string(&vc).map_err(|e| e.to_string())?.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let proof = Proof {
        proof_type: "JsonWebSignature2020".to_string(),
        created: Utc::now(),
        jws: BASE64_STANDARD.encode(jws.as_ref()),
        proof_purpose: "assertionMethod".to_string(),
    };
    vc.proof = Some(proof);
    to_string(&vc).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn verify(public_key: &[u8], verifiable_credential: &str) -> Result<(), String> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key);
    let mut vc: VerifiableCredential =
        from_str(verifiable_credential).map_err(|e| e.to_string())?;
    let jws = vc.proof.take().ok_or("VC is unsigned")?.jws;
    public_key
        .verify(
            to_string(&vc).map_err(|e| e.to_string())?.as_bytes(),
            BASE64_STANDARD
                .decode(jws)
                .map_err(|e| e.to_string())?
                .as_slice(),
        )
        .map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub struct KeyPairStruct {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPairStruct {
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[wasm_bindgen]
pub fn genkeys() -> Result<KeyPairStruct, String> {
    let random = ring::rand::SystemRandom::new();
    let private_key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .map_err(|e| e.to_string())?;
    let public_key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        private_key.as_ref(),
        &random,
    )
    .map_err(|e| e.to_string())?;
    Ok(KeyPairStruct {
        private_key: private_key.as_ref().to_vec(),
        public_key: public_key.public_key().as_ref().to_vec(),
    })
}
