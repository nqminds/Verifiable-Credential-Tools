use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string, Value};
use std::io::ErrorKind;
use url::Url;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ID {
    Uuid(Uuid),
    Url(Url),
}

#[derive(Serialize, Deserialize)]
struct VerifiableCredential {
    #[serde(rename = "@context")]
    context: Vec<Url>,
    id: ID,
    #[serde(rename = "type")]
    vc_type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
    #[serde(rename = "credentialSchema")]
    credential_schema: CredentialSchema,
    issuer: String,
    #[serde(rename = "issuanceDate")]
    issuance_date: DateTime<Utc>,
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize)]
struct CredentialSchema {
    id: ID,
    #[serde(rename = "type")]
    credential_type: String,
    jws: String,
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

pub fn sign(
    private_key: &[u8],
    verifiable_credential: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let random = ring::rand::SystemRandom::new();
    let private_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, &random)
            .map_err(|_| std::io::Error::new(ErrorKind::Other, "KeyRejected"))?;
    let mut vc: VerifiableCredential = from_str(verifiable_credential)?;
    let jws = private_key
        .sign(&random, to_string(&vc)?.as_bytes())
        .map_err(|_| std::io::Error::new(ErrorKind::Other, "SigningError"))?;
    let proof = Proof {
        proof_type: "JsonWebSignature2020".to_string(),
        created: Utc::now(),
        jws: BASE64_STANDARD.encode(jws.as_ref()),
        proof_purpose: "assertionMethod".to_string(),
    };
    vc.proof = Some(proof);
    Ok(to_string(&vc)?)
}

pub fn verify(
    public_key: &[u8],
    verifiable_credential: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key);
    let mut vc: VerifiableCredential = from_str(verifiable_credential)?;
    let jws = vc.proof.take().ok_or("Proof partially moved")?.jws;
    Ok(public_key
        .verify(
            to_string(&vc)?.as_bytes(),
            BASE64_STANDARD.decode(jws)?.as_slice(),
        )
        .map_err(|_| std::io::Error::new(ErrorKind::Other, "VerifyingError"))?)
}

pub fn genkeys() -> Result<(Vec<u8>, Vec<u8>), ring::error::Unspecified> {
    let random = ring::rand::SystemRandom::new();
    let private_key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)?;
    Ok((
        private_key.as_ref().to_vec(),
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            private_key.as_ref(),
            &random,
        )?
        .public_key()
        .as_ref()
        .to_vec(),
    ))
}
