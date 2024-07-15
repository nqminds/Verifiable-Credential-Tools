use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string, Value};
use std::fs::{read, write};
use std::io::{stdin, Read};
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

fn main() {
    let mut args = std::env::args();
    let random = ring::rand::SystemRandom::new();
    match args.nth(1).as_deref() {
        Some("-sign") => {
            if let Some(path) = args.next() {
                if let Ok(contents) = read(path) {
                    let private_key = EcdsaKeyPair::from_pkcs8(
                        &ECDSA_P256_SHA256_ASN1_SIGNING,
                        &contents,
                        &random,
                    )
                    .unwrap();
                    let mut buffer = String::new();
                    stdin().read_to_string(&mut buffer).unwrap();
                    let mut vc: VerifiableCredential = from_str(&buffer).unwrap();
                    let jws = private_key
                        .sign(&random, to_string(&vc).unwrap().as_bytes())
                        .unwrap();
                    let proof = Proof {
                        proof_type: "JsonWebSignature2020".to_string(),
                        created: Utc::now(),
                        jws: BASE64_STANDARD.encode(jws.as_ref()),
                        proof_purpose: "assertionMethod".to_string(),
                    };
                    vc.proof = Some(proof);
                    println!("{}", to_string(&vc).unwrap());
                } else {
                    eprintln!("Invalid key");
                }
            } else {
                eprintln!("Missing key arg");
            }
        }
        Some("-verify") => {
            if let Some(path) = args.next() {
                if let Ok(contents) = read(path) {
                    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &contents);
                    let mut buffer = String::new();
                    stdin().read_to_string(&mut buffer).unwrap();
                    let mut vc: VerifiableCredential = from_str(&buffer).unwrap();
                    let jws = vc.proof.take().unwrap().jws;
                    println!(
                        "{:?}",
                        public_key.verify(
                            to_string(&vc).unwrap().as_bytes(),
                            BASE64_STANDARD.decode(jws).unwrap().as_slice()
                        )
                    );
                } else {
                    eprintln!("Invalid key");
                }
            } else {
                eprintln!("Missing key arg");
            }
        }
        Some("-genkeys") => {
            let private_key =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            write(
                args.next().unwrap_or(String::from("private_key")),
                private_key.as_ref(),
            )
            .unwrap();
            write(
                args.next().unwrap_or(String::from("public_key")),
                EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    private_key.as_ref(),
                    &random,
                )
                .unwrap()
                .public_key(),
            )
            .unwrap();
        }
        _ => {
            println!(
                "Usage: verifiable_credentials -sign key_path|-verify key_path|-genkeys \
                [private_key_path public_key_path]\nVCs are supplied to stdin \
                (either pasted or piped), signed and returned on stdout"
            );
        }
    }
}
