use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use serde_json::json;

pub fn sign(
    private_key: &[u8],
    verifiable_credential: &str,
    schema: &str,
) -> Result<String, String> {
    let schema: serde_yaml::Value = serde_yaml::from_str(schema).unwrap();
    let mut verifiable_credential: serde_json::Value =
        serde_json::from_str(verifiable_credential).unwrap();

    for key in schema.get("required").unwrap().as_sequence().unwrap() {
        if verifiable_credential.get(key.as_str().unwrap()).is_none() {
            return Err("Missing required field".to_string());
        }
    }
    let properties = schema.get("properties").unwrap().as_mapping().unwrap();
    for key in verifiable_credential.as_object().unwrap() {
        match properties.get(key.0) {
            Some(info) => {
                match info
                    .as_mapping()
                    .unwrap()
                    .get("type")
                    .unwrap()
                    .as_str()
                    .unwrap()
                {
                    "object" => {
                        if !key.1.is_object() {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "array" => {
                        if !key.1.is_array() {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "number" => {
                        if !(key.1.is_number() && key.1.as_number().unwrap().is_f64()) {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "integer" => {
                        if !(key.1.is_number() && key.1.as_number().unwrap().is_i64()) {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "string" => {
                        if !key.1.is_string() {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "boolean" => {
                        if !key.1.is_boolean() {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    "null" => {
                        if !key.1.is_null() {
                            return Err(format!("{} incorrect type", key.0));
                        }
                    }
                    other => return Err(format!("Unknown type: {}", other)),
                }
            }
            None => {
                return Err("VC contains unknown property".to_string());
            }
        }
    }

    // must have: required
    // can have: properties
    // types: object, array, number, string (+pattern,format), boolean, null

    let random = ring::rand::SystemRandom::new();
    let private_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, &random)
            .map_err(|_| "KeyRejected")?;
    let jws = private_key
        .sign(&random, verifiable_credential.to_string().as_bytes())
        .map_err(|_| "SigningError")?;
    verifiable_credential["proof"] = json!({
        "type": "JsonWebSignature2020",
        "created": Utc::now(),
        "jws": BASE64_STANDARD.encode(jws.as_ref()),
        "proof_purpose": "assertionMethod",
    });
    Ok(verifiable_credential.to_string())
}

pub fn verify(
    public_key: &[u8],
    verifiable_credential: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key);
    let mut vc: serde_json::Value = serde_json::from_str(verifiable_credential)?;
    let jws = vc
        .get("proof")
        .ok_or("VC is unsigned")?
        .get("jws")
        .unwrap()
        .clone();
    vc.as_object_mut().unwrap().remove("proof").unwrap();
    Ok(public_key
        .verify(
            vc.to_string().as_bytes(),
            BASE64_STANDARD
                .decode(jws.as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .map_err(|_| "VerifyingError")?)
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
