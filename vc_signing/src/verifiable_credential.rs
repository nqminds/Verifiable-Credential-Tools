use crate::{CredentialSchema, SchemaEnum, TypeEnum};
use crate::{Proof, VerifiableCredential};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{from_str, to_string};
#[cfg(not(target_family = "wasm"))]
use serde_json::{from_value, Value};
use std::error::Error;
use url::Url;
use uuid::Uuid;
#[cfg(target_family = "wasm")]
use {
    serde::Serializer,
    serde_wasm_bindgen::from_value,
    wasm_bindgen::{prelude::wasm_bindgen, JsError, JsValue},
};

const SCHEMA_SCHEMA: &str = include_str!("../schema_schema.json");

#[cfg(not(target_family = "wasm"))]
pub struct SignedSchema<'a> {
    vc: VerifiableCredential,
    public_key: &'a [u8],
}

#[cfg(not(target_family = "wasm"))]
impl<'a> SignedSchema<'a> {
    pub fn new(vc: VerifiableCredential, public_key: &'a [u8]) -> Self {
        Self { vc, public_key }
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct SignedSchema {
    vc: VerifiableCredential,
    public_key: Vec<u8>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl SignedSchema {
    #[wasm_bindgen(constructor)]
    pub fn new(vc: VerifiableCredential, public_key: Vec<u8>) -> Self {
        Self { vc, public_key }
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifiableCredential {
    fn schema_check(
        verifiable_credential: Self,
        schema: Option<SignedSchema>,
    ) -> Result<Self, String> {
        match schema {
            None => {
                if let SchemaEnum::Single(CredentialSchema {
                    id,
                    credential_type: _,
                }) = &verifiable_credential.credential_schema
                {
                    if id.to_string() == "https://json-schema.org/draft/2020-12/schema" {
                        let schema = from_str(SCHEMA_SCHEMA).map_err(|e| e.to_string())?;
                        let validator =
                            jsonschema::validator_for(&schema).map_err(|e| e.to_string())?;
                        let errors: Vec<_> = validator
                            .iter_errors(&verifiable_credential.credential_subject)
                            .collect();
                        match errors.is_empty() {
                            true => Ok(verifiable_credential),
                            false => {
                                let errors: Vec<_> = errors
                                    .iter()
                                    .map(|e| {
                                        format!(
                                            "Schema validation error: {} At: {}",
                                            e, e.instance_path
                                        )
                                    })
                                    .collect();
                                Err(errors.join("\n"))
                            }
                        }
                    } else {
                        Err("Missing schema".into())
                    }
                } else {
                    Err("Missing schema".into())
                }
            }
            Some(schema) => {
                if schema.vc.verify(&schema.public_key).is_ok() {
                    let validator = jsonschema::validator_for(&schema.vc.credential_subject)
                        .map_err(|e| e.to_string())?;
                    let errors: Vec<_> = validator
                        .iter_errors(&verifiable_credential.credential_subject)
                        .collect();
                    match errors.is_empty() {
                        true => Ok(verifiable_credential),
                        false => {
                            let errors: Vec<_> = errors
                                .iter()
                                .map(|e| {
                                    format!(
                                        "Schema validation error: {} At: {}",
                                        e, e.instance_path
                                    )
                                })
                                .collect();
                            Err(errors.join("\n"))
                        }
                    }
                } else {
                    Err("Failed to verify schema signature".into())
                }
            }
        }
    }
    #[cfg(not(target_family = "wasm"))]
    /// Creates a VerifiableCredential structure from a json value
    pub fn new(verifiable_credential: Value, schema: Option<SignedSchema>) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        Self::schema_check(
            from_value::<Self>(verifiable_credential).map_err(|e| e.to_string())?,
            schema,
        )
    }
    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(constructor)]
    pub fn new(
        verifiable_credential: JsValue,
        create: bool,
        schema: Option<SignedSchema>,
    ) -> Result<Self, String>
    where
        Self: DeserializeOwned,
    {
        match create {
            true => {
                let create = |input, schema_id| -> Result<Self, Box<dyn Error>> {
                    Ok(Self {
                        context: vec![Url::parse("https://www.w3.org/ns/credentials/v2")?],
                        id: Some(Url::parse(&format!("urn:uuid:{}", Uuid::new_v4()))?),
                        vc_type: TypeEnum::Single("VerifiableCredential".to_string()),
                        name: None,
                        description: None,
                        issuer: Url::parse(&format!("urn:uuid:{}", Uuid::new_v4()))?,
                        valid_from: None,
                        valid_until: None,
                        credential_status: None,
                        credential_schema: SchemaEnum::Single(CredentialSchema {
                            id: Url::parse(schema_id)?,
                            credential_type: "JsonSchema".to_string(),
                        }),
                        credential_subject: from_value(input)?,
                        proof: None,
                    })
                };
                match schema {
                    None => Self::schema_check(
                        create(
                            verifiable_credential,
                            "https://json-schema.org/draft/2020-12/schema",
                        )
                        .map_err(|e| e.to_string())?,
                        None,
                    ),
                    Some(schema) => Self::schema_check(
                        create(
                            verifiable_credential,
                            schema
                                .vc
                                .credential_subject
                                .get("$id")
                                .ok_or("No $id field in schema")?
                                .as_str()
                                .ok_or("$id is not str")?,
                        )
                        .map_err(|e| e.to_string())?,
                        Some(schema),
                    ),
                }
            }
            false => Self::schema_check(
                from_value::<Self>(verifiable_credential).map_err(|e| e.to_string())?,
                schema,
            ),
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
            .decode(clone.proof.take().ok_or("VC is unsigned")?.proof_value)
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
    pub fn create(subject: Value, schema: Option<SignedSchema>) -> Result<Self, String> {
        let create = |input, schema_id| -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                context: vec![Url::parse("https://www.w3.org/ns/credentials/v2")?],
                id: Some(Url::parse(&format!("urn:uuid:{}", Uuid::new_v4()))?),
                vc_type: TypeEnum::Single("VerifiableCredential".to_string()),
                name: None,
                description: None,
                issuer: Url::parse(&format!("urn:uuid:{}", Uuid::new_v4()))?,
                valid_from: None,
                valid_until: None,
                credential_status: None,
                credential_schema: SchemaEnum::Single(CredentialSchema {
                    id: Url::parse(schema_id)?,
                    credential_type: "JsonSchema".to_string(),
                }),
                credential_subject: input,
                proof: None,
            })
        };
        match schema {
            None => Self::schema_check(
                create(subject, "https://json-schema.org/draft/2020-12/schema")
                    .map_err(|e| e.to_string())?,
                None,
            ),
            Some(schema) => Self::schema_check(
                create(
                    subject,
                    schema
                        .vc
                        .credential_subject
                        .get("$id")
                        .ok_or("No $id field in schema")?
                        .as_str()
                        .ok_or("$id is not str")?,
                )
                .map_err(|e| e.to_string())?,
                Some(schema),
            ),
        }
    }
    #[cfg(target_family = "wasm")]
    /// Converts a VerifiableCredential to a JavaScript object
    pub fn to_object(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::Serializer::json_compatible().serialize_newtype_struct("", self)?)
    }
}
