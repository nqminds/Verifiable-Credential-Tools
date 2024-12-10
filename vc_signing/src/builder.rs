use crate::Proof;
use crate::{CredentialSchema, SchemaEnum, TypeEnum};
use crate::{StatusEnum, VerifiableCredential};
use chrono::{DateTime, Utc};
use serde_json::Value;
use url::Url;

pub struct VerifiableCredentialBuilder {
    context: Vec<Url>,
    id: Option<Url>,
    vc_type: TypeEnum,
    name: Option<String>,
    description: Option<String>,
    issuer: Url,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    credential_status: Option<StatusEnum>,
    credential_schema: SchemaEnum,
    credential_subject: Value,
    proof: Option<Proof>,
}

impl VerifiableCredentialBuilder {
    pub fn new(credential_subject: Value, schema_id: &str) -> Result<Self, String> {
        let context =
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").map_err(|e| e.to_string())?];
        let id = Some(
            Url::parse(&format!("urn:uuid:{}", uuid::Uuid::new_v4())).map_err(|e| e.to_string())?,
        );
        let vc_type = TypeEnum::Single("VerifiableCredential".to_string());
        let issuer =
            Url::parse(&format!("urn:uuid:{}", uuid::Uuid::new_v4())).map_err(|e| e.to_string())?;

        let credential_schema = SchemaEnum::Single(CredentialSchema {
            id: Url::parse(schema_id).map_err(|e| e.to_string())?,
            credential_type: "JsonSchema".to_string(),
        });

        Ok(Self {
            context,
            id,
            vc_type,
            name: None,
            description: None,
            issuer,
            valid_from: None,
            valid_until: None,
            credential_status: None,
            credential_schema,
            credential_subject,
            proof: None,
        })
    }

    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub fn description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }

    pub fn valid_from(mut self, valid_from: Option<DateTime<Utc>>) -> Self {
        self.valid_from = valid_from;
        self
    }

    pub fn valid_until(mut self, valid_until: Option<DateTime<Utc>>) -> Self {
        self.valid_until = valid_until;
        self
    }

    pub fn issuer(mut self, issuer: Url) -> Self {
        self.issuer = issuer;
        self
    }

    pub fn proof(mut self, proof: Option<Proof>) -> Self {
        self.proof = proof;
        self
    }

    pub fn add_context(mut self, url: Url) -> Self {
        self.context.push(url);
        self
    }

    pub fn id(mut self, id: Option<Url>) -> Self {
        self.id = id;
        self
    }

    pub fn build(self) -> Result<VerifiableCredential, String> {
        Ok(VerifiableCredential {
            context: self.context,
            id: self.id,
            vc_type: self.vc_type,
            name: self.name,
            description: self.description,
            issuer: self.issuer,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            credential_status: self.credential_status,
            credential_schema: self.credential_schema,
            credential_subject: self.credential_subject,
            proof: self.proof,
        })
    }
}
