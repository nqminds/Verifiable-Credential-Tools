use crate::verifiable_credentials::type_struct::{OneofType, RepeatedType};
use crate::verifiable_credentials::verifiable_credential::{
    CredentialSchema, CredentialSchemaStruct, CredentialStatus, CredentialStatusStruct,
    RepeatedCredentialSchema, RepeatedCredentialStatus,
};
use crate::verifiable_credentials::{TypeStruct, VerifiableCredential};
use chrono::DateTime;
use prost::Message;
use serde_json::json;
use std::str::FromStr;
use url::Url;
use vc_signing::native::{CryptoTrait, SchemaEnum, StatusEnum, TypeEnum};

pub mod verifiable_credentials {
    include!(concat!(env!("OUT_DIR"), "/verifiable_credentials.rs"));
}

impl From<VerifiableCredential> for vc_signing::native::VerifiableCredential {
    fn from(vc: VerifiableCredential) -> Self {
        let context = vc
            .context
            .iter()
            .map(|context| Url::from_str(context).unwrap())
            .collect();

        let credential_schema = match vc.credential_schema.unwrap() {
            CredentialSchema::MultipleSchema(RepeatedCredentialSchema { repeated_schema }) => {
                SchemaEnum::Multiple(
                    repeated_schema
                        .iter()
                        .map(|schema| vc_signing::native::CredentialSchema {
                            id: Url::from_str(&schema.schema_id).unwrap(),
                            credential_type: schema.schema_type.clone(),
                        })
                        .collect(),
                )
            }
            CredentialSchema::SingleSchema(CredentialSchemaStruct {
                schema_id,
                schema_type,
            }) => SchemaEnum::Single(vc_signing::native::CredentialSchema {
                id: Url::from_str(&schema_id).unwrap(),
                credential_type: schema_type,
            }),
        };

        let credential_status =
            vc.credential_status
                .map(|credential_status| match credential_status {
                    CredentialStatus::MultipleStatus(RepeatedCredentialStatus {
                        repeated_status,
                    }) => StatusEnum::Multiple(
                        repeated_status
                            .iter()
                            .map(|status| vc_signing::native::CredentialStatus {
                                id: status
                                    .status_id
                                    .clone()
                                    .map(|id| Url::from_str(&id).unwrap()),
                                status_type: match status.status_type.clone().unwrap() {
                                    TypeStruct {
                                        oneof_type: Some(OneofType::SingleType(single_type)),
                                    } => TypeEnum::Single(single_type),
                                    TypeStruct {
                                        oneof_type:
                                            Some(OneofType::MultipleType(RepeatedType {
                                                repeated_type,
                                            })),
                                    } => TypeEnum::Multiple(repeated_type),
                                    _ => panic!("Error in credential status"),
                                },
                            })
                            .collect(),
                    ),
                    CredentialStatus::SingleStatus(CredentialStatusStruct {
                        status_type,
                        status_id,
                    }) => StatusEnum::Single(vc_signing::native::CredentialStatus {
                        id: status_id.map(|id| Url::from_str(&id).unwrap()),
                        status_type: match status_type.unwrap() {
                            TypeStruct {
                                oneof_type: Some(OneofType::SingleType(single_type)),
                            } => TypeEnum::Single(single_type),
                            TypeStruct {
                                oneof_type:
                                    Some(OneofType::MultipleType(RepeatedType { repeated_type })),
                            } => TypeEnum::Multiple(repeated_type),
                            _ => panic!("Error in credential status"),
                        },
                    }),
                });

        let prost_types::Any { type_url: _, value } = vc.credential_subject.unwrap();
        let credential_subject: String = prost::Message::decode(value.as_slice()).unwrap();
        let credential_subject = serde_json::from_str(&credential_subject).unwrap();

        let valid_from = vc
            .valid_from
            .map(|x| DateTime::from_timestamp(x.seconds, x.nanos as u32).unwrap());
        let valid_until = vc
            .valid_until
            .map(|x| DateTime::from_timestamp(x.seconds, x.nanos as u32).unwrap());

        let proof = vc.proof.map(|proof| vc_signing::native::Proof {
            proof_type: proof.proof_type,
            jws: proof.jws,
            proof_purpose: proof.proof_purpose,
            created: DateTime::from_timestamp(
                proof.created.unwrap().seconds,
                proof.created.unwrap().nanos as u32,
            )
            .unwrap(),
        });

        let vc_type = match vc.vc_type.unwrap() {
            TypeStruct {
                oneof_type: Some(OneofType::SingleType(vc_type)),
            } => TypeEnum::Single(vc_type),
            TypeStruct {
                oneof_type: Some(OneofType::MultipleType(RepeatedType { repeated_type })),
            } => TypeEnum::Multiple(repeated_type),
            _ => panic!("Error in vc type"),
        };

        Self {
            context,
            credential_schema,
            credential_status,
            credential_subject,
            description: vc.description,
            id: vc.vc_id.map(|id| Url::from_str(&id).unwrap()),
            issuer: Url::from_str(&vc.issuer).unwrap(),
            name: vc.name,
            proof,
            valid_from,
            valid_until,
            vc_type,
        }
    }
}

impl From<vc_signing::native::VerifiableCredential> for VerifiableCredential {
    fn from(vc: vc_signing::native::VerifiableCredential) -> Self {
        let context = vc
            .context
            .iter()
            .map(|context| context.to_string())
            .collect();
        let vc_id = vc.id.map(|id| id.to_string());

        let vc_type = match vc.vc_type {
            TypeEnum::Single(vc_type) => Some(TypeStruct {
                oneof_type: Some(OneofType::SingleType(vc_type)),
            }),
            TypeEnum::Multiple(vc_type) => Some(TypeStruct {
                oneof_type: Some(OneofType::MultipleType(RepeatedType {
                    repeated_type: vc_type,
                })),
            }),
        };

        let valid_from = vc
            .valid_from
            .map(|valid_from| prost_types::Timestamp::from_str(&valid_from.to_rfc3339()).unwrap());
        let valid_until = vc.valid_until.map(|valid_until| {
            prost_types::Timestamp::from_str(&valid_until.to_rfc3339()).unwrap()
        });

        let credential_schema = match vc.credential_schema {
            SchemaEnum::Single(credential_schema) => {
                Some(CredentialSchema::SingleSchema(CredentialSchemaStruct {
                    schema_id: credential_schema.id.to_string(),
                    schema_type: credential_schema.credential_type,
                }))
            }
            SchemaEnum::Multiple(credential_schema) => {
                Some(CredentialSchema::MultipleSchema(RepeatedCredentialSchema {
                    repeated_schema: credential_schema
                        .iter()
                        .map(|schema| CredentialSchemaStruct {
                            schema_id: schema.id.to_string(),
                            schema_type: schema.credential_type.clone(),
                        })
                        .collect(),
                }))
            }
        };

        let credential_subject = Some(prost_types::Any {
            type_url: "Value.to_string()".to_string(),
            value: vc.credential_subject.to_string().encode_to_vec(),
        });

        let credential_status =
            vc.credential_status
                .map(|credential_status| match credential_status {
                    StatusEnum::Single(credential_status) => {
                        CredentialStatus::SingleStatus(CredentialStatusStruct {
                            status_id: credential_status.id.map(|id| id.to_string()),
                            status_type: Some(TypeStruct {
                                oneof_type: Some(match credential_status.status_type {
                                    TypeEnum::Single(status_type) => {
                                        OneofType::SingleType(status_type)
                                    }
                                    TypeEnum::Multiple(repeated_type) => {
                                        OneofType::MultipleType(RepeatedType { repeated_type })
                                    }
                                }),
                            }),
                        })
                    }
                    StatusEnum::Multiple(credential_status) => {
                        CredentialStatus::MultipleStatus(RepeatedCredentialStatus {
                            repeated_status: credential_status
                                .iter()
                                .map(|status| CredentialStatusStruct {
                                    status_id: status.id.clone().map(|id| id.to_string()),
                                    status_type: Some(TypeStruct {
                                        oneof_type: Some(match status.status_type.clone() {
                                            TypeEnum::Single(status_type) => {
                                                OneofType::SingleType(status_type)
                                            }
                                            TypeEnum::Multiple(repeated_type) => {
                                                OneofType::MultipleType(RepeatedType {
                                                    repeated_type,
                                                })
                                            }
                                        }),
                                    }),
                                })
                                .collect(),
                        })
                    }
                });

        let proof = vc.proof.map(|proof| verifiable_credentials::Proof {
            proof_type: proof.proof_type,
            jws: proof.jws,
            proof_purpose: proof.proof_purpose,
            created: Some(prost_types::Timestamp::from_str(&proof.created.to_rfc3339()).unwrap()),
        });

        Self {
            context,
            vc_type,
            name: vc.name,
            description: vc.description,
            valid_from,
            valid_until,
            credential_schema,
            credential_subject,
            proof,
            vc_id,
            issuer: vc.issuer.to_string(),
            credential_status,
        }
    }
}

fn main() {
    let vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:5c229716-4159-490b-bb49-ce59a2472248",
        "type": ["VerifiableCredential", "Example"],
        "issuer": "urn:uuid:8bbabf61-758b-4bcb-8dab-4a4d1d493e25",
        "validFrom": "2024-08-29T12:00:00Z",
        "credentialSchema": {
            "id": "urn:uuid:da87634c-19df-4e55-8bc4-0191730f8304",
            "type": "JsonSchema",
        },
        "credentialSubject": {
            "id": "example_id",
            "created_at": 1724929200
        }
    });

    let schema = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:46e2ee61-d759-40c8-b226-10a7c162dee1",
        "type": ["VerifiableCredential", "Schema"],
        "issuer": "urn:uuid:8fef183c-c18d-44c6-ba65-5a0bdb8025e9",
        "validFrom": "2024-08-29T12:00:00Z",
        "credentialSchema": {
            "id": "urn:uuid:da87634c-19df-4e55-8bc4-0191730f8304",
            "type": "JsonSchema",
        },
        "credentialSubject": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:uuid:36862033-fc98-46de-b63e-2af0c79f3b01",
            "title": "example",
            "description": "An example schema",
            "type": "object",
            "properties": {
                "id": {
                    "description": "id",
                    "type": "string",
                },
                "created_at": {
                    "description": "timestamp",
                    "type": "integer",
                },
            },
            "required": ["id", "created_at"]
        }
    });

    let (private, _public) = vc_signing::native::gen_keys().unwrap();
    let vc = vc_signing::native::VerifiableCredential::new(vc, schema)
        .unwrap()
        .sign(&private)
        .unwrap();
    println!("{:?}", vc);

    let message = Into::<VerifiableCredential>::into(vc).encode_to_vec();
    println!("{:?}", message);

    let vc = VerifiableCredential::decode(message.as_slice()).unwrap();
    let vc = Into::<vc_signing::native::VerifiableCredential>::into(vc);
    println!("{:?}", vc);
}
