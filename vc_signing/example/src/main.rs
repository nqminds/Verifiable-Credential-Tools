use serde_json::json;
use vc_signing::native::{gen_keys, CryptoTrait};
use vc_signing::VerifiableCredential;

fn main() {
    let (private, public) = gen_keys().unwrap();

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

    let vc = VerifiableCredential::new(vc, schema)
        .unwrap()
        .sign(&private)
        .unwrap();
    println!("{:?}", vc.verify(&public));
}
