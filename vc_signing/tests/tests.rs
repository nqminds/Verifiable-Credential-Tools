use serde_json::{json, Value};
use vc_signing::verifiable_credential::SignedSchema;
use vc_signing::{SignatureKeyPair, VerifiableCredential};

fn vc_one() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSchema": {
            "id": "urn:uuid:9a2dc235-17a2-471c-b1f3-a8b29ed4a3d3",
            "type": "JsonSchema"
        },
        "credentialSubject": {
            "id": "example_id"
        },
        "id": "urn:uuid:a8059f21-dc57-4684-a88f-9d2457e21631",
        "issuer": "urn:uuid:67cddd6f-727f-4aea-91d4-e5f314252671",
        "type": ["VerifiableCredential", "Example"],
        "validFrom": "2024-11-15T15:21:33.057003610Z"
    })
}

fn vc_two() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSchema": {
            "id": "urn:uuid:9a2dc235-17a2-471c-b1f3-a8b29ed4a3d3",
            "type": "JsonSchema"
        },
        "credentialSubject": {
            "field": "example_field"
        },
        "id": "urn:uuid:5b29c11d-a757-4ded-aad1-291a4b585e8a",
        "issuer": "urn:uuid:67cddd6f-727f-4aea-91d4-e5f314252671",
        "type": ["VerifiableCredential", "Example"],
        "validFrom": "2024-11-15T15:21:33.057003610Z"
    })
}

fn schema() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSchema": {
            "id": "https://json-schema.org/draft/2020-12/schema",
            "type": "JsonSchema"
        },
        "credentialSubject": {
            "$id": "urn:uuid:9a2dc235-17a2-471c-b1f3-a8b29ed4a3d3",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "description": "An example schema",
            "properties": {
                "id": {
                    "description": "id",
                    "type": "string"
                }
            },
            "required": ["id"],
            "title": "example",
            "type": "object"
        },
        "id": "urn:uuid:72e074e5-248e-4721-ad79-d5e1308a8d60",
        "issuer": "urn:uuid:67cddd6f-727f-4aea-91d4-e5f314252671",
        "type": ["VerifiableCredential", "Schema"],
        "validFrom": "2024-11-15T15:21:33.057078058Z"
    })
}

#[test]
fn basic_test() {
    let SignatureKeyPair {
        private_key,
        public_key,
    } = SignatureKeyPair::new().unwrap();
    let schema_vc = VerifiableCredential::new(schema(), None)
        .unwrap()
        .sign(&private_key)
        .unwrap();
    let vc = VerifiableCredential::new(vc_one(), Some(SignedSchema::new(schema_vc, &public_key)))
        .unwrap()
        .sign(&private_key)
        .unwrap();
    assert!(vc.verify(&public_key).is_ok());
}

#[test]
fn create_vc() {
    let SignatureKeyPair {
        private_key,
        public_key,
    } = SignatureKeyPair::new().unwrap();
    let schema =
        VerifiableCredential::create(schema().get("credentialSubject").unwrap().clone(), None)
            .unwrap()
            .sign(&private_key)
            .unwrap();
    let vc = VerifiableCredential::create(
        json!({"id": "example_id"}),
        Some(SignedSchema::new(schema, &public_key)),
    )
    .unwrap()
    .sign(&private_key)
    .unwrap();
    assert!(vc.verify(&public_key).is_ok());
}

#[test]
fn bad_schema() {
    assert!(VerifiableCredential::new(json!({}), None).is_err());
}

#[test]
fn tampering() {
    let SignatureKeyPair {
        private_key,
        public_key,
    } = SignatureKeyPair::new().unwrap();
    let schema_vc = VerifiableCredential::new(schema(), None)
        .unwrap()
        .sign(&private_key)
        .unwrap();
    let mut vc = VerifiableCredential::new(
        vc_one(),
        Some(SignedSchema::new(schema_vc.clone(), &public_key)),
    )
    .unwrap()
    .sign(&private_key)
    .unwrap();
    assert!(vc.verify(&public_key).is_ok());
    let mut json = serde_json::to_value(vc).unwrap();
    json["issuer"] = json!("urn:uuid:051d3f2a-3bdb-4f25-bd36-48e6ecc1db9c");
    vc = VerifiableCredential::new(json, Some(SignedSchema::new(schema_vc, &public_key))).unwrap();
    assert!(vc.verify(&public_key).is_err());
}

#[test]
fn no_schema_match() {
    let SignatureKeyPair {
        private_key,
        public_key,
    } = SignatureKeyPair::new().unwrap();
    let schema_vc = VerifiableCredential::new(schema(), None)
        .unwrap()
        .sign(&private_key)
        .unwrap();
    assert!(
        VerifiableCredential::new(vc_two(), Some(SignedSchema::new(schema_vc, &public_key)))
            .is_err()
    );
}

#[test]
fn wrong_key() {
    let keys_one = SignatureKeyPair::new().unwrap();
    let keys_two = SignatureKeyPair::new().unwrap();
    let schema_vc = VerifiableCredential::new(schema(), None)
        .unwrap()
        .sign(&keys_one.private_key)
        .unwrap();
    let vc = VerifiableCredential::new(
        vc_one(),
        Some(SignedSchema::new(schema_vc, &keys_one.public_key)),
    )
    .unwrap()
    .sign(&keys_one.private_key)
    .unwrap();
    assert!(vc.verify(&keys_two.public_key).is_err());
}
