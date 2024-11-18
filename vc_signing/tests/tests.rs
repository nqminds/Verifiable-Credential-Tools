use serde_json::{json, Value};
use vc_signing::{SignatureKeyPair, VerifiableCredential};

fn vc() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSchema": {
            "id": "urn:uuid:ded1499c-c797-447a-8478-8d0fd7519834",
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

fn schema() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSchema": {
            "id": "urn:uuid:442ea47b-3b2a-4602-a721-4cc22bdae9ce",
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
        "issuer": "urn:uuid:acf7b57c-0cab-4771-ad62-adb753923cc1",
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
    let vc = VerifiableCredential::new(vc(), schema())
        .unwrap()
        .sign(&private_key)
        .unwrap();
    assert!(vc.verify(&public_key).is_ok());
}

#[test]
fn create_vc() {
    let schema = schema().get("credentialSubject").unwrap().clone();
    VerifiableCredential::create(json!({"id": "example_id"}), schema).unwrap();
}
