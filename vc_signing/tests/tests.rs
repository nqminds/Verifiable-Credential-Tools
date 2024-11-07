#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;
    use vc_signing::native::VerifiableFunctions;
    use vc_signing::{KeyPairStruct, VerifiableCredential};

    #[test]
    fn test() {
        let keys = KeyPairStruct::new().unwrap();
        let vc = VerifiableCredential::new(
            json!({
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "id": format!("urn:uuid:{}", Uuid::new_v4()),
              "type": ["VerifiableCredential", "Example"],
              "issuer": format!("urn:uuid:{}", Uuid::new_v4()),
              "validFrom": Utc::now(),
              "credentialSchema": {
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "type": "JsonSchema"
              },
              "credentialSubject": {
                "id": "example_id"
              }
            }),
            json!({
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "id": format!("urn:uuid:{}", Uuid::new_v4()),
              "type": ["VerifiableCredential", "Schema"],
              "issuer": format!("urn:uuid:{}", Uuid::new_v4()),
              "validFrom": Utc::now(),
              "credentialSchema": {
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "type": "JsonSchema"
              },
              "credentialSubject": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": format!("urn:uuid:{}", Uuid::new_v4()),
                "title": "example",
                "description": "An example schema",
                "type": "object",
                "properties": {
                  "id": {
                    "description": "id",
                    "type": "string"
                  }
                },
                "required": ["id"]
              }
            }
            ),
        )
        .unwrap();
        let signed = vc.sign(keys.private_key()).unwrap();
        assert!(signed.verify(&keys.public_key().unwrap()).is_ok());
    }
}
