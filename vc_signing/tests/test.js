const { VerifiableCredential, SignatureKeyPair, SignedSchema } = require("../pkg/vc_signing");

const keys = new SignatureKeyPair();

let schema = new SignedSchema(new VerifiableCredential({
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
    "issuer": "urn:uuid:acf7b57c-0cab-4771-ad62-adb753923cc1",
    "type": ["VerifiableCredential", "Schema"],
    "validFrom": "2024-11-15T15:21:33.057078058Z"
}, false).sign(keys.private_key()), keys.public_key());

let vc = new VerifiableCredential({
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
}, false, schema).sign(keys.private_key());

try {
    vc.verify(keys.public_key());
    console.log("Verified");
} catch (e) {
    console.log(e);
}

schema = new SignedSchema(new VerifiableCredential({
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
}, true).sign(keys.private_key()), keys.public_key());

vc = new VerifiableCredential({
    "id": "example_id"
}, true, schema).sign(keys.private_key());

try {
    vc.verify(keys.public_key());
    console.log("Verified");
} catch (e) {
    console.log(e);
}
