const {VerifiableCredential, VerifiablePresentation, gen_keys} = require("./vc_signing");

let keys = gen_keys();
let private_key = keys.private_key();
let public_key = keys.public_key();

let vc_obj = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:ac4ec86f-f601-400c-846d-097f41d09022",
    "type": ["VerifiableCredential"],
    "credentialSubject": {
        "device": "www.client.com",
        "deviceType": "Raspberry Pi",
        "validFrom": "2022-02-05T10:30:00.1Z"
    },
    "credentialSchema": {
        "id": "https://github.com/nqminds/nist-brski/blob/main/packages/schemas/src/device_type_binding.yaml",
        "type": "JsonSchema"
    },
    "issuer": "urn:uuid:2d58c8e9-a027-40ec-80c3-f053a3782335",
    "validFrom": "2024-05-23T12:22:33.723Z"
};

let vc = new VerifiableCredential(vc_obj, ""); // Create VerifiableCredential struct from JS object
let signed_obj = vc.sign(private_key).to_object(); // Signed VC can be converted to JS object
console.log(signed_obj);
let signed_vc = new VerifiableCredential(signed_obj, ""); // VerifiableCredential struct can be created from the signed object for verification

try {
    signed_vc.verify(public_key);
    console.log("Verified!");
} catch (e) {
    console.error(e);
}

let vp = new VerifiablePresentation({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:047dbd07-1320-4d54-a969-4d5b494b9ac7",
    type: ["VerifiablePresentation", "UserCredential"],
    verifiableCredential: signed_obj,
    holder: "urn:uuid:6e849dac-e581-4ba2-ac4d-e32bbc69e6fb"
});

let signed_vp = vp.sign(private_key); // Or the struct can be signed/verified directly
console.log(signed_vp.to_object());

try {
    signed_vp.verify(public_key);
    console.log("Verified!");
} catch (e) {
    console.error(e);
}