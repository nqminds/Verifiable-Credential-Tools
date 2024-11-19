## VC Tools CLI 
Command line tool for performing various tasks with verifiable credentials

## Build instructions (requires rust tool-chain):
cargo build --release && cd ./target/release/

## Usage instructions
Usage: `vc_tools_cli <COMMAND>`

### Available Commands:
### sign-vc
Takes the input path to a JSON verifiable credential and JSON schema verifiable credential OR a JSON credential subject and JSON schema (with the '-g' flag), and private key.\
Checks if the VC matches the schema and signs with the private key, and saves it to the specified output path, in the specified format (Protobuf, CBOR, or JSON).

`sign-vc <VC_PATH> <SCHEMA_PATH> <SIGNING_KEY_PATH> <SCHEMA_KEY_PATH> <OUTPUT_PATH> <FORMAT>`
### sign-schema
Takes the input path to a JSON schema verifiable credential OR a JSON schema (with the '-g' flag), and private key.\
Checks if the schema is valid, and signs the verifiable credential with the private key, and saves it to the specified output path, in the specified format (Protobuf, CBOR, or JSON).

`sign-schema <VC_PATH> <SIGNING_KEY_PATH> <OUTPUT_PATH> <FORMAT>`
### verify
Takes the path to a signed verifiable credential and public key and prints whether the credential was signed by the owner of the public key.

`verify <VC_PATH> <PUBLIC_KEY_PATH>`
### encode
Takes the path to a JSON verifiable credential, encodes it in Protobuf or CBOR and saves the result to the output path.

`encode <VC_PATH> <OUTPUT_PATH> <FORMAT>`
### decode
Takes the path to a Protobuf or CBOR verifiable credential, decodes it into JSON and saves the result to the output path.

`decode <VC_PATH> <OUTPUT_PATH>`
### gen-keys
Generates a random ED25519 public/private key pair, and saves them to the specified respective file paths.

`gen-keys <PRIVATE_KEY_PATH> <PUBLIC_KEY_PATH>`
