use clap::{Parser, Subcommand, ValueEnum};
use serde_json::from_str;
use std::{
    fs::{read, read_to_string},
    path::PathBuf,
};
use vc_signing::native::{SignatureKeyPair, VerifiableFunctions};
use vc_signing::VerifiableCredential;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    function: Function,
}

#[derive(Subcommand)]
enum Function {
    Sign {
        vc_path: PathBuf,
        schema_path: PathBuf,
        private_key_path: PathBuf,
        output_path: PathBuf,
        format: Format,
    },
    Verify {
        vc_path: PathBuf,
        public_key_path: PathBuf,
    },
    Encode {
        vc_path: PathBuf,
        output_path: PathBuf,
        format: Format,
    },
    Decode {
        vc_path: PathBuf,
        output_path: PathBuf,
    },
    GenKeys {
        private_key_path: PathBuf,
        public_key_path: PathBuf,
    },
}

#[derive(ValueEnum, Clone)]
enum Format {
    Protobuf,
    Cbor,
    Json,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.function {
        Function::Sign {
            vc_path,
            schema_path,
            private_key_path,
            output_path,
            format,
        } => {
            let vc: serde_json::Value = from_str(&read_to_string(vc_path)?)?;
            let schema: serde_json::Value = from_str(&read_to_string(schema_path)?)?;
            let vc = VerifiableCredential::new(vc, schema)?.sign(&read(private_key_path)?)?;
            match format {
                Format::Protobuf => std::fs::write(output_path, vc.serialize_protobuf())?,
                Format::Cbor => std::fs::write(output_path, vc.serialize_cbor()?)?,
                Format::Json => std::fs::write(output_path, serde_json::to_string(&vc)?)?,
            }
        }
        Function::Verify {
            vc_path,
            public_key_path,
        } => {
            let vc: VerifiableCredential = from_str(&read_to_string(vc_path)?)?;
            println!("{:?}", vc.verify(&read(public_key_path)?));
        }
        Function::Encode {
            vc_path,
            output_path,
            format,
        } => {
            let vc: VerifiableCredential = from_str(&read_to_string(vc_path)?)?;
            match format {
                Format::Protobuf => std::fs::write(output_path, vc.serialize_protobuf())?,
                Format::Cbor => std::fs::write(output_path, vc.serialize_cbor()?)?,
                Format::Json => std::fs::write(output_path, serde_json::to_string(&vc)?)?,
            };
        }
        Function::Decode {
            vc_path,
            output_path,
        } => {
            let vc = read(vc_path)?;
            match VerifiableCredential::deserialize_protobuf(vc.clone()) {
                Ok(decoded_vc) => std::fs::write(output_path, serde_json::to_string(&decoded_vc)?)?,
                Err(_) => match VerifiableCredential::deserialize_cbor(vc) {
                    Ok(decoded_vc) => {
                        std::fs::write(output_path, serde_json::to_string(&decoded_vc)?)?
                    }
                    Err(_) => return Err("Failed to deserialize credential".into()),
                },
            }
        }
        Function::GenKeys {
            private_key_path,
            public_key_path,
        } => {
            let SignatureKeyPair {
                private_key,
                public_key,
            } = SignatureKeyPair::new().map_err(|_| "Failed to generate key pair")?;
            std::fs::write(private_key_path, private_key)?;
            std::fs::write(public_key_path, public_key)?;
        }
    };
    Ok(())
}
