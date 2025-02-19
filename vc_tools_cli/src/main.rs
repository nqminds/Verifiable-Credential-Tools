use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{from_str, Value};
use std::error::Error;
use std::path::Path;
use std::{
    fs::{read, read_to_string},
    path::PathBuf,
};
use vc_signing::verifiable_credential::SignedSchema;
use vc_signing::{SignatureKeyPair, VerifiableCredential};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    function: Function,
}

#[derive(Subcommand)]
enum Function {
    SignVC {
        vc_path: PathBuf,
        schema_path: PathBuf,
        signing_key_path: PathBuf,
        schema_key_path: PathBuf,
        output_path: PathBuf,
        format: Format,
        #[clap(long, short)]
        generate: bool,
    },
    SignSchema {
        vc_path: PathBuf,
        signing_key_path: PathBuf,
        output_path: PathBuf,
        format: Format,
        #[clap(long, short)]
        generate: bool,
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

fn write_format(
    format: Format,
    path: &Path,
    vc: VerifiableCredential,
) -> Result<(), Box<dyn Error>> {
    match format {
        Format::Protobuf => std::fs::write(path, vc.serialize_protobuf())?,
        Format::Cbor => std::fs::write(path, vc.serialize_cbor()?)?,
        Format::Json => std::fs::write(path, serde_json::to_string_pretty(&vc)?)?,
    };
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    match args.function {
        Function::SignVC {
            vc_path,
            signing_key_path,
            schema_path,
            schema_key_path,
            output_path,
            format,
            generate,
        } => {
            let vc: Value = from_str(&read_to_string(vc_path)?)?;
            let schema: Value = from_str(&read_to_string(schema_path)?)?;
            let vc = match generate {
                true => VerifiableCredential::create(
                    vc,
                    Some(SignedSchema::new(
                        VerifiableCredential::new(schema, None)?,
                        &read(schema_key_path)?,
                    )),
                )?,
                false => VerifiableCredential::new(
                    vc,
                    Some(SignedSchema::new(
                        VerifiableCredential::new(schema, None)?,
                        &read(schema_key_path)?,
                    )),
                )?,
            }
            .sign(&read(signing_key_path)?)?;
            write_format(format, &output_path, vc)?;
        }
        Function::SignSchema {
            vc_path,
            signing_key_path: private_key_path,
            output_path,
            format,
            generate,
        } => {
            let schema: Value = from_str(&read_to_string(vc_path)?)?;
            let vc = match generate {
                true => VerifiableCredential::create(schema, None)?,
                false => VerifiableCredential::new(schema, None)?,
            }
            .sign(&read(private_key_path)?)?;
            write_format(format, &output_path, vc)?;
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
            write_format(format, &output_path, vc)?;
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
            } = SignatureKeyPair::new()?;
            std::fs::write(private_key_path, private_key)?;
            std::fs::write(public_key_path, public_key)?;
        }
    };
    Ok(())
}
