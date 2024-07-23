use std::fs::{read, write};
use std::io::{Read, stdin};

fn main() {
    let mut args = std::env::args();
    match args.nth(1).as_deref() {
        Some("-sign") => {
            if let Some(path) = args.next() {
                if let Ok(contents) = read(path) {
                    let mut buffer = String::new();
                    stdin().read_to_string(&mut buffer).unwrap();
                    println!("{}", vc_signing::sign(&contents, &buffer).unwrap());
                } else {
                    eprintln!("Invalid key");
                }
            } else {
                eprintln!("Missing key arg");
            }
        }
        Some("-verify") => {
            if let Some(path) = args.next() {
                if let Ok(contents) = read(path) {
                    println!("{:?}", vc_signing::verify(&contents));
                } else {
                    eprintln!("Invalid key");
                }
            } else {
                eprintln!("Missing key arg");
            }
        }
        Some("-genkeys") => {
            let (private_key, public_key) = vc_signing::genkeys().unwrap();
            write(args.next().unwrap_or(String::from("private_key")), private_key).unwrap();
            write(args.next().unwrap_or(String::from("public_key")), public_key).unwrap();
        }
        _ => {
            println!(
                "Usage: verifiable_credentials -sign key_path|-verify key_path|-genkeys \
                [private_key_path public_key_path]\nVCs are supplied to stdin \
                (either pasted or piped), signed and returned on stdout"
            );
        }
    }
}
