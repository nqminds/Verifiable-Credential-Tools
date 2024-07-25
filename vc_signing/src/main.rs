use std::fs::{read, read_to_string, write};

fn main() {
    let mut args = std::env::args();
    match args.nth(1).as_deref() {
        Some("-sign") => {
            println!(
                "{}",
                vc_signing::sign(
                    &read(args.next().unwrap()).unwrap(),
                    &read_to_string(args.next().unwrap()).unwrap(),
                    &read_to_string(args.next().unwrap()).unwrap()
                )
                .unwrap()
            );
        }
        Some("-verify") => {
            println!(
                "{:?}",
                vc_signing::verify(
                    &read(args.next().unwrap()).unwrap(),
                    &read_to_string(args.next().unwrap()).unwrap()
                )
            );
        }
        Some("-genkeys") => {
            let (priv_key, pub_key) = vc_signing::genkeys().unwrap();
            write(args.next().unwrap_or("private_key".to_string()), priv_key).unwrap();
            write(args.next().unwrap_or("public_key".to_string()), pub_key).unwrap();
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
