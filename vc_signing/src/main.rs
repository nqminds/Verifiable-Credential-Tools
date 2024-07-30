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
            let (private_key, public_key) = vc_signing::genkeys().unwrap();
            write(
                args.next().unwrap_or("private_key".to_string()),
                private_key,
            )
            .unwrap();
            write(args.next().unwrap_or("public_key".to_string()), public_key).unwrap();
        }
        _ => println!(
            "Usage: vc_signing -sign key_path vc_path schema_path | \
            -verify key_path vc_path schema_path | -genkeys [private_key_path public_key_path]"
        ),
    }
}
