fn main() {
    prost_build::compile_protos(&["src/verifiable_credentials.proto"], &["src"]).unwrap();
}
