fn main() {
    #[cfg(feature = "protobuf")]
    prost_build::compile_protos(&["src/verifiable_credentials.proto"], &["src"]).unwrap();
}
