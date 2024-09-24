#[cfg(not(target_family = "wasm"))]
pub mod native;
#[cfg(feature = "protobuf")]
pub mod protobuf;
#[cfg(target_family = "wasm")]
pub mod wasm;
