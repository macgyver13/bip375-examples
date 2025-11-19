// UniFFI bindings for BIP-375 implementation
// This crate exposes the Rust BIP-375 implementation to Python and other languages

mod types;
// mod crypto;
// mod aggregation;
// mod file_io;
mod roles;
mod errors;

// Re-export public types
pub use types::*;
// pub use crypto::*;
// pub use aggregation::*;
// pub use file_io::*;
pub use roles::*;
pub use errors::*;

// UniFFI setup
uniffi::include_scaffolding!("bip375");
