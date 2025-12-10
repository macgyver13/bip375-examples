// UniFFI bindings for BIP-375 implementation
// This crate exposes the Rust BIP-375 implementation to Python and other languages

// mod aggregation;
mod crypto;
mod errors;
mod types;

// Re-export public types
pub use crypto::*;
pub use types::*;
// pub use aggregation::*;
pub use errors::*;

// UniFFI setup
uniffi::include_scaffolding!("bip375");
