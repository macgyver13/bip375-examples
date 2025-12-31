// UniFFI bindings for BIP-375 implementation
// This crate exposes the Rust BIP-375 implementation to Python and other languages

// mod aggregation;
mod crypto;
mod errors;
mod types;

// Re-export public types
pub use types::*;
// pub use aggregation::*;
pub use errors::*;

// Re-export crypto functions for UniFFI
pub use crypto::{
    bip352_compute_ecdh_share,
    dleq_generate_proof,
    dleq_verify_proof,
    signing_sign_p2wpkh_input,
};

// UniFFI setup
uniffi::include_scaffolding!("spdk_psbt");
