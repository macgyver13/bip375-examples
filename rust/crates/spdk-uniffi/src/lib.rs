// UniFFI bindings for BIP-375 implementation
// This crate exposes the Rust BIP-375 implementation to Python and other languages

mod crypto;
mod errors;
mod types;

// Re-export public types
pub use types::*;
pub use errors::*;

// Re-export crypto functions for UniFFI
pub use crypto::{
    bip352_apply_label_to_spend_key, bip352_compute_ecdh_share, bip352_compute_input_hash,
    bip352_compute_label_tweak, bip352_compute_shared_secret_tweak,
    bip352_derive_silent_payment_output_pubkey, bip352_pubkey_to_p2wpkh_script,
    bip352_tweaked_key_to_p2tr_script, dleq_generate_proof, dleq_verify_proof,
    signing_sign_p2wpkh_input,
};

// UniFFI setup
uniffi::include_scaffolding!("spdk_psbt");
