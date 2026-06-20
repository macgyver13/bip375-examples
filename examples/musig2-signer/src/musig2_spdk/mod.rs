//! MuSig2 PSBT signer-role logic intended for eventual inclusion in SPDK.
//!
//! The standard SPDK signer handles one ECDH share per eligible input. A MuSig2
//! input instead needs participant shares to be verified and combined with the
//! BIP-327 coefficients before the ordinary BIP-352 output calculation.

pub mod finalizer;
pub mod keyagg;
pub mod shares;
pub mod signing;

pub use finalizer::finalize_sp_outputs;
