//! BIP-375 Core Library
//!
//! Core data structures and types for BIP-375 (Sending Silent Payments with PSBTs).
//!
//! This crate provides:
//! - PSBT v2 data structures
//! - Silent payment address types
//! - ECDH share types
//! - UTXO types

pub mod ecdh_aggregation;
pub mod error;
pub mod extensions;
pub mod psbt_accessors;
pub mod types;

pub use ecdh_aggregation::{aggregate_ecdh_shares, AggregatedShare, AggregatedShares};
pub use error::{Error, Result};
pub use extensions::Bip375PsbtExt;
pub use types::{EcdhShareData, Output, OutputRecipient, SilentPaymentAddress, Utxo};

/// Type alias for PSBT v2 with BIP-375 extensions
///
/// Use the `Bip375PsbtExt` trait to access BIP-375 specific functionality.
pub type SilentPaymentPsbt = psbt_v2::v2::Psbt;
