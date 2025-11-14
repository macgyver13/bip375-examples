//! BIP-375 Core Library
//!
//! Core data structures and types for BIP-375 (Sending Silent Payments with PSBTs).
//!
//! This crate provides:
//! - PSBT v2 data structures
//! - Silent payment address types
//! - ECDH share types
//! - UTXO types
//! - Field type constants

pub mod constants;
pub mod ecdh_aggregation;
pub mod error;
pub mod field;
pub mod psbt;
pub mod psbt_accessors;
pub mod types;

pub use constants::*;
pub use ecdh_aggregation::{aggregate_ecdh_shares, AggregatedShare, AggregatedShares};
pub use error::{Error, Result};
pub use field::PsbtField;
pub use psbt::SilentPaymentPsbt;
pub use types::{EcdhShare, Output, OutputRecipient, SilentPaymentAddress, Utxo};
