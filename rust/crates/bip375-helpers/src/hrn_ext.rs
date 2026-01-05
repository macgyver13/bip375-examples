//! BIP-375 Extension Traits and PSBT Accessors
//!
//! This module provides extension traits that add BIP-375 silent payment functionality
//! to the `psbt_v2::v2::Psbt` type, along with convenience accessor functions for
//! common PSBT field access patterns.
//!
//! # Module Contents
//!
//! - **`Bip375PsbtExt` trait**: Adds BIP-375 specific methods to PSBT

use spdk_core::psbt::{Error, Result};
use spdk_core::psbt::{PsbtKey, SilentPaymentPsbt};

pub const PSBT_OUT_DNSSEC_PROOF: u8 = 0x35;

/// BIP-353 Human Readable Names PSBT Extension
///
/// Provides accessors for BIP-353 DNS Payment Instructions fields:
/// - DNSSEC proof storage for outputs
pub trait HrnPsbtExt {
    /// Set DNSSEC proof for an output (BIP-353 field)
    fn set_output_dnssec_proof(&mut self, output_idx: usize, proof: Vec<u8>) -> Result<()>;
}

impl HrnPsbtExt for SilentPaymentPsbt {
    fn set_output_dnssec_proof(&mut self, output_idx: usize, proof: Vec<u8>) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_idx)
            .ok_or(Error::InvalidOutputIndex(output_idx))?;

        let key = PsbtKey {
            type_value: PSBT_OUT_DNSSEC_PROOF,
            key: vec![],
        };

        output.unknowns.insert(key, proof);
        Ok(())
    }
}
