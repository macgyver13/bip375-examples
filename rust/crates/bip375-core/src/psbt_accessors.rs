//! PSBT Field Accessor Functions
//!
//! This module provides higher-level accessor functions for extracting typed data
//! from PSBT fields. It encapsulates the low-level field parsing logic and provides
//! a cleaner API for accessing PSBT data.
//!
//! # Design Principles
//!
//! - **Encapsulation**: Hide direct field access and parsing details
//! - **Type Safety**: Return typed values (PublicKey, Amount, etc.) not raw bytes
//! - **Error Handling**: Clear semantics for missing vs invalid fields
//! - **Reusability**: Common patterns extracted into reusable functions
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use bip375_core::psbt_accessors::get_input_pubkey;
//!
//! let pubkey = get_input_pubkey(&psbt, 0)?;
//! // Automatically tries BIP32 derivation, Taproot key, and partial signatures
//! ```

use crate::{constants::*, Error, Result, SilentPaymentPsbt};
use bitcoin::{hashes::Hash as BitcoinHash, OutPoint, Txid};
use secp256k1::{PublicKey, XOnlyPublicKey};

/// Get the transaction ID (TXID) for an input
///
/// Returns the 32-byte TXID from the PSBT_IN_PREVIOUS_TXID field.
pub fn get_input_txid(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Txid> {
    let txid_field = psbt
        .get_input_field(input_idx, PSBT_IN_PREVIOUS_TXID)
        .ok_or_else(|| {
            Error::MissingField(format!(
                "Input {} missing PSBT_IN_PREVIOUS_TXID",
                input_idx
            ))
        })?;

    if txid_field.value_data.len() != 32 {
        return Err(Error::Other(format!(
            "Input {} TXID must be 32 bytes",
            input_idx
        )));
    }

    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid_field.value_data);
    Ok(Txid::from_byte_array(txid_bytes))
}

/// Get the output index (vout) for an input
///
/// Returns the 4-byte little-endian output index from PSBT_IN_OUTPUT_INDEX field.
pub fn get_input_vout(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<u32> {
    let output_idx_field = psbt
        .get_input_field(input_idx, PSBT_IN_OUTPUT_INDEX)
        .ok_or_else(|| {
            Error::MissingField(format!(
                "Input {} missing PSBT_IN_OUTPUT_INDEX",
                input_idx
            ))
        })?;

    if output_idx_field.value_data.len() != 4 {
        return Err(Error::Other(format!(
            "Input {} output index must be 4 bytes",
            input_idx
        )));
    }

    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&output_idx_field.value_data);
    Ok(u32::from_le_bytes(bytes))
}

/// Get the outpoint (TXID + vout) for an input as raw bytes
///
/// Returns 36 bytes: txid (32 bytes) || vout (4 bytes LE)
/// This format is used for BIP-352 input hash computation.
pub fn get_input_outpoint_bytes(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Vec<u8>> {
    let txid_field = psbt
        .get_input_field(input_idx, PSBT_IN_PREVIOUS_TXID)
        .ok_or_else(|| {
            Error::MissingField(format!(
                "Input {} missing PSBT_IN_PREVIOUS_TXID",
                input_idx
            ))
        })?;

    let output_idx_field = psbt
        .get_input_field(input_idx, PSBT_IN_OUTPUT_INDEX)
        .ok_or_else(|| {
            Error::MissingField(format!(
                "Input {} missing PSBT_IN_OUTPUT_INDEX",
                input_idx
            ))
        })?;

    if txid_field.value_data.len() != 32 {
        return Err(Error::Other(format!(
            "Input {} TXID must be 32 bytes",
            input_idx
        )));
    }

    if output_idx_field.value_data.len() != 4 {
        return Err(Error::Other(format!(
            "Input {} output index must be 4 bytes",
            input_idx
        )));
    }

    let mut outpoint = Vec::with_capacity(36);
    outpoint.extend_from_slice(&txid_field.value_data);
    outpoint.extend_from_slice(&output_idx_field.value_data);
    Ok(outpoint)
}

/// Get the outpoint (TXID + vout) for an input as a typed OutPoint
///
/// Returns a bitcoin::OutPoint struct.
pub fn get_input_outpoint(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<OutPoint> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;
    Ok(OutPoint { txid, vout })
}

/// Get all BIP32 derivation public keys for an input
///
/// Returns a vector of all public keys found in PSBT_IN_BIP32_DERIVATION fields.
/// Returns an empty vector if no BIP32 derivation entries are found.
pub fn get_input_bip32_pubkeys(psbt: &SilentPaymentPsbt, input_idx: usize) -> Vec<PublicKey> {
    let mut pubkeys = Vec::new();

    if let Some(fields) = psbt.input_maps.get(input_idx) {
        for field in fields {
            if field.field_type == PSBT_IN_BIP32_DERIVATION && field.key_data.len() == 33 {
                if let Ok(pubkey) = PublicKey::from_slice(&field.key_data) {
                    pubkeys.push(pubkey);
                }
            }
        }
    }

    pubkeys
}

/// Get input public key from PSBT fields
///
/// Tries multiple methods in priority order:
/// 1. PSBT_IN_BIP32_DERIVATION (preferred - standard BIP-174, hardware wallet compatible)
/// 2. PSBT_IN_TAP_INTERNAL_KEY (for Taproot inputs)
/// 3. PSBT_IN_PARTIAL_SIG (public key is in the key field)
///
/// # Arguments
/// * `psbt` - The PSBT to extract from
/// * `input_idx` - Index of the input
///
/// # Returns
/// The extracted public key, or an error if no public key can be found.
///
/// # Example
/// ```rust,ignore
/// let pubkey = get_input_pubkey(&psbt, 0)?;
/// ```
pub fn get_input_pubkey(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<PublicKey> {
    // Method 1: Extract from BIP32 derivation field (HIGHEST PRIORITY)
    // This is the standard BIP-174 way and supports hardware wallets
    let bip32_pubkeys = get_input_bip32_pubkeys(psbt, input_idx);
    if let Some(pubkey) = bip32_pubkeys.first() {
        return Ok(*pubkey);
    }

    // Method 2: Extract from Taproot internal key (for Taproot inputs)
    // This handles key path spending for Taproot (Segwit v1)
    if let Some(tap_field) = psbt.get_input_field(input_idx, PSBT_IN_TAP_INTERNAL_KEY) {
        if tap_field.value_data.len() == 32 {
            // Taproot uses x-only keys - need to lift to full point
            // For DLEQ purposes, we assume even y-coordinate (BIP-340 convention)
            if XOnlyPublicKey::from_slice(&tap_field.value_data).is_ok() {
                // Convert x-only to full pubkey (assumes even y - prefix 0x02)
                let mut pubkey_bytes = vec![0x02];
                pubkey_bytes.extend_from_slice(&tap_field.value_data);
                if let Ok(pubkey) = PublicKey::from_slice(&pubkey_bytes) {
                    return Ok(pubkey);
                }
            }
        }
    }

    // Method 3: Extract from partial signature field
    // Public key is in the key field of PSBT_IN_PARTIAL_SIG
    let sigs = psbt.get_input_partial_sigs(input_idx);
    if !sigs.is_empty() {
        let pubkey_bytes = &sigs[0].0;
        if let Ok(pubkey) = PublicKey::from_slice(pubkey_bytes) {
            return Ok(pubkey);
        }
    }

    Err(Error::Other(format!(
        "Input {} missing public key (no BIP32 derivation, Taproot key, or partial signature found)",
        input_idx
    )))
}

/// Get silent payment keys (scan_key, spend_key) from output SP_V0_INFO field
///
/// Parses the PSBT_OUT_SP_V0_INFO field which contains:
/// - 33 bytes: scan_key (compressed public key)
/// - 33 bytes: spend_key (compressed public key)
///
/// # Arguments
/// * `psbt` - The PSBT to extract from
/// * `output_idx` - Index of the output
///
/// # Returns
/// A tuple of (scan_key, spend_key) if the field exists and is valid.
///
/// # Errors
/// * If the field is missing
/// * If the field is not exactly 66 bytes
/// * If either key fails to parse as a valid public key
///
/// # Example
/// ```rust,ignore
/// let (scan_key, spend_key) = get_output_sp_keys(&psbt, 0)?;
/// ```
pub fn get_output_sp_keys(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<(PublicKey, PublicKey)> {
    let sp_info_field = psbt
        .get_output_field(output_idx, PSBT_OUT_SP_V0_INFO)
        .ok_or_else(|| {
            Error::MissingField(format!(
                "Output {} missing PSBT_OUT_SP_V0_INFO",
                output_idx
            ))
        })?;

    if sp_info_field.value_data.len() != 66 {
        return Err(Error::Other(format!(
            "Output {} SP_V0_INFO must be 66 bytes (33 scan + 33 spend), got {}",
            output_idx,
            sp_info_field.value_data.len()
        )));
    }

    let scan_key = PublicKey::from_slice(&sp_info_field.value_data[0..33]).map_err(|e| {
        Error::Other(format!(
            "Output {} invalid scan key in SP_V0_INFO: {}",
            output_idx, e
        ))
    })?;

    let spend_key = PublicKey::from_slice(&sp_info_field.value_data[33..66]).map_err(|e| {
        Error::Other(format!(
            "Output {} invalid spend key in SP_V0_INFO: {}",
            output_idx, e
        ))
    })?;

    Ok((scan_key, spend_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests will be added as functions are implemented
}
