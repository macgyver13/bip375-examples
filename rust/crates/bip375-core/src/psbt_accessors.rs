//! PSBT Field Accessor Functions
//!
//! This module provides higher-level accessor functions for extracting typed data
//! from PSBT fields. It encapsulates the low-level field parsing logic and provides
//! a cleaner API for accessing PSBT data.

use crate::{extensions::Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use bitcoin::{OutPoint, Txid};
use secp256k1::PublicKey;

/// Get the transaction ID (TXID) for an input
pub fn get_input_txid(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Txid> {
    let input = psbt.inputs.get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // PSBT v2 inputs have explicit previous_txid field
    Ok(input.previous_txid)
}

/// Get the output index (vout) for an input
pub fn get_input_vout(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<u32> {
    let input = psbt.inputs.get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    Ok(input.spent_output_index)
}

/// Get the outpoint (TXID + vout) for an input as raw bytes
pub fn get_input_outpoint_bytes(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Vec<u8>> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;

    let mut outpoint = Vec::with_capacity(36);
    outpoint.extend_from_slice(&txid[..]);
    outpoint.extend_from_slice(&vout.to_le_bytes());
    Ok(outpoint)
}

/// Get the outpoint (TXID + vout) for an input as a typed OutPoint
pub fn get_input_outpoint(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<OutPoint> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;
    Ok(OutPoint { txid, vout })
}

/// Get all BIP32 derivation public keys for an input
pub fn get_input_bip32_pubkeys(psbt: &SilentPaymentPsbt, input_idx: usize) -> Vec<PublicKey> {
    let mut pubkeys = Vec::new();

    if let Some(input) = psbt.inputs.get(input_idx) {
        for key in input.bip32_derivations.keys() {
            // key is bitcoin::PublicKey, inner is secp256k1::PublicKey
            pubkeys.push(*key);
        }
    }

    pubkeys
}

/// Get input public key from PSBT fields
pub fn get_input_pubkey(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<PublicKey> {
    let input = psbt.inputs.get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // Method 1: Extract from BIP32 derivation field (HIGHEST PRIORITY)
    if !input.bip32_derivations.is_empty() {
        // Return the first key
        if let Some(key) = input.bip32_derivations.keys().next() {
            return Ok(*key);
        }
    }

    // Method 2: Extract from Taproot internal key (for Taproot inputs)
    if let Some(tap_key) = input.tap_internal_key {
        // tap_key is bitcoin::XOnlyPublicKey
        // We need to convert to secp256k1::PublicKey (even y)
        // bitcoin::XOnlyPublicKey has into_inner() -> secp256k1::XOnlyPublicKey
        let x_only = tap_key;
        
        // Convert x-only to full pubkey (assumes even y - prefix 0x02)
        let mut pubkey_bytes = vec![0x02];
        pubkey_bytes.extend_from_slice(&x_only.serialize());
        if let Ok(pubkey) = PublicKey::from_slice(&pubkey_bytes) {
            return Ok(pubkey);
        }
    }

    // Method 3: Extract from partial signature field
    if !input.partial_sigs.is_empty() {
        if let Some(key) = input.partial_sigs.keys().next() {
            return Ok(key.inner);
        }
    }

    Err(Error::Other(format!(
        "Input {} missing public key (no BIP32 derivation, Taproot key, or partial signature found)",
        input_idx
    )))
}

/// Get silent payment keys (scan_key, spend_key) from output SP_V0_INFO field
pub fn get_output_sp_keys(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<(PublicKey, PublicKey)> {
    // Use the extension trait method via SilentPaymentPsbt wrapper
    let address = psbt.get_output_sp_address(output_idx)
        .ok_or_else(|| Error::MissingField(format!(
            "Output {} missing PSBT_OUT_SP_V0_INFO",
            output_idx
        )))?;

    Ok((address.scan_key, address.spend_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests will be added as functions are implemented
}
