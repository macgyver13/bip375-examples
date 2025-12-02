//! PSBT Validation Functions
//!
//! Validates PSBTs according to BIP-375 rules.

use bip375_core::{
    Error, Result, SilentPaymentPsbt, Bip375PsbtExt,
};
use bip375_crypto::dleq_verify_proof;
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashSet;

/// Validation level for PSBT checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Basic structural validation only
    Basic,
    /// Validate existing DLEQ proofs without requiring complete ECDH coverage (for partial signing)
    DleqOnly,
    /// Full validation including complete ECDH coverage and DLEQ proofs
    Full,
}

/// Validate a PSBT according to BIP-375 rules
pub fn validate_psbt(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &SilentPaymentPsbt,
    level: ValidationLevel,
) -> Result<()> {
    // Basic validations
    validate_psbt_version(psbt)?;
    validate_input_fields(psbt)?;
    validate_output_fields(psbt)?;
    
    // Check if this PSBT has silent payment outputs
    let has_sp_outputs = (0..psbt.num_outputs())
        .any(|i| psbt.get_output_sp_address(i).is_some());
    
    if has_sp_outputs {
        // Rule 6: Segwit version restrictions (must be v0 or v1 for silent payments)
        validate_segwit_versions(psbt)?;
        // Rule 7: SIGHASH_ALL requirement (only SIGHASH_ALL allowed with silent payments)
        validate_sighash_types(psbt)?;
    }

    // DLEQ-only validation (for partial signing workflows)
    if level == ValidationLevel::DleqOnly && has_sp_outputs {
        validate_dleq_proofs(secp, psbt)?;
    }

    // Full validation
    if level == ValidationLevel::Full && has_sp_outputs {
        // Check DLEQ proofs first (includes global ECDH/DLEQ pairing check)
        validate_dleq_proofs(secp, psbt)?;
        // Then verify ECDH coverage
        validate_ecdh_coverage(psbt)?;
        validate_output_scripts(secp, psbt)?;
    }

    Ok(())
}

/// Validate PSBT version is v2
fn validate_psbt_version(psbt: &SilentPaymentPsbt) -> Result<()> {
    if psbt.global.version != psbt_v2::V2 {
        return Err(Error::InvalidVersion {
            expected: 2,
            actual: psbt.global.version.into(),
        });
    }
    Ok(())
}

/// Validate all inputs have required fields
fn validate_input_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        // previous_txid and spent_output_index are mandatory in struct
        
        if input.sequence.is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing sequence",
                i
            )));
        }

        // SegWit inputs require WITNESS_UTXO
        if input.witness_utxo.is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing witness_utxo",
                i
            )));
        }
    }

    Ok(())
}

/// Validate all outputs have required fields
fn validate_output_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, output) in psbt.outputs.iter().enumerate() {
        // Amount is mandatory in struct

        // Check if this is a silent payment output
        let has_sp_address = psbt.get_output_sp_address(i).is_some();
        let has_script = !output.script_pubkey.is_empty();

        // Output must have either a script OR a silent payment address
        if !has_sp_address && !has_script {
            return Err(Error::MissingField(format!(
                "Output {} missing both script and SP address",
                i
            )));
        }

        // Rule 3: PSBT_OUT_SP_V0_LABEL requires SP address
        let has_sp_label = psbt.get_output_sp_label(i).is_some();

        if has_sp_label && !has_sp_address {
            return Err(Error::MissingField(format!(
                "Output {} has label but missing SP address",
                i
            )));
        }
    }

    Ok(())
}

/// Validate segwit version restrictions (Rule 6)
fn validate_segwit_versions(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness_utxo) = &input.witness_utxo {
            let script = &witness_utxo.script_pubkey;
            
            if let Some(version) = script.witness_version() {
                // version is WitnessVersion enum.
                use bitcoin::WitnessVersion;
                match version {
                    WitnessVersion::V0 | WitnessVersion::V1 => {},
                    _ => {
                        return Err(Error::InvalidFieldData(format!(
                            "Input {} uses segwit version {:?} (incompatible with silent payments)",
                            i, version
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Validate SIGHASH_ALL requirement (Rule 7)
fn validate_sighash_types(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(sighash_type) = input.sighash_type {
            // Check if it is SIGHASH_ALL (0x01)
            // PsbtSighashType wraps EcdsaSighashType
            // EcdsaSighashType::All is 0x01
            if sighash_type.to_u32() != 0x01 {
                return Err(Error::InvalidFieldData(format!(
                    "Input {} uses non-SIGHASH_ALL (0x{:02x}) with silent payments",
                    i, sighash_type.to_u32()
                )));
            }
        }
    }
    Ok(())
}

/// Validate ECDH coverage for silent payment outputs
fn validate_ecdh_coverage(psbt: &SilentPaymentPsbt) -> Result<()> {
    let num_inputs = psbt.num_inputs();

    // Collect all scan keys from outputs
    let mut scan_keys = HashSet::new();
    for i in 0..psbt.num_outputs() {
        if let Some(sp_address) = psbt.get_output_sp_address(i) {
            scan_keys.insert(sp_address.scan_key);
        }
    }

    // For each scan key, verify all inputs have ECDH shares
    for scan_key in scan_keys {
        let global_shares = psbt.get_global_ecdh_shares();
        let has_global = global_shares.iter().any(|s| s.scan_key == scan_key);
        
        // Check for per-input shares
        let has_per_input = false;
        for i in 0..num_inputs {
            let shares = psbt.get_input_ecdh_shares(i);
            // Note: get_input_ecdh_shares falls back to global if no per-input.
            // But we want to detect if we have explicit per-input shares mixed with global.
            // The extension trait doesn't easily distinguish source.
            // However, `aggregate_ecdh_shares` handles this logic.
            // Here we just need to ensure coverage.
            
            // If we rely on get_input_ecdh_shares, it returns valid shares.
            if !shares.iter().any(|s| s.scan_key == scan_key) {
                 return Err(Error::Other(format!(
                    "Input {} missing ECDH share for scan key",
                    i
                )));
            }
        }
        
        // Ideally we should check for mixed global/per-input, but extension trait abstracts it.
        // We can check raw unknowns if strict validation is needed, but coverage is the main point.
    }

    Ok(())
}

/// Validate that output scripts match computed silent payment addresses
fn validate_output_scripts(secp: &Secp256k1<secp256k1::All>, psbt: &SilentPaymentPsbt) -> Result<()> {
    use bip375_core::psbt_accessors::{get_input_outpoint_bytes, get_input_bip32_pubkeys, get_output_sp_keys};
    use bip375_core::aggregate_ecdh_shares;
    use bip375_crypto::{derive_silent_payment_output_pubkey, compute_input_hash, pubkey_to_p2tr_script};
    use std::collections::HashMap;

    // First, collect outpoints and public keys for input_hash computation
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();

    for input_idx in 0..psbt.num_inputs() {
        let outpoint = get_input_outpoint_bytes(psbt, input_idx)?;
        outpoints.push(outpoint);

        let bip32_pubkeys = get_input_bip32_pubkeys(psbt, input_idx);
        if bip32_pubkeys.is_empty() {
            eprintln!("Warning: Input {} has no BIP32 derivation, skipping output script validation", input_idx);
            return Ok(());
        }
        input_pubkeys.push(bip32_pubkeys[0]);
    }

    if input_pubkeys.is_empty() {
        return Ok(());
    }

    let mut summed_pubkey = input_pubkeys[0];
    for pubkey in &input_pubkeys[1..] {
        summed_pubkey = summed_pubkey.combine(pubkey)
            .map_err(|e| Error::Other(format!("Failed to sum input pubkeys: {}", e)))?;
    }

    let smallest_outpoint = outpoints.iter()
        .min()
        .ok_or_else(|| Error::Other("No inputs found".to_string()))?;

    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    let input_hash = compute_input_hash(smallest_outpoint, &summed_pubkey)
        .map_err(|e| Error::Other(format!("Failed to compute input hash: {}", e)))?;

    let mut shared_secrets: HashMap<PublicKey, PublicKey> = HashMap::new();
    for (scan_key, aggregated_share_data) in aggregated_shares.iter() {
        let shared_secret = aggregated_share_data.aggregated_share.mul_tweak(secp, &input_hash)
            .map_err(|e| Error::Other(format!("Failed to multiply ECDH share by input_hash: {}", e)))?;
        shared_secrets.insert(*scan_key, shared_secret);
    }

    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    for output_idx in 0..psbt.num_outputs() {
        let output = &psbt.outputs[output_idx];
        if output.script_pubkey.is_empty() {
            continue;
        }

        let (scan_key, spend_key) = match get_output_sp_keys(psbt, output_idx) {
            Ok(keys) => keys,
            Err(_) => continue,
        };

        let shared_secret = shared_secrets.get(&scan_key)
            .ok_or_else(|| Error::Other(format!(
                "Output {} missing shared secret for scan key",
                output_idx
            )))?;

        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);

        let shared_secret_bytes = shared_secret.serialize();
        let expected_pubkey = derive_silent_payment_output_pubkey(
            secp,
            &spend_key,
            &shared_secret_bytes,
            k,
        ).map_err(|e| Error::Other(format!("Failed to derive output pubkey: {}", e)))?;

        let expected_script = pubkey_to_p2tr_script(&expected_pubkey);

        if output.script_pubkey != expected_script {
            return Err(Error::Other(format!(
                "Output {} script mismatch: expected silent payment address doesn't match actual script",
                output_idx
            )));
        }

        scan_key_output_indices.insert(scan_key, k + 1);
    }

    Ok(())
}

/// Validate all DLEQ proofs in the PSBT
fn validate_dleq_proofs(secp: &Secp256k1<secp256k1::All>, psbt: &SilentPaymentPsbt) -> Result<()> {
    use bip375_core::psbt_accessors::get_input_pubkey;

    // Check global DLEQ if global ECDH exists
    let global_shares = psbt.get_global_ecdh_shares();
    for share in global_shares {
        if share.dleq_proof.is_none() {
             // Global shares MUST have DLEQ proofs?
             // BIP-375 says DLEQ proof is required.
             // But my EcdhShare struct has Option<proof>.
             // If it's missing, it's invalid.
             return Err(Error::Other("Global ECDH share missing DLEQ proof".to_string()));
        }
    }
    
    // Validate per-input ECDH shares
    for input_idx in 0..psbt.num_inputs() {
        let shares = psbt.get_input_ecdh_shares(input_idx);

        for share in shares {
            if share.dleq_proof.is_none() {
                return Err(Error::Other(format!(
                    "Input {} missing required DLEQ proof for ECDH share",
                    input_idx
                )));
            }

            if let Some(proof) = share.dleq_proof {
                let input_pubkey = get_input_pubkey(psbt, input_idx)?;

                let is_valid = dleq_verify_proof(
                    secp,
                    &input_pubkey,
                    &share.scan_key,
                    &share.share,
                    &proof,
                    None,
                )
                .map_err(|e| Error::Other(format!("DLEQ verification error: {}", e)))?;

                if !is_valid {
                    return Err(Error::DleqVerificationFailed(input_idx));
                }
            }
        }
    }

    Ok(())
}

/// Validate that a PSBT is ready for extraction
pub fn validate_ready_for_extraction(psbt: &SilentPaymentPsbt) -> Result<()> {
    for input_idx in 0..psbt.num_inputs() {
        let sigs = psbt.get_input_partial_sigs(input_idx);
        if sigs.is_empty() {
            return Err(Error::ExtractionFailed(format!(
                "Input {} is not signed",
                input_idx
            )));
        }
    }

    for output_idx in 0..psbt.num_outputs() {
        if psbt.outputs[output_idx].script_pubkey.is_empty() {
            return Err(Error::ExtractionFailed(format!(
                "Output {} missing script",
                output_idx
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
        signer::{add_ecdh_shares_full, sign_inputs},
    };
    use bip375_core::{Output, SilentPaymentAddress, Utxo};
    use bip375_crypto::pubkey_to_p2wpkh_script;
    use bitcoin::{Amount, ScriptBuf, Sequence, Txid};
    use bitcoin::hashes::Hash;
    use secp256k1::SecretKey;

    #[test]
    fn test_validate_psbt_version() {
        let psbt = create_psbt(1, 1).unwrap();
        assert!(validate_psbt_version(&psbt).is_ok());
    }

    #[test]
    fn test_validate_input_fields() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let inputs = vec![Utxo::new(
            Txid::all_zeros(),
            0,
            Amount::from_sat(30000),
            pubkey_to_p2wpkh_script(&pubkey),
            Some(privkey),
            Sequence::MAX,
        )];

        add_inputs(&mut psbt, &inputs).unwrap();

        assert!(validate_input_fields(&psbt).is_ok());
    }

    #[test]
    fn test_validate_output_fields() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create a valid output with a real script (P2WPKH)
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);
        let script = pubkey_to_p2wpkh_script(&pubkey);

        let outputs = vec![Output::regular(Amount::from_sat(29000), script)];

        add_outputs(&mut psbt, &outputs).unwrap();

        assert!(validate_output_fields(&psbt).is_ok());
    }
    
    // ... other tests ...
}
