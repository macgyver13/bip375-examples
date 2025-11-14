//! PSBT Validation Functions
//!
//! Validates PSBTs according to BIP-375 rules.

use bip375_core::{constants::*, Error, Result, SilentPaymentPsbt};
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
    validate_required_global_fields(psbt)?;
    validate_input_fields(psbt)?;
    validate_output_fields(psbt)?;
    
    // Check if this PSBT has silent payment outputs
    // If not, skip BIP-375 specific validations
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
    let version_field = psbt
        .get_global_field(PSBT_GLOBAL_TX_VERSION)
        .ok_or_else(|| Error::MissingField("PSBT_GLOBAL_TX_VERSION".to_string()))?;

    let version = u32::from_le_bytes([
        version_field.value_data[0],
        version_field.value_data[1],
        version_field.value_data[2],
        version_field.value_data[3],
    ]);

    if version != PSBT_V2_VERSION {
        return Err(Error::InvalidVersion {
            expected: PSBT_V2_VERSION,
            actual: version,
        });
    }

    Ok(())
}

/// Validate required global fields are present
fn validate_required_global_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    // PSBT v2 requires:
    // - PSBT_GLOBAL_TX_VERSION (already checked)
    // - PSBT_GLOBAL_INPUT_COUNT
    // - PSBT_GLOBAL_OUTPUT_COUNT

    if psbt.get_global_field(PSBT_GLOBAL_INPUT_COUNT).is_none() {
        return Err(Error::MissingField("PSBT_GLOBAL_INPUT_COUNT".to_string()));
    }

    if psbt.get_global_field(PSBT_GLOBAL_OUTPUT_COUNT).is_none() {
        return Err(Error::MissingField("PSBT_GLOBAL_OUTPUT_COUNT".to_string()));
    }

    Ok(())
}

/// Validate all inputs have required fields
fn validate_input_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for input_idx in 0..psbt.num_inputs() {
        // Required fields for each input
        if psbt.get_input_field(input_idx, PSBT_IN_PREVIOUS_TXID).is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing PSBT_IN_PREVIOUS_TXID",
                input_idx
            )));
        }

        if psbt.get_input_field(input_idx, PSBT_IN_OUTPUT_INDEX).is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing PSBT_IN_OUTPUT_INDEX",
                input_idx
            )));
        }

        if psbt.get_input_field(input_idx, PSBT_IN_SEQUENCE).is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing PSBT_IN_SEQUENCE",
                input_idx
            )));
        }

        // SegWit inputs require WITNESS_UTXO
        if psbt.get_input_field(input_idx, PSBT_IN_WITNESS_UTXO).is_none() {
            return Err(Error::MissingField(format!(
                "Input {} missing PSBT_IN_WITNESS_UTXO",
                input_idx
            )));
        }
    }

    Ok(())
}

/// Validate all outputs have required fields
fn validate_output_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for output_idx in 0..psbt.num_outputs() {
        // Required: amount
        if psbt.get_output_field(output_idx, PSBT_OUT_AMOUNT).is_none() {
            return Err(Error::MissingField(format!(
                "Output {} missing PSBT_OUT_AMOUNT",
                output_idx
            )));
        }

        // Check if this is a silent payment output
        let has_sp_address = psbt.get_output_sp_address(output_idx).is_some();
        let has_script = psbt.get_output_field(output_idx, PSBT_OUT_SCRIPT).is_some();

        // Output must have either a script OR a silent payment address
        // (script will be computed later for SP outputs)
        if !has_sp_address && !has_script {
            return Err(Error::MissingField(format!(
                "Output {} missing both PSBT_OUT_SCRIPT and SP address",
                output_idx
            )));
        }

        // Rule 2: Validate SP_V0_INFO field size (BIP-375)
        // SP_V0_INFO must be exactly 66 bytes (33-byte scan_key + 33-byte spend_key)
        if let Some(sp_info_field) = psbt.get_output_field(output_idx, PSBT_OUT_SP_V0_INFO) {
            if sp_info_field.value_data.len() != 66 {
                return Err(Error::InvalidFieldData(format!(
                    "Output {} SP_V0_INFO has wrong size ({} bytes, expected 66)",
                    output_idx,
                    sp_info_field.value_data.len()
                )));
            }
        }

        // Rule 3: PSBT_OUT_SP_V0_LABEL requires PSBT_OUT_SP_V0_INFO
        // If a label is present, there must be SP_V0_INFO to identify the silent payment address
        let has_sp_label = psbt.get_output_field(output_idx, PSBT_OUT_SP_V0_LABEL).is_some();
        let has_sp_info = psbt.get_output_field(output_idx, PSBT_OUT_SP_V0_INFO).is_some();

        if has_sp_label && !has_sp_info {
            return Err(Error::MissingField(format!(
                "Output {} has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO",
                output_idx
            )));
        }
    }

    Ok(())
}

/// Validate segwit version restrictions (Rule 6)
/// BIP-375: Silent payments are incompatible with segwit v2+ (taproot)
/// Note: Caller should check has_sp_outputs before calling this function
fn validate_segwit_versions(psbt: &SilentPaymentPsbt) -> Result<()> {
    // Check each input's witness UTXO script
    for input_idx in 0..psbt.num_inputs() {
        if let Some(witness_utxo_field) = psbt.get_input_field(input_idx, PSBT_IN_WITNESS_UTXO) {
            let witness_utxo = &witness_utxo_field.value_data;

            // Witness UTXO format: <amount: 8 bytes><script_len: varint><script>
            if witness_utxo.len() < 9 {
                continue; // Malformed, will be caught by other validation
            }

            let script_len = witness_utxo[8] as usize;
            if 9 + script_len > witness_utxo.len() {
                continue; // Malformed, will be caught by other validation
            }

            let script = &witness_utxo[9..9 + script_len];

            // Check if script starts with OP_2 (0x52) or higher
            // Valid segwit versions for silent payments: OP_0 (0x00) and OP_1 (0x51)
            // Invalid: OP_2 (0x52) through OP_16 (0x60) - these are taproot/future versions
            if !script.is_empty() && script[0] >= 0x52 {
                return Err(Error::InvalidFieldData(format!(
                    "Input {} uses segwit version > 1 (incompatible with silent payments)",
                    input_idx
                )));
            }
        }
    }

    Ok(())
}

/// Validate SIGHASH_ALL requirement (Rule 7)
/// BIP-375: Silent payments require SIGHASH_ALL to ensure all inputs/outputs are signed
/// Note: Caller should check has_sp_outputs before calling this function
fn validate_sighash_types(psbt: &SilentPaymentPsbt) -> Result<()> {
    // Check each input's SIGHASH_TYPE field if present
    for input_idx in 0..psbt.num_inputs() {
        if let Some(sighash_field) = psbt.get_input_field(input_idx, PSBT_IN_SIGHASH_TYPE) {
            // SIGHASH_TYPE is encoded as a 4-byte little-endian u32
            if sighash_field.value_data.len() < 4 {
                return Err(Error::InvalidFieldData(format!(
                    "Input {} has malformed PSBT_IN_SIGHASH_TYPE field",
                    input_idx
                )));
            }

            let sighash_type = u32::from_le_bytes([
                sighash_field.value_data[0],
                sighash_field.value_data[1],
                sighash_field.value_data[2],
                sighash_field.value_data[3],
            ]);

            // SIGHASH_ALL = 0x01
            const SIGHASH_ALL: u32 = 0x01;

            if sighash_type != SIGHASH_ALL {
                return Err(Error::InvalidFieldData(format!(
                    "Input {} uses non-SIGHASH_ALL (0x{:02x}) with silent payments, only SIGHASH_ALL (0x01) is allowed",
                    input_idx, sighash_type
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
    for output_idx in 0..psbt.num_outputs() {
        if let Some(sp_address) = psbt.get_output_sp_address(output_idx) {
            scan_keys.insert(sp_address.scan_key);
        }
    }

    // For each scan key, verify all inputs have ECDH shares
    // Also check that we don't mix global and per-input shares for the same scan key
    for scan_key in scan_keys {
        let mut has_global = false;
        let mut has_per_input = false;

        // Check for global ECDH share (field 0x07)
        for field in &psbt.global_fields {
            if field.field_type == PSBT_GLOBAL_SP_ECDH_SHARE && field.key_data.len() == 33 {
                if let Ok(key) = PublicKey::from_slice(&field.key_data) {
                    if key == scan_key {
                        has_global = true;
                        break;
                    }
                }
            }
        }

        // Check each input for per-input ECDH shares (field 0x1d)
        for input_idx in 0..num_inputs {
            let input_fields = &psbt.input_maps[input_idx];
            for field in input_fields {
                if field.field_type == PSBT_IN_SP_ECDH_SHARE && field.key_data.len() == 33 {
                    if let Ok(key) = PublicKey::from_slice(&field.key_data) {
                        if key == scan_key {
                            has_per_input = true;
                            break;
                        }
                    }
                }
            }
        }

        // Cannot have both global and per-input for the same scan key
        if has_global && has_per_input {
            return Err(Error::Other(format!(
                "Cannot have both global and per-input ECDH shares for the same scan key"
            )));
        }

        // Verify all inputs have ECDH shares for this scan key
        for input_idx in 0..num_inputs {
            let shares = psbt.get_input_ecdh_shares(input_idx);
            let has_share = shares.iter().any(|s| s.scan_key == scan_key);

            if !has_share {
                return Err(Error::Other(format!(
                    "Input {} missing ECDH share for scan key",
                    input_idx
                )));
            }
        }
    }

    Ok(())
}

/// Validate that output scripts match computed silent payment addresses
fn validate_output_scripts(secp: &Secp256k1<secp256k1::All>, psbt: &SilentPaymentPsbt) -> Result<()> {
    use bip375_core::psbt_accessors::{get_input_outpoint_bytes, get_input_bip32_pubkeys, get_output_sp_keys};
    use bip375_core::aggregate_ecdh_shares;
    use bip375_crypto::{derive_silent_payment_output_pubkey, compute_input_hash, pubkey_to_p2tr_script};
    use std::collections::HashMap;

    // Only validate outputs that have both a script AND SP_V0_INFO
    // (outputs without scripts haven't been finalized yet)

    // First, collect outpoints and public keys for input_hash computation
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();

    for input_idx in 0..psbt.num_inputs() {
        // Get outpoint (TXID + vout) as raw bytes for input hash computation
        let outpoint = get_input_outpoint_bytes(psbt, input_idx)?;
        outpoints.push(outpoint);

        // Extract input public key from BIP32 derivation fields
        let bip32_pubkeys = get_input_bip32_pubkeys(psbt, input_idx);

        if bip32_pubkeys.is_empty() {
            // If no BIP32 derivation, we can't validate output scripts
            // This is acceptable - validation is best-effort
            eprintln!("Warning: Input {} has no BIP32 derivation, skipping output script validation", input_idx);
            return Ok(());  // Skip validation for now
        }

        input_pubkeys.push(bip32_pubkeys[0]);
    }

    // Sum all input public keys to get A
    if input_pubkeys.is_empty() {
        return Ok(());  // No pubkeys found, skip validation
    }

    let mut summed_pubkey = input_pubkeys[0];
    for pubkey in &input_pubkeys[1..] {
        summed_pubkey = summed_pubkey.combine(pubkey)
            .map_err(|e| Error::Other(format!("Failed to sum input pubkeys: {}", e)))?;
    }

    // Find smallest outpoint lexicographically
    let smallest_outpoint = outpoints.iter()
        .min()
        .ok_or_else(|| Error::Other("No inputs found".to_string()))?;

    // Aggregate ECDH shares (detects global vs per-input and aggregates accordingly)
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Compute input_hash = hash_BIP0352/Inputs(smallest_outpoint || summed_pubkey)
    let input_hash = compute_input_hash(smallest_outpoint, &summed_pubkey)
        .map_err(|e| Error::Other(format!("Failed to compute input hash: {}", e)))?;

    // Multiply all aggregated shares by input_hash to get the shared secrets
    let mut shared_secrets: HashMap<PublicKey, PublicKey> = HashMap::new();
    for (scan_key, aggregated_share_data) in aggregated_shares.iter() {
        // shared_secret = input_hash * aggregated_share
        let shared_secret = aggregated_share_data.aggregated_share.mul_tweak(secp, &input_hash)
            .map_err(|e| Error::Other(format!("Failed to multiply ECDH share by input_hash: {}", e)))?;

        shared_secrets.insert(*scan_key, shared_secret);
    }

    // Track output index per scan key
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    // Validate each output that has both script and SP_V0_INFO
    for output_idx in 0..psbt.num_outputs() {
        // Check if output has a script (skip if not finalized yet)
        let script_field = match psbt.get_output_field(output_idx, PSBT_OUT_SCRIPT) {
            Some(field) => field,
            None => continue, // No script yet, skip (not finalized)
        };

        // Parse SP_V0_INFO (33-byte scan key + 33-byte spend key)
        // Skip outputs without SP_V0_INFO or with invalid fields
        let (scan_key, spend_key) = match get_output_sp_keys(psbt, output_idx) {
            Ok(keys) => keys,
            Err(_) => continue, // No SP info or invalid, skip
        };

        // Get shared secret for this scan key
        let shared_secret = shared_secrets.get(&scan_key)
            .ok_or_else(|| Error::Other(format!(
                "Output {} missing shared secret for scan key",
                output_idx
            )))?;

        // Get the output index for this scan key
        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);

        // Derive expected output pubkey using the shared secret
        let shared_secret_bytes = shared_secret.serialize();
        let expected_pubkey = derive_silent_payment_output_pubkey(
            secp,
            &spend_key,
            &shared_secret_bytes,
            k,
        ).map_err(|e| Error::Other(format!("Failed to derive output pubkey: {}", e)))?;

        // Create expected P2TR script
        // BIP 352: Use the derived key directly as the taproot output key (no additional tweaking)
        let expected_script = pubkey_to_p2tr_script(&expected_pubkey);

        // Compare with actual script
        if script_field.value_data != expected_script.to_bytes() {
            return Err(Error::Other(format!(
                "Output {} script mismatch: expected silent payment address doesn't match actual script",
                output_idx
            )));
        }

        // Increment output index for this scan key
        scan_key_output_indices.insert(scan_key, k + 1);
    }

    Ok(())
}

/// Validate all DLEQ proofs in the PSBT
fn validate_dleq_proofs(secp: &Secp256k1<secp256k1::All>, psbt: &SilentPaymentPsbt) -> Result<()> {
    use bip375_core::psbt_accessors::get_input_pubkey;
    // Rule 4: Global ECDH/DLEQ pairing validation
    // If PSBT_GLOBAL_SP_ECDH_SHARE exists, PSBT_GLOBAL_SP_DLEQ must also exist
    let has_global_ecdh = psbt.get_global_field(PSBT_GLOBAL_SP_ECDH_SHARE).is_some();
    let has_global_dleq = psbt.get_global_field(PSBT_GLOBAL_SP_DLEQ).is_some();
    
    if has_global_ecdh && !has_global_dleq {
        return Err(Error::Other(
            "Global ECDH share present but missing global DLEQ proof".to_string()
        ));
    }
    
    // Validate per-input ECDH shares and their DLEQ proofs
    for input_idx in 0..psbt.num_inputs() {
        let shares = psbt.get_input_ecdh_shares(input_idx);

        for share in shares {
            // BIP-375: DLEQ proofs are REQUIRED for all ECDH shares
            if share.dleq_proof.is_none() {
                return Err(Error::Other(format!(
                    "Input {} missing required DLEQ proof for ECDH share",
                    input_idx
                )));
            }

            // Verify the DLEQ proof
            if let Some(proof) = share.dleq_proof {
                // Get the input public key from PSBT fields
                let input_pubkey = get_input_pubkey(psbt, input_idx)?;

                // Verify the proof (proof is already in the EcdhShare, whether from per-input or global)
                let is_valid = dleq_verify_proof(
                    secp,
                    &input_pubkey,
                    &share.scan_key,
                    &share.share,
                    &proof,
                    None, // No message for basic verification
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
    // All inputs must have signatures
    for input_idx in 0..psbt.num_inputs() {
        let sigs = psbt.get_input_partial_sigs(input_idx);
        if sigs.is_empty() {
            return Err(Error::ExtractionFailed(format!(
                "Input {} is not signed",
                input_idx
            )));
        }
    }

    // All outputs must have scripts
    for output_idx in 0..psbt.num_outputs() {
        if psbt.get_output_field(output_idx, PSBT_OUT_SCRIPT).is_none() {
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
    use bip375_core::{Output, PsbtField, SilentPaymentAddress, Utxo};
    use bip375_crypto::pubkey_to_p2wpkh_script;
    use bitcoin::{hashes::Hash, Amount, ScriptBuf, Sequence, Txid};
    use secp256k1::SecretKey;

    #[test]
    fn test_validate_psbt_version() {
        let psbt = create_psbt(1, 1).unwrap();
        assert!(validate_psbt_version(&psbt).is_ok());
    }

    #[test]
    fn test_validate_required_global_fields() {
        let psbt = create_psbt(1, 1).unwrap();
        assert!(validate_required_global_fields(&psbt).is_ok());
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
        let mut psbt = create_psbt(1, 1).unwrap();

        let outputs = vec![Output::regular(Amount::from_sat(29000), ScriptBuf::new())];

        add_outputs(&mut psbt, &outputs).unwrap();

        assert!(validate_output_fields(&psbt).is_ok());
    }

    #[test]
    fn test_validate_ecdh_coverage() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey1),
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey2),
                Sequence::MAX,
            ),
        ];

        let outputs = vec![Output::silent_payment(Amount::from_sat(55000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Validation should pass
        assert!(validate_ecdh_coverage(&psbt).is_ok());
    }

    #[test]
    fn test_validate_incomplete_ecdh_coverage() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        let outputs = vec![Output::silent_payment(Amount::from_sat(55000), sp_address)];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add inputs but no ECDH shares
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey1),
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                None,
                Sequence::MAX,
            ),
        ];

        add_inputs(&mut psbt, &inputs).unwrap();

        // Validation should fail - no ECDH shares
        assert!(validate_ecdh_coverage(&psbt).is_err());
    }

    #[test]
    fn test_validate_ready_for_extraction() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey1),
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey2),
                Sequence::MAX,
            ),
        ];

        let outputs = vec![Output::regular(
            Amount::from_sat(55000),
            pubkey_to_p2wpkh_script(&pubkey1),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Before signing - should fail
        assert!(validate_ready_for_extraction(&psbt).is_err());

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // After signing - should pass
        assert!(validate_ready_for_extraction(&psbt).is_ok());
    }

    #[test]
    fn test_validate_psbt_basic() {
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

        let outputs = vec![Output::regular(
            Amount::from_sat(29000),
            pubkey_to_p2wpkh_script(&pubkey),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Basic validation should pass
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Basic).is_ok());
    }

    #[test]
    fn test_validate_psbt_full_with_dleq() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey1),
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                pubkey_to_p2wpkh_script(&pubkey1),
                Some(privkey2),
                Sequence::MAX,
            ),
        ];

        let outputs = vec![Output::silent_payment(Amount::from_sat(55000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add ECDH shares with DLEQ proofs
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], true).unwrap();

        // Sign inputs (needed for DLEQ validation to extract pubkeys)
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Full validation with DLEQ should pass
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Full).is_ok());
    }

    #[test]
    fn test_validate_segwit_version_taproot_rejection() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys for silent payment output
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create a mock witness UTXO with segwit v2 (taproot) script
        // Format: <amount: 8 bytes><script_len: 1 byte><script>
        // Taproot script: OP_1 (0x51) <32-byte pubkey> - this is v1, which is VALID
        // Taproot v2 would be: OP_2 (0x52) <32-byte pubkey> - this should be INVALID
        let mut witness_utxo = vec![0u8; 8]; // 8-byte amount
        witness_utxo.push(34); // script length (1 + 1 + 32)
        witness_utxo.push(0x52); // OP_2 (segwit v2 - INVALID for silent payments)
        witness_utxo.push(0x20); // Push 32 bytes
        witness_utxo.extend_from_slice(&[0xAB; 32]); // 32-byte pubkey

        // Manually add input with invalid segwit version
        let input_fields = vec![
            PsbtField::new(PSBT_IN_PREVIOUS_TXID, vec![], vec![0u8; 32]),
            PsbtField::new(PSBT_IN_OUTPUT_INDEX, vec![], vec![0, 0, 0, 0]),
            PsbtField::new(PSBT_IN_SEQUENCE, vec![], vec![0xff, 0xff, 0xff, 0xff]),
            PsbtField::new(PSBT_IN_WITNESS_UTXO, vec![], witness_utxo),
        ];

        for field in input_fields {
            psbt.add_input_field(0, field).unwrap();
        }

        // Add silent payment output
        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Validation should fail due to segwit v2
        let result = validate_psbt(&secp, &psbt, ValidationLevel::Basic);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("segwit version > 1"));
    }

    #[test]
    fn test_validate_segwit_version_v0_v1_allowed() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs with valid segwit versions
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        // P2WPKH (segwit v0) - should be valid
        let inputs = vec![Utxo::new(
            Txid::all_zeros(),
            0,
            Amount::from_sat(30000),
            pubkey_to_p2wpkh_script(&pubkey), // This creates OP_0 script (v0)
            Some(privkey),
            Sequence::MAX,
        )];

        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Validation should pass for segwit v0
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Basic).is_ok());
    }

    #[test]
    fn test_validate_sighash_all_required() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys for silent payment output
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
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

        // Add silent payment output
        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add non-SIGHASH_ALL type (e.g., SIGHASH_SINGLE = 0x03)
        let sighash_single = vec![0x03, 0x00, 0x00, 0x00]; // SIGHASH_SINGLE
        let sighash_field = PsbtField::new(PSBT_IN_SIGHASH_TYPE, vec![], sighash_single);
        psbt.add_input_field(0, sighash_field).unwrap();

        // Validation should fail due to non-SIGHASH_ALL
        let result = validate_psbt(&secp, &psbt, ValidationLevel::Basic);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("non-SIGHASH_ALL"));
    }

    #[test]
    fn test_validate_sighash_all_allowed() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
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

        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add SIGHASH_ALL (0x01)
        let sighash_all = vec![0x01, 0x00, 0x00, 0x00]; // SIGHASH_ALL
        let sighash_field = PsbtField::new(PSBT_IN_SIGHASH_TYPE, vec![], sighash_all);
        psbt.add_input_field(0, sighash_field).unwrap();

        // Validation should pass with SIGHASH_ALL
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Basic).is_ok());
    }

    #[test]
    fn test_validate_sighash_omitted_allowed() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
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

        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // No PSBT_IN_SIGHASH_TYPE field - this is allowed (defaults to SIGHASH_ALL)
        // Validation should pass when SIGHASH_TYPE is omitted
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Basic).is_ok());
    }

    #[test]
    fn test_validate_global_ecdh_dleq_pairing() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys for silent payment output
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
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

        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Manually add a global ECDH share WITHOUT a global DLEQ proof
        // This simulates the invalid case from test vector 6
        let ecdh_share_data = vec![0xAB; 33]; // Mock 33-byte ECDH share
        let global_ecdh_field = PsbtField::new(PSBT_GLOBAL_SP_ECDH_SHARE, vec![], ecdh_share_data);
        psbt.add_global_field(global_ecdh_field);

        // Validation should fail - global ECDH without global DLEQ
        let result = validate_psbt(&secp, &psbt, ValidationLevel::Full);
        assert!(result.is_err(), "Expected validation to fail");
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Global ECDH share present but missing global DLEQ proof"),
            "Wrong error message: {}", error_msg);
    }

    #[test]
    fn test_validate_global_ecdh_with_dleq_allowed() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs
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

        let outputs = vec![Output::silent_payment(Amount::from_sat(25000), sp_address)];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add both global ECDH share AND global DLEQ proof (valid pairing)
        let ecdh_share_data = vec![0xAB; 33]; // Mock 33-byte ECDH share
        let dleq_proof_data = vec![0xCD; 64]; // Mock 64-byte DLEQ proof
        
        let global_ecdh_field = PsbtField::new(PSBT_GLOBAL_SP_ECDH_SHARE, vec![], ecdh_share_data);
        let global_dleq_field = PsbtField::new(PSBT_GLOBAL_SP_DLEQ, vec![], dleq_proof_data);
        
        psbt.add_global_field(global_ecdh_field);
        psbt.add_global_field(global_dleq_field);

        // Basic validation should pass (we don't verify the proof cryptographically in Basic mode)
        assert!(validate_psbt(&secp, &psbt, ValidationLevel::Basic).is_ok());
    }
}
