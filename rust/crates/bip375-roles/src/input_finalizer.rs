//! PSBT Input Finalizer Role
//!
//! Aggregates ECDH shares and computes final output scripts for silent payments.

use bip375_core::{
    constants::*, Error, PsbtField, Result, SilentPaymentAddress,
    SilentPaymentPsbt, aggregate_ecdh_shares,
};
use bip375_crypto::{apply_label_to_spend_key, derive_silent_payment_output_pubkey, pubkey_to_p2tr_script};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;

/// Finalize inputs by computing output scripts from ECDH shares
///
/// This function:
/// 1. Aggregates ECDH shares across all inputs for each scan key
/// 2. For each silent payment output, derives the output public key
/// 3. Applies label tweaks if scan private keys are provided (for change outputs)
/// 4. Computes and adds the output script to the PSBT
///
/// BIP 352 Note: The output index `k` is per scan key, not global.
/// Multiple outputs with the same scan key use k=0, k=1, k=2, etc.
/// Outputs with different scan keys each start from k=0.
///
/// Args:
///   secp: Secp256k1 context
///   psbt: PSBT to finalize
///   scan_privkeys: Optional map of scan_key -> scan_privkey for applying label tweaks
pub fn finalize_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    scan_privkeys: Option<&HashMap<PublicKey, SecretKey>>,
) -> Result<()> {
    // Aggregate ECDH shares by scan key (detects global vs per-input automatically)
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Track output index per scan key (for BIP 352 k parameter)
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    // Process each output
    for output_idx in 0..psbt.num_outputs() {
        // Check if this is a silent payment output
        let sp_address = match get_silent_payment_address(psbt, output_idx) {
            Some(addr) => addr,
            None => continue, // Not a silent payment output, skip
        };

        // Get the aggregated share for this scan key
        let aggregated = aggregated_shares
            .get(&sp_address.scan_key)
            .ok_or(Error::IncompleteEcdhCoverage(output_idx))?;

        // Verify all inputs contributed shares (unless it's a global share)
        if !aggregated.is_global && aggregated.num_inputs != psbt.num_inputs() {
            return Err(Error::IncompleteEcdhCoverage(output_idx));
        }

        let aggregated_share = aggregated.aggregated_share;

        // Check for label and apply if present and we have scan private key
        let mut spend_key_to_use = sp_address.spend_key;
        
        // Check if there's a label field for this output
        if let Some(label_field) = psbt.get_output_field(output_idx, PSBT_OUT_SP_V0_LABEL) {
            if label_field.value_data.len() == 4 {
                let label_bytes: [u8; 4] = label_field.value_data[..4].try_into()
                    .map_err(|_| Error::Other("Invalid label bytes".to_string()))?;
                let label = u32::from_le_bytes(label_bytes);
                
                // If we have the scan private key, apply the label tweak to spend key
                if let Some(privkeys) = scan_privkeys {
                    if let Some(scan_privkey) = privkeys.get(&sp_address.scan_key) {
                        spend_key_to_use = apply_label_to_spend_key(
                            secp,
                            &sp_address.spend_key,
                            scan_privkey,
                            label,
                        ).map_err(|e| Error::Other(format!("Failed to apply label tweak: {}", e)))?;
                        
                        // Note: Label tweak applied for change output
                    }
                }
            }
        }
        
        // Get or initialize the output index for this scan key
        let k = *scan_key_output_indices.get(&sp_address.scan_key).unwrap_or(&0);
        
        // Derive the output public key using BIP-352
        // Convert aggregated share to bytes (33-byte compressed public key)
        let ecdh_secret = aggregated_share.serialize();
        let output_pubkey = derive_silent_payment_output_pubkey(
            secp,
            &spend_key_to_use, // Use labeled spend key if label was applied
            &ecdh_secret,
            k, // Use per-scan-key index
        )
        .map_err(|e| Error::Other(format!("Output derivation failed: {}", e)))?;

        // Create P2TR output script
        let output_script = pubkey_to_p2tr_script(&output_pubkey);

        // Add output script to PSBT
        psbt.add_output_field(
            output_idx,
            PsbtField::with_value(PSBT_OUT_SCRIPT, output_script.to_bytes()),
        )?;
        
        // Increment the output index for this scan key
        scan_key_output_indices.insert(sp_address.scan_key, k + 1);
    }

    Ok(())
}

/// Get silent payment address from output if present
fn get_silent_payment_address(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Option<SilentPaymentAddress> {
    // Look for PSBT_OUT_SP_SILENT_PAYMENT_ADDRESS proprietary field
    // Use the existing get_output_sp_address method
    psbt.get_output_sp_address(output_idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constructor::add_outputs, creator::create_psbt, signer::add_ecdh_shares_full};
    use bip375_core::{Output, Utxo};
    use bitcoin::{hashes::Hash, Amount, ScriptBuf, Sequence, Txid};
    use secp256k1::SecretKey;

    #[test]
    fn test_finalize_inputs_basic() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Add output
        let outputs = vec![Output::silent_payment(Amount::from_sat(50000), sp_address)];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(30000),
                ScriptBuf::new(),
                Some(privkey1),
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                ScriptBuf::new(),
                Some(privkey2),
                Sequence::MAX,
            ),
        ];

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_inputs(&secp, &mut psbt, None).unwrap();

        // Verify output script was added
        let script_field = psbt.get_output_field(0, PSBT_OUT_SCRIPT);
        assert!(script_field.is_some());

        let script = ScriptBuf::from_bytes(script_field.unwrap().value_data.clone());
        // P2TR scripts are 34 bytes: OP_1 + 32-byte x-only pubkey
        assert_eq!(script.len(), 34);
        assert!(script.is_p2tr());
    }

    #[test]
    fn test_incomplete_ecdh_coverage() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Add output
        let outputs = vec![Output::silent_payment(Amount::from_sat(50000), sp_address)];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Only add ECDH share for one input (incomplete)
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let inputs = vec![Utxo::new(
            Txid::all_zeros(),
            0,
            Amount::from_sat(30000),
            ScriptBuf::new(),
            Some(privkey1),
            Sequence::MAX,
        )];

        // Use partial signing to only add share for input 0
        use crate::signer::add_ecdh_shares_partial;
        add_ecdh_shares_partial(&secp, &mut psbt, &inputs, &[scan_key], &[0], false).unwrap();

        // Finalize should fail due to incomplete coverage
        let result = finalize_inputs(&secp, &mut psbt, None);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::IncompleteEcdhCoverage(0))));
    }
}
