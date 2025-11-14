//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.

use bip375_core::{constants::*, Error, PsbtField, Result, SilentPaymentPsbt, Utxo};
use bip375_crypto::{compute_ecdh_share, dleq_generate_proof, sign_p2wpkh_input};
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashSet;

/// Add ECDH shares for all inputs (full signing)
///
/// This is used when a single signer controls all inputs.
pub fn add_ecdh_shares_full(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
    scan_keys: &[PublicKey],
    include_dleq: bool,
) -> Result<()> {
    // Add ECDH shares for each input to each scan key
    for (input_idx, utxo) in inputs.iter().enumerate() {
        let Some(privkey) = &utxo.private_key else {
            return Err(Error::Other(format!(
                "Input {} missing private key",
                input_idx
            )));
        };

        for scan_key in scan_keys {
            // Compute ECDH share
            let share = compute_ecdh_share(secp, privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            // Generate DLEQ proof if requested
            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32]; // Deterministic aux for testing
                Some(dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
                    .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?)
            } else {
                None
            };

            // Add ECDH share field (BIP-375 field type 0x1d)
            // key_data = 33-byte scan key, value = 33-byte ECDH share (just the share point)
            psbt.add_input_field(
                input_idx,
                PsbtField::new(
                    PSBT_IN_SP_ECDH_SHARE,
                    scan_key.serialize().to_vec(),
                    share.serialize().to_vec(),  // Just the 33-byte share point
                ),
            )?;

            // Add DLEQ proof field if present (BIP-375 field type 0x1e)
            // key_data = 33-byte scan key, value = 64-byte DLEQ proof
            if let Some(proof) = dleq_proof {
                psbt.add_input_field(
                    input_idx,
                    PsbtField::new(PSBT_IN_SP_DLEQ, scan_key.serialize().to_vec(), proof.to_vec()),
                )?;
            }
        }
    }

    Ok(())
}

/// Add ECDH shares for specific inputs (partial signing)
///
/// This is used in multi-party scenarios where each signer controls only some inputs.
pub fn add_ecdh_shares_partial(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
    scan_keys: &[PublicKey],
    controlled_indices: &[usize],
    include_dleq: bool,
) -> Result<()> {
    let controlled_set: HashSet<usize> = controlled_indices.iter().copied().collect();

    for (input_idx, utxo) in inputs.iter().enumerate() {
        // Only process inputs controlled by this signer
        if !controlled_set.contains(&input_idx) {
            continue;
        }

        let Some(privkey) = &utxo.private_key else {
            return Err(Error::Other(format!(
                "Controlled input {} missing private key",
                input_idx
            )));
        };

        for scan_key in scan_keys {
            // Compute ECDH share
            let share = compute_ecdh_share(secp, privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            // Generate DLEQ proof if requested
            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32];
                Some(dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
                    .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?)
            } else {
                None
            };

            // Add ECDH share field (BIP-375 field type 0x1d)
            // key_data = 33-byte scan key, value = 33-byte ECDH share (just the share point)
            psbt.add_input_field(
                input_idx,
                PsbtField::new(
                    PSBT_IN_SP_ECDH_SHARE,
                    scan_key.serialize().to_vec(),
                    share.serialize().to_vec(),  // Just the 33-byte share point
                ),
            )?;

            // Add DLEQ proof field if present (BIP-375 field type 0x1e)
            // key_data = 33-byte scan key, value = 64-byte DLEQ proof
            if let Some(proof) = dleq_proof {
                psbt.add_input_field(
                    input_idx,
                    PsbtField::new(PSBT_IN_SP_DLEQ, scan_key.serialize().to_vec(), proof.to_vec()),
                )?;
            }
        }
    }

    Ok(())
}

/// Sign all inputs
///
/// Signs inputs with the provided private keys using SIGHASH_ALL.
pub fn sign_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
) -> Result<()> {
    // Extract transaction data needed for signing
    let tx = extract_tx_for_signing(psbt)?;

    for (input_idx, utxo) in inputs.iter().enumerate() {
        let Some(privkey) = &utxo.private_key else {
            continue; // Skip inputs without private keys
        };

        // Sign this input
        let signature = sign_p2wpkh_input(
            secp,
            &tx,
            input_idx,
            &utxo.script_pubkey,
            utxo.amount,
            privkey,
        )
        .map_err(|e| Error::Other(format!("Signing failed: {}", e)))?;

        // Add signature to PSBT
        let pubkey = PublicKey::from_secret_key(secp, privkey);
        let key_data = pubkey.serialize().to_vec();

        psbt.add_input_field(
            input_idx,
            PsbtField::new(PSBT_IN_PARTIAL_SIG, key_data, signature),
        )?;
    }

    Ok(())
}

/// Extract transaction data needed for signing
fn extract_tx_for_signing(psbt: &SilentPaymentPsbt) -> Result<bitcoin::Transaction> {
    use bitcoin::{
        absolute::LockTime, hashes::Hash as BitcoinHash, transaction::Version, OutPoint,
        Sequence, Transaction, TxIn, Txid,
    };

    // Get version
    let version_field = psbt
        .get_global_field(PSBT_GLOBAL_TX_VERSION)
        .ok_or_else(|| Error::MissingField("PSBT_GLOBAL_TX_VERSION".to_string()))?;
    let version = i32::from_le_bytes([
        version_field.value_data[0],
        version_field.value_data[1],
        version_field.value_data[2],
        version_field.value_data[3],
    ]);

    // Get locktime (if present, otherwise 0)
    let locktime = if let Some(locktime_field) = psbt.get_global_field(PSBT_GLOBAL_FALLBACK_LOCKTIME) {
        u32::from_le_bytes([
            locktime_field.value_data[0],
            locktime_field.value_data[1],
            locktime_field.value_data[2],
            locktime_field.value_data[3],
        ])
    } else {
        0
    };

    // Build inputs
    let mut inputs = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        let txid_field = psbt
            .get_input_field(input_idx, PSBT_IN_PREVIOUS_TXID)
            .ok_or_else(|| Error::MissingField(format!("Input {} TXID", input_idx)))?;

        let vout_field = psbt
            .get_input_field(input_idx, PSBT_IN_OUTPUT_INDEX)
            .ok_or_else(|| Error::MissingField(format!("Input {} vout", input_idx)))?;

        let sequence_field = psbt
            .get_input_field(input_idx, PSBT_IN_SEQUENCE)
            .ok_or_else(|| Error::MissingField(format!("Input {} sequence", input_idx)))?;

        let txid = Txid::from_slice(&txid_field.value_data)
            .map_err(|e| Error::InvalidFieldData(format!("Invalid TXID: {}", e)))?;

        let vout = u32::from_le_bytes([
            vout_field.value_data[0],
            vout_field.value_data[1],
            vout_field.value_data[2],
            vout_field.value_data[3],
        ]);

        let sequence = Sequence::from_consensus(u32::from_le_bytes([
            sequence_field.value_data[0],
            sequence_field.value_data[1],
            sequence_field.value_data[2],
            sequence_field.value_data[3],
        ]));

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence,
            witness: bitcoin::Witness::new(),
        });
    }

    // Build outputs (empty for signing)
    let outputs = Vec::new();

    Ok(Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(locktime),
        input: inputs,
        output: outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constructor::add_inputs, creator::create_psbt};
    use bitcoin::{hashes::Hash, Amount, Sequence, Txid};
    use secp256k1::SecretKey;

    #[test]
    fn test_add_ecdh_shares_full() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(50000),
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

        add_inputs(&mut psbt, &inputs).unwrap();
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], true).unwrap();

        // Verify ECDH shares were added
        let shares0 = psbt.get_input_ecdh_shares(0);
        assert_eq!(shares0.len(), 1);
        assert_eq!(shares0[0].scan_key, scan_key);

        let shares1 = psbt.get_input_ecdh_shares(1);
        assert_eq!(shares1.len(), 1);
    }

    #[test]
    fn test_add_ecdh_shares_partial() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1).unwrap();

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(50000),
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

        add_inputs(&mut psbt, &inputs).unwrap();

        // Only sign input 0
        add_ecdh_shares_partial(&secp, &mut psbt, &inputs, &[scan_key], &[0], false).unwrap();

        // Input 0 should have shares
        let shares0 = psbt.get_input_ecdh_shares(0);
        assert_eq!(shares0.len(), 1);

        // Input 1 should not have shares
        let shares1 = psbt.get_input_ecdh_shares(1);
        assert_eq!(shares1.len(), 0);
    }
}
