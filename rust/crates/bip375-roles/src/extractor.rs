//! PSBT Extractor Role
//!
//! Extracts the final Bitcoin transaction from a completed PSBT.

use bip375_core::{constants::*, Error, Result, SilentPaymentPsbt};
use bitcoin::{
    absolute::LockTime, hashes::Hash as BitcoinHash, transaction::Version, Amount, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

/// Extract the final signed transaction from a PSBT
///
/// This verifies that:
/// - All inputs have required witness data (signatures)
/// - All outputs have scripts assigned
/// - Transaction is complete and ready to broadcast
pub fn extract_transaction(psbt: &SilentPaymentPsbt) -> Result<Transaction> {
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
    let locktime =
        if let Some(locktime_field) = psbt.get_global_field(PSBT_GLOBAL_FALLBACK_LOCKTIME) {
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
        inputs.push(extract_input(psbt, input_idx)?);
    }

    // Build outputs
    let mut outputs = Vec::new();
    for output_idx in 0..psbt.num_outputs() {
        outputs.push(extract_output(psbt, output_idx)?);
    }

    Ok(Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(locktime),
        input: inputs,
        output: outputs,
    })
}

/// Extract a single input from the PSBT
fn extract_input(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<TxIn> {
    // Get TXID
    let txid_field = psbt
        .get_input_field(input_idx, PSBT_IN_PREVIOUS_TXID)
        .ok_or_else(|| Error::MissingField(format!("Input {} TXID", input_idx)))?;
    let txid = Txid::from_slice(&txid_field.value_data)
        .map_err(|e| Error::InvalidFieldData(format!("Invalid TXID: {}", e)))?;

    // Get vout
    let vout_field = psbt
        .get_input_field(input_idx, PSBT_IN_OUTPUT_INDEX)
        .ok_or_else(|| Error::MissingField(format!("Input {} vout", input_idx)))?;
    let vout = u32::from_le_bytes([
        vout_field.value_data[0],
        vout_field.value_data[1],
        vout_field.value_data[2],
        vout_field.value_data[3],
    ]);

    // Get sequence
    let sequence_field = psbt
        .get_input_field(input_idx, PSBT_IN_SEQUENCE)
        .ok_or_else(|| Error::MissingField(format!("Input {} sequence", input_idx)))?;
    let sequence = Sequence::from_consensus(u32::from_le_bytes([
        sequence_field.value_data[0],
        sequence_field.value_data[1],
        sequence_field.value_data[2],
        sequence_field.value_data[3],
    ]));

    // Build witness from partial signatures
    let witness = extract_witness(psbt, input_idx)?;

    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(), // SegWit inputs have empty script_sig
        sequence,
        witness,
    })
}

/// Extract witness data from input
fn extract_witness(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Witness> {
    // Get partial signatures
    let sigs = psbt.get_input_partial_sigs(input_idx);

    if sigs.is_empty() {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has no signatures",
            input_idx
        )));
    }

    // For P2WPKH, witness is: <signature> <pubkey>
    // We expect exactly one signature for single-key P2WPKH
    if sigs.len() != 1 {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has {} signatures, expected 1 for P2WPKH",
            input_idx,
            sigs.len()
        )));
    }

    let (pubkey, signature) = &sigs[0];

    // Build witness stack
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(pubkey);

    Ok(witness)
}

/// Extract a single output from the PSBT
fn extract_output(psbt: &SilentPaymentPsbt, output_idx: usize) -> Result<TxOut> {
    // Get amount
    let amount_field = psbt
        .get_output_field(output_idx, PSBT_OUT_AMOUNT)
        .ok_or_else(|| Error::MissingField(format!("Output {} amount", output_idx)))?;

    // Parse 64-bit little-endian amount (PSBT v2 spec)
    if amount_field.value_data.len() != 8 {
        return Err(Error::InvalidFieldData(format!(
            "Invalid amount length: expected 8 bytes, got {}",
            amount_field.value_data.len()
        )));
    }
    let amount_bytes: [u8; 8] = amount_field.value_data[0..8]
        .try_into()
        .expect("amount bytes did not convert to 8 bytes");
    let amount_sats = u64::from_le_bytes(amount_bytes);
    let amount = Amount::from_sat(amount_sats);

    // Get script
    let script_field = psbt
        .get_output_field(output_idx, PSBT_OUT_SCRIPT)
        .ok_or_else(|| Error::MissingField(format!("Output {} script", output_idx)))?;
    let script_pubkey = ScriptBuf::from_bytes(script_field.value_data.clone());

    Ok(TxOut {
        value: amount,
        script_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
        input_finalizer::finalize_inputs,
        signer::{add_ecdh_shares_full, sign_inputs},
    };
    use bip375_core::{Output, SilentPaymentAddress, Utxo};
    use bip375_crypto::pubkey_to_p2wpkh_script;
    use bitcoin::{hashes::Hash, ScriptBuf};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_extract_transaction_regular_output() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 regular output
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        // Create P2WPKH script for output
        let output_script = pubkey_to_p2wpkh_script(&pubkey1);

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

        let outputs = vec![Output::regular(Amount::from_sat(55000), output_script)];

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Extract transaction
        let tx = extract_transaction(&psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_transaction_silent_payment() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1).unwrap();

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(scan_key, spend_key, None);

        // Create inputs with private keys
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

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_inputs(&secp, &mut psbt, None).unwrap();

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Extract transaction
        let tx = extract_transaction(&psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify output is P2TR (silent payment outputs are taproot)
        assert!(tx.output[0].script_pubkey.is_p2tr());

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_fails_without_signatures() {
        let mut psbt = create_psbt(1, 1).unwrap();

        let inputs = vec![Utxo::new(
            Txid::all_zeros(),
            0,
            Amount::from_sat(30000),
            ScriptBuf::new(),
            None, // No private key = no signature
            Sequence::MAX,
        )];

        let outputs = vec![Output::regular(Amount::from_sat(29000), ScriptBuf::new())];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Extraction should fail without signatures
        let result = extract_transaction(&psbt);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ExtractionFailed(_))));
    }
}
