//! PSBT Extractor Role
//!
//! Extracts the final Bitcoin transaction from a completed PSBT.

use bip375_core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Extract the final signed transaction from a PSBT
pub fn extract_transaction(psbt: &SilentPaymentPsbt) -> Result<Transaction> {
    let global = &psbt.global;
    let version = global.tx_version;
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    // Extract inputs with witnesses
    let mut inputs = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        inputs.push(extract_input(psbt, input_idx)?);
    }

    // Extract outputs
    let mut outputs = Vec::new();
    for output_idx in 0..psbt.num_outputs() {
        outputs.push(extract_output(psbt, output_idx)?);
    }

    Ok(Transaction {
        version,
        lock_time,
        input: inputs,
        output: outputs,
    })
}

/// Extract a single input from the PSBT
fn extract_input(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<TxIn> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // Build witness from partial signatures
    let witness = extract_witness(psbt, input_idx)?;

    Ok(TxIn {
        previous_output: OutPoint {
            txid: input.previous_txid,
            vout: input.spent_output_index,
        },
        script_sig: ScriptBuf::new(), // SegWit inputs have empty script_sig
        sequence: input.sequence.unwrap_or(Sequence::MAX),
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
    let output = psbt
        .outputs
        .get(output_idx)
        .ok_or(Error::InvalidOutputIndex(output_idx))?;

    Ok(TxOut {
        value: Amount::from_sat(output.amount.to_sat()),
        script_pubkey: output.script_pubkey.clone(),
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
    use bitcoin::{hashes::Hash, ScriptBuf, Txid};
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
