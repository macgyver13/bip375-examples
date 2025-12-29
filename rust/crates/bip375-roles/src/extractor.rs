//! PSBT Extractor Role
//!
//! Extracts the final Bitcoin transaction from a completed PSBT.
//!
//! Supports both P2WPKH and P2TR witness extraction:
//! - **P2WPKH**: Extracts from `partial_sigs` → witness: `[<ecdsa_sig>, <pubkey>]`
//! - **P2TR**: Extracts from `tap_key_sig` → witness: `[<schnorr_sig>]`
//!
//! After successful extraction, `PSBT_IN_SP_TWEAK` fields are cleaned up to prevent
//! accidental re-use and keep PSBTs cleaner.

use bip375_core::{Error, Result, SilentPaymentPsbt};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use silentpayments::psbt::Bip375PsbtExt;

/// Extract the final signed transaction from a PSBT
///
/// After successful extraction, cleans up `PSBT_IN_SP_TWEAK` fields to prevent
/// accidental re-use and keep PSBTs cleaner.
///
/// # Note
/// This function takes a mutable reference to allow cleanup of SP tweaks.
pub fn extract_transaction(psbt: &mut SilentPaymentPsbt) -> Result<Transaction> {
    let global = &psbt.global;
    let version = global.tx_version;
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    // Extract inputs with witnesses
    let inputs: Result<Vec<_>> = (0..psbt.inputs.len())
        .map(|input_idx| extract_input(psbt, input_idx))
        .collect();
    let inputs = inputs?;

    // Extract outputs
    let outputs: Result<Vec<_>> = (0..psbt.outputs.len())
        .map(|output_idx| extract_output(psbt, output_idx))
        .collect();
    let outputs = outputs?;

    let tx = Transaction {
        version,
        lock_time,
        input: inputs,
        output: outputs,
    };

    // Clean up SP tweaks after successful extraction
    // This prevents accidental re-use of tweaks and keeps PSBTs cleaner
    let indices_to_clean: Vec<_> = (0..psbt.inputs.len())
        .filter(|&idx| psbt.get_input_sp_tweak(idx).is_some())
        .collect();

    for idx in indices_to_clean {
        psbt.remove_input_sp_tweak(idx)?;
    }

    Ok(tx)
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
///
/// Handles both P2WPKH and P2TR witness formats:
/// - **P2TR** (Taproot key path): Check for `tap_key_sig` first
///   - Witness: `[<bip340_signature>]` (single element, 65 bytes)
/// - **P2WPKH**: Fall back to `partial_sigs`
///   - Witness: `[<ecdsa_signature>, <pubkey>]` (two elements)
fn extract_witness(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Witness> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // Check for P2TR tap_key_sig first (Taproot key-path spend)
    if let Some(tap_sig) = &input.tap_key_sig {
        // P2TR witness has single element: BIP-340 Schnorr signature
        let mut witness = Witness::new();
        witness.push(tap_sig.to_vec());
        return Ok(witness);
    }

    // Fall back to P2WPKH partial_sigs (ECDSA)
    let sigs = &input.partial_sigs;

    if sigs.is_empty() {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has no signatures (neither tap_key_sig nor partial_sigs)",
            input_idx
        )));
    }

    // For P2WPKH, witness is: <signature> <pubkey>
    // We expect exactly one signature for single-key P2WPKH
    if sigs.len() != 1 {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has {} partial signatures, expected 1 for P2WPKH",
            input_idx,
            sigs.len()
        )));
    }

    let (pubkey, signature) = sigs.iter().next().unwrap();

    // Build P2WPKH witness stack
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(pubkey.to_bytes());

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
