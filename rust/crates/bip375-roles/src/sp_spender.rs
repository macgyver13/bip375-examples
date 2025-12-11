//! Silent Payment Spender Role
//!
//! Signs inputs that spend silent payment outputs using tweaked keys.

use bip375_core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use bip375_crypto::{apply_tweak_to_privkey, sign_p2tr_input};
use bitcoin::TxOut;
use secp256k1::{Secp256k1, SecretKey};

/// Sign silent payment inputs using tweaked private keys
///
/// For each input with PSBT_IN_SP_TWEAK:
/// 1. Apply tweak: tweaked_privkey = spend_privkey + tweak
/// 2. Sign with BIP-340 Schnorr
/// 3. Add tap_key_sig to PSBT
///
/// Note: PSBT_IN_SP_TWEAK is left in PSBT after signing
/// TODO: Define removal policy in BIP-375 spending specification
pub fn sign_silent_payment_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    spend_privkey: &SecretKey,
    input_indices: &[usize],
) -> Result<()> {
    // Build prevouts array for Taproot sighash
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(Error::Other(format!("Input {} missing witness_utxo", idx)))
        })
        .collect::<Result<Vec<_>>>()?;

    // Build transaction for signing
    let tx = build_unsigned_tx(psbt)?;

    // Sign each input with tweak
    for &input_idx in input_indices {
        let Some(tweak) = psbt.get_input_sp_tweak(input_idx) else {
            continue; // Not a silent payment input
        };

        let tweaked_privkey = apply_tweak_to_privkey(spend_privkey, &tweak)
            .map_err(|e| Error::Other(format!("Tweak application failed: {}", e)))?;

        let signature = sign_p2tr_input(secp, &tx, input_idx, &prevouts, &tweaked_privkey)
            .map_err(|e| Error::Other(format!("Schnorr signing failed: {}", e)))?;

        psbt.inputs[input_idx].tap_key_sig = Some(signature);
    }

    Ok(())
}

fn build_unsigned_tx(psbt: &SilentPaymentPsbt) -> Result<bitcoin::Transaction> {
    use bitcoin::{absolute::LockTime, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};

    let inputs: Vec<TxIn> = psbt
        .inputs
        .iter()
        .map(|input| TxIn {
            previous_output: OutPoint {
                txid: input.previous_txid,
                vout: input.spent_output_index,
            },
            script_sig: ScriptBuf::new(),
            sequence: input.sequence.unwrap_or(Sequence::MAX),
            witness: bitcoin::Witness::new(),
        })
        .collect();

    let outputs: Vec<TxOut> = psbt
        .outputs
        .iter()
        .map(|output| TxOut {
            value: output.amount,
            script_pubkey: output.script_pubkey.clone(),
        })
        .collect();

    Ok(Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: inputs,
        output: outputs,
    })
}
