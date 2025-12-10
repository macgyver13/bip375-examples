//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.

use bip375_core::{Bip375PsbtExt, EcdhShareData, Error, Result, SilentPaymentPsbt, Utxo};
use bip375_crypto::{compute_ecdh_share, dleq_generate_proof, sign_p2wpkh_input};
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashSet;

/// Add ECDH shares for all inputs (full signing)
pub fn add_ecdh_shares_full(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
    scan_keys: &[PublicKey],
    include_dleq: bool,
) -> Result<()> {
    for (input_idx, utxo) in inputs.iter().enumerate() {
        let Some(privkey) = &utxo.private_key else {
            return Err(Error::Other(format!(
                "Input {} missing private key",
                input_idx
            )));
        };

        for scan_key in scan_keys {
            let share_point = compute_ecdh_share(secp, privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32];
                Some(
                    dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
                        .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
                )
            } else {
                None
            };

            let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
            psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
        }
    }
    Ok(())
}

/// Add ECDH shares for specific inputs (partial signing)
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
            let share_point = compute_ecdh_share(secp, privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32];
                Some(
                    dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
                        .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
                )
            } else {
                None
            };

            let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
            psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
        }
    }
    Ok(())
}

/// Sign all inputs
pub fn sign_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
) -> Result<()> {
    let tx = extract_tx_for_signing(psbt)?;

    for (input_idx, utxo) in inputs.iter().enumerate() {
        let Some(privkey) = &utxo.private_key else {
            continue;
        };

        let signature = sign_p2wpkh_input(
            secp,
            &tx,
            input_idx,
            &utxo.script_pubkey,
            utxo.amount,
            privkey,
        )
        .map_err(|e| Error::Other(format!("Signing failed: {}", e)))?;

        let pubkey = PublicKey::from_secret_key(secp, privkey);
        let bitcoin_pubkey = bitcoin::PublicKey::new(pubkey);

        let sig = bitcoin::ecdsa::Signature::from_slice(&signature)
            .map_err(|e| Error::Other(format!("Invalid signature DER: {}", e)))?;

        psbt.inputs[input_idx]
            .partial_sigs
            .insert(bitcoin_pubkey, sig);
    }
    Ok(())
}

/// Extract transaction data needed for signing
fn extract_tx_for_signing(psbt: &SilentPaymentPsbt) -> Result<bitcoin::Transaction> {
    use bitcoin::{absolute::LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut};

    let global = &psbt.global;
    let version = global.tx_version; // Already Version type
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    let mut inputs = Vec::new();
    for input in &psbt.inputs {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: input.previous_txid,
                vout: input.spent_output_index,
            },
            script_sig: ScriptBuf::new(),
            sequence: input.sequence.unwrap_or(Sequence::MAX),
            witness: bitcoin::Witness::new(),
        });
    }

    let mut outputs = Vec::new();
    for output in &psbt.outputs {
        outputs.push(TxOut {
            value: output.amount, // Already Amount type
            script_pubkey: output.script_pubkey.clone(),
        });
    }

    Ok(Transaction {
        version,
        lock_time,
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
