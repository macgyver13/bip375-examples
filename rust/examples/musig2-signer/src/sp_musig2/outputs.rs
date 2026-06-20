//! Silent-payment output script derivation (BIP-352).
//!
//! Ported from old `spdk-core::psbt::roles::input_finalizer::finalize_sp_outputs`
//! and `crypto::bip352::derive_silent_payment_output_pubkey`. UPSTREAM CANDIDATE.

use anyhow::{anyhow, Result};
use bip375_helpers::crypto::tweaked_key_to_p2tr_script;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::HashMap;

use super::bip352_hash::shared_secret_tweak;
use super::psbt_fields::get_output_sp_info;
use super::shares::{aggregate_ecdh_shares, compute_sp_shared_secrets};
use psbt::Psbt;

/// Derive a BIP-352 silent-payment output public key:
/// `P_k = B_spend + hash_BIP0352/SharedSecret(serP(shared_secret) || k) * G`.
pub fn derive_silent_payment_output_pubkey(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    ecdh_secret: &[u8; 33],
    k: u32,
) -> Result<PublicKey> {
    let ecdh_secret_pubkey = PublicKey::from_slice(ecdh_secret)?;
    let tweak_bytes = shared_secret_tweak(&ecdh_secret_pubkey, k);
    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| anyhow!("shared secret hash is invalid scalar"))?;
    let tweak_key = SecretKey::from_slice(&tweak.to_be_bytes())?;
    let tweak_point = PublicKey::from_secret_key(secp, &tweak_key);
    spend_key
        .combine(&tweak_point)
        .map_err(|e| anyhow!("failed to derive output pubkey: {e}"))
}

/// Compute silent-payment output scripts from the (partial) ECDH shares present in
/// the PSBT and write them into `output.script_pubkey`. Clears `tx_modifiable_flags`.
pub fn finalize_sp_outputs(secp: &Secp256k1<secp256k1::All>, psbt: &mut Psbt) -> Result<()> {
    let aggregated = aggregate_ecdh_shares(psbt, secp)?;
    let shared_secrets = compute_sp_shared_secrets(secp, psbt, &aggregated)?;

    // Track per-scan-key output index (BIP-352 `k`).
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    for output_idx in 0..psbt.outputs.len() {
        let Some((scan_key, spend_key)) = get_output_sp_info(&psbt.outputs[output_idx]) else {
            continue;
        };

        let shared_secret = shared_secrets
            .get(&scan_key)
            .ok_or_else(|| anyhow!("no shared secret for output {output_idx}"))?;

        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);
        let output_pubkey =
            derive_silent_payment_output_pubkey(secp, &spend_key, &shared_secret.serialize(), k)?;

        psbt.outputs[output_idx].script_pubkey = tweaked_key_to_p2tr_script(&output_pubkey);
        scan_key_output_indices.insert(scan_key, k + 1);
    }

    psbt.global.tx_modifiable_flags = 0x00;
    Ok(())
}
