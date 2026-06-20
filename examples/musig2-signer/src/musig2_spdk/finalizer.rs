//! MuSig2-aware silent-payment output finalization.
//!
//! SPDK already implements ordinary BIP-352 output generation, but its public
//! API cannot construct a `TransactionSharedSecret` from a verified, weighted
//! MuSig2 aggregate share. The small hash/output bridge below is retained until
//! that constructor is available upstream.

use anyhow::{anyhow, Result};
use bip375_helpers::crypto::tweaked_key_to_p2tr_script;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use psbt::Psbt;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::HashMap;

use super::shares::{aggregate_ecdh_shares, compute_sp_shared_secrets};
use crate::musig2_psbt::get_output_sp_info;

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    for part in parts {
        eng.input(part);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// Temporary bridge for `hash_BIP0352/Inputs(smallest_outpoint || A_sum)`.
pub fn input_hash_bytes(smallest_outpoint: &[u8; 36], a_sum: &PublicKey) -> [u8; 32] {
    tagged(b"BIP0352/Inputs", &[smallest_outpoint, &a_sum.serialize()])
}

fn shared_secret_tweak(ecdh_shared_secret: &PublicKey, k: u32) -> [u8; 32] {
    tagged(
        b"BIP0352/SharedSecret",
        &[&ecdh_shared_secret.serialize(), &k.to_be_bytes()],
    )
}

/// Temporary bridge for deriving a BIP-352 output from a weighted MuSig2 share.
pub fn derive_silent_payment_output_pubkey(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    ecdh_secret: &[u8; 33],
    k: u32,
) -> Result<PublicKey> {
    let ecdh_secret_pubkey = PublicKey::from_slice(ecdh_secret)?;
    let tweak = Scalar::from_be_bytes(shared_secret_tweak(&ecdh_secret_pubkey, k))
        .map_err(|_| anyhow!("shared secret hash is invalid scalar"))?;
    let tweak_key = SecretKey::from_slice(&tweak.to_be_bytes())?;
    let tweak_point = PublicKey::from_secret_key(secp, &tweak_key);
    spend_key
        .combine(&tweak_point)
        .map_err(|e| anyhow!("failed to derive output pubkey: {e}"))
}

/// Verify and aggregate MuSig2 ECDH contributions, then set every SP output.
pub fn finalize_sp_outputs(secp: &Secp256k1<secp256k1::All>, psbt: &mut Psbt) -> Result<()> {
    let aggregated = aggregate_ecdh_shares(psbt, secp)?;
    let shared_secrets = compute_sp_shared_secrets(secp, psbt, &aggregated)?;
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    for output_idx in 0..psbt.outputs.len() {
        let Some((scan_key, spend_key)) = get_output_sp_info(&psbt.outputs[output_idx])? else {
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

    psbt.global.tx_modifiable_flags = 0;
    Ok(())
}
