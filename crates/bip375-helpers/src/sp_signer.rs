//! Silent-payment ECDH share + DLEQ proof generation (UPSTREAM CANDIDATE).
//!
//! This module reimplements the per-input ECDH share and DLEQ proof *generation*
//! that the old `spdk_core::psbt` provided via `add_ecdh_shares_partial` /
//! `compute_ecdh_share` / `dleq_generate_proof`. The new standalone `psbt` crate
//! kept only the *aggregation/verification* side (`SignerPsbtExt::aggregate_ecdh_shares`),
//! so a signer still needs a way to produce the shares/proofs it consumes.
//!
//! It is intentionally isolated here (no dependencies on the rest of bip375-helpers)
//! so it can be lifted into the spdk `psbt` signer role wholesale. The shares/proofs
//! it writes are exactly what `aggregate_ecdh_shares` reads and DLEQ-verifies:
//! `input.sp_ecdh_shares` (scan_key -> share point) and `input.sp_dleq_proofs`.

use bitcoin::CompressedPublicKey;
use psbt::core::utils::to_psbt_dleq;
use psbt::generate_dleq_proof;
use psbt_v2::Input;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Add a per-input ECDH share and DLEQ proof for one recipient scan key.
///
/// Computes the ECDH share `C = input_privkey * scan_key` and a DLEQ proof that
/// `log_G(input_privkey*G) = log_scan_key(C)`, then stores both on the input.
///
/// `input_privkey` must correspond to the public key the aggregator will recover
/// for this input (the BIP32-derivation pubkey for ordinary inputs, or the tweaked
/// taproot key for silent-payment inputs).
pub fn add_input_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    input: &mut Input,
    input_index: usize,
    input_privkey: &SecretKey,
    scan_key: &PublicKey,
) -> Result<(), String> {
    let scalar = (*input_privkey).into();
    let share_point = scan_key
        .mul_tweak(secp, &scalar)
        .map_err(|e| format!("ECDH computation failed: {}", e))?;

    // Deterministic aux randomness, matching the previous spdk behavior.
    let rand_aux = [input_index as u8; 32];
    let proof = generate_dleq_proof(secp, input_privkey, scan_key, &rand_aux, None)
        .map_err(|e| format!("DLEQ generation failed: {:?}", e))?;

    input
        .sp_ecdh_shares
        .insert(CompressedPublicKey(*scan_key), CompressedPublicKey(share_point));
    input
        .sp_dleq_proofs
        .insert(CompressedPublicKey(*scan_key), to_psbt_dleq(proof));

    Ok(())
}
