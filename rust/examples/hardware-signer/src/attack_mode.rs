//! Attack Mode — Malicious Firmware Simulation
//!
//! All functions here represent adversarial firmware behavior mirroring their
//! honest counterparts in spdk:
//!
//! | attack_mode fn               | honest counterpart                  |
//! |------------------------------|-------------------------------------|
//! | `prepare_scan_keys`          | `psbt.get_output_scan_keys()` + BIP32 verify |
//! | `finalize_sp_outputs_malicious` | `finalize_sp_outputs`            |
//!
//! This module exists solely for the attack-simulation demo and must NOT be
//! used in any production code path.

use hex;
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::SilentPaymentAddress;
use spdk_core::psbt::core::{
    aggregate_ecdh_shares, get_input_outpoint_bytes, get_input_pubkey, SilentPaymentPsbt,
    Bip375PsbtExt,
};
use spdk_core::psbt::crypto::{
    compute_shared_secrets, derive_silent_payment_output_pubkey, tweaked_key_to_p2tr_script,
};

/// Return the PSBT's scan keys with the recipient key replaced by the attacker's.
///
/// Mirrors `psbt.get_output_scan_keys()` (the honest firmware call), but
/// substitutes scan_keys[1] (recipient) with the attacker's scan key so that
/// subsequent `add_ecdh_shares_partial` computes shares for the wrong key.
pub fn prepare_scan_keys(
    psbt: &SilentPaymentPsbt,
    attacker_address: &SilentPaymentAddress,
) -> Vec<PublicKey> {
    let mut scan_keys = psbt.get_output_scan_keys();

    if scan_keys.len() >= 2 {
        let attacker_scan_key = attacker_address.get_scan_key();
        println!(
            "   🚨 Replacing recipient scan key: {} -> {}",
            hex::encode(scan_keys[1].serialize()),
            hex::encode(attacker_scan_key.serialize()),
        );
        scan_keys[1] = attacker_scan_key;
    }

    scan_keys
}

/// Finalize SP output scripts in attack mode.
///
/// Output 0 (change, hw wallet): derived honestly using the hw wallet's scan key.
/// Output 1 (recipient): derived maliciously using the attacker's scan/spend keys.
///
/// The ECDH shares in the PSBT at this point were computed against the attacker's
/// scan key (see `hw_device::sign_psbt` attack branch), so:
///   - `derive_honest_output` finds shares keyed by `hw_scan_key`
///   - `derive_malicious_output` finds shares keyed by attacker's scan key
pub fn finalize_sp_outputs_malicious(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    hw_scan_key: &PublicKey,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Build shared input data (outpoints + pubkeys) for BIP-352 input_hash
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        outpoints.push(get_input_outpoint_bytes(psbt, input_idx)?);
        if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
            input_pubkeys.push(pubkey);
        }
    }

    // Finalize output 0 (change) honestly using the hw wallet scan key
    let change_script = derive_honest_output(
        secp,
        hw_scan_key,
        &aggregated_shares,
        &outpoints,
        &input_pubkeys,
        psbt,
        0,
    )?;
    psbt.outputs[0].script_pubkey = change_script;

    // Finalize output 1 (recipient) maliciously using the attacker's keys
    let attacker_scan_key = attacker_address.get_scan_key();
    let attacker_spend_key = attacker_address.get_spend_key();
    let malicious_script = derive_malicious_output(
        secp,
        &attacker_scan_key,
        &attacker_spend_key,
        &aggregated_shares,
        &outpoints,
        &input_pubkeys,
    )?;
    psbt.outputs[1].script_pubkey = malicious_script.clone();

    println!(
        "   🚨 Malicious script_pubkey for recipient output: {}",
        hex::encode(malicious_script.as_bytes())
    );

    // Mirror spdk behavior: clear tx_modifiable_flags after finalization
    psbt.global.tx_modifiable_flags = 0x00;

    Ok(())
}

/// Derive the honest P2TR script for the change output.
///
/// Mirrors the per-output logic in `finalize_sp_outputs` for a single scan key.
fn derive_honest_output(
    secp: &Secp256k1<secp256k1::All>,
    scan_key: &PublicKey,
    aggregated_shares: &spdk_core::psbt::core::AggregatedShares,
    outpoints: &[Vec<u8>],
    input_pubkeys: &[PublicKey],
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<bitcoin::ScriptBuf, Box<dyn std::error::Error>> {
    let agg = aggregated_shares
        .get(scan_key)
        .ok_or("No ECDH shares found for hw scan key (change output)")?;

    let shared_secrets = compute_shared_secrets(
        secp,
        &[(*scan_key, agg.aggregated_share)],
        outpoints,
        input_pubkeys,
    )?;
    let shared_secret = shared_secrets
        .get(scan_key)
        .ok_or("Shared secret missing for hw scan key")?;

    let (_, spend_key) = psbt
        .get_output_sp_info(output_idx)
        .ok_or("Output 0 has no SP info")?;

    let output_pubkey = derive_silent_payment_output_pubkey(
        secp,
        &spend_key,
        &shared_secret.serialize(),
        0,
    )?;
    Ok(tweaked_key_to_p2tr_script(&output_pubkey))
}

/// Derive the malicious P2TR script for the redirected recipient output.
///
/// Uses ECDH shares computed against the attacker's scan key — the shares were
/// computed by the compromised firmware in `hw_device::sign_psbt`.
fn derive_malicious_output(
    secp: &Secp256k1<secp256k1::All>,
    attacker_scan_key: &PublicKey,
    attacker_spend_key: &PublicKey,
    aggregated_shares: &spdk_core::psbt::core::AggregatedShares,
    outpoints: &[Vec<u8>],
    input_pubkeys: &[PublicKey],
) -> Result<bitcoin::ScriptBuf, Box<dyn std::error::Error>> {
    let agg = aggregated_shares
        .get(attacker_scan_key)
        .ok_or("No ECDH shares found for attacker scan key")?;

    let shared_secrets = compute_shared_secrets(
        secp,
        &[(*attacker_scan_key, agg.aggregated_share)],
        outpoints,
        input_pubkeys,
    )?;
    let shared_secret = shared_secrets
        .get(attacker_scan_key)
        .ok_or("Shared secret missing for attacker scan key")?;

    let output_pubkey = derive_silent_payment_output_pubkey(
        secp,
        attacker_spend_key,
        &shared_secret.serialize(),
        0,
    )?;
    Ok(tweaked_key_to_p2tr_script(&output_pubkey))
}
