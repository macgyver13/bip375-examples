//! Attack Mode — Malicious Firmware Simulation
//!
//! All functions here represent adversarial firmware behavior mirroring their
//! honest counterparts in spdk:
//!
//! | attack_mode fn               | honest counterpart                           |
//! |------------------------------|----------------------------------------------|
//! | `prepare_scan_keys`          | `psbt.get_output_scan_keys()` + BIP32 verify |
//! | `finalize_sp_outputs_malicious` | `finalize_sp_outputs`                     |
//! | `sign_inputs_malicious`      | `sign_inputs`                                |
//! | `substitute_spend_key`       | `finalize_sp_outputs` (honest)               |
//! | `strip_sp_fields`            | (no honest counterpart — pure omission).     |
//!
//! This module exists solely for the attack-simulation demo and must NOT be
//! used in any production code path.

use hex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::SilentPaymentAddress;
use spdk_core::psbt::core::{
    aggregate_ecdh_shares, get_input_outpoint_bytes, get_input_pubkey, Bip375PsbtExt,
    SilentPaymentPsbt,
};
use spdk_core::psbt::crypto::{
    compute_shared_secrets, derive_silent_payment_output_pubkey, tweaked_key_to_p2tr_script,
};
use spdk_core::psbt::PsbtInput;

/// Which attack variant the firmware is simulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVariant {
    /// No attack — honest firmware behavior.
    None,
    /// Attack 1: redirect output AND sign with the attacker's private key.
    /// Detection: output script mismatch (validate_output_scripts) or sig verification.
    MitmWrongSignature,
    /// Attack 2: replace the recipient scan key with the attacker's (current demo).
    /// Detection: scan key mismatch check + output script mismatch.
    WrongScanKey,
    /// Attack 3: use honest scan key + DLEQ proofs, but substitute attacker's spend key
    /// into sp_v0_info and recompute the output script accordingly.
    /// Detection: SP field integrity check (spend key != expected recipient spend key).
    SubstituteSpendKey,
    /// Attack 4: strip all BIP-375 SP fields, set output directly to attacker's P2TR address.
    /// Detection: SP field presence check (sp_v0_info missing on expected SP output).
    StripSpFields,
}

impl AttackVariant {
    /// True when any attack is active.
    pub fn is_active(self) -> bool {
        self != AttackVariant::None
    }

    /// True when the attack replaces the recipient scan key with the attacker's.
    pub fn uses_wrong_scan_key(self) -> bool {
        matches!(
            self,
            AttackVariant::WrongScanKey | AttackVariant::MitmWrongSignature
        )
    }
}

// ---------------------------------------------------------------------------
// Attack 1 & 2 helpers
// ---------------------------------------------------------------------------

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
            "   Replacing recipient scan key: {} -> {}",
            hex::encode(scan_keys[1].serialize()),
            hex::encode(attacker_scan_key.serialize()),
        );
        scan_keys[1] = attacker_scan_key;
    }

    scan_keys
}

/// Finalize SP output scripts in attack mode (Attack 1 & 2).
///
/// Output 0 (change, hw wallet): derived honestly using the hw wallet's scan key.
/// Output 1 (recipient): derived maliciously using the attacker's keys.
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
        "   Malicious script_pubkey for recipient output: {}",
        hex::encode(malicious_script.as_bytes())
    );

    // Mirror spdk behavior: clear tx_modifiable_flags after finalization
    psbt.global.tx_modifiable_flags = 0x00;

    Ok(())
}

/// Sign inputs using the attacker's private key instead of the hardware wallet's
/// (Attack 1: MitmWrongSignature).
///
/// Mirrors `sign_inputs` from spdk, but replaces each input's `private_key` with
/// the attacker's spend private key.  The sighash still commits to the (now
/// malicious) output scripts, making the signature valid for the attacker's key.
/// The coordinator rejects this because the signed pubkey doesn't match the UTXO's
/// `script_pubkey`.
pub fn sign_inputs_malicious(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[PsbtInput],
    attacker_spend_privkey: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    use spdk_core::psbt::roles::signer::sign_inputs;

    // Clone the input list and replace every private_key with the attacker's.
    let poisoned: Vec<PsbtInput> = inputs
        .iter()
        .map(|i| {
            let mut poisoned_input = i.clone();
            if i.private_key.is_some() {
                poisoned_input.private_key = Some(*attacker_spend_privkey);
            }
            poisoned_input
        })
        .collect();

    sign_inputs(secp, psbt, &poisoned)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attack 3 helper
// ---------------------------------------------------------------------------

/// Substitute the attacker's spend key into the recipient output's `sp_v0_info`
/// (Attack 3: SubstituteSpendKey).
///
/// The honest scan key (and its DLEQ proofs) are kept intact so cryptographic
/// proof verification passes.  But the spend key stored in the PSBT field is
/// swapped to the attacker's, and the output script is recomputed accordingly.
/// The coordinator catches this by comparing `sp_v0_info` spend key against the
/// expected recipient spend key.
pub fn substitute_spend_key(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Build input data for BIP-352 shared-secret derivation
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        outpoints.push(get_input_outpoint_bytes(psbt, input_idx)?);
        if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
            input_pubkeys.push(pubkey);
        }
    }

    // Read the HONEST scan key for output 1 from the PSBT (unchanged by this attack)
    let (recipient_scan_key, _old_spend_key) = psbt
        .get_output_sp_info(1)
        .ok_or("Output 1 has no SP info")?;

    // Derive shared secret using the HONEST scan key's ECDH share
    let agg = aggregated_shares
        .get(&recipient_scan_key)
        .ok_or("No ECDH shares found for recipient scan key")?;

    let shared_secrets = compute_shared_secrets(
        secp,
        &[(recipient_scan_key, agg.aggregated_share)],
        &outpoints,
        &input_pubkeys,
    )?;
    let shared_secret = shared_secrets
        .get(&recipient_scan_key)
        .ok_or("Shared secret missing for recipient scan key")?;

    // Derive output pubkey using honest ECDH result but ATTACKER's spend key
    let attacker_spend_key = attacker_address.get_spend_key();
    let output_pubkey = derive_silent_payment_output_pubkey(
        secp,
        &attacker_spend_key,
        &shared_secret.serialize(),
        0,
    )?;
    let malicious_script = tweaked_key_to_p2tr_script(&output_pubkey);

    // Overwrite sp_v0_info bytes: keep honest scan key, swap spend key
    let mut sp_info_bytes = Vec::with_capacity(66);
    sp_info_bytes.extend_from_slice(&recipient_scan_key.serialize());
    sp_info_bytes.extend_from_slice(&attacker_spend_key.serialize());
    psbt.outputs[1].sp_v0_info = Some(sp_info_bytes);

    // Set the malicious output script
    psbt.outputs[1].script_pubkey = malicious_script.clone();

    println!("   Substituted spend key in sp_v0_info for output 1");
    println!(
        "   Malicious script_pubkey: {}",
        hex::encode(malicious_script.as_bytes())
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Attack 4 helper
// ---------------------------------------------------------------------------

/// Strip all BIP-375 SP fields from the recipient output and replace with the
/// attacker's plain P2TR address (Attack 4: StripSpFields).
///
/// After stripping, `validate_psbt(Full)` would skip the now-plain output.
/// The coordinator must check that sp_v0_info is still present on every output
/// that was originally created as an SP output.
pub fn strip_sp_fields(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    // Strip sp_v0_info and sp_v0_label from the recipient output (index 1)
    psbt.outputs[1].sp_v0_info = None;
    psbt.outputs[1].sp_v0_label = None;

    // Strip per-input DLEQ proofs and ECDH shares
    for input in psbt.inputs.iter_mut() {
        input.sp_dleq_proofs.clear();
        input.sp_ecdh_shares.clear();
    }

    // Strip global DLEQ proofs and ECDH shares
    psbt.global.sp_dleq_proofs.clear();
    psbt.global.sp_ecdh_shares.clear();

    // Set output 1 script_pubkey directly to attacker's P2TR address
    let attacker_spend_key = attacker_address.get_spend_key();
    let (xonly, _) = attacker_spend_key.x_only_public_key();
    let attacker_script = bitcoin::ScriptBuf::new_p2tr(secp, xonly, None);
    psbt.outputs[1].script_pubkey = attacker_script.clone();

    // Clear modifiable flags so the PSBT appears finalized
    psbt.global.tx_modifiable_flags = 0x00;

    println!("   Stripped all BIP-375 SP fields from recipient output");
    println!(
        "   Set output 1 script_pubkey to attacker P2TR: {}",
        hex::encode(attacker_script.as_bytes())
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers (mirrors of finalize_sp_outputs per-output logic)
// ---------------------------------------------------------------------------

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

    let output_pubkey =
        derive_silent_payment_output_pubkey(secp, &spend_key, &shared_secret.serialize(), 0)?;
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
