//! Attack Mode — Malicious Firmware Simulation
//!
//! All functions here represent adversarial firmware behavior mirroring their honest
//! counterparts. Each attack mutates the PSBT so the wallet coordinator's verification
//! (SP-field integrity + ECDH-share recomputation in `wallet_coordinator`) rejects it.
//!
//! | attack_mode fn                  | honest counterpart                              |
//! |---------------------------------|-------------------------------------------------|
//! | `prepare_scan_keys`             | `shared_utils::output_scan_keys` (+ BIP32 check)|
//! | `finalize_sp_outputs_malicious` | `finalize_sp_outputs_honest`                    |
//! | `sign_inputs_malicious`         | `sign_controlled_inputs`                        |
//! | `substitute_spend_key`          | `finalize_sp_outputs_honest` (honest)           |
//! | `strip_sp_fields`               | (no honest counterpart — pure omission)         |
//!
//! Outputs are located by scan key (not by index) because BIP-375 shuffles them.
//! This module exists solely for the attack-simulation demo and must NOT be used in
//! any production code path.

use crate::shared_utils::{get_recipient_address, output_scan_keys, output_sp_info};
use bitcoin::{NetworkKind, ScriptBuf};
use psbt::roles::SignerPsbtExt;
use psbt::Psbt;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::SilentPaymentAddress;
use std::collections::BTreeMap;

/// Which attack variant the firmware is simulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVariant {
    /// No attack — honest firmware behavior.
    None,
    /// Attack 1: redirect output AND sign with the attacker's private key.
    /// Detection: output script / scan-key mismatch (and signature verification).
    MitmWrongSignature,
    /// Attack 2: replace the recipient scan key with the attacker's.
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

/// A hardware-controlled input: PSBT index, the private key, and whether it is a
/// silent-payment (tweaked taproot) input. Mirrors `hw_device::ControlledInput`.
type ControlledInput = (usize, SecretKey, bool);

// ---------------------------------------------------------------------------
// Attack 1 & 2 helpers
// ---------------------------------------------------------------------------

/// Return the PSBT's output scan keys with every non-change (recipient) key replaced
/// by the attacker's, so the firmware computes ECDH shares for the wrong scan key.
///
/// Mirrors `shared_utils::output_scan_keys`, identifying the change output by the
/// hardware wallet's own scan key (robust to BIP-375 output shuffling).
pub fn prepare_scan_keys(
    psbt: &Psbt,
    attacker_address: &SilentPaymentAddress,
    hw_scan_key: &PublicKey,
) -> Vec<PublicKey> {
    let attacker_scan_key = attacker_address.get_scan_key();
    output_scan_keys(psbt)
        .into_iter()
        .map(|sk| {
            if sk.serialize() == hw_scan_key.serialize() {
                sk
            } else {
                println!(
                    "   Replacing recipient scan key: {} -> {}",
                    hex::encode(sk.serialize()),
                    hex::encode(attacker_scan_key.serialize()),
                );
                attacker_scan_key
            }
        })
        .collect()
}

/// Finalize SP output scripts in attack mode (Attack 1 & 2).
///
/// Overwrites the recipient output's `sp_v0_info` with the attacker's keys, then runs the
/// honest signer (`compute_sp_outputs` + `set_sp_scriptpubkey`). Because the firmware
/// already produced ECDH shares for the attacker's scan key, the recipient output is
/// derived to pay the attacker; the change output (hardware scan key) stays honest.
pub fn finalize_sp_outputs_malicious(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    hw_scan_key: &PublicKey,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let attacker_scan_key = attacker_address.get_scan_key();
    let attacker_spend_key = attacker_address.get_spend_key();

    // Recipient output = the SP output whose scan key is not the hardware wallet's.
    let recipient_idx = psbt
        .outputs
        .iter()
        .position(|o| {
            output_sp_info(o)
                .map(|(scan, _)| scan.serialize() != hw_scan_key.serialize())
                .unwrap_or(false)
        })
        .ok_or("Recipient SP output not found")?;

    let mut sp_info_bytes = [0u8; 66];
    sp_info_bytes[..33].copy_from_slice(&attacker_scan_key.serialize());
    sp_info_bytes[33..].copy_from_slice(&attacker_spend_key.serialize());
    psbt.outputs[recipient_idx].sp_v0_info = Some(sp_info_bytes);

    let xonly_map = psbt.compute_sp_outputs(secp)?;
    psbt.set_sp_scriptpubkey(xonly_map)?;

    println!(
        "   Malicious script_pubkey for recipient output {}: {}",
        recipient_idx,
        hex::encode(psbt.outputs[recipient_idx].script_pubkey.as_bytes())
    );

    Ok(())
}

/// Sign inputs using the attacker's private key instead of the hardware wallet's
/// (Attack 1: MitmWrongSignature).
///
/// Uses a pubkey→privkey keystore that maps each input's *honest* public key to the
/// attacker's secret key. `GetKey` for the map does not verify the pair, so the signer
/// produces signatures under the attacker's key. The coordinator rejects the transaction
/// because the recipient output was redirected (and the signatures don't match the UTXOs).
pub fn sign_inputs_malicious(
    psbt: &mut Psbt,
    secp: &Secp256k1<secp256k1::All>,
    controlled: &[ControlledInput],
    hw_spend_pubkey: &PublicKey,
    attacker_spend_privkey: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let attacker_priv = bitcoin::PrivateKey::new(*attacker_spend_privkey, NetworkKind::Main);

    // SP inputs: map the honest spend pubkey (in sp_spend_bip32_derivations) -> attacker key.
    if controlled.iter().any(|(_, _, is_sp)| *is_sp) {
        let mut sp_keystore: BTreeMap<bitcoin::PublicKey, bitcoin::PrivateKey> = BTreeMap::new();
        sp_keystore.insert(bitcoin::PublicKey::new(*hw_spend_pubkey), attacker_priv);
        psbt.sign_silent_payment_inputs(&sp_keystore, secp)
            .map_err(|e| format!("malicious SP signing failed: {}", e))?;
    }

    // Non-SP inputs: P2WPKH via ECDSA, non-SP P2TR via taproot key-spend — each mapping the
    // input's honest output pubkey to the attacker's key so the signature is produced under it.
    let mut tr_keystore: BTreeMap<bitcoin::PublicKey, bitcoin::PrivateKey> = BTreeMap::new();
    for (idx, privkey, is_sp) in controlled {
        if *is_sp {
            continue;
        }
        let honest_pk = bitcoin::PublicKey::new(privkey.public_key(secp));
        let is_p2tr = psbt.inputs[*idx]
            .witness_utxo
            .as_ref()
            .map_or(false, |u| u.script_pubkey.is_p2tr());
        if is_p2tr {
            tr_keystore.insert(honest_pk, attacker_priv);
        } else {
            let mut keystore: BTreeMap<bitcoin::PublicKey, bitcoin::PrivateKey> = BTreeMap::new();
            keystore.insert(honest_pk, attacker_priv);
            psbt.sign_input(*idx, &keystore, secp)
                .map_err(|e| format!("malicious ECDSA signing failed for input {}: {}", idx, e))?;
        }
    }
    if !tr_keystore.is_empty() {
        psbt.sign_taproot_key_spend_inputs(&tr_keystore, secp)
            .map_err(|e| format!("malicious taproot signing failed: {}", e))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Attack 3 helper
// ---------------------------------------------------------------------------

/// Substitute the attacker's spend key into the recipient output's `sp_v0_info`
/// (Attack 3: SubstituteSpendKey).
///
/// The honest scan key (and its DLEQ proofs / ECDH shares) are kept intact so the
/// shared-secret derivation is valid, but the spend key is swapped to the attacker's
/// and the output script is recomputed (now spendable by the attacker). The coordinator
/// catches this by comparing the `sp_v0_info` spend key against the expected recipient.
pub fn substitute_spend_key(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let recipient_scan = get_recipient_address().get_scan_key();
    let attacker_spend_key = attacker_address.get_spend_key();

    // Recipient output = the SP output carrying the honest recipient scan key.
    let recipient_idx = psbt
        .outputs
        .iter()
        .position(|o| {
            output_sp_info(o)
                .map(|(scan, _)| scan.serialize() == recipient_scan.serialize())
                .unwrap_or(false)
        })
        .ok_or("Recipient SP output not found")?;

    // Keep the honest scan key, swap the spend key to the attacker's.
    let mut sp_info_bytes = psbt.outputs[recipient_idx]
        .sp_v0_info
        .ok_or("Recipient output missing sp_v0_info")?;
    sp_info_bytes[33..].copy_from_slice(&attacker_spend_key.serialize());
    psbt.outputs[recipient_idx].sp_v0_info = Some(sp_info_bytes);

    // Recompute output scripts: the recipient now uses the honest shared secret with the
    // attacker's spend key, so the script pays a key the attacker controls.
    let xonly_map = psbt.compute_sp_outputs(secp)?;
    psbt.set_sp_scriptpubkey(xonly_map)?;

    println!(
        "   Substituted spend key in sp_v0_info for output {}",
        recipient_idx
    );
    println!(
        "   Malicious script_pubkey: {}",
        hex::encode(psbt.outputs[recipient_idx].script_pubkey.as_bytes())
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Attack 4 helper
// ---------------------------------------------------------------------------

/// Strip all BIP-375 SP fields from the recipient output and replace it with the
/// attacker's plain P2TR address (Attack 4: StripSpFields).
///
/// The coordinator must check that every output originally created as an SP output still
/// carries `sp_v0_info`; the stripped recipient output trips that presence/count check.
pub fn strip_sp_fields(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    attacker_address: &SilentPaymentAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let recipient_scan = get_recipient_address().get_scan_key();

    let recipient_idx = psbt
        .outputs
        .iter()
        .position(|o| {
            output_sp_info(o)
                .map(|(scan, _)| scan.serialize() == recipient_scan.serialize())
                .unwrap_or(false)
        })
        .ok_or("Recipient SP output not found")?;

    // Strip sp_v0_info and sp_v0_label from the recipient output.
    psbt.outputs[recipient_idx].sp_v0_info = None;
    psbt.outputs[recipient_idx].sp_v0_label = None;

    // Strip per-input and global DLEQ proofs and ECDH shares.
    for input in psbt.inputs.iter_mut() {
        input.sp_dleq_proofs.clear();
        input.sp_ecdh_shares.clear();
    }
    psbt.global.sp_dleq_proofs.clear();
    psbt.global.sp_ecdh_shares.clear();

    // Set the recipient script directly to the attacker's plain P2TR address.
    let attacker_spend_key = attacker_address.get_spend_key();
    let (xonly, _) = attacker_spend_key.x_only_public_key();
    let attacker_script = ScriptBuf::new_p2tr(secp, xonly, None);
    psbt.outputs[recipient_idx].script_pubkey = attacker_script.clone();

    // Clear modifiable flags so the PSBT appears finalized.
    psbt.global.tx_modifiable_flags = 0x00;

    println!("   Stripped all BIP-375 SP fields from recipient output");
    println!(
        "   Set output {} script_pubkey to attacker P2TR: {}",
        recipient_idx,
        hex::encode(attacker_script.as_bytes())
    );

    Ok(())
}
