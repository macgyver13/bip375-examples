use bip375_helpers::display::psbt_io::{load_psbt, save_psbt};
use bip375_helpers::transaction::{
    build_inputs_from_multi_party_config, build_outputs, build_psbt, validate_transaction_balance,
};
use bip375_helpers::wallet::{MultiPartyConfig, PartyConfig, SimpleWallet, VirtualWallet};
use bip375_helpers::crypto::{apply_tweak_to_privkey, script_type_string};
use bip375_helpers::io::PsbtMetadata;
use bip375_helpers::sp_signer::add_input_ecdh_share;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{CompressedPublicKey, NetworkKind, Transaction};
use psbt::roles::{Bip375UpdaterExt, ExtractorPsbtExt, SignerPsbtExt};
use psbt::Psbt;
use psbt_v2::v2::Input;
use secp256k1::{Parity, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::collections::BTreeMap;

use crate::shared_utils;

type ControlledInput = (usize, SecretKey, bool);

fn to_derivation_path(raw: Vec<u32>) -> DerivationPath {
    DerivationPath::from(raw.into_iter().map(ChildNumber::from).collect::<Vec<_>>())
}

fn finalize_input_witnesses(psbt: &mut Psbt) -> Result<(), String> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        if let Some(sig) = input.tap_key_sig {
            let mut witness = bitcoin::Witness::new();
            witness.push(sig.to_vec());
            input.final_script_sig = Some(bitcoin::ScriptBuf::new());
            input.final_script_witness = Some(witness);
            input.tap_key_sig = None;
            input.sighash_type = None;
        } else if let Some((pubkey, sig)) = input.partial_sigs.iter().next().map(|(k, v)| (*k, *v))
        {
            let mut witness = bitcoin::Witness::new();
            witness.push(sig.to_vec());
            witness.push(pubkey.to_bytes());
            input.final_script_sig = Some(bitcoin::ScriptBuf::new());
            input.final_script_witness = Some(witness);
            input.partial_sigs.clear();
            input.sighash_type = None;
        } else {
            return Err(format!("Missing signature on input {}", i));
        }
    }
    Ok(())
}

fn build_party_wallet(party_name: &str) -> VirtualWallet {
    VirtualWallet::multi_signer_wallet(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ))
}

fn resolve_regular_p2tr_privkey(
    secp: &Secp256k1<secp256k1::All>,
    candidate_privkey: SecretKey,
    candidate_pubkey: PublicKey,
) -> Result<SecretKey, String> {
    let (xonly, _) = candidate_pubkey.x_only_public_key();
    let tweak = TapTweakHash::from_key_and_tweak(xonly, None)
        .to_scalar()
        .to_be_bytes();
    let tweaked_sk = apply_tweak_to_privkey(&candidate_privkey, &tweak)
        .map_err(|e| format!("BIP-341 tweak failed: {}", e))?;
    let (_, parity) = PublicKey::from_secret_key(secp, &tweaked_sk).x_only_public_key();
    Ok(if parity == Parity::Odd {
        tweaked_sk.negate()
    } else {
        tweaked_sk
    })
}

fn add_input_metadata(
    psbt: &mut Psbt,
    config: &MultiPartyConfig,
) -> Result<(), String> {
    let mut input_idx = 0usize;
    for party in &config.parties {
        let wallet = build_party_wallet(&party.name);
        let simple_wallet = SimpleWallet::new(&wallet.wallet_seed().to_string());
        let fingerprint = Fingerprint::from(simple_wallet.master_fingerprint());

        for &utxo_id in &party.tx_config.selected_utxo_ids {
            let vu = wallet
                .get_utxo(utxo_id)
                .ok_or_else(|| format!("UTXO {} not found for party {}", utxo_id, party.name))?;
            let input = psbt
                .inputs
                .get_mut(input_idx)
                .ok_or_else(|| format!("Missing PSBT input {}", input_idx))?;

            if let Some(tweak) = vu.tweak {
                let (_, spend_pubkey) = simple_wallet.spend_key_pair();
                input.set_sp_tweak(tweak);
                input.set_sp_spend_bip32_derivation(
                    CompressedPublicKey(spend_pubkey),
                    fingerprint,
                    to_derivation_path(simple_wallet.get_sp_spend_derivation_path()),
                );
            } else {
                let (_, pubkey) = simple_wallet.input_key_pair(utxo_id as u32);
                let witness_utxo = input
                    .witness_utxo
                    .as_ref()
                    .ok_or_else(|| format!("Input {} missing witness_utxo", input_idx))?;
                let raw_path = if witness_utxo.script_pubkey.is_p2tr() {
                    simple_wallet.get_p2tr_derivation_path(utxo_id as u32)
                } else if witness_utxo.script_pubkey.is_p2wpkh() {
                    simple_wallet.get_p2wpkh_derivation_path(utxo_id as u32)
                } else {
                    input_idx += 1;
                    continue;
                };
                input.set_bip32_derivation(&pubkey, fingerprint, to_derivation_path(raw_path));
            }

            input_idx += 1;
        }
    }

    Ok(())
}

fn party_controlled_inputs(
    psbt: &Psbt,
    party: &PartyConfig,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Vec<ControlledInput>, String> {
    let wallet = build_party_wallet(&party.name);
    let simple_wallet = SimpleWallet::new(wallet.wallet_seed());
    let spend_privkey = simple_wallet.spend_key_pair().0;
    let mut controlled = Vec::new();

    for (offset, &utxo_id) in party.tx_config.selected_utxo_ids.iter().enumerate() {
        let input_idx = *party
            .controlled_input_indices
            .get(offset)
            .ok_or_else(|| format!("Missing controlled input index for party {}", party.name))?;
        let vu = wallet
            .get_utxo(utxo_id)
            .ok_or_else(|| format!("UTXO {} not found for party {}", utxo_id, party.name))?;
        let input = psbt
            .inputs
            .get(input_idx)
            .ok_or_else(|| format!("Missing PSBT input {}", input_idx))?;
        let witness_utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("Input {} missing witness_utxo", input_idx))?;

        let privkey = if let Some(tweak) = vu.tweak {
            apply_tweak_to_privkey(&spend_privkey, &tweak)?
        } else {
            let (candidate_privkey, candidate_pubkey) = simple_wallet.input_key_pair(utxo_id as u32);
            if witness_utxo.script_pubkey.is_p2tr() {
                //TODO: is this used?
                resolve_regular_p2tr_privkey(secp, candidate_privkey, candidate_pubkey)?
            } else if witness_utxo.script_pubkey.is_p2wpkh() {
                candidate_privkey
            } else {
                return Err(format!("Unsupported script type for input {}", input_idx));
            }
        };

        controlled.push((input_idx, privkey, vu.tweak.is_some()));
    }

    Ok(controlled)
}

fn sign_controlled_inputs(
    mut psbt: Psbt,
    secp: &Secp256k1<secp256k1::All>,
    controlled: &[ControlledInput],
    sp_spend_key: SecretKey,
) -> Result<Psbt, String> {
    if controlled.iter().any(|(_, _, is_sp)| *is_sp) {
        psbt.sign_sp_inputs(secp, sp_spend_key)
            .map_err(|e| format!("SP input signing failed: {}", e))?;
    }

    let mut tr_keystore: BTreeMap<bitcoin::PublicKey, bitcoin::PrivateKey> = BTreeMap::new();
    for (idx, privkey, is_sp) in controlled {
        if *is_sp {
            continue;
        }

        let is_p2tr = psbt.inputs[*idx]
            .witness_utxo
            .as_ref()
            .map_or(false, |u| u.script_pubkey.is_p2tr());
        if is_p2tr {
            tr_keystore.insert(
                bitcoin::PublicKey::new(privkey.public_key(secp)),
                bitcoin::PrivateKey::new(*privkey, NetworkKind::Main),
            );
        } else {
            psbt.sign_input(*idx, privkey, secp)
                .map_err(|e| format!("ECDSA signing failed for input {}: {}", idx, e))?;
        }
    }

    if !tr_keystore.is_empty() {
        psbt.sign_taproot_key_spend_inputs(&tr_keystore, secp)
            .map_err(|e| format!("Taproot key-spend signing failed: {}", e))?;
    }

    Ok(psbt)
}

/// Create a new PSBT with inputs and outputs (no ECDH shares, no signatures)
pub fn create_psbt_only(config: &MultiPartyConfig) -> Result<Psbt, String> {
    let inputs = build_inputs_from_multi_party_config(config)?;
    let recipient_address = shared_utils::get_recipient_address();
    let change_wallet = SimpleWallet::new("change_address_for_multi_signer_test");
    let outputs = build_outputs(
        config.get_recipient_amount(),
        config.get_change_amount(),
        &recipient_address,
        &change_wallet,
    )?;
    let mut psbt = build_psbt(inputs.clone(), outputs.clone())
        .map_err(|e| format!("Failed to build PSBT: {}", e))?;
    add_input_metadata(&mut psbt, config)?;

    validate_transaction_balance(&inputs, &outputs, config.total_fee)?;

    Ok(psbt)
}

/// Add ECDH shares and DLEQ proofs for a party's controlled inputs (no signing).
///
/// Per BIP 375, each Signer adds ECDH shares first. Signatures are only added
/// after all SP output scripts have been computed.
pub fn add_ecdh_shares_for_party(
    psbt: &mut Psbt,
    party: &PartyConfig,
    _config: &MultiPartyConfig,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Vec<usize>, String> {
    let scan_key = shared_utils::get_recipient_address().get_scan_key();
    let controlled = party_controlled_inputs(psbt, party, secp)?;
    for (idx, privkey, _) in &controlled {
        add_input_ecdh_share(secp, &mut psbt.inputs[*idx], *idx, privkey, &scan_key)
            .map_err(|e| format!("Failed to add ECDH share for input {}: {}", idx, e))?;
    }

    Ok(party.controlled_input_indices.clone())
}

/// Compute SP output scripts from aggregated ECDH shares.
///
/// Called automatically when all inputs have ECDH shares. This computes the
/// PSBT_OUT_SCRIPT for each SP output and clears tx_modifiable_flags.
pub fn compute_output_scripts(
    psbt: &mut Psbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<(), String> {
    let map = psbt
        .compute_sp_outputs(secp)
        .map_err(|e| format!("Failed to compute output scripts: {}", e))?;
    psbt.set_sp_scriptpubkey(map)
        .map_err(|e| format!("Failed to set output scripts: {}", e))
}

/// Sign inputs for a party. Must only be called after all SP output scripts are set.
///
/// Per BIP 375: "If any output does not have PSBT_OUT_SCRIPT set, the Signer
/// must not yet add a signature."
pub fn sign_inputs_for_party(
    psbt: &mut Psbt,
    party: &PartyConfig,
    _config: &MultiPartyConfig,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Vec<usize>, String> {
    // Guard: all outputs must have script_pubkey set before signing
    for (idx, output) in psbt.outputs.iter().enumerate() {
        if output.script_pubkey.is_empty() {
            return Err(format!(
                "Output {} has no script_pubkey - cannot sign until all SP output scripts are computed",
                idx
            ));
        }
    }

    let simple_wallet = SimpleWallet::new(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party.name.to_lowercase()
    ));
    let spend_privkey = simple_wallet.spend_key_pair().0;
    let controlled = party_controlled_inputs(psbt, party, secp)?;
    let signed = sign_controlled_inputs(psbt.clone(), secp, &controlled, spend_privkey)?;
    *psbt = signed;

    Ok(party.controlled_input_indices.clone())
}

/// Validate and extract the final transaction.
///
/// Output scripts must already be computed (via compute_output_scripts) and all
/// inputs must be signed before calling this.
pub fn validate_and_extract(
    psbt: &mut Psbt,
    _secp: &Secp256k1<secp256k1::All>,
) -> Result<Transaction, String> {
    finalize_input_witnesses(psbt).map_err(|e| format!("Finalization failed: {}", e))?;
    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|e| format!("Extraction failed: {}", e))?;

    Ok(tx)
}

pub fn get_party_private_key(party_name: &str) -> Result<SecretKey, String> {
    Ok(shared_utils::get_party_private_key(party_name))
}

pub fn create_input_assignments_metadata(config: &MultiPartyConfig) -> HashMap<usize, String> {
    let mut assignments = HashMap::new();
    for party in &config.parties {
        for &input_idx in &party.controlled_input_indices {
            assignments.insert(input_idx, party.name.clone());
        }
    }
    assignments
}

pub fn save_psbt_with_metadata(
    psbt: &Psbt,
    description: impl Into<String>,
) -> Result<(), String> {
    let mut metadata = PsbtMetadata::with_description(description);
    metadata.set_counts(psbt.inputs.len(), psbt.outputs.len());
    metadata.update_timestamps();

    save_psbt(psbt, Some(metadata)).map_err(|e| format!("Failed to save PSBT: {:?}", e))?;
    Ok(())
}

pub fn load_psbt_with_metadata() -> Result<(Psbt, Option<PsbtMetadata>), String> {
    load_psbt().map_err(|e| format!("Failed to load PSBT: {:?}", e))
}

pub fn print_transaction_summary(config: &MultiPartyConfig, inputs: &[Input]) {
    println!("Multi-Signer Silent Payment Transaction");
    println!("{}", "=".repeat(50));
    println!("  Configuration:");
    println!("   • Creator: {}", config.get_creator().name);
    println!("   • Total Inputs: {}", inputs.len());
    println!("   • Total Parties: {}", config.parties.len());
    println!();

    println!("  Input Assignments:");
    for (idx, input) in inputs.iter().enumerate() {
        let party = config
            .parties
            .iter()
            .find(|p| p.controlled_input_indices.contains(&idx))
            .map(|p| p.name.as_str())
            .unwrap_or("Unassigned");

        let utxo = input.witness_utxo.as_ref().expect("witness_utxo required");
        let input_type = script_type_string(&utxo.script_pubkey);
        println!(
            "   Input {} ({}): {} sats [{}]",
            idx,
            party,
            utxo.value.to_sat(),
            input_type
        );
    }

    let total_input: u64 = inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().map_or(0, |u| u.value.to_sat()))
        .sum();
    println!("   Total: {} sats", total_input);
    println!();

    println!("  Outputs:");
    println!(
        "   Recipient: {} sats (Silent Payment)",
        config.get_recipient_amount()
    );
    println!("   Change: {} sats", config.get_change_amount());
    println!("   Fee: {} sats", config.total_fee);
    println!("{}", "=".repeat(50));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip375_helpers::wallet::TransactionConfig;

    #[test]
    fn test_get_party_private_key() {
        let result = get_party_private_key("Alice");
        assert!(result.is_ok());

        let result = get_party_private_key("Bob");
        assert!(result.is_ok());

        let result = get_party_private_key("Charlie");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_input_assignments_metadata() {
        let alice_config = TransactionConfig::multi_signer_auto();
        let alice = PartyConfig::new("Alice", alice_config).with_controlled_inputs(vec![0]);

        let bob_config = TransactionConfig::multi_signer_auto();
        let bob = PartyConfig::new("Bob", bob_config).with_controlled_inputs(vec![1]);

        let config = MultiPartyConfig::new(
            vec![alice, bob],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        let assignments = create_input_assignments_metadata(&config);

        assert_eq!(assignments.get(&0), Some(&"Alice".to_string()));
        assert_eq!(assignments.get(&1), Some(&"Bob".to_string()));
    }
}
