//! Shared utilities and data for multi-signer silent payment example
//!
//! Contains common transaction inputs, outputs, keys and utility functions
//!
//! This implements a realistic 3-of-3 multi-signer workflow where:
//! - Alice controls input 0
//! - Bob controls input 1
//! - Charlie controls input 2

use bip375_helpers::crypto::{pubkey_to_p2wpkh_script, script_type_string};
use bip375_helpers::wallet::{MultiPartyConfig, SimpleWallet, TransactionConfig, VirtualWallet};
use bitcoin::Amount;
use bitcoin::{ScriptBuf, TxOut};
use psbt_v2::{Input, Output};
use secp256k1::SecretKey;
use silentpayments::{Network, SilentPaymentAddress, SpVersion};

fn sp_v0_info_bytes(address: &SilentPaymentAddress) -> [u8; 66] {
    let mut bytes = [0u8; 66];
    bytes[..33].copy_from_slice(&address.get_scan_key().serialize());
    bytes[33..].copy_from_slice(&address.get_spend_key().serialize());
    bytes
}

fn output_sp_info(output: &Output) -> Option<(secp256k1::PublicKey, secp256k1::PublicKey)> {
    let bytes = output.sp_v0_info.as_ref()?;
    let scan = secp256k1::PublicKey::from_slice(&bytes[..33]).ok()?;
    let spend = secp256k1::PublicKey::from_slice(&bytes[33..]).ok()?;
    Some((scan, spend))
}

/// Get the silent payment recipient address (same for all signers)
pub fn get_recipient_address() -> SilentPaymentAddress {
    let wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (scan_key, spend_key) = wallet.scan_spend_keys();

    SilentPaymentAddress::new(scan_key, spend_key, Network::Mainnet, SpVersion::ZERO)
}

/// Get a party's virtual wallet by name
pub fn get_party_wallet(party_name: &str) -> VirtualWallet {
    VirtualWallet::multi_signer_wallet(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ))
}

/// Get transaction inputs from MultiPartyConfig
pub fn get_transaction_inputs_from_config(config: &MultiPartyConfig) -> Vec<Input> {
    let mut inputs = Vec::new();

    for party in &config.parties {
        let wallet = get_party_wallet(&party.name);
        inputs.extend(
            wallet
                .select_by_ids(&party.tx_config.selected_utxo_ids)
                .into_iter()
                .map(|u| u.to_psbt_input()),
        );
    }

    inputs
}

/// Get a party's private key by name
pub fn get_party_private_key(party_name: &str) -> SecretKey {
    let wallet = SimpleWallet::new(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ));
    wallet.input_key_pair(0).0
}

/// Get the transaction outputs for the multi-signer scenario
///
/// 2 outputs:
/// - Output 0: Change output (configurable amount to a regular P2WPKH address)
/// - Output 1: Silent payment output (configurable amount)
///
/// The config should be the combined config with total amounts.
pub fn get_transaction_outputs(config: &TransactionConfig) -> Vec<Output> {
    // Change output to a regular P2WPKH address
    let change_wallet = SimpleWallet::new("change_address_for_multi_signer_test");
    let change_pubkey = change_wallet.input_key_pair(0).1;
    let change_script = pubkey_to_p2wpkh_script(&change_pubkey);

    let change_output = Output::new(TxOut {
        value: Amount::from_sat(config.change_amount),
        script_pubkey: change_script,
    });

    let mut sp_output = Output::new(TxOut {
        value: Amount::from_sat(config.recipient_amount),
        script_pubkey: ScriptBuf::new(),
    });
    sp_output.sp_v0_info = Some(sp_v0_info_bytes(&get_recipient_address()));

    vec![change_output, sp_output]
}

/// Format a txid for concise display: first 16 + last 8 hex chars.
fn format_txid_short(txid: &bitcoin::Txid) -> String {
    let s = txid.to_string();
    format!("{}...{}", &s[..16], &s[s.len() - 8..])
}

/// Print a formatted step header for consistency
pub fn print_step_header(step_number: u32, step_name: &str, party_name: &str) {
    println!("\n{}", "=".repeat(60));
    println!("Step {}: {}", step_number, step_name);
    println!("Party: {}", party_name);
    println!("{}", "=".repeat(60));
}

/// Print an overview of the multi-signer scenario
pub fn print_scenario_overview(inputs: &[Input], config: &TransactionConfig) {
    println!("Multi-Signer Silent Payment Scenario");
    println!("{}", "=".repeat(50));
    println!("  Transaction Overview:");
    println!("   • 3 inputs controlled by different parties");
    println!("   • 2 outputs: change + silent payment");
    println!("   • Per-input ECDH approach (not global)");
    println!("   • File-based handoffs between parties");
    println!();

    let outputs = get_transaction_outputs(config);

    println!("  Inputs:");
    let parties = ["Alice", "Bob", "Charlie"];
    for (i, (input, party)) in inputs.iter().zip(parties.iter()).enumerate() {
        let utxo = input.witness_utxo.as_ref().expect("witness_utxo required");
        let input_type = script_type_string(&utxo.script_pubkey);
        println!(
            "   Input {} ({}) [{}]: {} sats",
            i,
            party,
            input_type,
            utxo.value.to_sat()
        );
        println!("      TXID: {}", format_txid_short(&input.previous_txid));
        println!("      VOUT: {}", input.spent_output_index);
    }

    let total_input: u64 = inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().map_or(0, |u| u.value.to_sat()))
        .sum();
    println!("   Total Input: {} sats", total_input);
    println!();

    println!("  Outputs:");
    for (i, output) in outputs.iter().enumerate() {
        if let Some((scan, spend)) = output_sp_info(output) {
            println!("   Output {} (Silent Payment): {} sats", i, output.amount.to_sat());
            println!("      Scan Key:  {}", hex::encode(scan.serialize()));
            println!("      Spend Key: {}", hex::encode(spend.serialize()));
        } else {
            println!("   Output {} (Change): {} sats", i, output.amount.to_sat());
            println!(
                "      Script: {}",
                hex::encode(output.script_pubkey.as_bytes())
            );
        }
    }

    let total_output: u64 = outputs.iter().map(|o| o.amount.to_sat()).sum();
    let fee = total_input - total_output;
    println!("   Transaction Fee: {} sats", fee);
    println!();
}

/// Create default MultiPartyConfig for the standard three-party scenario
pub fn create_multi_party_config_default() -> Result<MultiPartyConfig, String> {
    MultiPartyConfig::default_three_party()
}
