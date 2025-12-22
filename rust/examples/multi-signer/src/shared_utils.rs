//! Shared utilities and data for multi-signer silent payment example
//!
//! Contains common transaction inputs, outputs, keys and utility functions
//!
//! This implements a realistic 3-of-3 multi-signer workflow where:
//! - Alice controls input 0
//! - Bob controls input 1
//! - Charlie controls input 2

use bip375_core::{PsbtInput, PsbtOutput, SilentPaymentAddress};
use bip375_crypto::script_type_string;
use bip375_helpers::wallet::{MultiPartyConfig, SimpleWallet, TransactionConfig, VirtualWallet};
use secp256k1::SecretKey;

/// Get the silent payment recipient address (same for all signers)
pub fn get_recipient_address() -> SilentPaymentAddress {
    let wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (scan_key, spend_key) = wallet.scan_spend_keys();
    SilentPaymentAddress::new(scan_key, spend_key, None)
}

/// Get a party's virtual wallet by name
pub fn get_party_wallet(party_name: &str) -> VirtualWallet {
    VirtualWallet::multi_signer_wallet(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ))
}

/// Get transaction inputs from MultiPartyConfig
pub fn get_transaction_inputs_from_config(config: &MultiPartyConfig) -> Vec<PsbtInput> {
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
pub fn get_transaction_outputs(config: &TransactionConfig) -> Vec<PsbtOutput> {
    use bip375_crypto::pubkey_to_p2wpkh_script;
    use bitcoin::Amount;
    // Change output to a regular P2WPKH address
    let change_wallet = SimpleWallet::new("change_address_for_multi_signer_test");
    let change_pubkey = change_wallet.input_key_pair(0).1;
    let change_script = pubkey_to_p2wpkh_script(&change_pubkey);

    vec![
        // Regular change output
        PsbtOutput::regular(Amount::from_sat(config.change_amount), change_script),
        // Silent payment output
        PsbtOutput::silent_payment(
            Amount::from_sat(config.recipient_amount),
            get_recipient_address(),
        ),
    ]
}

/// Print a formatted step header for consistency
pub fn print_step_header(step_number: u32, step_name: &str, party_name: &str) {
    println!("\n{}", "=".repeat(60));
    println!("Step {}: {}", step_number, step_name);
    println!("Party: {}", party_name);
    println!("{}", "=".repeat(60));
}

/// Print an overview of the multi-signer scenario
pub fn print_scenario_overview(inputs: &[PsbtInput], config: &TransactionConfig) {
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
        let input_type = script_type_string(&input.witness_utxo.script_pubkey);
        println!(
            "   Input {} ({}) [{}]: {} sats",
            i,
            party,
            input_type,
            input.witness_utxo.value.to_sat()
        );
        let txid_str = input.outpoint.txid.to_string();
        println!(
            "      TXID: {}...{}",
            &txid_str[..16],
            &txid_str[txid_str.len() - 8..]
        );
        println!("      VOUT: {}", input.outpoint.vout);
    }

    let total_input: u64 = inputs.iter().map(|i| i.witness_utxo.value.to_sat()).sum();
    println!("   Total Input: {} sats", total_input);
    println!();

    println!("  Outputs:");
    for (i, output) in outputs.iter().enumerate() {
        match output {
            PsbtOutput::SilentPayment { amount, address } => {
                println!("   Output {} (Silent Payment): {} sats", i, amount.to_sat());
                println!(
                    "      Scan Key:  {}",
                    hex::encode(address.scan_key.serialize())
                );
                println!(
                    "      Spend Key: {}",
                    hex::encode(address.spend_key.serialize())
                );
            }
            PsbtOutput::Regular(txout) => {
                println!("   Output {} (Change): {} sats", i, txout.value.to_sat());
                println!(
                    "      Script: {}",
                    hex::encode(txout.script_pubkey.as_bytes())
                );
            }
        }
    }

    let total_output: u64 = outputs
        .iter()
        .map(|o| match o {
            PsbtOutput::SilentPayment { amount, .. } => amount.to_sat(),
            PsbtOutput::Regular(txout) => txout.value.to_sat(),
        })
        .sum();
    let fee = total_input - total_output;
    println!("   Transaction Fee: {} sats", fee);
    println!();
}

/// Create default MultiPartyConfig for the standard three-party scenario
pub fn create_multi_party_config_default() -> Result<MultiPartyConfig, String> {
    MultiPartyConfig::default_three_party()
}
