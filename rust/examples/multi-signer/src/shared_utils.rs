//! Shared utilities and data for multi-signer silent payment example
//!
//! Contains common transaction inputs, outputs, keys and utility functions
//! shared across all three multi-signer scripts (alice_creates, bob_signs, charlie_finalizes).
//!
//! This implements a realistic 3-of-3 multi-signer workflow where:
//! - Alice controls input 0
//! - Bob controls input 1
//! - Charlie controls input 2

use bip375_core::{Output, OutputRecipient, SilentPaymentAddress, Utxo};
use bip375_crypto::pubkey_to_p2wpkh_script;
use bitcoin::{hashes::Hash, Amount, Sequence, Txid};
use secp256k1::SecretKey;
use common::SimpleWallet;



/// Get the silent payment recipient address (same for all signers)
pub fn get_recipient_address() -> SilentPaymentAddress {
    let wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (scan_key, spend_key) = wallet.scan_spend_keys();
    SilentPaymentAddress::new(scan_key, spend_key, None)
}

/// Get the transaction inputs for the multi-signer scenario
///
/// 3 inputs controlled by different parties:
/// - Input 0: Alice's UTXO (100,000 sats)
/// - Input 1: Bob's UTXO (150,000 sats)
/// - Input 2: Charlie's UTXO (200,000 sats)
pub fn get_transaction_inputs() -> Vec<Utxo> {
    // Create deterministic wallets for each party
    let alice_wallet = SimpleWallet::new("alice_multi_signer_silent_payment_test_seed");
    let bob_wallet = SimpleWallet::new("bob_multi_signer_silent_payment_test_seed");
    let charlie_wallet = SimpleWallet::new("charlie_multi_signer_silent_payment_test_seed");

    let alice_pubkey = alice_wallet.input_key_pair(0).1;
    let bob_pubkey = bob_wallet.input_key_pair(0).1;
    let charlie_pubkey = charlie_wallet.input_key_pair(0).1;

    vec![
        // Alice's input (index 0)
        Utxo::new(
            Txid::from_slice(&hex::decode("a1b2c3d4e5f6789012345678901234567890123456789012345678901234567a").unwrap())
                .expect("valid txid"),
            0,
            Amount::from_sat(100_000),
            pubkey_to_p2wpkh_script(&alice_pubkey),
            None, // Will be set by Alice
            Sequence::from_consensus(0xfffffffe),
        ),
        // Bob's input (index 1)
        Utxo::new(
            Txid::from_slice(&hex::decode("b1c2d3e4f5f6789012345678901234567890123456789012345678901234567b").unwrap())
                .expect("valid txid"),
            1,
            Amount::from_sat(150_000),
            pubkey_to_p2wpkh_script(&bob_pubkey),
            None, // Will be set by Bob
            Sequence::from_consensus(0xfffffffe),
        ),
        // Charlie's input (index 2)
        Utxo::new(
            Txid::from_slice(&hex::decode("c1d2e3f4f5f6789012345678901234567890123456789012345678901234567c").unwrap())
                .expect("valid txid"),
            2,
            Amount::from_sat(200_000),
            pubkey_to_p2wpkh_script(&charlie_pubkey),
            None, // Will be set by Charlie
            Sequence::from_consensus(0xfffffffe),
        ),
    ]
}

/// Get Alice's private key for her controlled input
pub fn get_alice_private_key() -> SecretKey {
    let alice_wallet = SimpleWallet::new("alice_multi_signer_silent_payment_test_seed");
    alice_wallet.input_key_pair(0).0
}

/// Get Bob's private key for his controlled input
pub fn get_bob_private_key() -> SecretKey {
    let bob_wallet = SimpleWallet::new("bob_multi_signer_silent_payment_test_seed");
    bob_wallet.input_key_pair(0).0
}

/// Get Charlie's private key for his controlled input
pub fn get_charlie_private_key() -> SecretKey {
    let charlie_wallet = SimpleWallet::new("charlie_multi_signer_silent_payment_test_seed");
    charlie_wallet.input_key_pair(0).0
}

/// Get the transaction outputs for the multi-signer scenario
///
/// 2 outputs:
/// - Output 0: Change output (100,000 sats to a regular P2WPKH address)
/// - Output 1: Silent payment output (340,000 sats = 450,000 total input - 100,000 change - 10,000 fee)
pub fn get_transaction_outputs() -> Vec<Output> {
    // Change output to a regular P2WPKH address
    let change_wallet = SimpleWallet::new("change_address_for_multi_signer_test");
    let change_pubkey = change_wallet.input_key_pair(0).1;
    let change_script = pubkey_to_p2wpkh_script(&change_pubkey);

    vec![
        // Regular change output
        Output::regular(Amount::from_sat(100_000), change_script),
        // Silent payment output (340,000 sats)
        Output::silent_payment(Amount::from_sat(340_000), get_recipient_address()),
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
pub fn print_scenario_overview() {
    println!("Multi-Signer Silent Payment Scenario");
    println!("{}", "=".repeat(50));
    println!("  Transaction Overview:");
    println!("   • 3 inputs controlled by different parties");
    println!("   • 2 outputs: change + silent payment");
    println!("   • Per-input ECDH approach (not global)");
    println!("   • File-based handoffs between parties");
    println!();

    let inputs = get_transaction_inputs();
    let outputs = get_transaction_outputs();

    println!("  Inputs:");
    let parties = ["Alice", "Bob", "Charlie"];
    for (i, (utxo, party)) in inputs.iter().zip(parties.iter()).enumerate() {
        println!("   Input {} ({}): {} sats", i, party, utxo.amount.to_sat());
        println!("      TXID: {}...{}",
            &utxo.txid.to_string()[..16],
            &utxo.txid.to_string()[utxo.txid.to_string().len()-8..]);
        println!("      VOUT: {}", utxo.vout);
    }

    let total_input: u64 = inputs.iter().map(|u| u.amount.to_sat()).sum();
    println!("   Total Input: {} sats", total_input);
    println!();

    println!("  Outputs:");
    for (i, output) in outputs.iter().enumerate() {
        match &output.recipient {
            OutputRecipient::SilentPayment(address) => {
                println!("   Output {} (Silent Payment): {} sats", i, output.amount.to_sat());
                println!("      Scan Key:  {}", hex::encode(address.scan_key.serialize()));
                println!("      Spend Key: {}", hex::encode(address.spend_key.serialize()));
            }
            OutputRecipient::Address(script_pubkey) => {
                println!("   Output {} (Change): {} sats", i, output.amount.to_sat());
                println!("      Script: {}", hex::encode(script_pubkey.as_bytes()));
            }
        }
    }

    let total_output: u64 = outputs.iter().map(|o| o.amount.to_sat()).sum();
    let fee = total_input - total_output;
    println!("   Transaction Fee: {} sats", fee);
    println!();
}