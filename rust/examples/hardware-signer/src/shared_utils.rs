//! Shared utilities for hardware signer silent payment example
//!
//! Contains common transaction inputs, outputs, wallet utilities and display functions
//! shared across the wallet coordinator and hardware device simulator.
//!
//! This implements a realistic air-gapped hardware wallet workflow where:
//! - Wallet coordinator: Online device creating and finalizing PSBTs
//! - Hardware device: Air-gapped device that signs transactions
//! - File-based transfer: Simulates QR codes or USB transfer

use bip375_core::{Output, OutputRecipient, SilentPaymentAddress, Utxo};
use bip375_crypto::pubkey_to_p2wpkh_script;
use bitcoin::{hashes::Hash, Amount, Sequence, Txid};
use common::SimpleWallet;

/// Wallet seeds for deterministic key generation
pub const HW_WALLET_SEED: &str = "hardware_wallet_coldcard_demo";
pub const RECIPIENT_SEED: &str = "recipient_hardware_signer_demo";
pub const ATTACKER_SEED: &str = "attacker_malicious_scan_key";

/// Get the hardware wallet instance
pub fn get_hardware_wallet() -> SimpleWallet {
    SimpleWallet::new(HW_WALLET_SEED)
}

/// Get the recipient address for silent payment
pub fn get_recipient_address() -> SilentPaymentAddress {
    let wallet = SimpleWallet::new(RECIPIENT_SEED);
    let (scan_key, spend_key) = wallet.scan_spend_keys();
    SilentPaymentAddress::new(scan_key, spend_key, None)
}

/// Get the attacker's address (for attack simulation)
pub fn get_attacker_address() -> SilentPaymentAddress {
    let wallet = SimpleWallet::new(ATTACKER_SEED);
    let (scan_key, spend_key) = wallet.scan_spend_keys();
    SilentPaymentAddress::new(scan_key, spend_key, None)
}

/// Create transaction inputs for the hardware signer scenario
///
/// 2 inputs controlled by the hardware wallet:
/// - Input 0: 100,000 sats
/// - Input 1: 200,000 sats
/// - Total: 300,000 sats
pub fn create_transaction_inputs() -> Vec<Utxo> {
    let hw_wallet = get_hardware_wallet();

    let pubkey0 = hw_wallet.input_key_pair(0).1;
    let pubkey1 = hw_wallet.input_key_pair(1).1;

    vec![
        Utxo::new(
            Txid::from_slice(
                &hex::decode("a1b2c3d4e5f6789012345678901234567890123456789012345678901234567a")
                    .unwrap(),
            )
            .expect("valid txid"),
            0,
            Amount::from_sat(100_000),
            pubkey_to_p2wpkh_script(&pubkey0),
            None, // Private key set later by hardware device
            Sequence::from_consensus(0xfffffffe),
        ),
        Utxo::new(
            Txid::from_slice(
                &hex::decode("b1c2d3e4f5f6789012345678901234567890123456789012345678901234567b")
                    .unwrap(),
            )
            .expect("valid txid"),
            1,
            Amount::from_sat(200_000),
            pubkey_to_p2wpkh_script(&pubkey1),
            None, // Private key set later by hardware device
            Sequence::from_consensus(0xfffffffe),
        ),
    ]
}

/// Create transaction outputs for the hardware signer scenario
///
/// 2 outputs:
/// - Output 0: Change to hardware wallet (50,000 sats) with label=0
/// - Output 1: Silent payment to recipient (245,000 sats)
/// - Fee: 5,000 sats (300,000 - 50,000 - 245,000)
///
/// Implementation Notes:
///
/// This demonstrates BIP 375 change detection using silent payment labels.
/// Per BIP 352, label=0 is RESERVED FOR CHANGE, allowing:
///
/// 1. Privacy: Change stays within silent payment protocol (no address reuse)
/// 2. Self-custody: Change returns to hardware wallet's own keys
/// 3. Change detection: Hardware can verify using BIP32 derivation paths
/// 4. Wallet recovery: Scanners know to check label=0 during backup recovery
///
/// See BIP 375 "Change Detection" section and BIP 352 "Labels" section.
pub fn create_transaction_outputs() -> Vec<Output> {
    let hw_wallet = get_hardware_wallet();
    let (scan_key, spend_key) = hw_wallet.scan_spend_keys();

    // Change output: Silent payment back to hardware wallet with label=0 (reserved for change per BIP 352)
    let change_address = SilentPaymentAddress::new(scan_key, spend_key, Some(0));

    vec![
        // Change output
        Output::silent_payment(Amount::from_sat(50_000), change_address),
        // Recipient output
        Output::silent_payment(Amount::from_sat(245_000), get_recipient_address()),
    ]
}

/// Display transaction summary for user review
pub fn display_transaction_summary() {
    let inputs = create_transaction_inputs();
    let outputs = create_transaction_outputs();

    println!("\n{}", "=".repeat(60));
    println!("  Transaction Summary");
    println!("{}\n", "=".repeat(60));

    println!("  Inputs:");
    for (i, utxo) in inputs.iter().enumerate() {
        println!(
            "   Input {}: {} sats",
            i,
            utxo.amount.to_sat()
        );
        println!(
            "      TXID: {}...{}",
            &utxo.txid.to_string()[..16],
            &utxo.txid.to_string()[utxo.txid.to_string().len() - 8..]
        );
        println!("      VOUT: {}", utxo.vout);
    }

    let total_input: u64 = inputs.iter().map(|u| u.amount.to_sat()).sum();
    println!("   Total Input: {} sats\n", total_input);

    println!("  Outputs:");
    for (i, output) in outputs.iter().enumerate() {
        match &output.recipient {
            OutputRecipient::SilentPayment(address) => {
                let label_info = match address.label {
                    Some(0) => " (Change - label 0)",
                    Some(n) => {
                        &format!(" (label {})", n)
                    }
                    None => "",
                };
                println!(
                    "   Output {}{}: {} sats",
                    i,
                    label_info,
                    output.amount.to_sat()
                );
                println!(
                    "      Scan Key:  {}",
                    hex::encode(address.scan_key.serialize())
                );
                println!(
                    "      Spend Key: {}",
                    hex::encode(address.spend_key.serialize())
                );
            }
            OutputRecipient::Address(script_pubkey) => {
                println!("   Output {}: {} sats", i, output.amount.to_sat());
                println!("      Script: {}", hex::encode(script_pubkey.as_bytes()));
            }
        }
    }

    let total_output: u64 = outputs.iter().map(|o| o.amount.to_sat()).sum();
    let fee = total_input - total_output;
    println!("\n   Fee: {} sats", fee);
    println!();
}

/// Print a step header
pub fn print_step_header(step_name: &str, role: &str) {
    println!("\n{}", "=".repeat(60));
    println!("{}", step_name);
    println!("Role: {}", role);
    println!("{}", "=".repeat(60));
    println!();
}

/// Display air-gap transfer instructions
pub fn display_air_gap_instructions(from: &str, to: &str, auto_continue: bool) {
    println!("\n{}", "=".repeat(60));
    println!("    AIR-GAP TRANSFER REQUIRED");
    println!("{}", "=".repeat(60));
    println!();
    println!("From: {}", from);
    println!("To:   {}", to);
    println!();
    println!("In a real scenario, you would:");
    println!("  • Export PSBT as QR code or to SD card");
    println!("  • Transfer via air-gap (QR scan or SD card)");
    println!("  • No network connection to hardware device!");
    println!();

    if !auto_continue {
        println!("Press Enter to continue...");
        println!("{}", "=".repeat(60));
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
    } else {
        println!("{}", "=".repeat(60));
    }
}
