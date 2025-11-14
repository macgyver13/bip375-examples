//! Charlie Finalizes PSBT - Step 3 of Multi-Signer Silent Payment
//!
//! Charlie acts as:
//! - SIGNER (final): Verifies all previous work, adds final ECDH share, computes output scripts, signs input 2
//! - INPUT FINALIZER: Aggregates ECDH shares and computes output scripts
//! - EXTRACTOR: Extracts the final transaction
//!
//! This script:
//! 1. Loads Bob's PSBT from output/current_psbt.json
//! 2. Verifies Alice's and Bob's DLEQ proofs
//! 3. Adds ECDH share + DLEQ proof for input 2 (Charlie's input)
//! 4. Achieves complete ECDH coverage, triggering output script computation
//! 5. Signs input 2
//! 6. Extracts the final transaction
//! 7. Saves transaction to output/final_transaction.hex
//!
//! Input coverage after Charlie:
//! - Input 0:   Alice (ECDH + signature)
//! - Input 1:   Bob (ECDH + signature)
//! - Input 2:   Charlie (ECDH + signature)
//! - Output scripts:   Computed
//! - Transaction:   Complete

use bip375_core::Result;
use bip375_io::{PsbtMetadata};
use bip375_roles::{
    extractor::extract_transaction,
    input_finalizer::finalize_inputs,
    signer::{add_ecdh_shares_partial, sign_inputs},
    validation::{validate_psbt, ValidationLevel},
};
use crate::shared_utils::*;
use common::{load_psbt,save_psbt,save_txn};
use secp256k1::Secp256k1;

pub fn charlie_finalizes() -> Result<()> {
    print_step_header(3, "Charlie Finalizes PSBT", "Charlie");

    // Load current working PSBT
    let (mut psbt, metadata) = load_psbt()
        .map_err(|e| bip375_core::Error::Other(format!("Failed to load PSBT: {}", e)))?;

    println!("\n Loaded previous work:");
    if let Some(ref meta) = metadata {
        if let Some(desc) = &meta.description {
            println!("   Description: {}", desc);
        }
        if let Some(num_inputs) = meta.num_inputs {
            println!("   Number of inputs: {}", num_inputs);
        }
    }

    // Get transaction inputs and set Charlie's private key
    let mut inputs = get_transaction_inputs();
    let outputs = get_transaction_outputs();
    let charlie_private_key = get_charlie_private_key();
    inputs[2].private_key = Some(charlie_private_key);
    println!("   Set Charlie's private key for input 2");

    // Print current ECDH coverage
    println!("\n  Current ECDH coverage (before Charlie):");
    let num_inputs = psbt.num_inputs();
    let mut inputs_with_ecdh_before = 0;
    for i in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(i);
        if !shares.is_empty() {
            inputs_with_ecdh_before += 1;
        }
    }
    println!("   ECDH Coverage: {}/{} inputs", inputs_with_ecdh_before, num_inputs);

    let secp = Secp256k1::new();

    // Validate previous work (including DLEQ proofs)
    println!("\n  Validating Alice's and Bob's DLEQ proofs...");
    validate_psbt(&secp, &psbt, ValidationLevel::DleqOnly)?;
    println!("     All DLEQ proofs valid");

    // Extract scan keys from outputs
    let scan_keys: Vec<_> = outputs
        .iter()
        .filter_map(|output| match &output.recipient {
            bip375_core::OutputRecipient::SilentPayment(address) => Some(address.scan_key),
            _ => None,
        })
        .collect();

    println!("\n   SIGNER (Charlie): Processing final input 2...");
    println!("   Computing ECDH share and DLEQ proof for input 2");
    println!("   This will complete ECDH coverage!");

    // Charlie only controls input 2
    let charlie_controlled_inputs = [2];

    // Add ECDH shares for Charlie's input
    add_ecdh_shares_partial(&secp, &mut psbt, &inputs, &scan_keys, &charlie_controlled_inputs, true)?;

    // Print final ECDH coverage
    println!("\n  Final ECDH coverage (after Charlie):");
    let mut inputs_with_ecdh_after = 0;
    for i in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(i);
        if !shares.is_empty() {
            inputs_with_ecdh_after += 1;
        }
    }
    println!("   ECDH Coverage: {}/{} inputs", inputs_with_ecdh_after, num_inputs);
    println!("   Covered inputs: [0, 1, 2]");
    let is_complete = inputs_with_ecdh_after == num_inputs;
    println!("   Complete: {}", if is_complete { "  YES" } else { "❌ NO" });

    if is_complete {
        println!("\n  Complete ECDH coverage achieved!");
        println!("   Running INPUT FINALIZER to compute output scripts...");

        // Finalize inputs - this computes the silent payment output scripts
        // No scan private keys provided (None) since we're not computing labels
        finalize_inputs(&secp, &mut psbt, None)?;

        println!("     Silent payment output scripts computed");
    } else {
        return Err(bip375_core::Error::Other("ECDH coverage incomplete".to_string()));
    }

    // Sign Charlie's input
    println!("\n   Signing input 2...");
    sign_inputs(&secp, &mut psbt, &inputs)?;
    println!("     All inputs signed");

    println!("\n📦 EXTRACTOR: Creating final transaction...");

    // Extract final transaction
    let transaction = extract_transaction(&psbt)?;
    let transaction_bytes = bitcoin::consensus::serialize(&transaction);

    println!("   Transaction extracted successfully ({} bytes)", transaction_bytes.len());

    save_txn(&transaction_bytes)
        .map_err(|e| bip375_core::Error::Other(format!("Failed to save transaction: {}", e)))?;

    // Save final PSBT state
    let mut metadata = PsbtMetadata::with_description("Charlie completed the workflow and extracted final transaction");
    metadata.set_counts(num_inputs, psbt.num_outputs());
    metadata.update_timestamps();
    
    save_psbt(&psbt, Some(metadata))
        .map_err(|e| bip375_core::Error::Other(format!("Failed to save PSBT: {}", e)))?;

    println!("\n  Multi-signer silent payment transaction complete!");

    // Display transaction summary
    println!("\n  Transaction Summary:");
    let total_input: u64 = inputs.iter().map(|u| u.amount.to_sat()).sum();
    println!("   Total Input:      {:>10} sats", total_input);
    println!("   Change:           {:>10} sats", 100_000);
    println!("   Silent Payment:   {:>10} sats", 340_000);
    println!("   Fee:              {:>10} sats", 10_000);
    println!("   Transaction:      {:>10} bytes", transaction_bytes.len());
    println!("\n   Hex: {}", hex::encode(&transaction_bytes));

    Ok(())
}
