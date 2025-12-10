//! Bob Signs PSBT - Step 2 of Multi-Signer Silent Payment
//!
//! Bob acts as:
//! - SIGNER (partial): Verifies Alice's work and adds ECDH share + signature for input 1
//!
//! This script:
//! 1. Loads Alice's PSBT from output/current_psbt.json
//! 2. Verifies Alice's DLEQ proof for input 0
//! 3. Adds ECDH share + DLEQ proof for input 1 (Bob's input)
//! 4. Signs input 1
//! 5. Saves the PSBT to output/psbt_step2.json for Charlie
//!
//! Input coverage after Bob:
//! - Input 0:   Alice (ECDH + signature)
//! - Input 1:   Bob (ECDH + signature)
//! - Input 2:   Waiting for Charlie

use crate::shared_utils::*;
use bip375_core::{Bip375PsbtExt, Result};
use bip375_io::PsbtMetadata;
use bip375_roles::{
    signer::{add_ecdh_shares_partial, sign_inputs},
    validation::{validate_psbt, ValidationLevel},
};
use common::{load_psbt, save_psbt};
use secp256k1::Secp256k1;

pub fn bob_signs() -> Result<()> {
    print_step_header(2, "Bob Signs PSBT", "Bob");

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

    // Get transaction inputs and set Bob's private key
    let mut inputs = get_transaction_inputs();
    let outputs = get_transaction_outputs();
    let bob_private_key = get_bob_private_key();
    inputs[1].private_key = Some(bob_private_key);
    println!("   Set Bob's private key for input 1");

    // Print current ECDH coverage
    println!("\n  Current ECDH coverage (before Bob):");
    let num_inputs = psbt.num_inputs();
    let mut inputs_with_ecdh_before = 0;
    for i in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(i);
        if !shares.is_empty() {
            inputs_with_ecdh_before += 1;
        }
    }
    println!(
        "   ECDH Coverage: {}/{} inputs",
        inputs_with_ecdh_before, num_inputs
    );

    let secp = Secp256k1::new();

    // Validate Alice's work (including DLEQ proofs)
    println!("\n  Validating Alice's DLEQ proofs...");
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

    println!("\n   SIGNER (Bob): Processing input 1...");
    println!("   Computing ECDH share and DLEQ proof for input 1");

    // Bob only controls input 1
    let bob_controlled_inputs = [1];

    // Add ECDH shares for Bob's input
    add_ecdh_shares_partial(
        &secp,
        &mut psbt,
        &inputs,
        &scan_keys,
        &bob_controlled_inputs,
        true,
    )?;

    // Sign Bob's input
    sign_inputs(&secp, &mut psbt, &inputs)?;

    // Print updated ECDH coverage
    println!("\n  Updated ECDH coverage (after Bob):");
    let mut inputs_with_ecdh_after = 0;
    for i in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(i);
        if !shares.is_empty() {
            inputs_with_ecdh_after += 1;
        }
    }
    println!(
        "   ECDH Coverage: {}/{} inputs",
        inputs_with_ecdh_after, num_inputs
    );
    println!("   Covered inputs: [0, 1]");
    let is_complete = inputs_with_ecdh_after == num_inputs;
    println!(
        "   Complete: {}",
        if is_complete { "  YES" } else { "❌ NO" }
    );

    // Save PSBT to files
    let mut metadata =
        PsbtMetadata::with_description("Bob verified Alice's work and processed input 1");
    metadata.set_counts(num_inputs, psbt.num_outputs());
    metadata.update_timestamps();

    // Update common working file for next party
    save_psbt(&psbt, Some(metadata))
        .map_err(|e| bip375_core::Error::Other(format!("Failed to save PSBT: {}", e)))?;

    println!("\n   Next: Run charlie-finalizes to complete the workflow");

    Ok(())
}
