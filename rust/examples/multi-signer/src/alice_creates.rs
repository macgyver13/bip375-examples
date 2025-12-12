//! Alice Creates PSBT - Step 1 of Multi-Signer Silent Payment
//!
//! Alice acts as:
//! - CREATOR: Creates the PSBT structure
//! - CONSTRUCTOR: Adds transaction inputs and outputs
//! - SIGNER (partial): Adds ECDH share and signature for input 0 only
//!
//! This script:
//! 1. Creates a PSBT with 3 inputs and 2 outputs
//! 2. Adds ECDH share + DLEQ proof for input 0 (Alice's input)
//! 3. Signs input 0
//! 4. Saves the PSBT to output/psbt_step1.json for Bob
//!
//! Input coverage after Alice:
//! - Input 0:   Alice (ECDH + signature)
//! - Input 1:   Waiting for Bob
//! - Input 2:   Waiting for Charlie

use bip375_core::{Bip375PsbtExt, Result};
use bip375_io::PsbtMetadata;
use bip375_roles::{
    constructor::{add_inputs, add_outputs},
    creator::create_psbt,
    signer::{add_ecdh_shares_partial, sign_inputs},
};
use common::save_psbt;
use secp256k1::Secp256k1;

// Import shared_utils from crate root (works when used as library module)
use crate::shared_utils::*;

pub fn alice_creates() -> Result<()> {
    alice_creates_main()
}

fn display_help() {
    println!("\nBIP-375 Multi-Signer Demo - Alice Creates PSBT");
    println!("{}\n", "=".repeat(60));
    println!("Alice acts as CREATOR, CONSTRUCTOR, and initial SIGNER.");
    println!("Creates PSBT with all inputs/outputs and signs her input.\n");
    println!("USAGE:");
    println!("    alice-creates [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    --help, -h              Show this help message");
    println!("    --utxos <ids>           Alice's UTXO IDs (default: 0)");
    println!("    --recipient <sats>      Recipient amount in satoshis");
    println!("    --change <sats>         Change amount in satoshis");
    println!("    --fee <sats>            Fee amount in satoshis\n");
    println!("EXAMPLES:");
    println!("    # Use default configuration");
    println!("    alice-creates\n");
    println!("    # Custom amounts");
    println!("    alice-creates --recipient 180000 --change 100000 --fee 20000\n");
}

fn alice_creates_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        display_help();
        return Ok(());
    }

    print_step_header(1, "Alice Creates PSBT", "Alice");

    // Parse configuration
    let (alice_config, bob_config, charlie_config, combined_config) = if args.len() > 1 {
        let alice_cfg = common::TransactionConfig::from_args(&args, common::TransactionConfig::multi_signer_auto());
        let bob_cfg = common::TransactionConfig::multi_signer_auto();
        let charlie_cfg = common::TransactionConfig::multi_signer_auto();
        
        // For combined config, use the parsed values for outputs
        let combined = common::TransactionConfig::new(
            vec![0, 0, 0],
            alice_cfg.recipient_amount,
            alice_cfg.change_amount,
            alice_cfg.fee,
        );
        (alice_cfg, bob_cfg, charlie_cfg, combined)
    } else {
        get_default_configs()
    };

    // Get transaction data
    let mut inputs = get_transaction_inputs(&alice_config, &bob_config, &charlie_config);
    
    print_scenario_overview(&inputs, &combined_config);
    let outputs = get_transaction_outputs(&combined_config);

    println!("🏗️  CREATOR: Setting up PSBT structure...");
    let mut psbt = create_psbt(inputs.len(), outputs.len())?;

    println!("🔨 CONSTRUCTOR: Adding transaction inputs and outputs...");
    add_inputs(&mut psbt, &inputs)?;
    add_outputs(&mut psbt, &outputs)?;
    println!(
        "   Created PSBT with {} inputs and {} outputs",
        inputs.len(),
        outputs.len()
    );

    // Set Alice's private key for input 0
    let alice_private_key = get_alice_private_key();
    inputs[0].private_key = Some(alice_private_key);
    println!("   Set Alice's private key for input 0");

    let secp = Secp256k1::new();

    // Extract scan keys from outputs
    let scan_keys: Vec<_> = outputs
        .iter()
        .filter_map(|output| match &output.recipient {
            bip375_core::OutputRecipient::SilentPayment(address) => Some(address.scan_key),
            _ => None,
        })
        .collect();

    println!("\n   SIGNER (Alice): Processing input 0...");
    println!("   Computing ECDH share and DLEQ proof for input 0");
    println!("   Verifying DLEQ proofs from other signers (none yet)");
    println!("   Checking ECDH coverage for output script computation");

    // Alice only controls input 0
    let alice_controlled_inputs = [0];

    // Add ECDH shares for Alice's input
    add_ecdh_shares_partial(
        &secp,
        &mut psbt,
        &inputs,
        &scan_keys,
        &alice_controlled_inputs,
        true,
    )?;

    // Sign Alice's input
    sign_inputs(&secp, &mut psbt, &inputs)?;

    // Print ECDH coverage status
    println!("\n  ECDH Coverage Status:");
    let num_inputs = psbt.num_inputs();
    let mut inputs_with_ecdh = 0;
    for i in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(i);
        if !shares.is_empty() {
            inputs_with_ecdh += 1;
        }
    }
    println!(
        "   ECDH Coverage: {}/{} inputs",
        inputs_with_ecdh, num_inputs
    );
    println!("   Covered inputs: {:?}", alice_controlled_inputs);
    let is_complete = inputs_with_ecdh == num_inputs;
    println!(
        "   Complete: {}",
        if is_complete { "  YES" } else { "❌ NO" }
    );

    // Save PSBT (uses memory storage in GUI mode, file storage in CLI mode)
    let mut metadata = PsbtMetadata::with_description("Alice created PSBT and processed input 0");
    metadata.set_counts(num_inputs, psbt.num_outputs());
    metadata.update_timestamps();

    // Save/update common working file for next party
    save_psbt(&psbt, Some(metadata))
        .map_err(|e| bip375_core::Error::Other(format!("Failed to save PSBT: {}", e)))?;

    println!("\n   Next: Run bob-signs to continue the workflow");

    Ok(())
}
