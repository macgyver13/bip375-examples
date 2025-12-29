//! Wallet Coordinator - Online device managing PSBT creation and finalization
//!
//! This module implements the online wallet coordinator which:
//! - Creates PSBTs with transaction inputs/outputs
//! - Adds BIP32 derivation info in privacy mode
//! - Verifies DLEQ proofs from hardware device
//! - Detects attacks (wrong scan keys)
//! - Finalizes and extracts transactions

use crate::shared_utils::TweakDatabase;
use crate::shared_utils::*;
use bip375_core::extensions::HrnPsbtExt;
use bip375_helpers::{display::psbt_io::*, wallet::TransactionConfig};
use secp256k1::Secp256k1;
use spdk_core::psbt::roles::{
    constructor::{add_inputs, add_outputs},
    creator::create_psbt,
    extractor::extract_transaction,
    input_finalizer::finalize_inputs,
    validation::{validate_psbt, ValidationLevel},
};
use spdk_core::psbt::{io::PsbtMetadata, Bip375PsbtExt, PsbtOutput};
use std::collections::HashSet;

pub struct WalletCoordinator;

impl WalletCoordinator {
    /// Create a new PSBT with inputs and outputs
    ///
    /// Roles: CREATOR + CONSTRUCTOR + UPDATER
    pub fn create_psbt(
        config: &TransactionConfig,
        auto_continue: bool,
        mnemonic: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        print_step_header(
            "Step 1: Create PSBT Structure",
            "WALLET COORDINATOR (Online)",
        );

        println!("  CREATOR + CONSTRUCTOR + UPDATER: Setting up transaction...\n");

        let virtual_wallet = get_virtual_wallet(mnemonic)?;
        config.display(&virtual_wallet);

        // Create wallet from mnemonic
        let hw_wallet = get_hardware_wallet(mnemonic)?;

        // Get transaction components
        let inputs = create_transaction_inputs(config, &virtual_wallet);
        let outputs = create_transaction_outputs(config, &hw_wallet);

        // Display transaction for user review
        display_transaction_summary(config, &hw_wallet, mnemonic);

        // Create PSBT
        let mut psbt = create_psbt(inputs.len(), outputs.len());

        // Add inputs and outputs
        add_inputs(&mut psbt, &inputs)?;
        add_outputs(&mut psbt, &outputs)?;

        println!(
            "  CREATOR + CONSTRUCTOR: Created PSBT with {} inputs and {} outputs\n",
            inputs.len(),
            outputs.len()
        );

        // UPDATER ROLE: Add silent payment tweaks for spending (if any)
        //
        // This demonstrates spending silent payment outputs. The wallet coordinator
        // maintains a database of tweaks discovered during blockchain scanning.
        // When spending a silent payment UTXO, the coordinator adds PSBT_IN_SP_TWEAK
        // so the hardware signer can apply the tweak to its spend key.
        //
        // Note: This must be done BEFORE adding BIP32 derivations, so the derivation
        // code can detect SP inputs and use the correct key (spend key vs input key).
        let tweak_db = TweakDatabase::from_virtual_wallet(&virtual_wallet);
        let mut sp_input_count = 0;

        for (input_idx, input) in inputs.iter().enumerate() {
            // Check if this input is a silent payment output we previously received
            if let Some(tweak) = tweak_db.get(&input.outpoint) {
                psbt.set_input_sp_tweak(input_idx, tweak)?;
                sp_input_count += 1;
            }
        }

        if sp_input_count > 0 {
            println!(
                "  UPDATER: Added {} PSBT_IN_SP_TWEAK field(s) for spending",
                sp_input_count
            );
            println!("   Note: Tweaks were stored during wallet scanning\n");
        }

        // UPDATER ROLE: Add BIP32 derivation paths
        // Note: This is done after SP tweaks so we can detect SP inputs
        let input_deriv_count =
            add_input_bip32_derivations(&mut psbt, &hw_wallet, &config.selected_utxo_ids)?;
        let output_deriv_count = add_output_bip32_derivations(&mut psbt, &outputs, &hw_wallet)?;
        let xpub_count = add_global_xpubs(&mut psbt, mnemonic)?;

        // Add BIP-353 DNSSEC proof to recipient output (Output 1)
        //
        // This demonstrates BIP-353 integration: the wallet coordinator resolves
        // a human-readable Bitcoin address (e.g., "donate@example.com") via DNS
        // and generates an RFC 9102 DNSSEC proof that cryptographically proves
        // the authenticity of the Bitcoin payment instruction.
        //
        // The proof is included in the PSBT so hardware wallets can independently
        // validate the DNS name and display it to the user for verification,
        // preventing MITM attacks on DNS resolution.
        let dns_name = "macgyver@spmac.xyz";
        println!("   Generating DNSSEC proof for recipient: {}", dns_name);

        // Note: create_dnssec_proof() attempts real DNS resolution with DNSSEC validation
        // and falls back to mock proof if resolution fails (for demo purposes)
        let dnssec_proof = create_dnssec_proof(dns_name);

        HrnPsbtExt::set_output_dnssec_proof(&mut psbt, outputs.len() - 1, dnssec_proof.clone())?;

        println!("   Added DNSSEC proof for recipient output");
        println!("   Proof Format: <1-byte-length><dns_name><RFC 9102 proof>");
        println!("   Proof Size: {} bytes\n", dnssec_proof.len());

        // Display BIP32 derivation info
        if input_deriv_count > 0 || output_deriv_count > 0 || xpub_count > 0 {
            println!("  UPDATER: Added BIP32 derivation information");
            if input_deriv_count > 0 {
                println!(
                    "   {} PSBT_IN_BIP32_DERIVATION entries across {} inputs",
                    input_deriv_count,
                    inputs.len()
                );
            }
            if output_deriv_count > 0 {
                println!(
                    "   {} PSBT_OUT_BIP32_DERIVATION entries",
                    output_deriv_count
                );
            }
            if xpub_count > 0 {
                println!("   {} PSBT_GLOBAL_XPUB entries", xpub_count);
            }
            println!("   Hardware wallet can match keys using BIP32 paths\n");
        } else {
            // With our change, seed-based wallets now get BIP84 derivations for demo purposes
            println!("  UPDATER: Using BIP84 derivation paths for demo (seed-based wallet)");
            println!("   Note: Seed wallets use default m/84'/0'/0' path for PSBT compatibility\n");
        }

        // Save to transfer file
        let metadata = PsbtMetadata {
            description: Some(format!(
                "Created PSBT with {} inputs and {} outputs. Privacy mode enabled.",
                inputs.len(),
                outputs.len()
            )),
            creator: Some("wallet_coordinator".to_string()),
            created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            ..Default::default()
        };

        save_psbt(&psbt, Some(metadata))?; // Use CLI path (persistent)

        // Display air-gap transfer instructions
        display_air_gap_instructions(
            "Wallet Coordinator (Online)",
            "Hardware Device (Air-gapped)",
            auto_continue,
        );

        println!("\n{}", "=".repeat(60));
        println!("    PSBT CREATED AND READY FOR HARDWARE DEVICE");
        println!("{}\n", "=".repeat(60));

        println!("  NEXT STEP:");
        println!("   Transfer PSBT to hardware device for signing");
        println!("   Select option 2 in the menu to sign on hardware device\n");

        Ok(())
    }

    /// Finalize transaction after hardware device signs
    ///
    /// Roles: SIGNER (verification) + EXTRACTOR
    pub fn finalize_transaction(
        config: &TransactionConfig,
        auto_read: bool,
        mnemonic: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        print_step_header(
            "Step 3: Verify and Finalize Transaction",
            "WALLET COORDINATOR (Online)",
        );

        println!("  Receiving signed PSBT from hardware device...\n");

        // Load signed PSBT
        if !auto_read {
            println!("Press Enter to load from transfer file...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
        }

        let (mut psbt, metadata) =
            load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;

        println!("  Loaded signed PSBT from: {}", TRANSFER_FILE);
        if let Some(meta) = &metadata {
            if let Some(creator) = &meta.creator {
                println!("   Completed by: {}", creator);
            }
            if let Some(desc) = &meta.description {
                println!("   Description: {}\n", desc);
            }
        }

        // Verify PSBT is actually signed
        // Note: P2WPKH uses partial_sigs, P2TR uses tap_key_sig
        let has_signatures = psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty() || input.tap_key_sig.is_some());

        if !has_signatures {
            return Err("PSBT is not signed yet! Hardware device must sign first.".into());
        }

        // COMPREHENSIVE VALIDATION
        println!("{}", "=".repeat(60));
        println!("    VALIDATING SIGNED PSBT");
        println!("{}\n", "=".repeat(60));

        let secp = Secp256k1::new();

        let virtual_wallet = get_virtual_wallet(mnemonic)?;
        let hw_wallet = get_hardware_wallet(mnemonic)?;
        let inputs = create_transaction_inputs(config, &virtual_wallet);
        let outputs = create_transaction_outputs(config, &hw_wallet);

        // Collect expected scan keys
        let hw_scan_key = hw_wallet.scan_key_pair().1;
        let recipient_address = get_recipient_address();
        let recipient_scan_key = recipient_address.get_scan_key();

        let expected_scan_keys: HashSet<Vec<u8>> = [
            hw_scan_key.serialize().to_vec(),
            recipient_scan_key.serialize().to_vec(),
        ]
        .iter()
        .cloned()
        .collect();

        // Collect all scan keys found in DLEQ proofs
        let mut found_scan_keys: HashSet<Vec<u8>> = HashSet::new();

        // Collect scan keys from input DLEQ proofs
        psbt.inputs.iter().for_each(|input| {
            for key in input.sp_dleq_proofs.keys() {
                found_scan_keys.insert(key.to_bytes().to_vec());
            }
        });

        // Collect scan keys from global DLEQ proofs
        for scan_key_compressed in psbt.global.sp_dleq_proofs.keys() {
            found_scan_keys.insert(scan_key_compressed.to_bytes().to_vec());
        }

        // ATTACK DETECTION: Check for unexpected scan keys
        let unexpected_keys: Vec<_> = found_scan_keys.difference(&expected_scan_keys).collect();

        if !unexpected_keys.is_empty() {
            println!("🚨 ATTACK DETECTED: DLEQ proofs for unexpected scan keys!");
            for key in &unexpected_keys {
                println!("   Unexpected key: {}", hex::encode(key));
            }
            println!("\n⚠️  CRITICAL: Hardware device used attacker's scan key!");
            println!("   Hardware computed ECDH shares with incorrect scan key");
            println!("   This indicates firmware corruption or malicious modification\n");
            return Err("Attack detected: unexpected scan keys in DLEQ proofs".into());
        }

        // Run full validation (includes DLEQ proofs, ECDH coverage, signatures, etc.)
        println!("  Running comprehensive validation...");
        match validate_psbt(&secp, &psbt, ValidationLevel::Full) {
            Ok(_) => {
                println!("     PASSED: All validation checks");
                println!("      - ECDH coverage complete ({} inputs)", inputs.len());
                println!("      - All DLEQ proofs verified");
                println!(
                    "      - Change scan key:    {}",
                    hex::encode(hw_scan_key.serialize())
                );
                println!(
                    "      - Recipient scan key: {}",
                    hex::encode(recipient_scan_key.serialize())
                );
                println!("      - All inputs signed");
                println!("      - Output scripts computed");
            }
            Err(e) => {
                println!("   ❌ FAILED: {}", e);
                println!("   ⚠️  CRITICAL: PSBT validation failed!\n");
                return Err(format!("Validation failed: {}", e).into());
            }
        }

        // Amount validation
        println!("\n  Validating transaction amounts...");
        let total_input: u64 = inputs.iter().map(|i| i.witness_utxo.value.to_sat()).sum();
        let total_output: u64 = outputs
            .iter()
            .map(|o| match o {
                PsbtOutput::SilentPayment { amount, .. } => amount.to_sat(),
                PsbtOutput::Regular(txout) => txout.value.to_sat(),
            })
            .sum();
        let fee = total_input - total_output;

        println!("   Total input:  {} sats", total_input);
        println!("   Total output: {} sats", total_output);
        println!("   Fee:          {} sats", fee);

        if fee > 100_000 {
            println!("   ⚠️  WARNING: High fee ({} sats)", fee);
        } else {
            println!("     PASSED: Amounts valid");
        }

        println!("\n{}", "=".repeat(60));
        println!("  ALL VALIDATION CHECKS PASSED");
        println!("{}\n", "=".repeat(60));

        // Finalize inputs to compute output scripts
        println!("\n INPUT FINALIZER: Computing silent payment output scripts...");

        // For change outputs with labels, we need the scan private key to apply label tweaks
        // In this demo, the hardware wallet's scan private key is needed for the change output
        let hw_wallet = get_hardware_wallet(mnemonic)?;
        let (scan_privkey, scan_pubkey) = hw_wallet.scan_key_pair();

        let mut scan_privkeys = std::collections::HashMap::new();
        scan_privkeys.insert(scan_pubkey, scan_privkey);

        finalize_inputs(&secp, &mut psbt, Some(&scan_privkeys))?;
        println!("     Silent payment output scripts computed\n");

        // Save the finalized PSBT (with output scripts computed)
        let finalized_metadata = PsbtMetadata {
            description: Some("Finalized PSBT with computed output scripts".to_string()),
            creator: Some("wallet_coordinator".to_string()),
            modified_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            ..Default::default()
        };
        save_psbt(&psbt, Some(finalized_metadata))?;

        // Extract transaction
        println!("  EXTRACTOR: Extracting final transaction...");

        let final_tx = extract_transaction(&mut psbt)?;
        let tx_bytes = bitcoin::consensus::serialize(&final_tx);

        println!("     Transaction extracted successfully");
        println!("   TxID: {}", final_tx.compute_txid());
        println!("   Size: {} bytes", tx_bytes.len());
        println!("   Weight: {} WU\n", final_tx.weight().to_wu());

        save_txn(&tx_bytes)?;

        println!("{}", "=".repeat(60));
        println!("    TRANSACTION FINALIZED AND READY FOR BROADCAST");
        println!("{}\n", "=".repeat(60));

        println!("  NEXT STEPS:");
        println!("   • Review transaction one final time");
        println!("   • Broadcast transaction to Bitcoin network");
        println!("   • Monitor for confirmations\n");

        Ok(())
    }

    /// Reset the workflow by removing generated files
    pub fn reset() -> std::io::Result<()> {
        reset_workflow()
    }
}
