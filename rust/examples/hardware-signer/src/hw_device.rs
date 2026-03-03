//! Hardware Device Simulator - Air-gapped device for signing transactions
//!
//! This module simulates an air-gapped hardware wallet that:
//! - Receives PSBTs from coordinator (via file/QR)
//! - Displays transaction details for user approval
//! - Computes ECDH shares and generates DLEQ proofs
//! - Signs transaction inputs
//! - Supports attack mode to demonstrate security model

use crate::attack_mode;
use crate::shared_utils::*;
use bip375_helpers::PSBT_OUT_DNSSEC_PROOF;
use bip375_helpers::{display::psbt_io::*, wallet::TransactionConfig};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{OutPoint, Sequence};
use secp256k1::{Parity, PublicKey, Secp256k1};
use spdk_core::psbt::crypto::{
    apply_tweak_to_privkey, internal_key_to_p2tr_script, pubkey_to_p2wpkh_script,
};
use spdk_core::psbt::io::PsbtMetadata;
use spdk_core::psbt::roles::input_finalizer::finalize_sp_outputs;
use spdk_core::psbt::roles::signer::{add_ecdh_shares_partial, sign_inputs};
use spdk_core::psbt::{Bip375PsbtExt, PsbtInput, SilentPaymentPsbt};
use std::io::{self, Write};

pub struct HardwareDevice;

impl HardwareDevice {
    /// Receive PSBT from wallet coordinator
    pub fn receive_psbt(
        auto_read: bool,
        auto_continue: bool,
    ) -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>), Box<dyn std::error::Error>> {
        print_step_header("Step 2a: Receive PSBT", "HARDWARE DEVICE (Air-gapped)");

        println!("  Receiving PSBT from wallet coordinator...\n");

        if !auto_read {
            println!("Press Enter to load from transfer file...");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
        }

        let (psbt, metadata) = load_psbt() // Use CLI path (persistent)
            .map_err(|e| format!("Error loading PSBT: {}", e))?;

        if let Some(meta) = &metadata {
            if let Some(creator) = &meta.creator {
                println!("   Created by: {}", creator);
            }
            if let Some(desc) = &meta.description {
                println!("   Description: {}\n", desc);
            }
        }

        // Verify PSBT is unsigned
        let has_signatures = psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty());

        if has_signatures {
            return Err("PSBT is already signed!".into());
        }

        println!("  PSBT validated: Unsigned and ready for signing\n");

        display_air_gap_instructions(
            "Wallet Coordinator (Online)",
            "Hardware Device (Air-gapped)",
            auto_continue,
        );

        Ok((psbt, metadata))
    }

    /// Display transaction details and get user approval
    pub fn verify_and_approve(
        config: &TransactionConfig,
        auto_approve: bool,
        attack_mode: bool,
        mnemonic: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        print_step_header(
            "Step 2b: Verify Transaction",
            "HARDWARE DEVICE (Air-gapped)",
        );

        println!(" HARDWARE DEVICE SCREEN:");
        println!("{}\n", "=".repeat(60));

        // Create wallet from mnemonic or seed
        let hw_wallet = get_hardware_wallet(mnemonic)?;

        // Extract and validate DNSSEC proofs from PSBT
        let (psbt, _) = load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;

        let mut dnssec_proofs = std::collections::HashMap::new();
        let mut validation_failures = Vec::new();

        for (output_idx, output) in psbt.outputs.iter().enumerate() {
            for (key, value) in &output.unknowns {
                if key.type_value == PSBT_OUT_DNSSEC_PROOF {
                    // Try to validate the DNSSEC proof
                    match validate_dnssec_proof(value) {
                        Ok((dns_name, txt_records)) => {
                            println!(
                                "   ✓ DNSSEC proof validated for output {}: {}",
                                output_idx, dns_name
                            );
                            println!("     TXT records: {:?}", txt_records);
                            let proof_hex = hex::encode(value);
                            dnssec_proofs
                                .insert(output_idx, (format!("{} ✓", dns_name), proof_hex));
                        }
                        Err(e) => {
                            // Validation failed - try to decode at least the DNS name
                            match decode_dnssec_proof(value) {
                                Ok((dns_name, _)) => {
                                    eprintln!(
                                        "   ⚠ DNSSEC validation FAILED for output {}: {}",
                                        output_idx, dns_name
                                    );
                                    eprintln!("     Error: {}", e);
                                    validation_failures.push((
                                        output_idx,
                                        dns_name.clone(),
                                        e.clone(),
                                    ));
                                    let proof_hex = hex::encode(value);
                                    dnssec_proofs.insert(
                                        output_idx,
                                        (format!("{} ⚠ UNVERIFIED", dns_name), proof_hex),
                                    );
                                }
                                Err(decode_err) => {
                                    eprintln!(
                                        "   ✗ Failed to decode DNSSEC proof for output {}: {}",
                                        output_idx, decode_err
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Display transaction summary with DNSSEC proofs inline
        let has_dnssec = !dnssec_proofs.is_empty();
        display_transaction_summary_with_dnssec(
            config,
            if has_dnssec {
                Some(dnssec_proofs)
            } else {
                None
            },
            &hw_wallet,
            mnemonic,
        );

        println!("  Review transaction carefully!");
        println!("   • Check recipient addresses");
        if has_dnssec {
            println!("   • Verify DNS contact names");
            if !validation_failures.is_empty() {
                println!("\n   🚨 WARNING: DNSSEC VALIDATION FAILURES DETECTED!");
                for (idx, dns_name, err) in &validation_failures {
                    println!("     Output {}: {} - {}", idx, dns_name, err);
                }
                println!("   ⚠️  DO NOT sign this transaction unless you trust the DNS names!");
            }
        }
        println!("   • Verify amounts");
        println!("   • Confirm fee is reasonable\n");

        if attack_mode {
            println!("🚨 ATTACK MODE ENABLED");
            println!("   Hardware will use MALICIOUS scan key");
            println!("   This simulates compromised firmware\n");
            return Ok(true); // Auto-approve in attack mode
        }

        if auto_approve {
            println!("  Auto-approved (--auto-approve flag)\n");
            return Ok(true);
        }

        print!("Approve transaction? (yes/no): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "yes" | "y" => {
                println!("\n  Transaction approved\n");
                Ok(true)
            }
            _ => {
                println!("\n❌ Transaction rejected\n");
                Ok(false)
            }
        }
    }

    /// Sign PSBT with hardware wallet keys
    ///
    /// Roles: SIGNER
    pub fn sign_psbt(
        mut psbt: SilentPaymentPsbt,
        attack_mode: bool,
        mnemonic: Option<&str>,
    ) -> Result<SilentPaymentPsbt, Box<dyn std::error::Error>> {
        print_step_header("Step 2c: Sign Transaction", "HARDWARE DEVICE (Air-gapped)");

        println!("   SIGNER: Processing transaction with hardware keys...\n");

        // Create wallet from mnemonic or seed
        let hw_wallet = get_hardware_wallet(mnemonic)?;

        // Get hardware wallet's private keys from "secure storage"
        // Create PsbtInput vector from PSBT (PSBT is source of truth)
        let mut inputs: Vec<PsbtInput> = psbt
            .inputs
            .iter()
            .map(|psbt_input| {
                PsbtInput::new(
                    OutPoint {
                        txid: psbt_input.previous_txid,
                        vout: psbt_input.spent_output_index,
                    },
                    psbt_input
                        .witness_utxo
                        .clone()
                        .expect("witness_utxo required"),
                    psbt_input
                        .sequence
                        .unwrap_or(Sequence::from_consensus(0xfffffffe)),
                    None, // private_key set later for controlled inputs
                )
            })
            .collect();

        let secp = Secp256k1::new();

        // Resolve attacker address once so it's available for both scan key substitution
        // and output finalization in attack mode.
        let attacker_address_opt = if attack_mode {
            let attacker = get_attacker_address();
            let recipient = get_recipient_address();
            println!("🚨 ATTACK MODE: Using malicious scan key!");
            println!("   Real recipient scan key would be used in honest mode\n");
            println!(
                "   Legitimate recipient: {}",
                hex::encode(recipient.get_scan_key().serialize())
            );
            println!(
                "   Malicious attacker:   {}",
                hex::encode(attacker.get_scan_key().serialize())
            );
            println!("   ⚠️  Funds would go to attacker if this succeeds!\n");
            Some(attacker)
        } else {
            None
        };

        // Extract scan keys: attack mode substitutes the recipient's key with the attacker's;
        // honest mode reads the PSBT directly and verifies ownership via BIP32 derivations.
        let scan_keys: Vec<PublicKey> = if attack_mode {
            attack_mode::prepare_scan_keys(&psbt, attacker_address_opt.as_ref().unwrap())
        } else {
            let honest_scan_keys = psbt.get_output_scan_keys();
            println!(
                "   Extracted {} scan key(s) from PSBT outputs:",
                honest_scan_keys.len()
            );
            for (i, sk) in honest_scan_keys.iter().enumerate() {
                println!("     Scan key {}: {}", i, hex::encode(sk.serialize()));
            }

            // CHANGE VERIFICATION: Use BIP32 derivations to verify
            // which outputs are change (returning to our wallet) vs recipient outputs.
            println!("\n   Verifying output ownership via BIP32 derivations...");

            let hw_master_fingerprint = hw_wallet.master_fingerprint();
            let (hw_scan_key, hw_spend_key) = hw_wallet.scan_spend_keys();

            let mut change_output_count = 0;
            let mut recipient_output_count = 0;

            for (output_idx, output) in psbt.outputs.iter().enumerate() {
                // Check if output has BIP32 derivations
                let has_derivations = !output.bip32_derivations.is_empty();

                if !has_derivations {
                    // No derivations = recipient output (not owned by wallet)
                    recipient_output_count += 1;
                    println!(
                        "     Output {}: No BIP32 derivations (recipient output)",
                        output_idx
                    );
                    continue;
                }

                // Output has derivations - verify they match wallet
                let mut scan_deriv_valid = false;
                let mut spend_deriv_valid = false;

                for (pubkey, (fingerprint, path)) in &output.bip32_derivations {
                    // SECURITY CHECK 1: Verify fingerprint matches wallet
                    if fingerprint.to_bytes() != hw_master_fingerprint {
                        println!(
                            "     ⚠️  Output {}: BIP32 fingerprint mismatch!",
                            output_idx
                        );
                        println!("         Expected: {}", hex::encode(hw_master_fingerprint));
                        println!("         Found:    {}", hex::encode(fingerprint.to_bytes()));
                        return Err("BIP32 fingerprint mismatch - possible attack!".into());
                    }

                    // SECURITY CHECK 2: Verify path follows BIP352 pattern
                    let path_vec: Vec<u32> = path
                        .into_iter()
                        .map(|cn| {
                            let child_num: u32 = (*cn).into();
                            child_num
                        })
                        .collect();

                    // Expected patterns:
                    // Scan:  m/352'/0'/0'/0/{index}
                    // Spend: m/352'/0'/0'/1/{index}

                    if path_vec.len() == 5
                        && path_vec[0] == 0x80000160  // 352'
                        && path_vec[1] == 0x80000000  // 0'
                        && path_vec[2] == 0x80000000
                    // 0'
                    {
                        if path_vec[3] == 0x00000000 {
                            // scan branch (0)
                            // SECURITY CHECK 3: Verify pubkey matches wallet's scan key
                            if pubkey.serialize() == hw_scan_key.serialize() {
                                scan_deriv_valid = true;
                                println!("     ✓ Output {}: Scan key derivation verified (path index {})",
                                         output_idx, path_vec[4]);
                            } else {
                                println!("     ⚠️  Output {}: Scan key mismatch!", output_idx);
                                return Err(
                                    "Scan key mismatch in BIP32 derivation - possible attack!"
                                        .into(),
                                );
                            }
                        } else if path_vec[3] == 0x00000001 {
                            // spend branch (1)
                            // SECURITY CHECK 4: Verify pubkey matches wallet's spend key
                            if pubkey.serialize() == hw_spend_key.serialize() {
                                spend_deriv_valid = true;
                                println!("     ✓ Output {}: Spend key derivation verified (path index {})",
                                         output_idx, path_vec[4]);
                            } else {
                                println!("     ⚠️  Output {}: Spend key mismatch!", output_idx);
                                return Err(
                                    "Spend key mismatch in BIP32 derivation - possible attack!"
                                        .into(),
                                );
                            }
                        } else {
                            println!("     ⚠️  Output {}: Invalid BIP352 branch (expected 0 or 1, got {})",
                                     output_idx, path_vec[3]);
                            return Err("Invalid BIP352 derivation path - wrong branch".into());
                        }
                    } else {
                        println!(
                            "     ⚠️  Output {}: Invalid BIP352 derivation path structure",
                            output_idx
                        );
                        println!("         Expected: m/352'/0'/0'/[0|1]/{{index}}");
                        println!("         Got path length: {}", path_vec.len());
                        if path_vec.len() >= 3 {
                            println!(
                                "         Got: m/{}'/{}'/{}'...",
                                path_vec[0] & 0x7FFFFFFF,
                                path_vec[1] & 0x7FFFFFFF,
                                path_vec[2] & 0x7FFFFFFF
                            );
                        }
                        return Err("Invalid BIP352 derivation path structure".into());
                    }
                }

                // SECURITY CHECK 5: BOTH scan and spend derivations must be present and valid
                if scan_deriv_valid && spend_deriv_valid {
                    change_output_count += 1;
                    println!(
                        "     ✓ Output {} verified as CHANGE to hardware wallet",
                        output_idx
                    );
                } else if scan_deriv_valid || spend_deriv_valid {
                    // Partial match - suspicious! Possible attack
                    println!(
                        "     ⚠️  Output {}: Incomplete BIP32 derivations!",
                        output_idx
                    );
                    println!("         Scan derivation valid: {}", scan_deriv_valid);
                    println!("         Spend derivation valid: {}", spend_deriv_valid);
                    return Err("Incomplete BIP32 derivations - possible attack! Both scan and spend required.".into());
                } else {
                    // Has derivations but they don't match - definite attack
                    println!(
                        "     ⚠️  Output {}: BIP32 derivations present but validation failed!",
                        output_idx
                    );
                    return Err("BIP32 derivations validation failed - possible attack!".into());
                }
            }

            // Summary
            println!("\n   Change Verification Summary:");
            println!("     Method: BIP32 derivation validation");
            println!("     Change outputs identified: {}", change_output_count);
            println!("     Recipient outputs: {}", recipient_output_count);
            if change_output_count > 0 {
                println!("     Security: Cryptographic proof of ownership ✓");
            }

            println!();
            honest_scan_keys
        };

        // Determine which inputs are controlled by hardware wallet via BIP32 derivations
        // Priority order:
        // 1. PSBT_IN_SP_SPEND_BIP32_DERIVATION (0x1f) - BIP-376 for Silent Payment inputs
        // 2. PSBT_IN_TAP_BIP32_DERIVATION (0x16) - Standard P2TR inputs
        // 3. PSBT_IN_BIP32_DERIVATION (0x06) - Legacy/SegWit inputs
        println!("   Verifying input control via BIP32 derivations...");

        let hw_master_fingerprint = hw_wallet.master_fingerprint();
        let mut hw_controlled_inputs = Vec::new();

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            // Check for Silent Payment spend derivation FIRST (BIP-376)
            let sp_derivation = psbt.get_input_sp_spend_bip32_derivation(input_idx);
            let has_sp_derivation = sp_derivation
                .as_ref()
                .map(|(_, fp, _)| *fp == hw_master_fingerprint)
                .unwrap_or(false);

            // Check standard BIP32 derivations
            let has_tap_derivation = !input.tap_key_origins.is_empty()
                && input
                    .tap_key_origins
                    .values()
                    .any(|(_, (fp, _))| fp.to_bytes() == hw_master_fingerprint);

            let has_legacy_derivation = !input.bip32_derivations.is_empty()
                && input
                    .bip32_derivations
                    .values()
                    .any(|(fp, _)| fp.to_bytes() == hw_master_fingerprint);

            let has_our_derivation =
                has_sp_derivation || has_tap_derivation || has_legacy_derivation;

            if has_our_derivation {
                hw_controlled_inputs.push(input_idx);
                let derivation_type = if has_sp_derivation {
                    "SP_SPEND_BIP32_DERIVATION"
                } else if has_tap_derivation {
                    "TAP_BIP32_DERIVATION"
                } else {
                    "BIP32_DERIVATION"
                };
                println!(
                    "     ✓ Input {}: Controlled by hardware wallet ({} verified)",
                    input_idx, derivation_type
                );
            } else {
                println!(
                    "     Input {}: Not controlled by hardware wallet (no matching derivation)",
                    input_idx
                );
            }
        }

        println!(
            "   Hardware wallet controls {} input(s): {:?}\n",
            hw_controlled_inputs.len(),
            hw_controlled_inputs
        );

        if hw_controlled_inputs.is_empty() {
            return Err("No inputs controlled by hardware wallet! Cannot sign transaction.".into());
        }

        // Set private keys for hardware-controlled inputs
        for &input_idx in &hw_controlled_inputs {
            // Check if this is a Silent Payment input (has tweak)
            // If so, we must use the spend private key
            if psbt.get_input_sp_tweak(input_idx).is_some() {
                let (spend_privkey, _) = hw_wallet.spend_key_pair();
                inputs[input_idx].private_key = Some(spend_privkey);
            } else {
                // Otherwise use standard derived key
                let witness_utxo = &inputs[input_idx].witness_utxo;

                // Try all possible key derivation indices until we find a match
                let mut found_key = false;
                for try_idx in 0..10 {
                    // Reasonable gap limit for demo wallet
                    let (candidate_privkey, candidate_pubkey) = hw_wallet.input_key_pair(try_idx);

                    // Check if this pubkey matches the UTXO's script
                    let candidate_script = if witness_utxo.script_pubkey.is_p2wpkh() {
                        pubkey_to_p2wpkh_script(&candidate_pubkey)
                    } else if witness_utxo.script_pubkey.is_p2tr() {
                        // For P2TR, BIP-86 internal key (regular taproot)
                        internal_key_to_p2tr_script(&candidate_pubkey)
                    } else {
                        continue; // Unsupported script type
                    };

                    // If the candidate script matches the UTXO's scriptPubKey, we found the right key
                    if candidate_script == witness_utxo.script_pubkey {
                        // BIP-352: for P2TR inputs, use the tweaked taproot output private key for ECDH, not the internal key.
                        let privkey = if witness_utxo.script_pubkey.is_p2tr() {
                            let (xonly, _) = candidate_pubkey.x_only_public_key();
                            let tweak = TapTweakHash::from_key_and_tweak(xonly, None)
                                .to_scalar()
                                .to_be_bytes();
                            let tweaked_sk =
                                apply_tweak_to_privkey(&candidate_privkey, &tweak)
                                    .map_err(|e| format!("BIP-341 tweak failed: {}", e))?;
                            let (_, parity) =
                                PublicKey::from_secret_key(&secp, &tweaked_sk)
                                    .x_only_public_key();
                            if parity == Parity::Odd {
                                tweaked_sk.negate()
                            } else {
                                tweaked_sk
                            }
                        } else {
                            candidate_privkey
                        };
                        inputs[input_idx].private_key = Some(privkey);
                        found_key = true;
                        break;
                    }
                }

                if !found_key {
                    return Err(format!(
                        "Could not find matching private key for input {} (not controlled by this hardware wallet)",
                        input_idx
                    ).into());
                }
            }
        }

        println!(
            "   Set private keys for inputs {:?}\n",
            hw_controlled_inputs
        );

        if attack_mode {
            println!("   ⚠️  This attack tries to redirect funds while maintaining valid signatures");
            println!("   ⚠️  The coordinator should detect this via DLEQ proof verification!\n");
        } else {
            println!("   Computing ECDH shares...");
            println!("   Generating DLEQ proofs...");
            println!("   Deriving silent payment output scripts...");
            println!("   Signing inputs...\n");
        }

        // Add ECDH shares and DLEQ proofs
        add_ecdh_shares_partial(
            &secp,
            &mut psbt,
            &inputs,
            &scan_keys,
            &hw_controlled_inputs,
            true, // generate DLEQ proofs
        )?;

        // Finalize SP output scripts before signing so the sighash commits to the
        // correct output scripts. sign_inputs() builds the transaction from the PSBT,
        // and SP outputs must have script_pubkey set at that point.
        //
        // In attack mode, ECDH shares were computed against the attacker's scan key, so
        // standard finalization would fail for the recipient output (no coverage for the
        // legitimate scan key). Instead, finalize using malicious scripts: the change
        // output gets the honest script, but the recipient output is redirected to the
        // attacker's address. The coordinator detects the attack via scan key mismatch
        // in the DLEQ proofs.
        if attack_mode {
            let hw_scan_key = scan_keys[0]; // scan_keys[0] was not replaced — still the hw wallet's key
            let attacker_address = attacker_address_opt.as_ref().unwrap();
            attack_mode::finalize_sp_outputs_malicious(
                &secp,
                &mut psbt,
                &hw_scan_key,
                attacker_address,
            )?;
        } else {
            finalize_sp_outputs(&secp, &mut psbt)?;
        }

        // Sign all inputs (automatically detects P2PKH, P2WPKH, P2TR, and Silent Payments)
        sign_inputs(&secp, &mut psbt, &inputs)?;

        if attack_mode {
            println!("\n   🚨 ECDH shares computed with MALICIOUS scan key");
            println!("   🚨 DLEQ proofs generated for WRONG scan key");
            println!("   🚨 Recipient output script_pubkey set to ATTACKER address");
            println!("   ✓  Change output script_pubkey set honestly (hw wallet)");
            println!("   ✓  Inputs signed with correct private keys");
            println!("   Attack attempt complete - coordinator should reject this!");
        } else {
            println!("\n    Standard Signing:");
            println!("      ECDH shares computed");
            println!("      DLEQ proofs generated");
            println!("      Inputs signed");
        }

        // Check ECDH coverage
        let num_inputs = psbt.inputs.len();
        let mut inputs_with_ecdh = 0;
        for i in 0..num_inputs {
            let shares = psbt.get_input_ecdh_shares(i);
            if !shares.is_empty() {
                inputs_with_ecdh += 1;
            }
        }

        let ecdh_complete = inputs_with_ecdh == num_inputs;
        println!(
            "\n   ECDH coverage: {} ({}/{} inputs)",
            if ecdh_complete {
                "Complete"
            } else {
                "Incomplete"
            },
            inputs_with_ecdh,
            num_inputs
        );

        if !ecdh_complete {
            println!("   ⚠️  Warning: Incomplete ECDH coverage");
        }

        Ok(psbt)
    }

    /// Send signed PSBT back to coordinator
    pub fn send_psbt(
        psbt: &SilentPaymentPsbt,
        auto_continue: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", "=".repeat(60));
        println!("    Sending Signed PSBT");
        println!("{}\n", "=".repeat(60));

        let metadata = PsbtMetadata {
            description: Some(
                "Signed PSBT with ECDH shares, DLEQ proofs, and signatures".to_string(),
            ),
            creator: Some("hardware_device".to_string()),
            modified_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            ..Default::default()
        };

        save_psbt(psbt, Some(metadata))?; // Use CLI path (persistent)

        display_air_gap_instructions(
            "Hardware Device (Air-gapped)",
            "Wallet Coordinator (Online)",
            auto_continue,
        );

        println!("\n{}", "=".repeat(60));
        println!("    PSBT SIGNED AND READY FOR COORDINATOR");
        println!("{}\n", "=".repeat(60));

        println!("  NEXT STEP:");
        println!("   Transfer PSBT back to coordinator for finalization");
        println!("   Select option 3 in the menu to finalize transaction\n");

        Ok(())
    }

    /// Complete signing workflow
    pub fn sign_workflow(
        config: &TransactionConfig,
        auto_read: bool,
        auto_approve: bool,
        attack_mode: bool,
        mnemonic: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Receive PSBT
        let (psbt, _metadata) = Self::receive_psbt(auto_read, true)?;

        // Display and get approval
        let approved = Self::verify_and_approve(config, auto_approve, attack_mode, mnemonic)?;

        if !approved {
            println!("❌ Transaction not approved. Aborting.\n");
            return Ok(());
        }

        // Sign PSBT
        let signed_psbt = Self::sign_psbt(psbt, attack_mode, mnemonic)?;

        // Send back to coordinator
        Self::send_psbt(&signed_psbt, true)?;

        Ok(())
    }
}
