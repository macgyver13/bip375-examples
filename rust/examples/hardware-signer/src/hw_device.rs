//! Hardware Device Simulator - Air-gapped device for signing transactions
//!
//! This module simulates an air-gapped hardware wallet that:
//! - Receives PSBTs from coordinator (via file/QR)
//! - Displays transaction details for user approval
//! - Computes ECDH shares and generates DLEQ proofs
//! - Signs transaction inputs
//! - Supports attack mode to demonstrate security model

use crate::shared_utils::*;
use bip375_core::{constants, OutputRecipient, SilentPaymentPsbt};
use bip375_io::PsbtMetadata;
use bip375_roles::signer::{add_ecdh_shares_partial, sign_inputs};
use common::{save_psbt,load_psbt};
use secp256k1::{PublicKey, Secp256k1};
use std::io::{self, Write};

pub struct HardwareDevice;

impl HardwareDevice {
    /// Receive PSBT from wallet coordinator
    pub fn receive_psbt(
        auto_read: bool,
        auto_continue: bool,
    ) -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>), Box<dyn std::error::Error>> {
        print_step_header(
            "Step 2a: Receive PSBT",
            "HARDWARE DEVICE (Air-gapped)",
        );

        println!("  Receiving PSBT from wallet coordinator...\n");

        if !auto_read {
            println!("Press Enter to load from transfer file...");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
        }

        let (psbt, metadata) = load_psbt()  // Use CLI path (persistent)
            .map_err(|e| format!("Failed to load PSBT: {}", e))?;

        if let Some(meta) = &metadata {
            if let Some(creator) = &meta.creator {
                println!("   Created by: {}", creator);
            }
            if let Some(desc) = &meta.description {
                println!("   Description: {}\n", desc);
            }
        }

        // Verify PSBT is unsigned
        let has_signatures = psbt.input_maps.iter().any(|input_fields| {
            input_fields
                .iter()
                .any(|field| field.field_type == constants::PSBT_IN_PARTIAL_SIG)
        });

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
    pub fn verify_and_approve(auto_approve: bool, attack_mode: bool) -> Result<bool, Box<dyn std::error::Error>> {
        print_step_header(
            "Step 2b: Verify Transaction",
            "HARDWARE DEVICE (Air-gapped)",
        );

        println!(" HARDWARE DEVICE SCREEN:");
        println!("{}\n", "=".repeat(60));

        // Extract DNSSEC proofs from PSBT
        let (psbt, _) = load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;
        
        let mut dnssec_proofs = std::collections::HashMap::new();
        for (output_idx, output_fields) in psbt.output_maps.iter().enumerate() {
            for field in output_fields {
                if field.field_type == constants::PSBT_OUT_DNSSEC_PROOF {
                    match decode_dnssec_proof(&field.value_data) {
                        Ok((dns_name, _proof_data)) => {
                            let proof_hex = hex::encode(&field.value_data);
                            dnssec_proofs.insert(output_idx, (dns_name, proof_hex));
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to decode DNSSEC proof for output {}: {}", output_idx, e);
                        }
                    }
                }
            }
        }
        
        // Display transaction summary with DNSSEC proofs inline
        let has_dnssec = !dnssec_proofs.is_empty();
        display_transaction_summary_with_dnssec(if has_dnssec { Some(dnssec_proofs) } else { None });

        println!("  Review transaction carefully!");
        println!("   • Check recipient addresses");
        if has_dnssec {
            println!("   • Verify DNS contact names");
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
    ) -> Result<SilentPaymentPsbt, Box<dyn std::error::Error>> {
        print_step_header(
            "Step 2c: Sign Transaction",
            "HARDWARE DEVICE (Air-gapped)",
        );

        println!("   SIGNER: Processing transaction with hardware keys...\n");

        // Get hardware wallet's private keys from "secure storage"
        let hw_wallet = get_hardware_wallet();
        let mut inputs = create_transaction_inputs();
        let outputs = create_transaction_outputs();
        let secp = Secp256k1::new();

        // Extract scan keys from outputs
        let mut scan_keys: Vec<PublicKey> = outputs
            .iter()
            .filter_map(|output| match &output.recipient {
                OutputRecipient::SilentPayment(address) => Some(address.scan_key),
                _ => None,
            })
            .collect();

        if attack_mode {
            // ATTACK SIMULATION: Replace recipient scan key with attacker's scan key
            println!("🚨 ATTACK MODE: Using malicious scan key!");
            println!("   Real recipient scan key would be used in honest mode\n");

            let recipient_address = get_recipient_address();
            let attacker_address = get_attacker_address();

            println!("   Legitimate recipient: {}", hex::encode(recipient_address.scan_key.serialize()));
            println!("   Malicious attacker:   {}", hex::encode(attacker_address.scan_key.serialize()));
            println!("   ⚠️  Funds would go to attacker if this succeeds!\n");

            // Replace recipient scan key with attacker's scan key
            // Output 0 is change (hardware wallet), Output 1 is recipient
            if scan_keys.len() >= 2 {
                println!("   🚨 Replacing recipient scan key with attacker's...");
                scan_keys[1] = attacker_address.scan_key;
            }
        } else {
            println!("   Extracted {} scan key(s) from PSBT outputs:", scan_keys.len());
            for (i, sk) in scan_keys.iter().enumerate() {
                println!("     Scan key {}: {}", i, hex::encode(sk.serialize()));
            }

            // Display which output is which (for demo purposes)
            if scan_keys.len() >= 2 {
                let hw_scan_key = hw_wallet.scan_key_pair().1;
                if scan_keys[0].serialize() == hw_scan_key.serialize() {
                    println!("     (Output 0 is change to hardware wallet)");
                }
                println!("     (Output 1 is payment to recipient)");
            }
            println!();
        }

        // Hardware wallet controls both inputs
        let hw_controlled_inputs = vec![0, 1];

        println!("   Hardware wallet controls inputs: {:?}", hw_controlled_inputs);

        // Set private keys for hardware-controlled inputs
        for input_idx in &hw_controlled_inputs {
            let privkey = hw_wallet.input_key_pair(*input_idx as u32).0;
            inputs[*input_idx].private_key = Some(privkey);
        }

        println!("   Set private keys for inputs {:?}\n", hw_controlled_inputs);

        if attack_mode {
            println!("   🚨 Computing ECDH shares with MALICIOUS scan key...");
            println!("   🚨 Generating DLEQ proofs for WRONG scan key...");
            println!("   ✓  Signing inputs with CORRECT private keys...\n");
            println!("   ⚠️  This attack tries to redirect funds while maintaining valid signatures");
            println!("   ⚠️  The coordinator should detect this via DLEQ proof verification!\n");
        } else {
            println!("   Computing ECDH shares...");
            println!("   Generating DLEQ proofs...");
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

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs)?;

        if attack_mode {
            println!("   🚨 ECDH shares computed with MALICIOUS scan key");
            println!("   🚨 DLEQ proofs generated for WRONG scan key");
            println!("   ✓  Inputs signed with correct private keys\n");
            println!("   Attack attempt complete - coordinator should reject this!");
        } else {
            println!("     ECDH shares computed");
            println!("     DLEQ proofs generated");
            println!("     Inputs signed");
        }

        // Check ECDH coverage
        let num_inputs = psbt.num_inputs();
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
    pub fn send_psbt(psbt: &SilentPaymentPsbt, auto_continue: bool) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", "=".repeat(60));
        println!("    Sending Signed PSBT");
        println!("{}\n", "=".repeat(60));

        let metadata = PsbtMetadata {
            description: Some("Signed PSBT with ECDH shares, DLEQ proofs, and signatures".to_string()),
            creator: Some("hardware_device".to_string()),
            modified_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
            ..Default::default()
        };

        save_psbt(psbt, Some(metadata))?;  // Use CLI path (persistent)

        

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
        auto_read: bool,
        auto_approve: bool,
        attack_mode: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Receive PSBT
        let (psbt, _metadata) = Self::receive_psbt(auto_read, true)?;

        // Display and get approval
        let approved = Self::verify_and_approve(auto_approve, attack_mode)?;

        if !approved {
            println!("❌ Transaction not approved. Aborting.\n");
            return Ok(());
        }

        // Sign PSBT
        let signed_psbt = Self::sign_psbt(psbt, attack_mode)?;

        // Send back to coordinator
        Self::send_psbt(&signed_psbt, true)?;

        Ok(())
    }
}
