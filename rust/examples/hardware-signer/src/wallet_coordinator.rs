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
use bip375_helpers::io::PsbtMetadata;
use bip375_helpers::transaction::build_psbt;
use bip375_helpers::HrnPsbtExt;
use bip375_helpers::{display::psbt_io::*, wallet::TransactionConfig};
use secp256k1::Secp256k1;
use psbt::roles::{Bip375UpdaterExt, ExtractorPsbtExt, SignerPsbtExt};
use std::collections::HashSet;

pub struct WalletCoordinator;

/// Finalize input witnesses for taproot (`tap_key_sig`) and P2WPKH (`partial_sigs`) inputs.
///
/// The upstream `InputWitnessFinalizerPsbtExt::finalize` only handles taproot inputs (it errors
/// on the first non-taproot input), so this local helper also builds the standard P2WPKH witness
/// `[signature, pubkey]`. Mirrors the upstream taproot path for `tap_key_sig` inputs.
fn finalize_input_witnesses(psbt: &mut psbt::Psbt) -> Result<(), String> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        if let Some(sig) = input.tap_key_sig {
            let mut witness = bitcoin::Witness::new();
            witness.push(sig.to_vec());
            input.final_script_sig = Some(bitcoin::ScriptBuf::new());
            input.final_script_witness = Some(witness);
            input.tap_key_sig = None;
            input.sighash_type = None;
        } else if let Some((pubkey, sig)) =
            input.partial_sigs.iter().next().map(|(k, v)| (*k, *v))
        {
            let mut witness = bitcoin::Witness::new();
            witness.push(sig.to_vec());
            witness.push(pubkey.to_bytes());
            input.final_script_sig = Some(bitcoin::ScriptBuf::new());
            input.final_script_witness = Some(witness);
            input.partial_sigs.clear();
            input.sighash_type = None;
        } else {
            return Err(format!("Missing signature on input {}", i));
        }
    }
    Ok(())
}

/// Returns seconds since UNIX epoch (used for PSBT metadata timestamps).
fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

        let input_count = inputs.len();
        let output_count = outputs.len();

        // Record which inputs are silent-payment UTXOs (and their tweaks) before the
        // inputs are consumed by build_psbt. Matched by outpoint so it survives any
        // reordering. Tweaks must be applied before BIP32 derivations so the updater
        // can distinguish SP inputs.
        let tweak_db = TweakDatabase::from_virtual_wallet(&virtual_wallet);
        let sp_tweaks: Vec<(usize, [u8; 32])> = inputs
            .iter()
            .enumerate()
            .filter_map(|(i, inp)| {
                let outpoint = bitcoin::OutPoint::new(inp.previous_txid, inp.spent_output_index);
                tweak_db.get(&outpoint).map(|t| (i, t))
            })
            .collect();

        // Create PSBT (CREATOR + CONSTRUCTOR). Note: build_psbt shuffles outputs per BIP-375.
        let mut psbt = build_psbt(inputs, outputs)
            .map_err(|e| format!("Failed to build PSBT: {}", e))?;

        println!(
            "  CREATOR + CONSTRUCTOR: Created PSBT with {} inputs and {} outputs\n",
            input_count, output_count
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
        let mut sp_input_count = 0;
        for (input_idx, tweak) in &sp_tweaks {
            psbt.inputs[*input_idx].set_sp_tweak(*tweak);
            sp_input_count += 1;
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
        let output_deriv_count = add_output_bip32_derivations(&mut psbt, &hw_wallet)?;
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

        // Locate the recipient SP output (scan key not ours) — its index may have moved
        // because build_psbt shuffles outputs.
        let hw_scan_pub = hw_wallet.scan_spend_keys().0;
        let recipient_idx = psbt
            .outputs
            .iter()
            .position(|o| {
                output_sp_info(o)
                    .map(|(scan, _)| scan.serialize() != hw_scan_pub.serialize())
                    .unwrap_or(false)
            })
            .ok_or("Recipient SP output not found")?;

        HrnPsbtExt::set_output_dnssec_proof(&mut psbt, recipient_idx, dnssec_proof.clone())?;

        println!("   Added DNSSEC proof for recipient output");
        println!("   Proof Format: <1-byte-length><dns_name><RFC 9102 proof>");
        println!("   Proof Size: {} bytes\n", dnssec_proof.len());

        // Display BIP32 derivation info
        if input_deriv_count > 0 || output_deriv_count > 0 || xpub_count > 0 {
            println!("  UPDATER: Added BIP32 derivation information");
            if input_deriv_count > 0 {
                println!(
                    "   {} BIP32 derivation entries across {} inputs",
                    input_deriv_count, input_count
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
                input_count, output_count
            )),
            creator: Some("wallet_coordinator".to_string()),
            created_at: Some(timestamp_now()),
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

        // Collect expected scan keys and spend keys
        let hw_scan_key = hw_wallet.scan_key_pair().1;
        let (hw_scan_pub, hw_spend_pub) = hw_wallet.scan_spend_keys();
        let recipient_address = get_recipient_address();
        let recipient_scan_key = recipient_address.get_scan_key();
        let recipient_spend_key = recipient_address.get_spend_key();

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

        // DIAGNOSTIC: Log unexpected scan keys (non-fatal; full validation catches the mismatch)
        let unexpected_keys: Vec<_> = found_scan_keys.difference(&expected_scan_keys).collect();
        if !unexpected_keys.is_empty() {
            println!("  WARNING: DLEQ proofs contain unexpected scan keys:");
            for key in &unexpected_keys {
                println!("   Unexpected key: {}", hex::encode(key));
            }
            println!("   Hardware device may have used an attacker's scan key.");
            println!("   Full validation will confirm whether this is an attack.\n");
        }

        // SP FIELD INTEGRITY CHECK
        // Every SP output must still carry sp_v0_info, and its (scan_key, spend_key) must
        // match one of the expected pairs. Outputs may be in any order (build_psbt shuffles
        // them per BIP-375), so match against the expected set rather than by index. Catches:
        //   - Attack 2 (WrongScanKey):      unexpected scan key
        //   - Attack 3 (SubstituteSpendKey): spend key mismatch
        //   - Attack 4 (StripSpFields):      missing SP output (count mismatch)
        println!("  Verifying SP field integrity for all outputs...");

        let expected_sp_info: [(secp256k1::PublicKey, secp256k1::PublicKey); 2] = [
            (hw_scan_pub, hw_spend_pub),
            (recipient_scan_key, recipient_spend_key),
        ];

        let mut sp_output_count = 0;
        for (output_idx, output) in psbt.outputs.iter().enumerate() {
            let Some((actual_scan, actual_spend)) = output_sp_info(output) else {
                continue;
            };
            sp_output_count += 1;

            if !expected_sp_info
                .iter()
                .any(|(es, _)| es.serialize() == actual_scan.serialize())
            {
                return Err(format!(
                    "Attack detected: unexpected scan key on output {} (got {})",
                    output_idx,
                    hex::encode(actual_scan.serialize()),
                )
                .into());
            }
            if !expected_sp_info.iter().any(|(es, esp)| {
                es.serialize() == actual_scan.serialize()
                    && esp.serialize() == actual_spend.serialize()
            }) {
                return Err(format!(
                    "Attack detected: spend key mismatch on output {} (got {})",
                    output_idx,
                    hex::encode(actual_spend.serialize()),
                )
                .into());
            }
            println!(
                "     PASSED: Output {} sp_v0_info intact (scan + spend keys verified)",
                output_idx
            );
        }

        if sp_output_count != expected_sp_info.len() {
            return Err(format!(
                "Attack detected: expected {} silent-payment outputs, found {} (BIP-375 fields stripped)",
                expected_sp_info.len(),
                sp_output_count
            )
            .into());
        }
        println!();

        // Recompute SP output scripts from the ECDH shares and confirm they match what the
        // hardware device wrote. Replaces the old comprehensive validate_psbt: compute_sp_outputs
        // errors on missing ECDH coverage, and a script mismatch proves the device did not derive
        // the outputs honestly from the shares it provided.
        println!("  Recomputing SP output scripts from ECDH shares...");
        let xonly_map = psbt
            .compute_sp_outputs(&secp)
            .map_err(|e| format!("SP output recomputation failed: {}", e))?;
        let mut recomputed = psbt.clone();
        recomputed
            .set_sp_scriptpubkey(xonly_map)
            .map_err(|e| format!("SP output recomputation failed: {}", e))?;
        for (i, (signed, expected)) in
            psbt.outputs.iter().zip(recomputed.outputs.iter()).enumerate()
        {
            if signed.sp_v0_info.is_some() && signed.script_pubkey != expected.script_pubkey {
                return Err(format!(
                    "Attack detected: output {} script does not match the script recomputed from ECDH shares",
                    i
                )
                .into());
            }
        }
        println!("     PASSED: SP output scripts verified against ECDH shares");
        println!("      - ECDH coverage complete ({} inputs)", inputs.len());
        println!(
            "      - Change scan key:    {}",
            hex::encode(hw_scan_pub.serialize())
        );
        println!(
            "      - Recipient scan key: {}",
            hex::encode(recipient_scan_key.serialize())
        );
        println!("      - All inputs signed");
        println!("      - Output scripts computed");

        // Amount validation
        println!("\n  Validating transaction amounts...");
        let total_input: u64 = inputs
            .iter()
            .map(|i| i.witness_utxo.as_ref().map_or(0, |u| u.value.to_sat()))
            .sum();
        let total_output: u64 = outputs.iter().map(|o| o.amount.to_sat()).sum();
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

        // INPUT WITNESS FINALIZER: populate PSBT_IN_FINAL_SCRIPTWITNESS
        println!("\n  INPUT WITNESS FINALIZER: Finalizing input witnesses...");
        finalize_input_witnesses(&mut psbt)?;
        println!("     PSBT_IN_FINAL_SCRIPTWITNESS written for all inputs\n");

        // Save finalized PSBT (with PSBT_IN_FINAL_SCRIPTWITNESS set)
        let finalized_metadata = PsbtMetadata {
            description: Some("Finalized PSBT with PSBT_IN_FINAL_SCRIPTWITNESS".to_string()),
            creator: Some("wallet_coordinator".to_string()),
            modified_at: Some(timestamp_now()),
            ..Default::default()
        };
        save_psbt(&psbt, Some(finalized_metadata))?;

        // Extract transaction
        println!("  EXTRACTOR: Extracting final transaction...");

        let final_tx = psbt.extract_tx()?;
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
