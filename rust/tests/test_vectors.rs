//! BIP-375 Test Vectors
//!
//! This module tests the Rust implementation against the official BIP-375 test vectors.
//! The test vectors include both valid and invalid PSBTs to ensure correct handling.
//!
//! Test vector format:
//! - Base64-encoded PSBTs
//! - Expected ECDH shares (with DLEQ proofs)
//! - Expected output scripts
//! - Input key information
//! - Scan keys for silent payment outputs

use bip375_core::{constants::*, SilentPaymentPsbt};
use bip375_roles::validation::{validate_psbt, ValidationLevel};
use secp256k1::{Secp256k1, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;

/// Test vector file location
const TEST_VECTORS_FILE: &str = "../test_vectors.json";

/// Root structure for all test vectors
#[derive(Debug, Deserialize, Serialize)]
struct TestVectors {
    description: String,
    version: String,
    format_notes: Vec<String>,
    invalid: Vec<TestVector>,
    valid: Vec<TestVector>,
}

/// Individual test vector
#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    description: String,
    psbt: String, // Base64-encoded PSBT
    input_keys: Vec<InputKey>,
    scan_keys: Vec<ScanKey>,
    expected_ecdh_shares: Vec<EcdhShare>,
    expected_outputs: Vec<ExpectedOutput>,
    comment: String,
}

/// Input key information
#[derive(Debug, Deserialize, Serialize)]
struct InputKey {
    input_index: usize,
    private_key: String,
    public_key: String,
    prevout_txid: String,
    prevout_index: u32,
    prevout_scriptpubkey: String,
    amount: u64,
    witness_utxo: String,
    sequence: u32,
}

/// Scan key for silent payment
#[derive(Debug, Deserialize, Serialize)]
struct ScanKey {
    scan_pubkey: String,
    spend_pubkey: String,
    label: Option<u32>,
}

/// Expected ECDH share
#[derive(Debug, Deserialize, Serialize)]
struct EcdhShare {
    scan_key: String,
    ecdh_result: String,
    dleq_proof: Option<String>,
    is_global: bool,
    input_index: Option<usize>,
}

/// Expected output
#[derive(Debug, Deserialize, Serialize)]
struct ExpectedOutput {
    output_index: usize,
    amount: u64,
    script: String,
    is_silent_payment: bool,
    sp_info: Option<String>,
    sp_label: Option<u32>,
}

/// Load test vectors from JSON file
fn load_test_vectors() -> TestVectors {
    let content = fs::read_to_string(TEST_VECTORS_FILE)
        .expect("Failed to read test vectors file");
    serde_json::from_str(&content)
        .expect("Failed to parse test vectors JSON")
}

/// Decode a hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex string")
}

/// Decode a base64 string to bytes
fn base64_to_bytes(b64: &str) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(b64).expect("Invalid base64 string")
}

/// Parse a public key from hex
fn parse_pubkey(hex: &str) -> PublicKey {
    let bytes = hex_to_bytes(hex);
    PublicKey::from_slice(&bytes).expect("Invalid public key")
}

#[test]
fn test_invalid_vectors() {
    let vectors = load_test_vectors();
    let secp = Secp256k1::new();

    println!("\n=== Testing {} Invalid Vectors ===\n", vectors.invalid.len());

    for (i, vector) in vectors.invalid.iter().enumerate() {
        println!("Invalid Test {}: {}", i + 1, vector.description);
        println!("  Comment: {}", vector.comment);

        // Decode PSBT from base64
        let psbt_bytes = base64_to_bytes(&vector.psbt);

        // Try to parse PSBT
        let psbt = match SilentPaymentPsbt::deserialize(&psbt_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("    Failed to parse (expected): {}", e);
                continue;
            }
        };

        println!("  PSBT parsed. Inputs: {}, Outputs: {}", psbt.num_inputs(), psbt.num_outputs());

        // Debug: Check for BIP-375 dedicated fields
        for i in 0..psbt.num_inputs() {
            let has_ecdh = psbt.get_input_field(i, PSBT_IN_SP_ECDH_SHARE).is_some();
            let has_dleq = psbt.get_input_field(i, PSBT_IN_SP_DLEQ).is_some();
            println!("  Input {}: ECDH={}, DLEQ={}", i, has_ecdh, has_dleq);
        }

        // Debug: Check for ECDH shares
        for i in 0..psbt.num_inputs() {
            let shares = psbt.get_input_ecdh_shares(i);
            println!("  Input {}: {} ECDH shares", i, shares.len());
            for share in shares {
                println!("    - has DLEQ proof: {}", share.dleq_proof.is_some());
            }
        }

        // PSBT parsed, but validation should fail
        match validate_psbt(&secp, &psbt, ValidationLevel::Full) {
            Ok(_) => {
                panic!("  ❌ Test failed: PSBT validation should have failed for: {}", vector.description);
            }
            Err(e) => {
                println!("    Validation failed (expected): {}", e);
            }
        }
    }

    println!("\n  All {} invalid vectors handled correctly\n", vectors.invalid.len());
}

#[test]
fn test_valid_vectors() {
    let vectors = load_test_vectors();
    let secp = Secp256k1::new();

    println!("\n=== Testing {} Valid Vectors ===\n", vectors.valid.len());

    for (i, vector) in vectors.valid.iter().enumerate() {
        println!("Valid Test {}: {}", i + 1, vector.description);
        println!("  Comment: {}", vector.comment);

        // Decode PSBT from base64
        let psbt_bytes = base64_to_bytes(&vector.psbt);

        // Parse PSBT
        let psbt = match SilentPaymentPsbt::deserialize(&psbt_bytes) {
            Ok(p) => p,
            Err(e) => {
                panic!("  ❌ Failed to parse valid PSBT: {}", e);
            }
        };

        println!("    PSBT parsed successfully");
        println!("     Inputs: {}, Outputs: {}", psbt.num_inputs(), psbt.num_outputs());

        // Validate PSBT structure (basic validation - test vectors don't have signatures)
        match validate_psbt(&secp, &psbt, ValidationLevel::Full) {
            Ok(_) => {
                println!("    PSBT validation passed (basic)");
            }
            Err(e) => {
                panic!("  ❌ Validation failed: {}", e);
            }
        }

        // Verify ECDH shares
        verify_ecdh_shares(&psbt, &vector.expected_ecdh_shares);

        // Verify outputs
        verify_outputs(&psbt, &vector.expected_outputs);

        println!("    Test passed\n");
    }

    println!("\n  All {} valid vectors passed\n", vectors.valid.len());
}

/// Verify ECDH shares match expected values
fn verify_ecdh_shares(psbt: &SilentPaymentPsbt, expected: &[EcdhShare]) {
    println!("  Verifying {} ECDH shares...", expected.len());

    for exp in expected {
        let scan_key = parse_pubkey(&exp.scan_key);

        if exp.is_global {
            // For global ECDH shares, check all inputs for shares matching this scan key
            let mut found = false;
            for i in 0..psbt.num_inputs() {
                let shares = psbt.get_input_ecdh_shares(i);
                if let Some(share) = shares.iter().find(|s| s.scan_key == scan_key) {
                    let expected_ecdh = hex_to_bytes(&exp.ecdh_result);
                    assert_eq!(share.share.serialize().to_vec(), expected_ecdh,
                        "Global ECDH share mismatch");

                    if let Some(expected_proof) = &exp.dleq_proof {
                        let proof_bytes = hex_to_bytes(expected_proof);
                        let proof_array: [u8; 64] = proof_bytes.try_into()
                            .expect("DLEQ proof must be 64 bytes");
                        assert_eq!(share.dleq_proof, Some(proof_array), "Global DLEQ proof mismatch");
                    }

                    found = true;
                    break;
                }
            }
            assert!(found, "Missing global ECDH share for scan key");
            println!("      Global ECDH share verified");
        } else {
            // Check per-input ECDH share
            let input_idx = exp.input_index.expect("Missing input_index for per-input share");
            let shares = psbt.get_input_ecdh_shares(input_idx);

            // Find the share for this scan key
            let share = shares.iter()
                .find(|s| s.scan_key == scan_key)
                .expect("Missing per-input ECDH share");

            let expected_ecdh = hex_to_bytes(&exp.ecdh_result);
            assert_eq!(share.share.serialize().to_vec(), expected_ecdh,
                "Input {} ECDH share mismatch", input_idx);

            if let Some(expected_proof) = &exp.dleq_proof {
                let proof_bytes = hex_to_bytes(expected_proof);
                let proof_array: [u8; 64] = proof_bytes.try_into()
                    .expect("DLEQ proof must be 64 bytes");
                assert_eq!(share.dleq_proof, Some(proof_array),
                    "Input {} DLEQ proof mismatch", input_idx);
            }

            println!("      Input {} ECDH share verified", input_idx);
        }
    }
}

/// Verify outputs match expected values
fn verify_outputs(psbt: &SilentPaymentPsbt, expected: &[ExpectedOutput]) {
    println!("  Verifying {} outputs...", expected.len());

    for exp in expected {
        // Verify amount (PSBT_OUT_AMOUNT)
        if let Some(amount_field) = psbt.get_output_field(exp.output_index, PSBT_OUT_AMOUNT) {
            let amount = u64::from_le_bytes(amount_field.value_data[0..8].try_into().unwrap());
            assert_eq!(amount, exp.amount,
                "Output {} amount mismatch", exp.output_index);
        } else {
            panic!("Missing PSBT_OUT_AMOUNT for output {}", exp.output_index);
        }

        // Verify script (PSBT_OUT_SCRIPT)
        if let Some(script_field) = psbt.get_output_field(exp.output_index, PSBT_OUT_SCRIPT) {
            let expected_script = hex_to_bytes(&exp.script);
            assert_eq!(script_field.value_data, expected_script,
                "Output {} script mismatch", exp.output_index);
        } else {
            panic!("Missing PSBT_OUT_SCRIPT for output {}", exp.output_index);
        }

        // Verify silent payment info if expected
        if exp.is_silent_payment {
            if let Some(exp_info) = &exp.sp_info {
                // Get SP_V0_INFO field (BIP-375 field type 0x09)
                let sp_info_field = psbt.get_output_field(exp.output_index, PSBT_OUT_SP_V0_INFO)
                    .expect("Missing PSBT_OUT_SP_V0_INFO for silent payment output");

                let expected_info = hex_to_bytes(exp_info);
                assert_eq!(sp_info_field.value_data, expected_info,
                    "Output {} PSBT_OUT_SP_V0_INFO mismatch", exp.output_index);

                // Note: Labels in the test vectors refer to BIP-352 labels within the silent payment address,
                // not a separate PSBT field. The label is encoded in the silent payment address itself.
            }
        }

        println!("      Output {} verified ({} sats, {})",
            exp.output_index, exp.amount,
            if exp.is_silent_payment { "silent payment" } else { "regular" });
    }
}

#[test]
fn test_vector_file_exists() {
    assert!(std::path::Path::new(TEST_VECTORS_FILE).exists(),
        "Test vectors file not found: {}", TEST_VECTORS_FILE);
}

#[test]
fn test_vector_count() {
    let vectors = load_test_vectors();

    println!("\n=== Test Vector Summary ===");
    println!("Version: {}", vectors.version);
    println!("Description: {}", vectors.description);
    println!("Invalid vectors: {}", vectors.invalid.len());
    println!("Valid vectors: {}", vectors.valid.len());
    println!("Total vectors: {}", vectors.invalid.len() + vectors.valid.len());

    assert_eq!(vectors.invalid.len(), 13, "Expected 13 invalid test vectors");
    assert_eq!(vectors.valid.len(), 4, "Expected 4 valid test vectors");
}
