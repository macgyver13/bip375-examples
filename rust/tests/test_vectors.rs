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

use bip375_core::{Bip375PsbtExt, SilentPaymentPsbt};
use bip375_roles::validation::{validate_psbt, ValidationLevel};
use secp256k1::Secp256k1;
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
    input_index: Option<usize>,
}

/// Expected output
#[derive(Debug, Deserialize, Serialize)]
struct ExpectedOutput {
    output_index: usize,
    amount: u64,
    is_silent_payment: bool,
    script: Option<String>,
    sp_info: Option<String>,
    sp_label: Option<u32>,
}

/// Load test vectors from JSON file
fn load_test_vectors() -> TestVectors {
    let content = fs::read_to_string(TEST_VECTORS_FILE).expect("Failed to read test vectors file");
    serde_json::from_str(&content).expect("Failed to parse test vectors JSON")
}

/// Decode a base64 string to bytes
fn base64_to_bytes(b64: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(b64).expect("Invalid base64 string")
}

#[test]
fn test_invalid_vectors() {
    let vectors = load_test_vectors();
    let secp = Secp256k1::new();

    println!(
        "\n=== Testing {} Invalid Vectors ===\n",
        vectors.invalid.len()
    );

    for (i, vector) in vectors.invalid.iter().enumerate() {
        println!("Invalid Test {}: {}", i + 1, vector.description);

        // Decode PSBT from base64
        let psbt_bytes = base64_to_bytes(&vector.psbt);

        // Try to parse PSBT
        let psbt = match SilentPaymentPsbt::deserialize(&psbt_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("    Failed to parse (expected): {:?}", e);
                continue;
            }
        };

        // PSBT parsed, but validation should fail
        match validate_psbt(&secp, &psbt, ValidationLevel::Full) {
            Ok(_) => {
                panic!(
                    "  ❌ Test failed: PSBT validation should have failed for: {}",
                    vector.description
                );
            }
            Err(e) => {
                println!("    Validation failed (expected): {}", e);
            }
        }
    }

    println!(
        "\n  All {} invalid vectors handled correctly\n",
        vectors.invalid.len()
    );
}

#[test]
fn test_valid_vectors() {
    let vectors = load_test_vectors();
    let secp = Secp256k1::new();

    println!("\n=== Testing {} Valid Vectors ===\n", vectors.valid.len());

    for (i, vector) in vectors.valid.iter().enumerate() {
        println!("Valid Test {}: {}", i + 1, vector.description);

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
        println!(
            "     Inputs: {}, Outputs: {}",
            psbt.num_inputs(),
            psbt.num_outputs()
        );

        // Validate PSBT structure (basic validation - test vectors don't have signatures)
        match validate_psbt(&secp, &psbt, ValidationLevel::Full) {
            Ok(_) => {
                println!("    PSBT validation passed (full)");
            }
            Err(e) => {
                panic!("  ❌ Validation failed: {}", e);
            }
        }

        println!("    Test passed\n");
    }

    println!("\n  All {} valid vectors passed\n", vectors.valid.len());
}

#[test]
fn test_vector_file_exists() {
    assert!(
        std::path::Path::new(TEST_VECTORS_FILE).exists(),
        "Test vectors file not found: {}",
        TEST_VECTORS_FILE
    );
}
