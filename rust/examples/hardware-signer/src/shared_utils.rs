//! Shared utilities for hardware signer silent payment example
//!
//! Contains common transaction inputs, outputs, wallet utilities and display functions
//! shared across the wallet coordinator and hardware device simulator.
//!
//! This implements a realistic air-gapped hardware wallet workflow where:
//! - Wallet coordinator: Online device creating and finalizing PSBTs
//! - Hardware device: Air-gapped device that signs transactions
//! - File-based transfer: Simulates QR codes or USB transfer

use bip375_core::{PsbtInput, PsbtOutput, SilentPaymentAddress};
use bip375_crypto::script_type_string;
use bip375_helpers::wallet::{SimpleWallet, TransactionConfig, VirtualWallet};

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

/// Get the virtual wallet with pre-configured UTXOs
pub fn get_virtual_wallet() -> VirtualWallet {
    VirtualWallet::hardware_wallet_default()
}

/// Create transaction inputs based on configuration
///
/// Uses VirtualWallet to select UTXOs based on TransactionConfig.
/// Supports flexible input selection including Silent Payment outputs.
pub fn create_transaction_inputs(config: &TransactionConfig) -> Vec<PsbtInput> {
    let wallet = get_virtual_wallet();
    wallet
        .select_by_ids(&config.selected_utxo_ids)
        .into_iter()
        .map(|utxo| utxo.to_psbt_input())
        .collect()
}

/// Create transaction outputs based on configuration
///
/// Creates two outputs:
/// - Output 0: Change to hardware wallet (configurable amount) with label=0
/// - Output 1: Silent payment to recipient (configurable amount)
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
pub fn create_transaction_outputs(config: &TransactionConfig) -> Vec<PsbtOutput> {
    use bitcoin::Amount;
    let hw_wallet = get_hardware_wallet();
    let (scan_key, spend_key) = hw_wallet.scan_spend_keys();

    // Change output: Silent payment back to hardware wallet with label=0 (reserved for change per BIP 352)
    let change_address = SilentPaymentAddress::new(scan_key, spend_key, Some(0));

    vec![
        // Change output
        PsbtOutput::silent_payment(Amount::from_sat(config.change_amount), change_address),
        // Recipient output
        PsbtOutput::silent_payment(
            Amount::from_sat(config.recipient_amount),
            get_recipient_address(),
        ),
    ]
}

/// Display transaction summary for user review
///
/// # Arguments
/// * `config` - Transaction configuration
/// * `dnssec_proofs` - Optional map of output_index -> (dns_name, proof_hex) for inline display
pub fn display_transaction_summary_with_dnssec(
    config: &TransactionConfig,
    dnssec_proofs: Option<std::collections::HashMap<usize, (String, String)>>,
) {
    let inputs = create_transaction_inputs(config);
    let outputs = create_transaction_outputs(config);

    println!("\n{}", "=".repeat(60));
    println!("  Transaction Summary");
    println!("{}\n", "=".repeat(60));

    println!("  Inputs:");
    for (i, input) in inputs.iter().enumerate() {
        println!("   Input {}: {} sats", i, input.witness_utxo.value.to_sat());
        let txid_str = input.outpoint.txid.to_string();
        println!(
            "      TXID: {}...{}",
            &txid_str[..16],
            &txid_str[txid_str.len() - 8..]
        );
        println!("      VOUT: {}", input.outpoint.vout);
        println!(
            "      Type: {}",
            script_type_string(&input.witness_utxo.script_pubkey)
        );
    }

    let total_input: u64 = inputs.iter().map(|i| i.witness_utxo.value.to_sat()).sum();
    println!("   Total Input: {} sats\n", total_input);

    println!("  Outputs:");
    for (i, output) in outputs.iter().enumerate() {
        match output {
            PsbtOutput::SilentPayment { amount, address } => {
                let label_info = match address.label {
                    Some(0) => " (Change - label 0)",
                    Some(n) => &format!(" (label {})", n),
                    None => "",
                };
                println!("   Output {}{}: {} sats", i, label_info, amount.to_sat());
                println!(
                    "      Scan Key:  {}",
                    hex::encode(address.scan_key.serialize())
                );
                println!(
                    "      Spend Key: {}",
                    hex::encode(address.spend_key.serialize())
                );

                // Display DNSSEC proof inline if available for this output
                if let Some(ref proofs) = dnssec_proofs {
                    if let Some((dns_name, proof_hex)) = proofs.get(&i) {
                        println!("      Contact: {}", dns_name);
                        let proof_display = if proof_hex.len() > 70 {
                            format!(
                                "{}...{} ({} bytes)",
                                &proof_hex[..30],
                                &proof_hex[proof_hex.len() - 30..],
                                proof_hex.len() / 2
                            ) // hex string is 2 chars per byte
                        } else {
                            proof_hex.clone()
                        };
                        println!("      DNS Proof: {}", proof_display);
                    }
                }
            }
            PsbtOutput::Regular(txout) => {
                println!("   Output {}: {} sats", i, txout.value.to_sat());
                println!(
                    "      Script: {}",
                    hex::encode(txout.script_pubkey.as_bytes())
                );
            }
        }
    }

    let total_output: u64 = outputs
        .iter()
        .map(|o| match o {
            PsbtOutput::SilentPayment { amount, .. } => amount.to_sat(),
            PsbtOutput::Regular(txout) => txout.value.to_sat(),
        })
        .sum();
    let fee = total_input - total_output;
    println!("\n   Fee: {} sats", fee);
    println!();
}

/// Display transaction summary for user review (without DNSSEC proofs)
pub fn display_transaction_summary(config: &TransactionConfig) {
    display_transaction_summary_with_dnssec(config, None);
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

// =============================================================================
// DNSSEC Proof Utilities (BIP 353)
// =============================================================================

/// Create a BIP 353 DNSSEC proof for a DNS name
///
/// Format: <1-byte-length-prefixed BIP 353 human-readable name without the ₿ prefix>
///         <RFC 9102-formatted DNSSEC Proof>
///
/// # Arguments
/// * `dns_name` - DNS name (e.g., "donate@example.com")
/// * `resolver_addr` - DNS resolver address (e.g., "8.8.8.8:53" for Google DNS)
///
/// # Returns
/// Encoded bytes ready for PSBT_OUT_DNSSEC_PROOF field, or error
///
/// # Note
/// This function performs real DNSSEC resolution and proof generation using RFC 9102.
/// It queries DNS servers to build cryptographically verifiable proofs.
///
/// # BIP-353 DNS Format
/// For a BIP-353 address like "user@domain.com", the DNS query targets:
/// `user.user._bitcoin-payment.domain.com.` (TXT record)
///
/// # Async Requirement
/// This function must be called from within a tokio runtime context.
pub async fn create_dnssec_proof_async(
    dns_name: &str,
    resolver_addr: &str,
) -> Result<Vec<u8>, String> {
    use dnssec_prover::query::build_txt_proof_async;
    use dnssec_prover::rr::Name;
    use std::net::SocketAddr;

    let dns_name_bytes = dns_name.as_bytes();
    if dns_name_bytes.len() > 255 {
        return Err(format!(
            "DNS name too long: {} bytes (max 255)",
            dns_name_bytes.len()
        ));
    }

    // Parse BIP-353 address format: user@domain.com -> user.user._bitcoin-payment.domain.com.
    let dns_query_name = if dns_name.contains('@') {
        let parts: Vec<&str> = dns_name.split('@').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid BIP-353 format: {}", dns_name));
        }
        let (user, domain) = (parts[0], parts[1]);
        format!("{}.user._bitcoin-payment.{}.", user, domain)
    } else {
        // If no @, assume it's already in DNS format
        if !dns_name.ends_with('.') {
            format!("{}.", dns_name)
        } else {
            dns_name.to_string()
        }
    };

    // Convert to dnssec-prover Name type
    let name = Name::try_from(dns_query_name.as_str())
        .map_err(|_| format!("Invalid DNS name: {}", dns_query_name))?;

    // Parse resolver address
    let resolver: SocketAddr = resolver_addr
        .parse()
        .map_err(|e| format!("Invalid resolver address {}: {}", resolver_addr, e))?;

    // Build RFC 9102 DNSSEC proof by querying DNS
    let (proof_bytes, _ttl) = build_txt_proof_async(resolver, &name)
        .await
        .map_err(|e| format!("Failed to build DNSSEC proof: {:?}", e))?;

    // Encode as BIP-353 format: <1-byte-length><dns_name><RFC 9102 proof>
    let mut result = Vec::new();
    result.push(dns_name_bytes.len() as u8);
    result.extend_from_slice(dns_name_bytes);
    result.extend_from_slice(&proof_bytes);

    Ok(result)
}

/// Create a BIP 353 DNSSEC proof synchronously (blocking version)
///
/// This is a convenience wrapper that creates a temporary tokio runtime.
/// For better performance in async contexts, use `create_dnssec_proof_async`.
///
/// # Arguments
/// * `dns_name` - DNS name (e.g., "donate@example.com")
///
/// # Returns
/// Encoded bytes ready for PSBT_OUT_DNSSEC_PROOF field
///
/// # Note
/// For demo/testing purposes with fallback to mock data on errors.
/// In production wallets, handle errors appropriately.
pub fn create_dnssec_proof(dns_name: &str) -> Vec<u8> {
    // Try to create real DNSSEC proof using Google's public DNS (8.8.8.8)
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    match runtime.block_on(create_dnssec_proof_async(dns_name, "8.8.8.8:53")) {
        Ok(proof) => {
            println!("✓ Generated real DNSSEC proof for: {}", dns_name);
            proof
        }
        Err(e) => {
            // Fallback to mock for demo purposes
            eprintln!("⚠ DNSSEC proof generation failed ({}), using mock data", e);
            create_mock_dnssec_proof(dns_name)
        }
    }
}

/// Create a mock DNSSEC proof for demonstration purposes
///
/// This is used as a fallback when real DNSSEC resolution fails.
/// Mock proofs will fail validation.
fn create_mock_dnssec_proof(dns_name: &str) -> Vec<u8> {
    use bitcoin::hashes::{sha256, Hash};

    let dns_name_bytes = dns_name.as_bytes();

    // Create mock proof data
    let mut mock_proof = b"MOCK_DNSSEC_PROOF_".to_vec();
    let hash = sha256::Hash::hash(dns_name_bytes);
    mock_proof.extend_from_slice(hash.as_byte_array());

    // Encode as BIP-353 format
    let mut proof_bytes = Vec::new();
    proof_bytes.push(dns_name_bytes.len() as u8);
    proof_bytes.extend_from_slice(dns_name_bytes);
    proof_bytes.extend_from_slice(&mock_proof);

    proof_bytes
}

/// Decode a BIP 353 DNSSEC proof
///
/// # Arguments
/// * `proof_bytes` - Encoded DNSSEC proof from PSBT_OUT_DNSSEC_PROOF field
///
/// # Returns
/// Result containing (dns_name, proof_data) or error message
pub fn decode_dnssec_proof(proof_bytes: &[u8]) -> Result<(String, Vec<u8>), String> {
    if proof_bytes.is_empty() {
        return Err("DNSSEC proof too short (missing length byte)".to_string());
    }

    // Extract DNS name length (first byte)
    let dns_name_length = proof_bytes[0] as usize;

    if proof_bytes.len() < 1 + dns_name_length {
        return Err(format!(
            "DNSSEC proof too short (expected {} bytes minimum)",
            1 + dns_name_length
        ));
    }

    // Extract DNS name
    let dns_name_bytes = &proof_bytes[1..1 + dns_name_length];
    let dns_name = String::from_utf8(dns_name_bytes.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in DNS name: {}", e))?;

    // Extract proof data (remainder)
    let proof_data = proof_bytes[1 + dns_name_length..].to_vec();

    Ok((dns_name, proof_data))
}

/// Validate a BIP 353 DNSSEC proof using RFC 9102 validation
///
/// # Arguments
/// * `proof_bytes` - Encoded DNSSEC proof from PSBT_OUT_DNSSEC_PROOF field
///
/// # Returns
/// Result containing (dns_name, validated_txt_records) or error message
///
/// # Note
/// This function performs cryptographic validation of the DNSSEC chain
/// from the DNS root to the target domain, verifying all RRSIG signatures.
pub fn validate_dnssec_proof(proof_bytes: &[u8]) -> Result<(String, Vec<String>), String> {
    use dnssec_prover::rr::RR;
    use dnssec_prover::ser::parse_rr_stream;
    use dnssec_prover::validation::verify_rr_stream;

    // First decode to get DNS name and RFC 9102 proof data
    let (dns_name, rfc9102_proof) = decode_dnssec_proof(proof_bytes)?;

    // Check if this is a mock proof (starts with known mock prefix)
    if rfc9102_proof.starts_with(b"MOCK_DNSSEC_PROOF_") {
        return Err(format!(
            "Cannot validate mock DNSSEC proof for '{}'. Use real DNSSEC resolution.",
            dns_name
        ));
    }

    // Parse RFC 9102 proof into Resource Records
    let rrs = parse_rr_stream(&rfc9102_proof)
        .map_err(|_| "Failed to parse RFC 9102 proof data".to_string())?;

    // Verify DNSSEC chain from root to target using cryptographic validation
    // Note: verify_rr_stream() uses root_hints() internally for trust anchor validation
    let verified_rrs =
        verify_rr_stream(&rrs).map_err(|e| format!("DNSSEC validation failed: {:?}", e))?;

    // Extract TXT records for the DNS name
    // BIP-353 format: user@domain.com -> user.user._bitcoin-payment.domain.com.
    let dns_query_name = if dns_name.contains('@') {
        let parts: Vec<&str> = dns_name.split('@').collect();
        if parts.len() == 2 {
            let (user, domain) = (parts[0], parts[1]);
            format!("{}.user._bitcoin-payment.{}.", user, domain)
        } else {
            dns_name.clone()
        }
    } else {
        dns_name.clone()
    };

    let txt_records: Vec<String> = verified_rrs
        .resolve_name(
            &dnssec_prover::rr::Name::try_from(dns_query_name.as_str())
                .map_err(|_| "Invalid DNS name format")?,
        )
        .iter()
        .filter_map(|rr| {
            if let RR::Txt(txt) = rr {
                // txt.data.iter() returns an iterator over u8 bytes
                let bytes: Vec<u8> = txt.data.iter().collect();
                Some(String::from_utf8_lossy(&bytes).to_string())
            } else {
                None
            }
        })
        .collect();

    if txt_records.is_empty() {
        return Err(format!(
            "No TXT records found in validated proof for '{}'",
            dns_name
        ));
    }

    Ok((dns_name, txt_records))
}

// =============================================================================
// Silent Payment Tweak Storage (for spending)
// =============================================================================

use bitcoin::OutPoint;
use std::collections::HashMap;

/// Mock tweak database (simulates wallet scanning results)
///
/// In a real wallet implementation, this would be a persistent database
/// that stores tweaks alongside UTXOs after scanning the blockchain.
pub struct TweakDatabase {
    tweaks: HashMap<OutPoint, [u8; 32]>,
}

impl TweakDatabase {
    pub fn new() -> Self {
        Self {
            tweaks: HashMap::new(),
        }
    }

    pub fn store(&mut self, outpoint: OutPoint, tweak: [u8; 32]) {
        self.tweaks.insert(outpoint, tweak);
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<[u8; 32]> {
        self.tweaks.get(outpoint).copied()
    }

    /// Create demo data for testing silent payment spending
    ///
    /// This simulates a wallet that has previously scanned the blockchain
    /// and detected silent payment outputs, storing their tweaks for later spending.
    /// Automatically loads tweaks from VirtualWallet for SP outputs.
    pub fn from_virtual_wallet(wallet: &VirtualWallet) -> Self {
        let mut db = Self::new();

        // Load tweaks from all SP outputs in the virtual wallet
        for vu in wallet.list_utxos() {
            if let Some(tweak) = vu.tweak {
                let outpoint = OutPoint {
                    txid: vu.utxo.txid,
                    vout: vu.utxo.vout,
                };
                db.store(outpoint, tweak);
            }
        }

        db
    }
}

impl Default for TweakDatabase {
    fn default() -> Self {
        Self::new()
    }
}
