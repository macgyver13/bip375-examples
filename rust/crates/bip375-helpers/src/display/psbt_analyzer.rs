//! PSBT analysis utilities for GUI visualization
//!
//! Provides functions for extracting field information from PSBTs,
//! computing differences between PSBT states, and identifying field types.

use super::field_identifier::{FieldIdentifier, TransactionSummary};

use crate::PSBT_OUT_DNSSEC_PROOF;
use spdk_core::psbt::{GlobalFieldsExt, InputFieldsExt, OutputFieldsExt, SilentPaymentPsbt};
use std::collections::HashSet;

/// Extract all field identifiers from a PSBT
///
/// Returns a set of unique field identifiers covering all global, input, and output fields.
pub fn extract_all_field_identifiers(psbt: &SilentPaymentPsbt) -> HashSet<FieldIdentifier> {
    let mut fields = HashSet::new();

    // Global fields (standard + unknown)
    for (key_type, key_data, _) in psbt.global.iter_global_fields() {
        let identifier = FieldIdentifier::Global {
            key_type,
            key_data: key_data.clone(),
        };
        fields.insert(identifier);
    }

    // Input fields (standard + unknown)
    for (index, input) in psbt.inputs.iter().enumerate() {
        for (key_type, key_data, _) in input.iter_input_fields() {
            let identifier = FieldIdentifier::Input {
                index,
                key_type,
                key_data: key_data.clone(),
            };
            fields.insert(identifier);
        }
    }

    // Output fields (standard + unknown)
    for (index, output) in psbt.outputs.iter().enumerate() {
        for (key_type, key_data, _) in output.iter_output_fields() {
            let identifier = FieldIdentifier::Output {
                index,
                key_type,
                key_data: key_data.clone(),
            };
            fields.insert(identifier);
        }
    }

    fields
}

/// Compute which fields are new by comparing two PSBTs
///
/// Returns the set of fields present in `after` but not in `before`.
/// If `before` is None, all fields in `after` are considered new.
pub fn compute_field_diff(
    before: Option<&SilentPaymentPsbt>,
    after: &SilentPaymentPsbt,
) -> HashSet<FieldIdentifier> {
    let before_fields = match before {
        Some(psbt) => extract_all_field_identifiers(psbt),
        None => HashSet::new(),
    };

    let after_fields = extract_all_field_identifiers(after);

    // New fields are in 'after' but not in 'before'
    after_fields.difference(&before_fields).cloned().collect()
}

/// Compute transaction summary from PSBT
///
/// Extracts input amounts from witness_utxo fields and output amounts
/// from the amount field to compute totals and fees.
/// Also extracts DNSSEC proofs for DNS contact display.
pub fn compute_transaction_summary(psbt: &SilentPaymentPsbt) -> TransactionSummary {
    let mut total_input = 0u64;
    let mut total_output = 0u64;
    let num_inputs = psbt.inputs.len();
    let num_outputs = psbt.outputs.len();
    let mut dnssec_contacts = std::collections::HashMap::new();

    // Extract input amounts from witness_utxo fields
    // In rust-psbt, witness_utxo is a structured field, not raw bytes
    for input in &psbt.inputs {
        if let Some(witness_utxo) = &input.witness_utxo {
            total_input += witness_utxo.value.to_sat();
        }
    }

    // Extract output amounts and DNSSEC proofs
    for (output_idx, output) in psbt.outputs.iter().enumerate() {
        // In rust-psbt, amount is a structured field
        total_output += output.amount.to_sat();

        // Check for DNSSEC proofs in unknown fields
        for (key, value) in &output.unknowns {
            if key.type_value == PSBT_OUT_DNSSEC_PROOF {
                // Try to validate DNSSEC proof, fall back to decode-only
                match validate_dnssec_proof(value) {
                    Ok((dns_name, _txt_records)) => {
                        // DNSSEC validation succeeded
                        dnssec_contacts.insert(output_idx, format!("{} ✓", dns_name));
                    }
                    Err(_) => {
                        // Validation failed, try to at least decode the DNS name
                        if let Ok(dns_name) = decode_dnssec_proof(value) {
                            dnssec_contacts.insert(output_idx, format!("{} ⚠", dns_name));
                        }
                    }
                }
            }
        }
    }

    // Calculate fee (inputs - outputs)
    let fee = total_input.saturating_sub(total_output);

    TransactionSummary {
        total_input,
        total_output,
        fee,
        num_inputs,
        num_outputs,
        dnssec_contacts,
    }
}

/// Decode DNSSEC proof to extract DNS name (BIP 353 format)
///
/// Format: <1-byte-length><dns_name><proof_data>
fn decode_dnssec_proof(proof_bytes: &[u8]) -> Result<String, String> {
    if proof_bytes.is_empty() {
        return Err("DNSSEC proof too short (missing length byte)".to_string());
    }

    let dns_name_length = proof_bytes[0] as usize;

    if proof_bytes.len() < 1 + dns_name_length {
        return Err(format!(
            "DNSSEC proof too short (expected {} bytes minimum)",
            1 + dns_name_length
        ));
    }

    let dns_name_bytes = &proof_bytes[1..1 + dns_name_length];
    String::from_utf8(dns_name_bytes.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in DNS name: {}", e))
}

/// Validate DNSSEC proof using RFC 9102 validation (BIP 353 format)
///
/// Returns (dns_name, txt_records) if validation succeeds, or an error if it fails.
/// This performs cryptographic validation of the DNSSEC chain.
fn validate_dnssec_proof(proof_bytes: &[u8]) -> Result<(String, Vec<String>), String> {
    use dnssec_prover::rr::{Name, RR};
    use dnssec_prover::ser::parse_rr_stream;
    use dnssec_prover::validation::verify_rr_stream;

    // First decode to get DNS name and RFC 9102 proof data
    if proof_bytes.is_empty() {
        return Err("DNSSEC proof too short".to_string());
    }

    let dns_name_length = proof_bytes[0] as usize;
    if proof_bytes.len() < 1 + dns_name_length {
        return Err("DNSSEC proof too short".to_string());
    }

    let dns_name_bytes = &proof_bytes[1..1 + dns_name_length];
    let dns_name = String::from_utf8(dns_name_bytes.to_vec())
        .map_err(|_| "Invalid UTF-8 in DNS name".to_string())?;

    let rfc9102_proof = &proof_bytes[1 + dns_name_length..];

    // Check if this is a mock proof
    if rfc9102_proof.starts_with(b"MOCK_DNSSEC_PROOF_") {
        return Err("Mock proof cannot be validated".to_string());
    }

    // Parse RFC 9102 proof
    let rrs =
        parse_rr_stream(rfc9102_proof).map_err(|_| "Failed to parse RFC 9102 proof".to_string())?;

    // Verify DNSSEC chain
    let verified_rrs =
        verify_rr_stream(&rrs).map_err(|_| "DNSSEC validation failed".to_string())?;

    // Extract TXT records
    let dns_query_name = if dns_name.contains('@') {
        let parts: Vec<&str> = dns_name.split('@').collect();
        if parts.len() == 2 {
            format!("{}.user._bitcoin-payment.{}.", parts[0], parts[1])
        } else {
            dns_name.clone()
        }
    } else {
        dns_name.clone()
    };

    let query_name = Name::try_from(dns_query_name.as_str())
        .map_err(|_| "Invalid DNS name format".to_string())?;

    let txt_records: Vec<String> = verified_rrs
        .resolve_name(&query_name)
        .iter()
        .filter_map(|rr| {
            if let RR::Txt(txt) = rr {
                let bytes: Vec<u8> = txt.data.iter().collect();
                Some(String::from_utf8_lossy(&bytes).to_string())
            } else {
                None
            }
        })
        .collect();

    if txt_records.is_empty() {
        return Err("No TXT records found".to_string());
    }

    Ok((dns_name, txt_records))
}
