//! PSBT analysis utilities for GUI visualization
//!
//! Provides functions for extracting field information from PSBTs,
//! computing differences between PSBT states, and identifying field types.

use crate::field_identifier::{FieldIdentifier, TransactionSummary};
use bip375_core::{constants, SilentPaymentPsbt};
use std::collections::HashSet;

/// Extract all field identifiers from a PSBT
///
/// Returns a set of unique field identifiers covering all global, input, and output fields.
pub fn extract_all_field_identifiers(psbt: &SilentPaymentPsbt) -> HashSet<FieldIdentifier> {
    let mut fields = HashSet::new();

    // Global unknown fields (custom/proprietary fields stored in unknowns map)
    // TODO: use psbt.global named fields instead of unknowns
    for key in psbt.global.unknowns.keys() {
        fields.insert(FieldIdentifier::Global {
            field_type: key.type_value,
            key_data: key.key.clone(),
        });
    }

    // Input unknown fields
    for (index, input) in psbt.inputs.iter().enumerate() {
        for key in input.unknowns.keys() {
            fields.insert(FieldIdentifier::Input {
                index,
                field_type: key.type_value,
                key_data: key.key.clone(),
            });
        }
    }

    // Output unknown fields
    for (index, output) in psbt.outputs.iter().enumerate() {
        for key in output.unknowns.keys() {
            fields.insert(FieldIdentifier::Output {
                index,
                field_type: key.type_value,
                key_data: key.key.clone(),
            });
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

/// Check if a field type is BIP-375 silent payment specific
pub fn is_sp_field(field_type: u8) -> bool {
    matches!(
        field_type,
        constants::PSBT_IN_SP_ECDH_SHARE
            | constants::PSBT_IN_SP_DLEQ
            | constants::PSBT_OUT_SP_V0_INFO
            | constants::PSBT_OUT_SP_V0_LABEL
    )
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
            if key.type_value == constants::PSBT_OUT_DNSSEC_PROOF {
                // Decode DNSSEC proof to extract DNS name
                if let Ok(dns_name) = decode_dnssec_proof(value) {
                    dnssec_contacts.insert(output_idx, dns_name);
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
