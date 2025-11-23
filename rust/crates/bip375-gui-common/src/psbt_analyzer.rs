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

    // Global fields
    for field in &psbt.global_fields {
        fields.insert(FieldIdentifier::Global {
            field_type: field.field_type,
            key_data: field.key_data.clone(),
        });
    }

    // Input fields
    for (index, input_map) in psbt.input_maps.iter().enumerate() {
        for field in input_map {
            fields.insert(FieldIdentifier::Input {
                index,
                field_type: field.field_type,
                key_data: field.key_data.clone(),
            });
        }
    }

    // Output fields
    for (index, output_map) in psbt.output_maps.iter().enumerate() {
        for field in output_map {
            fields.insert(FieldIdentifier::Output {
                index,
                field_type: field.field_type,
                key_data: field.key_data.clone(),
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
        constants::PSBT_GLOBAL_SP_ECDH_SHARE
            | constants::PSBT_GLOBAL_SP_DLEQ
            | constants::PSBT_IN_SP_ECDH_SHARE
            | constants::PSBT_IN_SP_DLEQ
            | constants::PSBT_OUT_SP_V0_INFO
            | constants::PSBT_OUT_SP_V0_LABEL
    )
}

/// Compute transaction summary from PSBT
///
/// Extracts input amounts from PSBT_IN_WITNESS_UTXO fields and output amounts
/// from PSBT_OUT_AMOUNT fields to compute totals and fees.
pub fn compute_transaction_summary(psbt: &SilentPaymentPsbt) -> TransactionSummary {
    let mut total_input = 0u64;
    let mut total_output = 0u64;
    let num_inputs = psbt.input_maps.len();
    let num_outputs = psbt.output_maps.len();

    // Extract input amounts from PSBT_IN_WITNESS_UTXO fields
    for input_map in &psbt.input_maps {
        for field in input_map {
            if field.field_type == constants::PSBT_IN_WITNESS_UTXO {
                // PSBT_IN_WITNESS_UTXO contains a TxOut structure:
                // - 8 bytes: amount (little-endian u64)
                // - variable: scriptPubKey (compact size + script)
                if field.value_data.len() >= 8 {
                    let amount_bytes: [u8; 8] = field.value_data[0..8]
                        .try_into()
                        .expect("slice is exactly 8 bytes as verified by length check");
                    let amount = u64::from_le_bytes(amount_bytes);
                    total_input += amount;
                }
            }
        }
    }

    // Extract output amounts from PSBT_OUT_AMOUNT fields
    for output_map in &psbt.output_maps {
        for field in output_map {
            if field.field_type == constants::PSBT_OUT_AMOUNT {
                // PSBT_OUT_AMOUNT is a 64-bit signed little-endian integer per PSBT v2 spec
                if field.value_data.len() == 8 {
                    let amount_bytes: [u8; 8] = field.value_data[0..8]
                        .try_into()
                        .expect("slice is exactly 8 bytes as verified by length check");
                    let amount = u64::from_le_bytes(amount_bytes);
                    total_output += amount;
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
    }
}
