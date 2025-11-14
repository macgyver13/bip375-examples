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
/// Note: This is a placeholder that needs actual transaction input/output data.
/// In a real implementation, this should extract amounts from the PSBT's witness_utxo
/// and output amount fields.
pub fn compute_transaction_summary(_psbt: &SilentPaymentPsbt) -> TransactionSummary {
    // TODO: Extract actual values from PSBT
    // For now, return placeholder values
    TransactionSummary {
        total_input: 0,
        total_output: 0,
        fee: 0,
        num_inputs: 0,
        num_outputs: 0,
    }
}
