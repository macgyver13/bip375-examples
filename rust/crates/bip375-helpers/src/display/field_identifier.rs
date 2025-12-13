//! Field identification types for PSBT visualization
//!
//! Provides types for uniquely identifying and tracking PSBT fields across
//! different map types (Global, Input, Output) for highlighting and comparison.

use serde::{Deserialize, Serialize};

/// Uniquely identifies a PSBT field by its location and key
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum FieldIdentifier {
    /// Global field (no index)
    Global { field_type: u8, key_data: Vec<u8> },
    /// Input field (with input index)
    Input {
        index: usize,
        field_type: u8,
        key_data: Vec<u8>,
    },
    /// Output field (with output index)
    Output {
        index: usize,
        field_type: u8,
        key_data: Vec<u8>,
    },
}

/// Transaction summary information
#[derive(Clone, Debug)]
pub struct TransactionSummary {
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
    pub num_inputs: usize,
    pub num_outputs: usize,
    /// DNS contacts for outputs (output_index -> dns_name)
    pub dnssec_contacts: std::collections::HashMap<usize, String>,
}
