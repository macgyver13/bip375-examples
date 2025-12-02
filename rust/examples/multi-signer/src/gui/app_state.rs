//! Application state management for multi-signer GUI
//!
//! Manages state for the 3-party signing workflow (Alice → Bob → Charlie)

use bip375_core::{Bip375PsbtExt, SilentPaymentPsbt};
use std::collections::HashSet;

// Re-export types from gui-common for convenience
pub use bip375_gui_common::field_identifier::{FieldIdentifier, TransactionSummary};

/// Main application state for multi-signer workflow
#[derive(Clone, Debug)]
pub struct AppState {
    /// Current workflow state
    pub workflow_state: MultiSignerState,

    /// Current PSBT (may be None if not created yet)
    pub current_psbt: Option<SilentPaymentPsbt>,

    /// Which fields were added in the last operation
    pub highlighted_fields: HashSet<FieldIdentifier>,

    /// ECDH coverage state (how many inputs have ECDH shares)
    pub ecdh_coverage: EcdhCoverageState,

    /// Per-input state tracking
    pub input_states: Vec<InputState>,

    /// Transaction summary data
    pub transaction_summary: Option<TransactionSummary>,

    /// Validation summary
    pub validation_summary: Option<ValidationSummary>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            workflow_state: MultiSignerState::Ready,
            current_psbt: None,
            highlighted_fields: HashSet::new(),
            ecdh_coverage: EcdhCoverageState::default(),
            input_states: Vec::new(),
            transaction_summary: None,
            validation_summary: None,
        }
    }
}

/// Workflow state for multi-party signing
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiSignerState {
    Ready,
    AliceComplete,
    BobComplete,
    CharlieComplete,
    TransactionExtracted,
}

/// ECDH coverage tracking
#[derive(Clone, Debug, Default)]
pub struct EcdhCoverageState {
    /// Number of inputs with ECDH shares
    pub inputs_with_ecdh: usize,
    /// Total number of inputs
    pub total_inputs: usize,
    /// Whether ECDH coverage is complete (equal to total inputs)
    pub is_complete: bool,
}

impl EcdhCoverageState {
    pub fn new(inputs_with_ecdh: usize, total_inputs: usize) -> Self {
        Self {
            inputs_with_ecdh,
            total_inputs,
            is_complete: inputs_with_ecdh >= total_inputs && total_inputs > 0,
        }
    }

    /// Get coverage as a fraction string (e.g., "2/3")
    pub fn as_fraction(&self) -> String {
        format!("{}/{}", self.inputs_with_ecdh, self.total_inputs)
    }

    /// Get coverage as a percentage (0-100)
    pub fn as_percentage(&self) -> f32 {
        if self.total_inputs == 0 {
            0.0
        } else {
            (self.inputs_with_ecdh as f32 / self.total_inputs as f32) * 100.0
        }
    }
}

/// Per-input state tracking
#[derive(Clone, Debug)]
pub struct InputState {
    /// Input index
    pub index: usize,
    /// Who signed this input (Alice=0, Bob=1, Charlie=2)
    pub signer: Option<usize>,
    /// Has ECDH share
    pub has_ecdh_share: bool,
    /// Has DLEQ proof
    pub has_dleq_proof: bool,
    /// Has signature
    pub has_signature: bool,
}

impl InputState {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            signer: None,
            has_ecdh_share: false,
            has_dleq_proof: false,
            has_signature: false,
        }
    }

    /// Get signer name
    pub fn signer_name(&self) -> &'static str {
        match self.signer {
            Some(0) => "Alice",
            Some(1) => "Bob",
            Some(2) => "Charlie",
            _ => "None",
        }
    }
}

/// Validation summary for multi-party workflow
#[derive(Clone, Debug)]
pub struct ValidationSummary {
    /// DLEQ proofs verified successfully
    pub dleq_proofs_valid: bool,
    /// All inputs have signatures
    pub all_signed: bool,
    /// Output scripts have been computed
    pub output_scripts_computed: bool,
    /// Transaction extracted successfully
    pub transaction_extracted: bool,
}
