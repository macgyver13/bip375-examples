//! Application state management for multi-signer GUI
//!
//! Manages state for flexible multi-party signing workflow

use bip375_helpers::wallet::MultiPartyConfig;
use spdk_core::psbt::SilentPaymentPsbt;
use std::collections::HashSet;

// Re-export types from gui-common for convenience
pub use bip375_helpers::display::field_identifier::{FieldIdentifier, TransactionSummary};

/// Main application state for multi-signer workflow
#[derive(Clone, Debug)]
pub struct AppState {
    /// Multi-party configuration (always present)
    pub multi_config: MultiPartyConfig,

    /// Current workflow state
    pub workflow_state: WorkflowState,

    /// Signing progress tracking
    pub signing_progress: SigningProgress,

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
        // Initialize with default 3-party configuration
        let multi_config = crate::shared_utils::create_multi_party_config_default()
            .expect("Failed to create default multi-party config");

        Self {
            multi_config,
            workflow_state: WorkflowState::ConfiguringParties,
            signing_progress: SigningProgress::default(),
            current_psbt: None,
            highlighted_fields: HashSet::new(),
            ecdh_coverage: EcdhCoverageState::default(),
            input_states: Vec::new(),
            transaction_summary: None,
            validation_summary: None,
        }
    }
}

/// Flexible workflow state for multi-party signing
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkflowState {
    ConfiguringParties,
    PsbtCreated,
    PartialSigned(usize),
    FullySigned,
    Finalized,
    TransactionExtracted,
}

/// Signing progress tracking
#[derive(Clone, Debug, Default)]
pub struct SigningProgress {
    pub total_inputs: usize,
    pub signed_inputs: HashSet<usize>,
    pub parties_completed: HashSet<String>,
}

impl SigningProgress {
    pub fn new(total_inputs: usize) -> Self {
        Self {
            total_inputs,
            signed_inputs: HashSet::new(),
            parties_completed: HashSet::new(),
        }
    }

    pub fn mark_input_signed(&mut self, input_index: usize) {
        self.signed_inputs.insert(input_index);
    }

    pub fn mark_party_completed(&mut self, party_name: String) {
        self.parties_completed.insert(party_name);
    }

    pub fn is_fully_signed(&self) -> bool {
        self.signed_inputs.len() >= self.total_inputs && self.total_inputs > 0
    }

    pub fn completion_fraction(&self) -> String {
        format!("{}/{}", self.signed_inputs.len(), self.total_inputs)
    }
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
    /// Party assigned to sign this input
    pub assigned_party: Option<String>,
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
            assigned_party: None,
            has_ecdh_share: false,
            has_dleq_proof: false,
            has_signature: false,
        }
    }

    pub fn with_party(index: usize, party_name: String) -> Self {
        Self {
            index,
            assigned_party: Some(party_name),
            has_ecdh_share: false,
            has_dleq_proof: false,
            has_signature: false,
        }
    }

    pub fn party_name(&self) -> &str {
        self.assigned_party.as_deref().unwrap_or("Unassigned")
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
