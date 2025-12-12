//! Application state management
//!
//! This module defines the single source of truth for the GUI application state.

use bip375_core::SilentPaymentPsbt;
use common::TransactionConfig;
use std::collections::HashSet;

// Re-export types from gui-common for convenience
pub use bip375_gui_common::field_identifier::{FieldIdentifier, TransactionSummary};

/// Main application state (single source of truth)
#[derive(Clone, Debug)]
pub struct AppState {
    /// Current workflow state
    pub workflow_state: WorkflowState,

    /// Current PSBT (may be None if not created yet)
    pub current_psbt: Option<SilentPaymentPsbt>,

    /// PSBT snapshots for "before/after" comparison
    pub psbt_history: Vec<PsbtSnapshot>,

    /// Which fields were added in the last operation
    pub highlighted_fields: HashSet<FieldIdentifier>,

    /// Attack mode toggle
    pub attack_mode: bool,

    /// Validation results
    pub validation_results: Option<ValidationResults>,

    /// Transaction summary data
    pub transaction_summary: Option<TransactionSummary>,

    /// Currently selected field (for detail view)
    pub selected_field: Option<FieldIdentifier>,

    /// Modal dialog state
    pub active_modal: Option<ModalType>,

    /// Transaction configuration (UTXO selection, amounts)
    pub tx_config: TransactionConfig,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            workflow_state: WorkflowState::Ready,
            current_psbt: None,
            psbt_history: Vec::new(),
            highlighted_fields: HashSet::new(),
            attack_mode: false,
            validation_results: None,
            transaction_summary: None,
            selected_field: None,
            active_modal: None,
            tx_config: TransactionConfig::hardware_wallet_auto(),
        }
    }
}

/// Workflow state machine
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkflowState {
    Ready,
    PsbtCreated,
    HardwareApprovalPending,
    PsbtSigned,
    TransactionExtracted,
}

/// PSBT snapshot for history (hardware-signer specific with role)
#[derive(Clone, Debug)]
pub struct PsbtSnapshot {
    pub timestamp: std::time::SystemTime,
    pub label: String,
    pub psbt: SilentPaymentPsbt,
    pub role: Role,
}

/// Role that created this snapshot
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Coordinator,
    HardwareDevice,
}

/// Validation results from comprehensive checks
#[derive(Clone, Debug)]
pub struct ValidationResults {
    pub ecdh_coverage_complete: bool,
    pub all_dleq_proofs_valid: bool,
    pub all_inputs_signed: bool,
    pub attack_detected: bool,
}

/// Modal dialog types
#[derive(Clone, Debug)]
pub enum ModalType {
    HardwareApproval {
        transaction_summary: String,
    },
    AirGapTransfer {
        from: String,
        to: String,
        filename: String,
    },
    ValidationError {
        error_message: String,
    },
    UtxoSelector, // Show UTXO selection dialog
}
