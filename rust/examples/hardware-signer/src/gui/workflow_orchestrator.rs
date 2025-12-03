//! Workflow Orchestrator - Bridge between GUI state and business logic
//!
//! This module orchestrates workflow steps and captures PSBT changes for visualization.
//! All operations are in-memory with no file I/O.

use super::app_state::*;
use crate::{hw_device::HardwareDevice, wallet_coordinator::WalletCoordinator};
use bip375_core::SilentPaymentPsbt;
use common::*;
use std::collections::HashSet;

/// Orchestrates workflow steps and captures PSBT changes
pub struct WorkflowOrchestrator;

impl WorkflowOrchestrator {
    /// Execute Step 1: Create PSBT
    pub fn execute_create_psbt(state: &mut AppState) -> Result<(), String> {
        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic (auto_continue for GUI mode)
        WalletCoordinator::create_psbt(true)
            .map_err(|e| format!("Failed to create PSBT: {}", e))?;

        // Load the created PSBT
        let (psbt, _metadata) = load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;

        // Identify new fields (all fields are new in this case)
        let new_fields = Self::compute_new_fields(before_psbt.as_ref(), &psbt);

        // Update state
        state.current_psbt = Some(psbt.clone());
        state.psbt_history.push(PsbtSnapshot {
            timestamp: std::time::SystemTime::now(),
            label: "Created by Coordinator".to_string(),
            psbt: psbt.clone(),
            role: Role::Coordinator,
        });
        state.highlighted_fields = new_fields;
        state.workflow_state = WorkflowState::PsbtCreated;
        state.transaction_summary = Some(Self::compute_transaction_summary(&psbt));

        Ok(())
    }

    /// Execute Step 2: Hardware Sign PSBT
    pub fn execute_sign_psbt(state: &mut AppState) -> Result<(), String> {
        // For GUI, we'll auto-approve for simplicity
        // In full implementation, would show approval modal
        Self::execute_sign_after_approval(state)
    }

    /// Actually execute signing after user approval
    fn execute_sign_after_approval(state: &mut AppState) -> Result<(), String> {
        state.active_modal = None;

        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic
        HardwareDevice::sign_workflow(true, true, state.attack_mode)
            .map_err(|e| format!("Failed to sign PSBT: {}", e))?;

        let (psbt, _metadata) =
            load_psbt().map_err(|e| format!("Failed to load signed PSBT: {}", e))?;
        // Identify new fields (ECDH shares, DLEQ proofs, signatures)
        let new_fields = Self::compute_new_fields(before_psbt.as_ref(), &psbt);

        // Update state
        state.current_psbt = Some(psbt.clone());
        state.psbt_history.push(PsbtSnapshot {
            timestamp: std::time::SystemTime::now(),
            label: if state.attack_mode {
                "Signed by Hardware (ATTACK MODE)".to_string()
            } else {
                "Signed by Hardware".to_string()
            },
            psbt: psbt.clone(),
            role: Role::HardwareDevice,
        });
        state.highlighted_fields = new_fields;
        state.workflow_state = WorkflowState::PsbtSigned;

        Ok(())
    }

    /// Execute Step 3: Finalize Transaction
    pub fn execute_finalize(state: &mut AppState) -> Result<(), String> {
        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic with validation
        match WalletCoordinator::finalize_transaction(true) {
            Ok(_) => {
                // Load finalized PSBT (need to reload to see output scripts)
                let (psbt, _) =
                    load_psbt().map_err(|e| format!("Failed to load finalized PSBT: {}", e))?;

                // Compute validation results
                let validation = ValidationResults {
                    ecdh_coverage_complete: true,
                    all_dleq_proofs_valid: true,
                    all_inputs_signed: true,
                    attack_detected: false,
                };

                // Identify new fields (output scripts)
                let new_fields = Self::compute_new_fields(before_psbt.as_ref(), &psbt);

                // Update state
                state.current_psbt = Some(psbt.clone());
                state.psbt_history.push(PsbtSnapshot {
                    timestamp: std::time::SystemTime::now(),
                    label: "Finalized by Coordinator".to_string(),
                    psbt,
                    role: Role::Coordinator,
                });
                state.highlighted_fields = new_fields;
                state.validation_results = Some(validation);
                state.workflow_state = WorkflowState::TransactionExtracted;

                Ok(())
            }
            Err(e) => {
                // Attack detected! Show error
                let validation = ValidationResults {
                    ecdh_coverage_complete: true,
                    all_dleq_proofs_valid: false,
                    all_inputs_signed: true,
                    attack_detected: true,
                };

                state.validation_results = Some(validation);
                state.active_modal = Some(ModalType::ValidationError {
                    error_message: format!("Attack Detected!\n\n{}", e),
                });

                Err(format!("Validation failed: {}", e))
            }
        }
    }

    /// Reset workflow
    pub fn execute_reset(state: &mut AppState) -> Result<(), String> {
        WalletCoordinator::reset().map_err(|e| format!("Failed to reset: {}", e))?;

        *state = AppState::default();
        Ok(())
    }

    /// Compute which fields are new by diffing PSBTs
    fn compute_new_fields(
        before: Option<&SilentPaymentPsbt>,
        after: &SilentPaymentPsbt,
    ) -> HashSet<FieldIdentifier> {
        bip375_gui_common::psbt_analyzer::compute_field_diff(before, after)
    }

    /// Compute transaction summary from PSBT
    fn compute_transaction_summary(psbt: &SilentPaymentPsbt) -> TransactionSummary {
        bip375_gui_common::psbt_analyzer::compute_transaction_summary(psbt)
    }
}
