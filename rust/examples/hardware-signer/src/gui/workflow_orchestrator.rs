//! Workflow Orchestrator - Bridge between GUI state and business logic
//!
//! This module orchestrates workflow steps and captures PSBT changes for visualization.
//! All operations are in-memory with no file I/O.

use super::app_state::*;
use crate::{hw_device::HardwareDevice, wallet_coordinator::WalletCoordinator};
use bip375_core::SilentPaymentPsbt;
use bip375_helpers::display::{psbt_analyzer, psbt_io::load_psbt};
use std::collections::HashSet;

/// Orchestrates workflow steps and captures PSBT changes
pub struct WorkflowOrchestrator;

impl WorkflowOrchestrator {
    /// Execute Step 1: Create PSBT
    #[allow(dead_code)]
    pub fn execute_create_psbt(state: &mut AppState) -> Result<(), String> {
        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic using the configured transaction config
        WalletCoordinator::create_psbt(&state.tx_config, true, state.mnemonic.as_deref())
            .map_err(|e| format!("Failed to create PSBT: {}", e))?;

        // Load the created PSBT
        let (psbt, _metadata) = load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;

        // Identify new fields (all fields are new in this case)
        let new_fields = Self::compute_new_fields(before_psbt.as_ref(), &psbt);

        // Update state
        state.current_psbt = Some(psbt.clone());
        state.highlighted_fields = new_fields;
        state.workflow_state = WorkflowState::PsbtCreated;
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&psbt));

        Ok(())
    }

    /// Execute Step 2: Hardware Sign PSBT
    #[allow(dead_code)]
    pub fn execute_sign_psbt(state: &mut AppState) -> Result<(), String> {
        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic with config
        HardwareDevice::sign_workflow(
            &state.tx_config,
            true,
            true,
            state.attack_mode,
            state.mnemonic.as_deref(),
        )
        .map_err(|e| format!("Failed to sign PSBT: {}", e))?;

        let (psbt, _metadata) =
            load_psbt().map_err(|e| format!("Failed to load signed PSBT: {}", e))?;
        // Identify new fields (ECDH shares, DLEQ proofs, signatures)
        let new_fields = Self::compute_new_fields(before_psbt.as_ref(), &psbt);

        // Update state
        state.current_psbt = Some(psbt.clone());
        state.highlighted_fields = new_fields;
        state.workflow_state = WorkflowState::PsbtSigned;

        Ok(())
    }

    /// Execute Step 3: Finalize Transaction
    #[allow(dead_code)]
    pub fn execute_finalize(state: &mut AppState) -> Result<(), String> {
        // Take snapshot before
        let before_psbt = state.current_psbt.clone();

        // Execute business logic with validation and config
        match WalletCoordinator::finalize_transaction(
            &state.tx_config,
            true,
            state.mnemonic.as_deref(),
        ) {
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

                Err(format!("Validation failed: {}", e))
            }
        }
    }

    /// Reset workflow
    #[allow(dead_code)]
    pub fn execute_reset(state: &mut AppState) -> Result<(), String> {
        WalletCoordinator::reset().map_err(|e| format!("Failed to reset: {}", e))?;

        // Preserve the transaction config and mnemonic across resets
        let preserved_config = state.tx_config.clone();
        let preserved_mnemonic = state.mnemonic.clone();
        *state = AppState::default();
        state.tx_config = preserved_config;
        state.mnemonic = preserved_mnemonic;
        Ok(())
    }

    /// Compute which fields are new by diffing PSBTs
    fn compute_new_fields(
        before: Option<&SilentPaymentPsbt>,
        after: &SilentPaymentPsbt,
    ) -> HashSet<FieldIdentifier> {
        psbt_analyzer::compute_field_diff(before, after)
    }
}
