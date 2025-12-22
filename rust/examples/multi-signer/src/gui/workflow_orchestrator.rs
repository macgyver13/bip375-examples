//! Workflow Orchestrator for Multi-Signer GUI
//!
//! Orchestrates flexible multi-party signing workflow and captures PSBT changes

use super::app_state::*;
use crate::alice_creates::alice_creates;
use crate::bob_signs::bob_signs;
use crate::charlie_finalizes::charlie_finalizes;
use crate::workflow_actions;
use bip375_core::{Bip375PsbtExt, SilentPaymentPsbt};
use bip375_helpers::display::{psbt_analyzer, psbt_io::load_psbt, psbt_io::save_psbt};
use bip375_io::PsbtMetadata;
use secp256k1::Secp256k1;

/// Orchestrates multi-party workflow steps
pub struct WorkflowOrchestrator;

impl WorkflowOrchestrator {
    /// Execute Step 1: Alice creates PSBT
    pub fn execute_alice_creates(state: &mut AppState) -> Result<(), String> {
        // Save current PSBT for diff computation
        let before_psbt = state.current_psbt.clone();

        // Execute Alice's workflow
        alice_creates().map_err(|e| format!("Alice creates failed: {}", e))?;

        // Load the PSBT and update state
        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        // Update workflow state
        state.workflow_state = WorkflowState::PartialSigned(1);

        Ok(())
    }

    /// Execute Step 2: Bob signs
    pub fn execute_bob_signs(state: &mut AppState) -> Result<(), String> {
        // Save current PSBT for diff computation
        let before_psbt = state.current_psbt.clone();

        // Execute Bob's workflow
        bob_signs().map_err(|e| format!("Bob signs failed: {}", e))?;

        // Load the PSBT and update state
        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        // Update workflow state
        state.workflow_state = WorkflowState::PartialSigned(2);

        Ok(())
    }

    /// Execute Step 3: Charlie finalizes
    pub fn execute_charlie_finalizes(state: &mut AppState) -> Result<(), String> {
        // Save current PSBT for diff computation
        let before_psbt = state.current_psbt.clone();

        // Execute Charlie's workflow
        charlie_finalizes().map_err(|e| format!("Charlie finalizes failed: {}", e))?;

        // Load the PSBT and update state
        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        // Update workflow state
        state.workflow_state = WorkflowState::TransactionExtracted;

        Ok(())
    }

    /// Reset workflow state
    pub fn execute_reset(state: &mut AppState) -> Result<(), String> {
        // Clear state
        *state = AppState::default();

        // TODO: Clean up output files

        Ok(())
    }

    /// Compute ECDH coverage from PSBT
    pub fn compute_ecdh_coverage(psbt: &SilentPaymentPsbt) -> EcdhCoverageState {
        let total_inputs = psbt.num_inputs();
        let mut inputs_with_ecdh = 0;

        // Count inputs that have ECDH shares
        for input in &psbt.inputs {
            if !input.sp_ecdh_shares.is_empty() {
                inputs_with_ecdh += 1;
            }
        }

        EcdhCoverageState::new(inputs_with_ecdh, total_inputs)
    }

    /// Compute per-input states from PSBT
    pub fn compute_input_states(psbt: &SilentPaymentPsbt) -> Vec<InputState> {
        let mut states = Vec::new();

        for (index, input) in psbt.inputs.iter().enumerate() {
            let mut state = InputState::new(index);

            // Check for ECDH share
            state.has_ecdh_share = !input.sp_ecdh_shares.is_empty();

            // Check for DLEQ proof
            state.has_dleq_proof = !input.sp_dleq_proofs.is_empty();

            // Check for signature (partial_sig in structured field)
            state.has_signature = !input.partial_sigs.is_empty();

            // Determine assigned party based on index (Alice=0, Bob=1, Charlie=2)
            if state.has_signature {
                let party_name = match index {
                    0 => "Alice",
                    1 => "Bob",
                    2 => "Charlie",
                    _ => "Unknown",
                };
                state.assigned_party = Some(party_name.to_string());
            }

            states.push(state);
        }

        states
    }

    /// Compute validation summary
    pub fn compute_validation_summary(psbt: &SilentPaymentPsbt) -> ValidationSummary {
        let input_states = Self::compute_input_states(psbt);

        // Check if all inputs are signed
        let all_signed = input_states.iter().all(|s| s.has_signature);

        // Check if all DLEQ proofs are present (simplified - not verifying validity here)
        let dleq_proofs_valid = input_states.iter().all(|s| s.has_dleq_proof);

        // Check if output scripts have been computed (outputs have script_pubkey set)
        let output_scripts_computed = psbt
            .outputs
            .iter()
            .any(|output| !output.script_pubkey.is_empty());

        // Check if transaction has been extracted (TX_MODIFIABLE flag in global)
        let transaction_extracted = psbt.global.tx_modifiable_flags == 0;

        ValidationSummary {
            dleq_proofs_valid,
            all_signed,
            output_scripts_computed,
            transaction_extracted,
        }
    }

    /// Load PSBT and update state
    pub fn load_psbt_and_update(
        state: &mut AppState,
        before_psbt: Option<&SilentPaymentPsbt>,
    ) -> Result<(), String> {
        // Load PSBT from transfer file
        let (psbt, _metadata) = load_psbt().map_err(|e| format!("Failed to load PSBT: {}", e))?;

        // Compute new fields
        let new_fields = psbt_analyzer::compute_field_diff(before_psbt, &psbt);

        // Update state
        state.current_psbt = Some(psbt.clone());
        state.highlighted_fields = new_fields;

        // Compute ECDH coverage
        state.ecdh_coverage = Self::compute_ecdh_coverage(&psbt);

        // Compute input states
        state.input_states = Self::compute_input_states(&psbt);

        // Compute transaction summary
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&psbt));

        // Compute validation summary
        state.validation_summary = Some(Self::compute_validation_summary(&psbt));

        Ok(())
    }
}
