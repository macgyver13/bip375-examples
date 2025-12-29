//! Workflow Orchestrator for Multi-Signer GUI
//!
//! Orchestrates flexible multi-party signing workflow and captures PSBT changes

use super::app_state::*;
use crate::workflow_actions;
use bip375_core::SilentPaymentPsbt;
use bip375_helpers::display::{psbt_analyzer, psbt_io::load_psbt};
use secp256k1::Secp256k1;
use silentpayments::psbt::Bip375PsbtExt;

/// Orchestrates multi-party workflow steps
pub struct WorkflowOrchestrator;

impl WorkflowOrchestrator {
    /// Reset workflow state
    pub fn execute_reset(state: &mut AppState) -> Result<(), String> {
        // Clear state
        *state = AppState::default();

        // TODO: Clean up output files

        Ok(())
    }

    /// Compute ECDH coverage from PSBT
    pub fn compute_ecdh_coverage(psbt: &SilentPaymentPsbt) -> EcdhCoverageState {
        let total_inputs = psbt.inputs.len();
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

    /// Flexible workflow: Create PSBT (without signing)
    pub fn execute_create_psbt_flexible(state: &mut AppState) -> Result<(), String> {
        let config = state.multi_config.clone();

        let before_psbt = state.current_psbt.clone();

        // Create PSBT without signing
        let psbt = workflow_actions::create_psbt_only(&config)?;

        workflow_actions::save_psbt_with_party_metadata(&psbt, &config, "PSBT Created")?;

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        // Initialize signing progress but don't mark anything as signed yet
        let total_inputs = config.get_total_inputs();
        state.signing_progress = SigningProgress::new(total_inputs);

        // State remains ready for first signer
        state.workflow_state = WorkflowState::PartialSigned(0);

        Ok(())
    }

    /// Flexible workflow: Sign inputs for a specific party
    pub fn execute_sign_for_party_flexible(
        state: &mut AppState,
        party_name: &str,
    ) -> Result<(), String> {
        let config = state.multi_config.clone();

        let party = config
            .parties
            .iter()
            .find(|p| p.name == party_name)
            .cloned()
            .ok_or(format!("Party {} not found", party_name))?;

        let secp = Secp256k1::new();
        let before_psbt = state.current_psbt.clone();

        let (mut psbt, _) = load_psbt().map_err(|e| format!("Load failed: {:?}", e))?;

        let signed_indices =
            workflow_actions::sign_inputs_for_party(&mut psbt, &party, &config, &secp)?;

        workflow_actions::save_psbt_with_party_metadata(
            &psbt,
            &config,
            format!("{} signed", party_name),
        )?;

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        for &idx in &signed_indices {
            state.signing_progress.mark_input_signed(idx);
        }
        state
            .signing_progress
            .mark_party_completed(party_name.to_string());

        let signed_count = state.signing_progress.signed_inputs.len();
        state.workflow_state = if state.signing_progress.is_fully_signed() {
            WorkflowState::FullySigned
        } else {
            WorkflowState::PartialSigned(signed_count)
        };

        Ok(())
    }

    /// Flexible workflow: Finalize and extract transaction
    pub fn execute_finalize_flexible(state: &mut AppState) -> Result<(), String> {
        let config = state.multi_config.clone();

        let secp = Secp256k1::new();
        let before_psbt = state.current_psbt.clone();

        let (mut psbt, _) = load_psbt().map_err(|e| format!("Load failed: {:?}", e))?;

        let _tx = workflow_actions::finalize_and_extract(&mut psbt, &secp)?;

        workflow_actions::save_psbt_with_party_metadata(&psbt, &config, "Transaction Extracted")?;

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        state.workflow_state = WorkflowState::TransactionExtracted;

        Ok(())
    }

    /// Check if party can sign (has unsigned inputs assigned to them)
    pub fn can_party_sign(state: &AppState, party_name: &str) -> bool {
        if let Some(party) = state
            .multi_config
            .parties
            .iter()
            .find(|p| p.name == party_name)
        {
            return party
                .controlled_input_indices
                .iter()
                .any(|&idx| !state.signing_progress.signed_inputs.contains(&idx));
        }
        false
    }

    /// Get pending input indices for party
    pub fn get_pending_inputs_for_party(state: &AppState, party_name: &str) -> Vec<usize> {
        if let Some(party) = state
            .multi_config
            .parties
            .iter()
            .find(|p| p.name == party_name)
        {
            return party
                .controlled_input_indices
                .iter()
                .filter(|&&idx| !state.signing_progress.signed_inputs.contains(&idx))
                .copied()
                .collect();
        }

        Vec::new()
    }

    /// Check if ready to finalize
    pub fn is_ready_to_finalize(state: &AppState) -> bool {
        state.signing_progress.is_fully_signed() && state.ecdh_coverage.is_complete
    }
}
