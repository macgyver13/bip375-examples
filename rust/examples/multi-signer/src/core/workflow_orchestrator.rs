//! Workflow Orchestrator for Multi-Signer GUI
//!
//! Orchestrates flexible multi-party signing workflow and captures PSBT changes

use super::app_state::*;
use crate::workflow_actions;
use bip375_helpers::display::{psbt_analyzer, psbt_io::load_psbt};
use bitcoin::consensus::encode::serialize_hex;
use secp256k1::Secp256k1;
use spdk_core::psbt::SilentPaymentPsbt;

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
            if state.has_ecdh_share || state.has_signature {
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

        // Check if all SP output scripts have been computed
        let output_scripts_computed = psbt.outputs.iter().all(|o| !o.script_pubkey.is_empty());

        // Transaction extracted is tracked by workflow state, not PSBT flags
        let transaction_extracted = false;

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

    /// Create PSBT (constructor role)
    pub fn execute_create_psbt(state: &mut AppState) -> Result<(), String> {
        let config = state.multi_config.clone();

        let before_psbt = state.current_psbt.clone();

        let psbt = workflow_actions::create_psbt_only(&config)?;

        workflow_actions::save_psbt_with_metadata(&psbt, "PSBT Created")?;

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        let total_inputs = config.get_total_inputs();
        state.ecdh_progress = EcdhProgress::new(total_inputs);
        state.signing_progress = SigningProgress::new(total_inputs);

        state.workflow_state = WorkflowState::EcdhInProgress(0);

        Ok(())
    }

    /// Phase 1: Add ECDH shares for a party (no signing).
    ///
    /// If this is the last party to contribute ECDH shares, automatically
    /// computes SP output scripts and transitions to OutputScriptsComputed.
    pub fn execute_add_ecdh_for_party(
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

        workflow_actions::add_ecdh_shares_for_party(&mut psbt, &party, &config, &secp)?;

        workflow_actions::save_psbt_with_metadata(
            &psbt,
            format!("{} ECDH shares added", party_name),
        )?;

        // Check if all ECDH shares are now present
        let ecdh_coverage = Self::compute_ecdh_coverage(&psbt);
        if ecdh_coverage.is_complete {
            workflow_actions::compute_output_scripts(&mut psbt, &secp)?;
            workflow_actions::save_psbt_with_metadata(&psbt, "Output scripts computed")?;
        }

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        state
            .ecdh_progress
            .mark_party_completed(party_name.to_string());

        let ecdh_parties = state.ecdh_progress.parties_completed.len();
        state.workflow_state = if state.ecdh_coverage.is_complete {
            WorkflowState::OutputScriptsComputed
        } else {
            WorkflowState::EcdhInProgress(ecdh_parties)
        };

        Ok(())
    }

    /// Phase 2: Sign inputs for a party.
    ///
    /// Only callable after SP output scripts are computed (OutputScriptsComputed
    /// or PartialSigned state).
    pub fn execute_sign_for_party(
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

        workflow_actions::save_psbt_with_metadata(&psbt, format!("{} signed", party_name))?;

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

    /// Validate and extract transaction
    pub fn execute_extract_transaction(state: &mut AppState) -> Result<(), String> {
        let secp = Secp256k1::new();
        let before_psbt = state.current_psbt.clone();

        let (mut psbt, _) = load_psbt().map_err(|e| format!("Load failed: {:?}", e))?;

        let tx = workflow_actions::validate_and_extract(&mut psbt, &secp)?;

        println!("Transaction validated and ready to broadcast:\n{}", serialize_hex(&tx));

        workflow_actions::save_psbt_with_metadata(&psbt, "Transaction Extracted")?;

        Self::load_psbt_and_update(state, before_psbt.as_ref())?;

        state.workflow_state = WorkflowState::TransactionExtracted;

        Ok(())
    }

    /// Check if party can add ECDH shares (hasn't contributed yet)
    pub fn can_party_add_ecdh(state: &AppState, party_name: &str) -> bool {
        !state.ecdh_progress.parties_completed.contains(party_name)
            && state
                .multi_config
                .parties
                .iter()
                .any(|p| p.name == party_name)
    }

    /// Check if party can sign (output scripts computed, has unsigned inputs)
    pub fn can_party_sign(state: &AppState, party_name: &str) -> bool {
        matches!(
            state.workflow_state,
            WorkflowState::OutputScriptsComputed | WorkflowState::PartialSigned(_)
        ) && !state.signing_progress.parties_completed.contains(party_name)
            && state
                .multi_config
                .parties
                .iter()
                .any(|p| p.name == party_name)
    }

    /// Check if ready to extract
    pub fn is_ready_to_extract(state: &AppState) -> bool {
        state.signing_progress.is_fully_signed()
    }
}
