//! GUI module for BIP-375 Multi-Signer using Slint
//!
//! Provides a graphical interface that visualizes the 3-party signing workflow
//! with progressive ECDH coverage and per-input state tracking.

pub mod app_state;
pub mod workflow_orchestrator;

use app_state::*;
use std::rc::Rc;
use workflow_orchestrator::WorkflowOrchestrator;

slint::include_modules!();

/// Convert AppState to Slint data structures
fn sync_state_to_ui(window: &AppWindow, state: &AppState) {
    // Update workflow state
    let state_str = match state.workflow_state {
        MultiSignerState::Ready => "Ready",
        MultiSignerState::AliceComplete => "AliceComplete",
        MultiSignerState::BobComplete => "BobComplete",
        MultiSignerState::CharlieComplete => "CharlieComplete",
        MultiSignerState::TransactionExtracted => "TransactionExtracted",
    };
    window.set_workflow_state(state_str.into());

    // Update PSBT fields
    if let Some(psbt) = &state.current_psbt {
        window.set_has_psbt(true);

        // Use display_adapter to extract and format fields
        let (global, inputs, outputs) = bip375_gui_common::display_adapter::extract_display_fields(
            psbt,
            &state.highlighted_fields,
        );

        // Convert to Slint models
        let global_fields: Vec<PsbtField> = global.into_iter().map(into_slint_field).collect();
        window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(global_fields)));

        let input_fields: Vec<PsbtField> = inputs.into_iter().map(into_slint_field).collect();
        window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(input_fields)));

        let output_fields: Vec<PsbtField> = outputs.into_iter().map(into_slint_field).collect();
        window.set_output_fields(slint::ModelRc::new(slint::VecModel::from(output_fields)));
    } else {
        window.set_has_psbt(false);
    }

    // Update transaction summary
    if let Some(summary) = &state.transaction_summary {
        window.set_tx_summary(TransactionSummary {
            total_input: summary.total_input as i32,
            total_output: summary.total_output as i32,
            fee: summary.fee as i32,
            num_inputs: summary.num_inputs as i32,
            num_outputs: summary.num_outputs as i32,
        });
    }

    // Update ECDH coverage
    window.set_ecdh_coverage(EcdhCoverage {
        inputs_with_ecdh: state.ecdh_coverage.inputs_with_ecdh as i32,
        total_inputs: state.ecdh_coverage.total_inputs as i32,
        percentage: state.ecdh_coverage.as_percentage(),
    });

    // Update input states
    let slint_input_states: Vec<InputState> = state
        .input_states
        .iter()
        .map(|s| InputState {
            index: s.index as i32,
            signer_name: s.signer_name().into(),
            has_ecdh: s.has_ecdh_share,
            has_dleq: s.has_dleq_proof,
            has_sig: s.has_signature,
        })
        .collect();
    window.set_input_states(slint::ModelRc::new(slint::VecModel::from(
        slint_input_states,
    )));

    // Update validation results
    if let Some(validation) = &state.validation_summary {
        window.set_has_validation(true);
        window.set_validation(ValidationSummary {
            dleq_valid: validation.dleq_proofs_valid,
            all_signed: validation.all_signed,
            scripts_computed: validation.output_scripts_computed,
            tx_extracted: validation.transaction_extracted,
        });
    } else {
        window.set_has_validation(false);
    }
}

fn into_slint_field(f: bip375_gui_common::display_adapter::DisplayField) -> PsbtField {
    PsbtField {
        field_name: f.field_name.into(),
        field_type: f.field_type_str.into(),
        key_preview: f.key_preview.into(),
        value_preview: f.value_preview.into(),
        is_highlighted: f.is_highlighted,
        map_index: f.map_index,
    }
}

/// Run the GUI application
pub fn run_gui() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    let state = AppState::default();

    // Sync initial state
    sync_state_to_ui(&window, &state);

    // Setup callbacks
    {
        let window_weak = window.as_weak();
        let state_rc = Rc::new(std::cell::RefCell::new(state.clone()));

        window.on_alice_creates({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_alice_creates(&mut state) {
                    eprintln!("Error in Alice creates: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_bob_signs({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_bob_signs(&mut state) {
                    eprintln!("Error in Bob signs: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_charlie_finalizes({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_charlie_finalizes(&mut state) {
                    eprintln!("Error in Charlie finalizes: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_reset({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_reset(&mut state) {
                    eprintln!("Error resetting: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });
    }

    window.run()
}
