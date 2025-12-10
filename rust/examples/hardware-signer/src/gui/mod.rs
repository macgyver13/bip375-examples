//! GUI module for BIP-375 Hardware Signer using Slint
//!
//! This module provides a graphical interface that visualizes PSBT property
//! changes in real-time as the signing workflow executes.

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
        WorkflowState::Ready => "Ready",
        WorkflowState::PsbtCreated => "PsbtCreated",
        WorkflowState::HardwareApprovalPending => "PsbtCreated",
        WorkflowState::PsbtSigned => "PsbtSigned",
        WorkflowState::TransactionExtracted => "TransactionExtracted",
    };
    window.set_workflow_state(state_str.into());

    // Update attack mode
    window.set_attack_mode(state.attack_mode);

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
        // Format DNS contacts for display
        let mut contacts_str = String::new();
        if !summary.dnssec_contacts.is_empty() {
            contacts_str.push_str("DNS Contacts: ");
            let mut first = true;
            for (idx, name) in &summary.dnssec_contacts {
                if !first {
                    contacts_str.push_str(", ");
                }
                contacts_str.push_str(&format!("[#{}] {}", idx, name));
                first = false;
            }
        }

        window.set_tx_summary(TransactionSummary {
            total_input: summary.total_input as i32,
            total_output: summary.total_output as i32,
            fee: summary.fee as i32,
            num_inputs: summary.num_inputs as i32,
            num_outputs: summary.num_outputs as i32,
            dns_contacts: contacts_str.into(),
        });
    }

    // Update validation results
    if let Some(validation) = &state.validation_results {
        window.set_has_validation(true);
        window.set_validation(ValidationResults {
            ecdh_complete: validation.ecdh_coverage_complete,
            dleq_valid: validation.all_dleq_proofs_valid,
            all_signed: validation.all_inputs_signed,
            attack_detected: validation.attack_detected,
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

        window.on_create_psbt({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_create_psbt(&mut state) {
                    eprintln!("Error creating PSBT: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_sign_psbt({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                // Read attack-mode directly from the window property
                if let Some(w) = window_weak.upgrade() {
                    state.attack_mode = w.get_attack_mode();
                }
                if let Err(e) = WorkflowOrchestrator::execute_sign_psbt(&mut state) {
                    eprintln!("Error signing PSBT: {}", e);
                }
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_finalize_transaction({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                let mut state = state_rc.borrow_mut();
                if let Err(e) = WorkflowOrchestrator::execute_finalize(&mut state) {
                    eprintln!("Error finalizing: {}", e);
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
