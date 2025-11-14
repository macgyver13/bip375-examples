//! GUI module for BIP-375 Hardware Signer using Slint
//!
//! This module provides a graphical interface that visualizes PSBT property
//! changes in real-time as the signing workflow executes.

pub mod app_state;
pub mod workflow_orchestrator;

use app_state::*;
use workflow_orchestrator::WorkflowOrchestrator;
use std::rc::Rc;

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

        // Convert global fields
        let global_fields: Vec<PsbtField> = psbt
            .global_fields
            .iter()
            .map(|field| {
                let identifier = FieldIdentifier::Global {
                    field_type: field.field_type,
                    key_data: field.key_data.clone(),
                };
                convert_field_to_slint(&identifier, field, &state.highlighted_fields)
            })
            .collect();
        window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(global_fields)));

        // Convert input fields (flatten all inputs)
        let mut input_fields = Vec::new();
        for (idx, input_map) in psbt.input_maps.iter().enumerate() {
            for field in input_map {
                let identifier = FieldIdentifier::Input {
                    index: idx,
                    field_type: field.field_type,
                    key_data: field.key_data.clone(),
                };
                input_fields.push(convert_field_to_slint(
                    &identifier,
                    field,
                    &state.highlighted_fields,
                ));
            }
        }
        window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(input_fields)));

        // Convert output fields (flatten all outputs)
        let mut output_fields = Vec::new();
        for (idx, output_map) in psbt.output_maps.iter().enumerate() {
            for field in output_map {
                let identifier = FieldIdentifier::Output {
                    index: idx,
                    field_type: field.field_type,
                    key_data: field.key_data.clone(),
                };
                output_fields.push(convert_field_to_slint(
                    &identifier,
                    field,
                    &state.highlighted_fields,
                ));
            }
        }
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

fn convert_field_to_slint(
    identifier: &FieldIdentifier,
    field: &bip375_core::field::PsbtField,
    highlighted: &std::collections::HashSet<FieldIdentifier>,
) -> PsbtField {
    use bip375_core::constants::FieldCategory;
    use bip375_gui_common::{display_formatting, psbt_analyzer};

    let is_highlighted = highlighted.contains(identifier);
    let is_sp_field = psbt_analyzer::is_sp_field(field.field_type);

    // Extract the map index and category from the identifier
    let (map_index, category) = match identifier {
        FieldIdentifier::Global { .. } => (-1, FieldCategory::Global),
        FieldIdentifier::Input { index, .. } => (*index as i32, FieldCategory::Input),
        FieldIdentifier::Output { index, .. } => (*index as i32, FieldCategory::Output),
    };

    let field_name = display_formatting::format_field_name(category, field.field_type);
    let field_type = format!("0x{:02x}", field.field_type);
    let key_preview = display_formatting::format_value_preview(&field.key_data);
    let value_preview = display_formatting::format_value_preview(&field.value_data);

    PsbtField {
        field_name: field_name.into(),
        field_type: field_type.into(),
        key_preview: key_preview.into(),
        value_preview: value_preview.into(),
        is_highlighted,
        is_sp_field,
        map_index,
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
