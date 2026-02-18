//! GUI module for BIP-375 Multi-Signer using Slint
//!
//! Provides a graphical interface that visualizes the 3-party signing workflow
//! with progressive ECDH coverage and per-input state tracking.

// Re-export core modules for backward compatibility
pub use crate::core::app_state;
pub use crate::core::workflow_orchestrator;

use crate::core::{AppState, WorkflowOrchestrator, WorkflowState};
use std::rc::Rc;

slint::include_modules!();

/// Convert AppState to Slint data structures
fn sync_state_to_ui(window: &AppWindow, state: &AppState) {
    // Update workflow state and party action availability
    match &state.workflow_state {
        WorkflowState::ConfiguringParties => {
            window.set_workflow_state("ConfiguringParties".into());
            window.set_has_unsigned_parties(false);
        }
        WorkflowState::PsbtCreated => {
            window.set_workflow_state("PsbtCreated".into());
            window.set_has_unsigned_parties(false);
        }
        WorkflowState::EcdhInProgress(n) => {
            window.set_workflow_state(format!("EcdhInProgress({})", n).into());
            let has_pending = state
                .multi_config
                .parties
                .iter()
                .any(|p| WorkflowOrchestrator::can_party_add_ecdh(state, &p.name));
            window.set_has_unsigned_parties(has_pending);
        }
        WorkflowState::OutputScriptsComputed => {
            window.set_workflow_state("OutputScriptsComputed".into());
            let has_unsigned = state
                .multi_config
                .parties
                .iter()
                .any(|p| WorkflowOrchestrator::can_party_sign(state, &p.name));
            window.set_has_unsigned_parties(has_unsigned);
        }
        WorkflowState::PartialSigned(n) => {
            window.set_workflow_state(format!("PartialSigned({})", n).into());
            let has_unsigned = state
                .multi_config
                .parties
                .iter()
                .any(|p| WorkflowOrchestrator::can_party_sign(state, &p.name));
            window.set_has_unsigned_parties(has_unsigned);
        }
        WorkflowState::FullySigned => {
            window.set_workflow_state("FullySigned".into());
            window.set_has_unsigned_parties(false);
        }
        WorkflowState::TransactionExtracted => {
            window.set_workflow_state("TransactionExtracted".into());
            window.set_has_unsigned_parties(false);
        }
    }

    // Update PSBT fields
    if let Some(psbt) = &state.current_psbt {
        window.set_has_psbt(true);

        // Use display_adapter to extract and format fields
        let (global, inputs, outputs) = bip375_helpers::display::adapter::extract_display_fields(
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
            signer_name: s.party_name().into(),
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

    // Populate dropdown with available parties based on current phase
    let is_ecdh_phase = matches!(
        state.workflow_state,
        WorkflowState::EcdhInProgress(_) | WorkflowState::PsbtCreated
    );
    let unsigned_parties: Vec<slint::SharedString> = state
        .multi_config
        .parties
        .iter()
        .filter(|p| {
            if is_ecdh_phase {
                WorkflowOrchestrator::can_party_add_ecdh(state, &p.name)
            } else {
                WorkflowOrchestrator::can_party_sign(state, &p.name)
            }
        })
        .map(|p| slint::SharedString::from(p.name.as_str()))
        .collect();

    window.set_available_parties(slint::ModelRc::new(slint::VecModel::from(
        unsigned_parties.clone(),
    )));

    // Auto-select first unsigned party if none selected or current selection completed
    let current_selected = window.get_selected_party();
    if current_selected.is_empty() || !unsigned_parties.iter().any(|p| p == &current_selected) {
        if let Some(first) = unsigned_parties.first() {
            window.set_selected_party(first.clone());
        } else {
            window.set_selected_party(slint::SharedString::from(""));
        }
    }
}

fn into_slint_field(f: bip375_helpers::display::adapter::DisplayField) -> PsbtField {
    PsbtField {
        field_name: f.field_name.into(),
        key_type: f.key_type_str.into(),
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
                    return;
                }
                eprintln!("PSBT created successfully");
                if let Some(window) = window_weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        });

        window.on_sign_party({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move |party_name: slint::SharedString| {
                let mut state = state_rc.borrow_mut();
                let party_str = party_name.as_str();

                let is_ecdh_phase = matches!(
                    state.workflow_state,
                    WorkflowState::EcdhInProgress(_) | WorkflowState::PsbtCreated
                );

                let result = if is_ecdh_phase {
                    eprintln!("Adding ECDH shares for: {}", party_str);
                    WorkflowOrchestrator::execute_add_ecdh_for_party(&mut state, party_str)
                } else {
                    eprintln!("Signing as: {}", party_str);
                    WorkflowOrchestrator::execute_sign_for_party(&mut state, party_str)
                };

                if let Err(e) = result {
                    eprintln!("Error for {}: {}", party_str, e);
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
                if let Err(e) = WorkflowOrchestrator::execute_extract_transaction(&mut state) {
                    eprintln!("Error extracting transaction: {}", e);
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

        window.on_export_psbt({
            let state_rc = state_rc.clone();
            move || {
                let state = state_rc.borrow();
                bip375_helpers::gui::export_psbt_callback(state.current_psbt.as_ref());
            }
        });

        window.on_configure_parties({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                if let Some(_window) = window_weak.upgrade() {
                    // Create party configuration dialog
                    if let Ok(dialog) = PartyConfigDialog::new() {
                        // Set up default party info
                        let parties = vec![
                            PartyInfo {
                                name: "Alice".into(),
                                utxo_count: 1,
                                total_amount: 100_000,
                            },
                            PartyInfo {
                                name: "Bob".into(),
                                utxo_count: 1,
                                total_amount: 90_000,
                            },
                            PartyInfo {
                                name: "Charlie".into(),
                                utxo_count: 1,
                                total_amount: 110_000,
                            },
                        ];

                        dialog.set_parties(slint::ModelRc::new(slint::VecModel::from(parties)));
                        dialog.set_creator_party("Alice".into());
                        dialog.set_recipient_amount(195_000);
                        dialog.set_change_amount(100_000);
                        dialog.set_fee_amount(5_000);

                        // Handle "Start Workflow" button
                        dialog.on_start_workflow({
                            let state_rc = state_rc.clone();
                            let window_weak = window_weak.clone();
                            let dialog_weak = dialog.as_weak();
                            move || {
                                let mut state = state_rc.borrow_mut();

                                // Get creator from dialog
                                let creator = if let Some(d) = dialog_weak.upgrade() {
                                    d.get_creator_party().to_string()
                                } else {
                                    "Alice".to_string()
                                };

                                // Update creator index based on selected party
                                let creator_index = match creator.as_str() {
                                    "Alice" => 0,
                                    "Bob" => 1,
                                    "Charlie" => 2,
                                    _ => 0,
                                };
                                state.multi_config.creator_index = creator_index;

                                eprintln!("✓ Ready to start workflow (Creator: {})", creator);
                                state.workflow_state = WorkflowState::PsbtCreated;

                                if let Some(window) = window_weak.upgrade() {
                                    window.set_creator_party(creator.into());
                                    sync_state_to_ui(&window, &state);
                                }

                                // Close dialog
                                if let Some(d) = dialog_weak.upgrade() {
                                    d.hide().ok();
                                }
                            }
                        });

                        // Handle "Use Default Config" button
                        dialog.on_use_default_config({
                            let state_rc = state_rc.clone();
                            let window_weak = window_weak.clone();
                            let dialog_weak = dialog.as_weak();
                            move || {
                                let mut state = state_rc.borrow_mut();

                                // Get creator from dialog
                                let creator = if let Some(d) = dialog_weak.upgrade() {
                                    d.get_creator_party().to_string()
                                } else {
                                    "Alice".to_string()
                                };

                                // Update creator index based on selected party
                                let creator_index = match creator.as_str() {
                                    "Alice" => 0,
                                    "Bob" => 1,
                                    "Charlie" => 2,
                                    _ => 0,
                                };
                                state.multi_config.creator_index = creator_index;

                                eprintln!(
                                    "✓ Using default 3-party configuration (Creator: {})",
                                    creator
                                );
                                state.workflow_state = WorkflowState::PsbtCreated;

                                if let Some(window) = window_weak.upgrade() {
                                    window.set_creator_party(creator.into());
                                    sync_state_to_ui(&window, &state);
                                }

                                // Close dialog
                                if let Some(d) = dialog_weak.upgrade() {
                                    d.hide().ok();
                                }
                            }
                        });

                        // Handle cancel button
                        dialog.on_cancel({
                            let dialog_weak = dialog.as_weak();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    d.hide().ok();
                                }
                            }
                        });

                        // Show the dialog
                        dialog.show().ok();
                    }
                }
            }
        });
    }

    window.run()
}
