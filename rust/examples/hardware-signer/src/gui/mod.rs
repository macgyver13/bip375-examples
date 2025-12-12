//! GUI module for BIP-375 Hardware Signer using Slint
//!
//! This module provides a graphical interface that visualizes PSBT property
//! changes in real-time as the signing workflow executes.

pub mod app_state;
pub mod workflow_orchestrator;

use app_state::*;
use common::{TransactionConfig, VirtualWallet};
use slint::Model;
use std::rc::Rc;
use workflow_orchestrator::WorkflowOrchestrator;

// This includes app.slint which in turn imports utxo_selector.slint
// The types UtxoData, TxConfig, UtxoSelectorDialog will be available after this
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

/// Format transaction config for display summary
fn format_config_summary(config: &TransactionConfig, wallet: &VirtualWallet) -> String {
    let utxo_ids: Vec<String> = config
        .selected_utxo_ids
        .iter()
        .map(|id| id.to_string())
        .collect();
    let mut summary = format!("UTXOs: [{}]", utxo_ids.join(", "));

    // Add type indicators
    let mut types = Vec::new();
    for id in &config.selected_utxo_ids {
        if let Some(vu) = wallet.get_utxo(*id) {
            let type_str = if vu.has_sp_tweak {
                format!("{} SP", vu.script_type.as_str())
            } else {
                vu.script_type.as_str().to_string()
            };
            if !types.contains(&type_str) {
                types.push(type_str);
            }
        }
    }

    if !types.is_empty() {
        summary.push_str(&format!("\nTypes: {}", types.join(", ")));
    }

    summary.push_str(&format!(
        "\nRecipient: {}k, Change: {}k, Fee: {}k",
        config.recipient_amount / 1000,
        config.change_amount / 1000,
        config.fee / 1000
    ));

    summary
}

/// Run the GUI application
pub fn run_gui() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    let state = AppState::default();

    // Set initial config summary
    let wallet = VirtualWallet::hardware_wallet_default();
    let initial_summary = format_config_summary(&state.tx_config, &wallet);
    window.set_tx_config_summary(initial_summary.into());

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

        window.on_configure_inputs({
            let window_weak = window_weak.clone();
            let state_rc = state_rc.clone();
            move || {
                if let Some(_window) = window_weak.upgrade() {
                    // Create UTXO selector dialog
                    if let Ok(dialog) = UtxoSelectorDialog::new() {
                        let wallet = VirtualWallet::hardware_wallet_default();
                        let state = state_rc.borrow();

                        // Populate UTXO list from wallet
                        let utxos: Vec<UtxoData> = wallet
                            .list_utxos()
                            .iter()
                            .map(|vu| UtxoData {
                                id: vu.id as i32,
                                amount: vu.utxo.amount.to_sat() as i32,
                                script_type: vu.script_type.as_str().into(),
                                has_sp_tweak: vu.has_sp_tweak,
                                selected: state.tx_config.selected_utxo_ids.contains(&vu.id),
                            })
                            .collect();

                        dialog.set_utxos(slint::ModelRc::new(slint::VecModel::from(utxos)));

                        // Set current config amounts
                        dialog.set_config(TxConfig {
                            recipient_amount: state.tx_config.recipient_amount as i32,
                            change_amount: state.tx_config.change_amount as i32,
                            fee: state.tx_config.fee as i32,
                        });

                        // Handle apply callback
                        dialog.on_apply_config({
                            let state_rc = state_rc.clone();
                            let window_weak = window_weak.clone();
                            let dialog_weak = dialog.as_weak();
                            move |new_config| {
                                let mut state = state_rc.borrow_mut();

                                // Extract selected IDs from dialog's utxos model
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    let ids: Vec<usize> = (0..utxos_model.row_count())
                                        .filter_map(|i| {
                                            let utxo = utxos_model.row_data(i)?;
                                            if utxo.selected {
                                                Some(utxo.id as usize)
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();

                                    // Update transaction config
                                    state.tx_config = TransactionConfig::new(
                                        ids,
                                        new_config.recipient_amount as u64,
                                        new_config.change_amount as u64,
                                        new_config.fee as u64,
                                    );

                                    // Update display summary
                                    if let Some(w) = window_weak.upgrade() {
                                        let wallet = VirtualWallet::hardware_wallet_default();
                                        let summary =
                                            format_config_summary(&state.tx_config, &wallet);
                                        w.set_tx_config_summary(summary.into());
                                    }

                                    // Close dialog
                                    d.hide().ok();
                                }
                            }
                        });

                        // Helper closure to auto-adjust change amount after selection changes
                        let auto_balance_change = {
                            let dialog_weak = dialog.as_weak();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    let mut total_input = 0;

                                    // Calculate total selected input
                                    for i in 0..utxos_model.row_count() {
                                        if let Some(utxo) = utxos_model.row_data(i) {
                                            if utxo.selected {
                                                total_input += utxo.amount;
                                            }
                                        }
                                    }

                                    // Auto-adjust change to balance: change = input - recipient - fee
                                    let config = d.get_config();
                                    let new_change =
                                        total_input - config.recipient_amount - config.fee;

                                    if new_change >= 0 {
                                        let mut updated_config = config;
                                        updated_config.change_amount = new_change;
                                        d.set_config(updated_config);
                                    }

                                    d.invoke_selection_changed();
                                }
                            }
                        };

                        // Handle preset button callbacks
                        dialog.on_preset_all_p2wpkh({
                            let dialog_weak = dialog.as_weak();
                            let auto_balance = auto_balance_change.clone();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    // Select P2WPKH UTXOs: [0, 2, 4, 6]
                                    for i in 0..utxos_model.row_count() {
                                        if let Some(mut utxo) = utxos_model.row_data(i) {
                                            utxo.selected = utxo.script_type.as_str() == "P2WPKH";
                                            utxos_model.set_row_data(i, utxo);
                                        }
                                    }
                                    auto_balance();
                                }
                            }
                        });

                        dialog.on_preset_all_p2tr({
                            let dialog_weak = dialog.as_weak();
                            let auto_balance = auto_balance_change.clone();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    // Select P2TR UTXOs: [1, 3, 5, 7]
                                    for i in 0..utxos_model.row_count() {
                                        if let Some(mut utxo) = utxos_model.row_data(i) {
                                            utxo.selected = utxo.script_type.as_str() == "P2TR";
                                            utxos_model.set_row_data(i, utxo);
                                        }
                                    }
                                    auto_balance();
                                }
                            }
                        });

                        dialog.on_preset_sp_only({
                            let dialog_weak = dialog.as_weak();
                            let auto_balance = auto_balance_change.clone();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    // Select SP UTXOs only: [1, 3, 5]
                                    for i in 0..utxos_model.row_count() {
                                        if let Some(mut utxo) = utxos_model.row_data(i) {
                                            utxo.selected = utxo.has_sp_tweak;
                                            utxos_model.set_row_data(i, utxo);
                                        }
                                    }
                                    auto_balance();
                                }
                            }
                        });

                        dialog.on_preset_mixed({
                            let dialog_weak = dialog.as_weak();
                            let auto_balance = auto_balance_change.clone();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    // Select mixed default: [1, 2] (one SP P2TR + one P2WPKH)
                                    for i in 0..utxos_model.row_count() {
                                        if let Some(mut utxo) = utxos_model.row_data(i) {
                                            utxo.selected = utxo.id == 1 || utxo.id == 2;
                                            utxos_model.set_row_data(i, utxo);
                                        }
                                    }
                                    auto_balance();
                                }
                            }
                        });

                        // Handle selection-changed callback to recompute totals
                        dialog.on_selection_changed({
                            let dialog_weak = dialog.as_weak();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    let utxos_model = d.get_utxos();
                                    let mut total_input = 0;
                                    let mut num_selected = 0;

                                    for i in 0..utxos_model.row_count() {
                                        if let Some(utxo) = utxos_model.row_data(i) {
                                            if utxo.selected {
                                                total_input += utxo.amount;
                                                num_selected += 1;
                                            }
                                        }
                                    }

                                    d.set_total_input(total_input);
                                    d.set_num_selected(num_selected);
                                }
                            }
                        });

                        // Initialize totals for current selection
                        {
                            let utxos_model = dialog.get_utxos();
                            let mut total_input = 0;
                            let mut num_selected = 0;

                            for i in 0..utxos_model.row_count() {
                                if let Some(utxo) = utxos_model.row_data(i) {
                                    if utxo.selected {
                                        total_input += utxo.amount;
                                        num_selected += 1;
                                    }
                                }
                            }

                            dialog.set_total_input(total_input);
                            dialog.set_num_selected(num_selected);
                        }

                        // Handle cancel callback
                        dialog.on_cancel({
                            let dialog_weak = dialog.as_weak();
                            move || {
                                if let Some(d) = dialog_weak.upgrade() {
                                    d.hide().ok();
                                }
                            }
                        });

                        // Show dialog
                        dialog.show().ok();
                    }
                }
            }
        });
    }

    window.run()
}
