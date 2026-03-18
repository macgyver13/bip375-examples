//! Slint GUI for the musig2-signer workflow.

use crate::core::{AppState, Orchestrator, WorkflowState};
use std::rc::Rc;

slint::include_modules!();

/// Sync Rust AppState → Slint UI properties.
fn sync_state_to_ui(window: &AppWindow, state: &AppState) {
    window.set_workflow_state(state.workflow_state.as_str().into());

    // Determine which parties are pending for the active phase and populate dropdown.
    let pending: Vec<slint::SharedString> = match &state.workflow_state {
        WorkflowState::ContributeInProgress(_) => state
            .pending_contribute_parties()
            .iter()
            .map(|&p| slint::SharedString::from(p))
            .collect(),
        WorkflowState::OutputDerived | WorkflowState::SigningInProgress(_) => state
            .pending_signing_parties()
            .iter()
            .map(|&p| slint::SharedString::from(p))
            .collect(),
        _ => vec![],
    };

    let has_pending = !pending.is_empty();
    window.set_has_pending_parties(has_pending);
    window.set_available_parties(slint::ModelRc::new(slint::VecModel::from(pending.clone())));

    // Auto-select first pending party if current selection is gone.
    let current = window.get_selected_party();
    if current.is_empty() || !pending.iter().any(|p| p == &current) {
        if let Some(first) = pending.first() {
            window.set_selected_party(first.clone());
        } else {
            window.set_selected_party(slint::SharedString::from(""));
        }
    }

    // PSBT fields.
    if let Some(fields) = crate::core::orchestrator::extract_display_fields_from_state(state) {
        let (global, inputs, outputs) = fields;
        window.set_has_psbt(true);
        window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(
            global.into_iter().map(into_slint_field).collect::<Vec<_>>(),
        )));
        window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(
            inputs.into_iter().map(into_slint_field).collect::<Vec<_>>(),
        )));
        window.set_output_fields(slint::ModelRc::new(slint::VecModel::from(
            outputs
                .into_iter()
                .map(into_slint_field)
                .collect::<Vec<_>>(),
        )));
    } else {
        window.set_has_psbt(false);
    }

    // Transaction summary.
    if let Some(summary) = &state.transaction_summary {
        window.set_tx_summary(TransactionSummary {
            total_input: summary.total_input as i32,
            total_output: summary.total_output as i32,
            fee: summary.fee as i32,
            num_inputs: summary.num_inputs as i32,
            num_outputs: summary.num_outputs as i32,
        });
    }

    // Phase progress counters.
    window.set_phase_progress(PhaseProgress {
        contribute_done: state.parties_contributed.len() as i32,
        signed_done: state.parties_signed.len() as i32,
    });

    // Aggregated Schnorr sig.
    if let Some(sig_hex) = &state.schnorr_sig_hex {
        window.set_schnorr_sig(sig_hex.as_str().into());
    } else {
        window.set_schnorr_sig(slint::SharedString::from(""));
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

/// Run the GUI event loop.
pub fn run_gui() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    let state = AppState::default();

    sync_state_to_ui(&window, &state);

    let state_rc = Rc::new(std::cell::RefCell::new(state));
    let window_weak = window.as_weak();

    // Helper macro to reduce boilerplate for each callback.
    macro_rules! callback {
        ($action:expr) => {{
            let w = window_weak.clone();
            let s = state_rc.clone();
            move || {
                let mut state = s.borrow_mut();
                if let Err(e) = $action(&mut state) {
                    eprintln!("Error: {e}");
                }
                if let Some(win) = w.upgrade() {
                    sync_state_to_ui(&win, &state);
                }
            }
        }};
        ($action:expr, $arg:ident) => {{
            let w = window_weak.clone();
            let s = state_rc.clone();
            move |$arg: slint::SharedString| {
                let mut state = s.borrow_mut();
                if let Err(e) = $action(&mut state, $arg.as_str()) {
                    eprintln!("Error: {e}");
                }
                if let Some(win) = w.upgrade() {
                    sync_state_to_ui(&win, &state);
                }
            }
        }};
    }

    window.on_create_psbt(callback!(Orchestrator::execute_create_psbt));

    window.on_contribute(callback!(Orchestrator::execute_contribute, party));

    window.on_partial_sign(callback!(Orchestrator::execute_partial_sign, party));

    window.on_extract({
        let w = window_weak.clone();
        let s = state_rc.clone();
        move || {
            let mut state = s.borrow_mut();
            if let Err(e) = Orchestrator::execute_extract(&mut state) {
                eprintln!("Error: {e}");
            }
            if let Some(win) = w.upgrade() {
                sync_state_to_ui(&win, &state);
            }
        }
    });

    window.on_reset({
        let w = window_weak.clone();
        let s = state_rc.clone();
        move || {
            let mut state = s.borrow_mut();
            Orchestrator::execute_reset(&mut state);
            if let Some(win) = w.upgrade() {
                sync_state_to_ui(&win, &state);
            }
        }
    });

    window.on_export_psbt({
        let s = state_rc.clone();
        move || {
            let state = s.borrow();
            bip375_helpers::gui::export_psbt_callback(state.psbt.as_ref());
        }
    });

    window.run()
}
