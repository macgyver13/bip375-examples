//! Slint GUI for the 2-of-3 FROST signer workflow.

use std::rc::Rc;

use crate::core::{AppState, Orchestrator};

slint::include_modules!();

fn sync_state_to_ui(window: &AppWindow, state: &AppState) {
    window.set_workflow_state(state.workflow_state.as_str().into());
    let pending: Vec<slint::SharedString> = state
        .pending_parties()
        .into_iter()
        .map(Into::into)
        .collect();
    window.set_has_pending_parties(!pending.is_empty());
    window.set_available_parties(slint::ModelRc::new(slint::VecModel::from(pending.clone())));
    let current = window.get_selected_party();
    if current.is_empty() || !pending.iter().any(|party| party == &current) {
        window.set_selected_party(pending.first().cloned().unwrap_or_default());
    }

    if let Some((global, inputs, outputs)) =
        crate::core::orchestrator::extract_display_fields_from_state(state)
    {
        window.set_has_psbt(true);
        window.set_global_fields(field_model(global));
        window.set_input_fields(field_model(inputs));
        window.set_output_fields(field_model(outputs));
    } else {
        window.set_has_psbt(false);
        window.set_global_fields(field_model(Vec::new()));
        window.set_input_fields(field_model(Vec::new()));
        window.set_output_fields(field_model(Vec::new()));
    }

    if let Some(summary) = &state.transaction_summary {
        window.set_tx_summary(TransactionSummary {
            total_input: summary.total_input as i32,
            total_output: summary.total_output as i32,
            fee: summary.fee as i32,
            num_inputs: summary.num_inputs as i32,
            num_outputs: summary.num_outputs as i32,
        });
    }
    window.set_phase_progress(PhaseProgress {
        contribute_done: state.selected_parties.len() as i32,
        signed_done: state.signed_parties.len() as i32,
    });
    window.set_schnorr_sig(state.schnorr_sig_hex.as_deref().unwrap_or("").into());
}

fn field_model(
    fields: Vec<bip375_helpers::display::adapter::DisplayField>,
) -> slint::ModelRc<PsbtField> {
    slint::ModelRc::new(slint::VecModel::from(
        fields.into_iter().map(into_slint_field).collect::<Vec<_>>(),
    ))
}

fn into_slint_field(field: bip375_helpers::display::adapter::DisplayField) -> PsbtField {
    let field_name = match &field.identifier {
        bip375_helpers::display::field_identifier::FieldIdentifier::Input { key_type, .. }
        | bip375_helpers::display::field_identifier::FieldIdentifier::Output { key_type, .. } => {
            crate::frost_psbt::field_name(*key_type).unwrap_or(&field.field_name)
        }
        _ => &field.field_name,
    };
    PsbtField {
        field_name: field_name.into(),
        key_type: field.key_type_str.into(),
        key_preview: field.key_preview.into(),
        value_preview: if field.value_tail.is_empty() {
            format!("{} {}", field.value_lead, field.value_count)
        } else {
            format!(
                "{}…{} {}",
                field.value_lead, field.value_tail, field.value_count
            )
        }
        .into(),
        is_highlighted: field.is_highlighted,
        map_index: field.map_index,
    }
}

pub fn run_gui() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    let state = Rc::new(std::cell::RefCell::new(AppState::default()));
    sync_state_to_ui(&window, &state.borrow());
    let weak = window.as_weak();

    macro_rules! callback {
        ($action:expr) => {{
            let weak = weak.clone();
            let state = state.clone();
            move || {
                let mut state = state.borrow_mut();
                if let Err(error) = $action(&mut state) {
                    eprintln!("Error: {error}");
                }
                if let Some(window) = weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        }};
        ($action:expr, $argument:ident) => {{
            let weak = weak.clone();
            let state = state.clone();
            move |$argument: slint::SharedString| {
                let mut state = state.borrow_mut();
                if let Err(error) = $action(&mut state, $argument.as_str()) {
                    eprintln!("Error: {error}");
                }
                if let Some(window) = weak.upgrade() {
                    sync_state_to_ui(&window, &state);
                }
            }
        }};
    }

    window.on_create_psbt(callback!(Orchestrator::execute_create_psbt));
    window.on_contribute(callback!(Orchestrator::execute_contribute, party));
    window.on_partial_sign(callback!(Orchestrator::execute_partial_sign, party));
    window.on_extract(callback!(Orchestrator::execute_extract));
    window.on_reset({
        let weak = weak.clone();
        let state = state.clone();
        move || {
            let mut state = state.borrow_mut();
            Orchestrator::execute_reset(&mut state);
            if let Some(window) = weak.upgrade() {
                sync_state_to_ui(&window, &state);
            }
        }
    });
    window.on_export_psbt({
        let state = state.clone();
        move || {
            let psbt = state.borrow().psbt().ok().flatten();
            bip375_helpers::gui::export_psbt_callback(psbt.as_ref())
        }
    });
    window.run()
}
