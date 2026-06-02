//! BIP-375 PSBT Viewer
//!
//! Standalone GUI tool for viewing and analyzing BIP-375 PSBTs.
//! Supports import/export via base64 encoding and browsing test vectors.

mod resources;
mod test_vector_helper;

use bip375_helpers::display::{adapter, psbt_analyzer, psbt_io};
use bip375_helpers::io::load_psbt;
use slint::Model;
use psbt::Psbt;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use test_vector_helper::{filter_vectors_by_description, TestVectorFile};

slint::include_modules!();

/// Convert PSBT fields to Slint-compatible format
fn convert_fields_to_slint(
    psbt: &Psbt,
) -> (Vec<PsbtField>, Vec<PsbtField>, Vec<PsbtField>) {
    // Extract all fields using the shared display adapter (no highlighting needed)
    let (global_fields, input_fields, output_fields) =
        adapter::extract_display_fields(psbt, &HashSet::new());

    // Convert DisplayField to Slint's PsbtField
    let convert = |field: adapter::DisplayField| PsbtField {
        field_name: field.field_name.into(),
        key_type: field.key_type_str.into(),
        key_preview: field.key_preview.into(),
        value_lead: field.value_lead.into(),
        value_tail: field.value_tail.into(),
        value_count: field.value_count.into(),
        map_index: field.map_index,
    };

    (
        global_fields.into_iter().map(convert).collect(),
        input_fields.into_iter().map(convert).collect(),
        output_fields.into_iter().map(convert).collect(),
    )
}

/// Update the UI with PSBT data
fn display_psbt(
    window: &AppWindow,
    psbt: &Psbt,
    current_psbt: &Rc<RefCell<Option<Psbt>>>,
) {
    // Store the current PSBT for export
    *current_psbt.borrow_mut() = Some(psbt.clone());

    let (global_fields, input_fields, output_fields) = convert_fields_to_slint(psbt);

    window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(global_fields)));
    window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(input_fields)));
    window.set_output_fields(slint::ModelRc::new(slint::VecModel::from(output_fields)));

    // Compute transaction summary
    let tx_summary = psbt_analyzer::compute_transaction_summary(psbt);

    // Format DNSSEC contacts for display (with validation status indicators)
    let dnssec_contacts_str = if !tx_summary.dnssec_contacts.is_empty() {
        tx_summary
            .dnssec_contacts
            .iter()
            .map(|(idx, name)| format!("[{}] {}", idx, name))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };

    window.set_tx_summary(TransactionSummary {
        total_input: tx_summary.total_input as i32,
        total_output: tx_summary.total_output as i32,
        fee: tx_summary.fee as i32,
        num_inputs: tx_summary.num_inputs as i32,
        num_outputs: tx_summary.num_outputs as i32,
        dnssec_contacts: dnssec_contacts_str.into(),
    });

    window.set_has_psbt(true);
}

/// Update the visible test vector list from the complete vector set.
fn apply_test_vector_filter(window: &AppWindow, all_vectors: &[TestVector], filter: &str) {
    let filtered_vectors = filter_vectors_by_description(all_vectors, filter);
    let filtered_count = filtered_vectors.len();
    let total_count = all_vectors.len();
    let trimmed_filter = filter.trim();

    window.set_test_vectors(slint::ModelRc::new(slint::VecModel::from(filtered_vectors)));
    window.set_selected_test_vector_index(-1);

    let status = if total_count == 0 {
        "No test vectors loaded".to_string()
    } else if trimmed_filter.is_empty() {
        format!("Loaded {} test vectors", total_count)
    } else if filtered_count == 0 {
        format!("No matches in {} test vectors", total_count)
    } else {
        format!("Showing {} of {} test vectors", filtered_count, total_count)
    };

    window.set_test_vector_status(status.into());
}

fn main() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;

    // Shared state for current PSBT
    let current_psbt: Rc<RefCell<Option<Psbt>>> = Rc::new(RefCell::new(None)); 
    let all_test_vectors: Rc<RefCell<Vec<TestVector>>> = Rc::new(RefCell::new(Vec::new()));

    // Auto-load test vectors on startup
    match resources::load_test_vectors() {
        Ok(json) => {
            if let Ok(vectors) = TestVectorFile::from_json(&json) {
                let slint_vectors = vectors.to_slint_vectors();
                *all_test_vectors.borrow_mut() = slint_vectors;
                apply_test_vector_filter(
                    &window,
                    &all_test_vectors.borrow(),
                    &window.get_test_vector_filter(),
                );
            }
        }
        Err(_) => {
            // Silently fail if test vectors aren't available - user can still browse for them
            window.set_test_vector_status(
                "Click 'Load Vectors' or 'Browse...' to load test cases".into(),
            );
        }
    }

    // Handle import-psbt callback
    let window_weak = window.as_weak();
    let current_psbt_clone = current_psbt.clone();
    window.on_import_psbt(move |base64_str| {
        let window = window_weak.unwrap();

        match psbt_io::import_from_base64(&base64_str) {
            Ok(psbt) => {
                display_psbt(&window, &psbt, &current_psbt_clone);
                window.set_status_message("✅ PSBT imported successfully".into());
            }
            Err(e) => {
                window.set_status_message(format!("❌ Import failed: {}", e).into());
            }
        }
    });

    // Handle clear callback
    let window_weak = window.as_weak();
    let current_psbt_clone = current_psbt.clone();
    let all_test_vectors_clone = all_test_vectors.clone();
    window.on_clear(move || {
        *current_psbt_clone.borrow_mut() = None;
        let window = window_weak.unwrap();
        window.set_has_psbt(false);
        window.set_import_text("".into());
        window.set_test_vector_filter("".into());
        window.set_status_message("".into());
        apply_test_vector_filter(&window, &all_test_vectors_clone.borrow(), "");
        window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(
            Vec::<PsbtField>::new(),
        )));
        window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(
            Vec::<PsbtField>::new(),
        )));
        window.set_output_fields(slint::ModelRc::new(slint::VecModel::from(
            Vec::<PsbtField>::new(),
        )));
    });

    // Handle browse-test-vectors callback
    let window_weak = window.as_weak();
    let all_test_vectors_clone = all_test_vectors.clone();
    window.on_browse_test_vectors(move || {
        let window = window_weak.unwrap();

        if let Some(json) = resources::browse_for_test_vectors() {
            match TestVectorFile::from_json(&json) {
                Ok(vectors) => {
                    let slint_vectors = vectors.to_slint_vectors();
                    *all_test_vectors_clone.borrow_mut() = slint_vectors;
                    apply_test_vector_filter(
                        &window,
                        &all_test_vectors_clone.borrow(),
                        &window.get_test_vector_filter(),
                    );
                }
                Err(e) => {
                    window.set_test_vector_status(format!("❌ Parse error: {}", e).into());
                }
            }
        }
    });

    // Handle test-vector filtering callback
    let window_weak = window.as_weak();
    let all_test_vectors_clone = all_test_vectors.clone();
    window.on_filter_test_vectors(move |filter| {
        let window = window_weak.unwrap();
        apply_test_vector_filter(&window, &all_test_vectors_clone.borrow(), &filter);
    });

    // Handle select-test-vector callback (populates import field and auto-imports)
    let window_weak = window.as_weak();
    let current_psbt_clone = current_psbt.clone();
    window.on_select_test_vector(move |index| {
        let window = window_weak.unwrap();
        let vectors = window.get_test_vectors();

        if index >= 0 && (index as usize) < vectors.row_count() {
            if let Some(vector) = vectors.row_data(index as usize) {
                // Populate the import text field with selected PSBT
                window.set_import_text(vector.psbt_base64.clone());
                window.set_selected_test_vector_index(index);
                window.set_test_vector_status(format!("Selected: {}", vector.description).into());

                // Auto-import the PSBT
                match psbt_io::import_from_base64(&vector.psbt_base64) {
                    Ok(psbt) => {
                        display_psbt(&window, &psbt, &current_psbt_clone);
                        window.set_status_message("PSBT imported successfully".into());
                    }
                    Err(e) => {
                        window.set_status_message(format!("Import failed: {}", e).into());
                    }
                }
            }
        }
    });

    // Handle load-psbt-file callback
    let window_weak = window.as_weak();
    let current_psbt_clone = current_psbt.clone();
    window.on_load_psbt_file(move || {
        let window = window_weak.unwrap();

        if let Some(path) = resources::browse_for_psbt_file() {
            match load_psbt(&path) {
                Ok((psbt, metadata)) => {
                    display_psbt(&window, &psbt, &current_psbt_clone);
                    let msg = if let Some(meta) = metadata {
                        format!(
                            "✅ Loaded PSBT from file ({})",
                            meta.creator.unwrap_or_default()
                        )
                    } else {
                        "✅ Loaded PSBT from file".to_string()
                    };
                    window.set_status_message(msg.into());
                }
                Err(e) => {
                    window.set_status_message(format!("❌ Failed to load PSBT: {}", e).into());
                }
            }
        }
    });

    // Handle export-psbt callback
    let current_psbt_clone = current_psbt.clone();
    window.on_export_psbt(move || {
        let psbt = current_psbt_clone.borrow();
        bip375_helpers::gui::export_psbt_callback(psbt.as_ref());
    });

    window.run()
}
