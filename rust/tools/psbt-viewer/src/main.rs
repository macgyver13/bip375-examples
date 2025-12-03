//! BIP-375 PSBT Viewer
//!
//! Standalone GUI tool for viewing and analyzing BIP-375 PSBTs.
//! Supports import/export via base64 encoding and browsing test vectors.

mod resources;
mod test_vector_helper;

use bip375_core::SilentPaymentPsbt;
use bip375_gui_common::{display_adapter, psbt_analyzer, psbt_io};
use slint::Model;
use std::collections::HashSet;
use test_vector_helper::TestVectorFile;

slint::include_modules!();

/// Convert PSBT fields to Slint-compatible format
fn convert_fields_to_slint(
    psbt: &SilentPaymentPsbt,
) -> (Vec<PsbtField>, Vec<PsbtField>, Vec<PsbtField>) {
    // Extract all fields using the shared display adapter (no highlighting needed)
    let (global_fields, input_fields, output_fields) =
        display_adapter::extract_display_fields(psbt, &HashSet::new());

    // Convert DisplayField to Slint's PsbtField
    let convert = |field: display_adapter::DisplayField| PsbtField {
        field_name: field.field_name.into(),
        field_type: field.field_type_str.into(),
        key_preview: field.key_preview.into(),
        value_preview: field.value_preview.into(),
        is_sp_field: field.is_sp_field,
        map_index: field.map_index,
    };

    (
        global_fields.into_iter().map(convert).collect(),
        input_fields.into_iter().map(convert).collect(),
        output_fields.into_iter().map(convert).collect(),
    )
}

/// Update the UI with PSBT data
fn display_psbt(window: &AppWindow, psbt: &SilentPaymentPsbt) {
    let (global_fields, input_fields, output_fields) = convert_fields_to_slint(psbt);

    window.set_global_fields(slint::ModelRc::new(slint::VecModel::from(global_fields)));
    window.set_input_fields(slint::ModelRc::new(slint::VecModel::from(input_fields)));
    window.set_output_fields(slint::ModelRc::new(slint::VecModel::from(output_fields)));

    // Compute transaction summary
    let tx_summary = psbt_analyzer::compute_transaction_summary(psbt);
    window.set_tx_summary(TransactionSummary {
        total_input: tx_summary.total_input as i32,
        total_output: tx_summary.total_output as i32,
        fee: tx_summary.fee as i32,
        num_inputs: tx_summary.num_inputs as i32,
        num_outputs: tx_summary.num_outputs as i32,
    });

    window.set_has_psbt(true);
}

fn main() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;

    // Auto-load test vectors on startup
    match resources::load_test_vectors() {
        Ok(json) => {
            if let Ok(vectors) = TestVectorFile::from_json(&json) {
                let slint_vectors = vectors.to_slint_vectors();
                let count = slint_vectors.len();
                window.set_test_vectors(slint::ModelRc::new(slint::VecModel::from(slint_vectors)));
                window.set_test_vector_status(format!("✅ Loaded {} test vectors", count).into());
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
    window.on_import_psbt(move |base64_str| {
        let window = window_weak.unwrap();

        match psbt_io::import_from_base64(&base64_str) {
            Ok(psbt) => {
                display_psbt(&window, &psbt);
                window.set_status_message("✅ PSBT imported successfully".into());
            }
            Err(e) => {
                window.set_status_message(format!("❌ Import failed: {}", e).into());
            }
        }
    });

    // Handle clear callback
    let window_weak = window.as_weak();
    window.on_clear(move || {
        let window = window_weak.unwrap();
        window.set_has_psbt(false);
        window.set_import_text("".into());
        window.set_status_message("".into());
        window.set_selected_test_vector_index(-1);
        window.set_test_vector_status("".into());
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
    window.on_browse_test_vectors(move || {
        let window = window_weak.unwrap();

        if let Some(json) = resources::browse_for_test_vectors() {
            match TestVectorFile::from_json(&json) {
                Ok(vectors) => {
                    let slint_vectors = vectors.to_slint_vectors();
                    let count = slint_vectors.len();
                    window.set_test_vectors(slint::ModelRc::new(slint::VecModel::from(
                        slint_vectors,
                    )));
                    window.set_test_vector_status(
                        format!("✅ Loaded {} test vectors from file", count).into(),
                    );
                }
                Err(e) => {
                    window.set_test_vector_status(format!("❌ Parse error: {}", e).into());
                }
            }
        }
    });

    // Handle select-test-vector callback (populates import field)
    let window_weak = window.as_weak();
    window.on_select_test_vector(move |index| {
        let window = window_weak.unwrap();
        let vectors = window.get_test_vectors();

        if index >= 0 && (index as usize) < vectors.row_count() {
            if let Some(vector) = vectors.row_data(index as usize) {
                // Populate the import text field with selected PSBT
                window.set_import_text(vector.psbt_base64);
                window.set_selected_test_vector_index(index);
                window.set_test_vector_status(format!("Selected: {}", vector.description).into());
            }
        }
    });

    // Handle load-psbt-file callback
    let window_weak = window.as_weak();
    window.on_load_psbt_file(move || {
        let window = window_weak.unwrap();

        if let Some(path) = resources::browse_for_psbt_file() {
            match bip375_io::file_io::load_psbt(&path) {
                Ok((psbt, metadata)) => {
                    display_psbt(&window, &psbt);
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

    window.run()
}
