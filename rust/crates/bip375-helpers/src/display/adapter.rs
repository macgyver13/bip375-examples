//! Adapter for displaying PSBT fields in GUIs
//!
//! Unifies the logic for extracting and formatting PSBT fields for display.

use super::field_identifier::FieldIdentifier;
use super::formatting::{self, FieldCategory};
use spdk_core::psbt::{GlobalFieldsExt, InputFieldsExt, OutputFieldsExt, SilentPaymentPsbt};
use std::collections::HashSet;

/// A generic representation of a PSBT field for display
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayField {
    pub identifier: FieldIdentifier,
    pub field_name: String,
    pub key_type_str: String,
    pub key_preview: String,
    pub value_preview: String,
    pub is_highlighted: bool,
    pub map_index: i32,
}

/// Extract all fields from a PSBT for display
pub fn extract_display_fields(
    psbt: &SilentPaymentPsbt,
    highlighted_fields: &HashSet<FieldIdentifier>,
) -> (Vec<DisplayField>, Vec<DisplayField>, Vec<DisplayField>) {
    let global_fields = extract_global_fields(psbt, highlighted_fields);
    let input_fields = extract_input_fields(psbt, highlighted_fields);
    let output_fields = extract_output_fields(psbt, highlighted_fields);

    (global_fields, input_fields, output_fields)
}

fn extract_global_fields(
    psbt: &SilentPaymentPsbt,
    highlighted_fields: &HashSet<FieldIdentifier>,
) -> Vec<DisplayField> {
    let mut fields = Vec::new();

    for (key_type, key_data, value_data) in psbt.global.iter_global_fields() {
        let identifier = FieldIdentifier::Global {
            key_type,
            key_data: key_data.clone(),
        };

        fields.push(create_display_field(
            identifier,
            key_type,
            &key_data,
            &value_data,
            highlighted_fields,
            -1,
            FieldCategory::Global,
        ));
    }

    fields
}

fn extract_input_fields(
    psbt: &SilentPaymentPsbt,
    highlighted_fields: &HashSet<FieldIdentifier>,
) -> Vec<DisplayField> {
    let mut fields = Vec::new();

    for (idx, input) in psbt.inputs.iter().enumerate() {
        for (key_type, key_data, value_data) in input.iter_input_fields() {
            let identifier = FieldIdentifier::Input {
                index: idx,
                key_type,
                key_data: key_data.clone(),
            };

            fields.push(create_display_field(
                identifier,
                key_type,
                &key_data,
                &value_data,
                highlighted_fields,
                idx as i32,
                FieldCategory::Input,
            ));
        }
    }

    fields
}

fn extract_output_fields(
    psbt: &SilentPaymentPsbt,
    highlighted_fields: &HashSet<FieldIdentifier>,
) -> Vec<DisplayField> {
    let mut fields = Vec::new();

    for (idx, output) in psbt.outputs.iter().enumerate() {
        for (key_type, key_data, value_data) in output.iter_output_fields() {
            let identifier = FieldIdentifier::Output {
                index: idx,
                key_type,
                key_data: key_data.clone(),
            };

            fields.push(create_display_field(
                identifier,
                key_type,
                &key_data,
                &value_data,
                highlighted_fields,
                idx as i32,
                FieldCategory::Output,
            ));
        }
    }

    fields
}

fn create_display_field(
    identifier: FieldIdentifier,
    key_type: u8,
    key_data: &[u8],
    value_data: &[u8],
    highlighted: &HashSet<FieldIdentifier>,
    map_index: i32,
    category: FieldCategory,
) -> DisplayField {
    let is_highlighted = highlighted.contains(&identifier);

    let field_name = formatting::format_field_name(category, key_type);
    let key_type_str = format!("0x{:02x}", key_type);
    let key_preview = formatting::format_value_preview(key_data);
    let value_preview = formatting::format_field_value(category, key_type, value_data);

    DisplayField {
        identifier,
        field_name: field_name.to_string(),
        key_type_str,
        key_preview,
        value_preview,
        is_highlighted,
        map_index,
    }
}
