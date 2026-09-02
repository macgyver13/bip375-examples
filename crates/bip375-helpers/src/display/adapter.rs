//! Adapter for displaying PSBT fields in GUIs
//!
//! Unifies the logic for extracting and formatting PSBT fields for display.

use super::field_identifier::FieldIdentifier;
use super::formatting::{self, FieldCategory};
use psbt::Psbt;
use crate::display::psbt_analyzer::parse_psbt_raw_fields;
use std::collections::HashSet;

/// A generic representation of a PSBT field for display
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayField {
    pub identifier: FieldIdentifier,
    pub field_name: String,
    pub key_type_str: String,
    pub key_preview: String,
    /// Leading significant hex segment (elided on its right; reveals more as width grows).
    pub value_lead: String,
    /// Trailing significant hex segment; empty for short values.
    pub value_tail: String,
    /// Byte count label (e.g. "(64 bytes)"); always shown, never elided.
    pub value_count: String,
    pub is_highlighted: bool,
    pub map_index: i32,
}

/// Extract all fields from a PSBT for display
pub fn extract_display_fields(
    psbt: &Psbt,
    highlighted_fields: &HashSet<FieldIdentifier>,
) -> (Vec<DisplayField>, Vec<DisplayField>, Vec<DisplayField>) {
    let raw_fields = parse_psbt_raw_fields(psbt).unwrap_or_default();

    let mut global_fields = Vec::new();
    for field in raw_fields.0 {
        let identifier = FieldIdentifier::Global {
            key_type: field.key_type,
            key_data: field.key_data.clone(),
        };
        global_fields.push(create_display_field(
            identifier, field.key_type, &field.key_data, &field.value_data, highlighted_fields, -1, FieldCategory::Global
        ));
    }

    let mut input_fields = Vec::new();
    for (idx, map) in raw_fields.1.into_iter().enumerate() {
        for field in map {
            let identifier = FieldIdentifier::Input {
                index: idx,
                key_type: field.key_type,
                key_data: field.key_data.clone(),
            };
            input_fields.push(create_display_field(
                identifier, field.key_type, &field.key_data, &field.value_data, highlighted_fields, idx as i32, FieldCategory::Input
            ));
        }
    }

    let mut output_fields = Vec::new();
    for (idx, map) in raw_fields.2.into_iter().enumerate() {
        for field in map {
            let identifier = FieldIdentifier::Output {
                index: idx,
                key_type: field.key_type,
                key_data: field.key_data.clone(),
            };
            output_fields.push(create_display_field(
                identifier, field.key_type, &field.key_data, &field.value_data, highlighted_fields, idx as i32, FieldCategory::Output
            ));
        }
    }

    (global_fields, input_fields, output_fields)
}

fn create_display_field(
    identifier: FieldIdentifier,
    key_type: u64,
    key_data: &[u8],
    value_data: &[u8],
    highlighted: &HashSet<FieldIdentifier>,
    map_index: i32,
    category: FieldCategory,
) -> DisplayField {
    let is_highlighted = highlighted.contains(&identifier);

    let field_name = formatting::format_field_name(category, key_type);
    let key_type_str = format!("0x{:02x}", key_type);
    let key_preview = if key_data.is_empty() {
        String::new()
    } else {
        formatting::format_value_preview(key_data)
    };
    let value_parts = formatting::format_field_value_parts(category, key_type, value_data);

    DisplayField {
        identifier,
        field_name: field_name.to_string(),
        key_type_str,
        key_preview,
        value_lead: value_parts.lead,
        value_tail: value_parts.tail,
        value_count: value_parts.count,
        is_highlighted,
        map_index,
    }
}
