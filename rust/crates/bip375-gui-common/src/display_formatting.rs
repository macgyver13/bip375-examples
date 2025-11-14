//! Display formatting utilities for PSBT fields
//!
//! Provides functions for formatting PSBT field data for human-readable display.

use bip375_core::constants::{field_type_name, FieldCategory};

/// Get human-readable field name based on category and type
pub fn format_field_name(category: FieldCategory, field_type: u8) -> &'static str {
    field_type_name(category, field_type)
}

/// Format field value data for preview display
///
/// For data longer than 80 hex characters, elides from the center showing
/// first and last 38 characters (19 bytes each) with "..." in between.
pub fn format_value_preview(data: &[u8]) -> String {
    if data.is_empty() {
        return "(empty)".to_string();
    }

    let hex = hex::encode(data);

    // Keep total length under 80 characters by eliding from the center
    if hex.len() > 80 {
        let start_len = 38; // First 19 bytes
        let end_len = 38;   // Last 19 bytes
        format!("{}...{} ({} bytes)", &hex[..start_len], &hex[hex.len()-end_len..], data.len())
    } else {
        format!("{} ({} bytes)", hex, data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_value_preview_empty() {
        assert_eq!(format_value_preview(&[]), "(empty)");
    }

    #[test]
    fn test_format_value_preview_short() {
        let data = vec![0x01, 0x02, 0x03];
        assert_eq!(format_value_preview(&data), "010203 (3 bytes)");
    }

    #[test]
    fn test_format_value_preview_long() {
        let data = vec![0xAB; 50]; // 50 bytes = 100 hex chars
        let result = format_value_preview(&data);
        assert!(result.contains("..."));
        assert!(result.contains("(50 bytes)"));
    }
}
