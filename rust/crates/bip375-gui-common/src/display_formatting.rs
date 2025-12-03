//! Display formatting utilities for PSBT fields
//!
//! Provides functions for formatting PSBT field data for human-readable display.

use bip375_core::constants::{field_type_name, FieldCategory, PSBT_OUT_DNSSEC_PROOF};

/// Get human-readable field name based on category and type
pub fn format_field_name(category: FieldCategory, field_type: u8) -> &'static str {
    field_type_name(category, field_type)
}

/// Format field value data with context-aware formatting
///
/// Provides specialized formatting for certain field types (e.g., DNSSEC proofs),
/// otherwise falls back to generic hex preview.
pub fn format_field_value(category: FieldCategory, field_type: u8, data: &[u8]) -> String {
    // Special formatting for DNSSEC proof fields
    if category == FieldCategory::Output && field_type == PSBT_OUT_DNSSEC_PROOF {
        return format_dnssec_proof(data);
    }

    // Default to generic preview
    format_value_preview(data)
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

/// Format DNSSEC proof data (BIP 353)
///
/// Format: <1-byte-length><dns_name><proof_data>
/// Displays as: "user@domain.com + <proof_bytes> (<total> bytes)"
fn format_dnssec_proof(data: &[u8]) -> String {
    if data.is_empty() {
        return "Invalid DNSSEC proof (empty)".to_string();
    }

    let dns_name_length = data[0] as usize;

    if data.len() < 1 + dns_name_length {
        return format!(
            "Invalid DNSSEC proof (expected {} bytes minimum, got {})",
            1 + dns_name_length,
            data.len()
        );
    }

    let dns_name_bytes = &data[1..1 + dns_name_length];
    let proof_bytes = &data[1 + dns_name_length..];

    match String::from_utf8(dns_name_bytes.to_vec()) {
        Ok(dns_name) => {
            let proof_hex = hex::encode(proof_bytes);
            if proof_hex.len() > 60 {
                // Elide long proofs
                format!(
                    "\"{}\" + {}...{} ({} bytes)",
                    dns_name,
                    &proof_hex[..28],
                    &proof_hex[proof_hex.len() - 28..],
                    data.len()
                )
            } else {
                format!("\"{}\" + {} ({} bytes)", dns_name, proof_hex, data.len())
            }
        }
        Err(_) => format!(
            "Invalid UTF-8 in DNS name + {} ({} bytes)",
            hex::encode(proof_bytes),
            data.len()
        ),
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

    #[test]
    fn test_format_dnssec_proof_short() {
        // Format: <length-byte><dns_name><proof_data>
        let dns_name = b"user@example.com";
        let proof_data = b"proof123";
        let mut data = vec![dns_name.len() as u8];
        data.extend_from_slice(dns_name);
        data.extend_from_slice(proof_data);

        let result = format_dnssec_proof(&data);
        assert!(result.contains("user@example.com"));
        // Proof data is hex-encoded
        assert!(result.contains(&hex::encode(proof_data)));
        assert!(result.contains(&format!("({} bytes)", data.len())));
    }

    #[test]
    fn test_format_dnssec_proof_empty() {
        let result = format_dnssec_proof(&[]);
        assert_eq!(result, "Invalid DNSSEC proof (empty)");
    }

    #[test]
    fn test_format_dnssec_proof_invalid_length() {
        // Length byte says 10, but only 5 bytes follow
        let data = vec![10, 1, 2, 3, 4, 5];
        let result = format_dnssec_proof(&data);
        assert!(result.contains("Invalid DNSSEC proof"));
    }

    #[test]
    fn test_format_field_value_uses_dnssec_formatting() {
        let dns_name = b"alice@bitcoin.org";
        let proof_data = b"proofdata";
        let mut data = vec![dns_name.len() as u8];
        data.extend_from_slice(dns_name);
        data.extend_from_slice(proof_data);

        let result = format_field_value(FieldCategory::Output, PSBT_OUT_DNSSEC_PROOF, &data);
        assert!(result.contains("alice@bitcoin.org"));
    }
}
