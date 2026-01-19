//! Display formatting utilities for PSBT fields
//!
//! Provides functions for formatting PSBT field data for human-readable display.
//!
//! # DNSSEC Validation Status Indicators
//!
//! When displaying DNSSEC proofs (BIP-353), validation status is indicated with symbols:
//! - `✓` - DNSSEC proof validated successfully using RFC 9102 cryptographic validation
//! - `⚠` - DNSSEC validation failed or proof could not be validated (e.g., mock proof)
//!
//! Example: "donate@example.com ✓" indicates a cryptographically verified DNS name.

/// DNSSEC proof field type for BIP-353 silent payment addresses
///
/// This field contains RFC 9102-formatted DNSSEC proofs that cryptographically
/// prove the authenticity of a DNS TXT record containing Bitcoin payment instructions.
///
/// Format: `<1-byte-length><dns_name><RFC 9102 DNSSEC proof>`
///
/// Note: The field type constant (0x35) is defined locally. Consider upstreaming to
/// rust-psbt or bip353-rs once BIP-353 PSBT integration is standardized.
/// New proposed field for tracking TWEAK associated with Silent Payment Input
use crate::PSBT_OUT_DNSSEC_PROOF;

/// PSBT field category for disambiguating field types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCategory {
    Global,
    Input,
    Output,
}

/// Get a human-readable name for a PSBT field type based on its category
///
/// Maps PSBT field type constants to their human-readable names.
/// Supports standard PSBT v2 fields as well as BIP-375 and BIP-353 extensions.
pub fn key_type_name(category: FieldCategory, key_type: u8) -> &'static str {
    match category {
        FieldCategory::Global => match key_type {
            0x01 => "PSBT_GLOBAL_XPUB",
            0x02 => "PSBT_GLOBAL_TX_VERSION",
            0x03 => "PSBT_GLOBAL_FALLBACK_LOCKTIME",
            0x04 => "PSBT_GLOBAL_INPUT_COUNT",
            0x05 => "PSBT_GLOBAL_OUTPUT_COUNT",
            0x06 => "PSBT_GLOBAL_TX_MODIFIABLE",
            0x07 => "PSBT_GLOBAL_SP_ECDH_SHARE", // BIP-375
            0x08 => "PSBT_GLOBAL_SP_DLEQ",       // BIP-375
            0xfb => "PSBT_GLOBAL_VERSION",
            0xfc => "PSBT_GLOBAL_PROPRIETARY",
            _ => "PSBT_GLOBAL_UNKNOWN",
        },
        FieldCategory::Input => match key_type {
            0x00 => "PSBT_IN_NON_WITNESS_UTXO",
            0x01 => "PSBT_IN_WITNESS_UTXO",
            0x02 => "PSBT_IN_PARTIAL_SIG",
            0x03 => "PSBT_IN_SIGHASH_TYPE",
            0x04 => "PSBT_IN_REDEEM_SCRIPT",
            0x05 => "PSBT_IN_WITNESS_SCRIPT",
            0x06 => "PSBT_IN_BIP32_DERIVATION",
            0x07 => "PSBT_IN_FINAL_SCRIPTSIG",
            0x08 => "PSBT_IN_FINAL_SCRIPTWITNESS",
            0x09 => "PSBT_IN_POR_COMMITMENT",
            0x0a => "PSBT_IN_RIPEMD160",
            0x0b => "PSBT_IN_SHA256",
            0x0c => "PSBT_IN_HASH160",
            0x0d => "PSBT_IN_HASH256",
            0x0e => "PSBT_IN_PREVIOUS_TXID",
            0x0f => "PSBT_IN_OUTPUT_INDEX",
            0x10 => "PSBT_IN_SEQUENCE",
            0x11 => "PSBT_IN_REQUIRED_TIME_LOCKTIME",
            0x12 => "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
            0x13 => "PSBT_IN_TAP_KEY_SIG",
            0x14 => "PSBT_IN_TAP_SCRIPT_SIG",
            0x15 => "PSBT_IN_TAP_LEAF_SCRIPT",
            0x16 => "PSBT_IN_TAP_BIP32_DERIVATION",
            0x17 => "PSBT_IN_TAP_INTERNAL_KEY",
            0x18 => "PSBT_IN_TAP_MERKLE_ROOT",
            0x1a => "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS",
            0x1b => "PSBT_IN_MUSIG2_PUB_NONCE",
            0x1c => "PSBT_IN_MUSIG2_PARTIAL_SIG",
            0x1d => "PSBT_IN_SP_ECDH_SHARE", // BIP-375
            0x1e => "PSBT_IN_SP_DLEQ",       // BIP-375
            0x1f => "PSBT_IN_SP_TWEAK",
            _ => "PSBT_IN_UNKNOWN",
        },
        FieldCategory::Output => match key_type {
            0x00 => "PSBT_OUT_REDEEM_SCRIPT",
            0x01 => "PSBT_OUT_WITNESS_SCRIPT",
            0x02 => "PSBT_OUT_BIP32_DERIVATION",
            0x03 => "PSBT_OUT_AMOUNT",
            0x04 => "PSBT_OUT_SCRIPT",
            0x05 => "PSBT_OUT_TAP_INTERNAL_KEY",
            0x06 => "PSBT_OUT_TAP_TREE",
            0x07 => "PSBT_OUT_TAP_BIP32_DERIVATION",
            0x08 => "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS",
            0x09 => "PSBT_OUT_SP_V0_INFO",  // BIP-375
            0x0a => "PSBT_OUT_SP_V0_LABEL", // BIP-375
            PSBT_OUT_DNSSEC_PROOF => "PSBT_OUT_DNSSEC_PROOF", // BIP-353
            _ => "PSBT_OUT_UNKNOWN",
        },
    }
}

/// Get human-readable field name based on category and type
pub fn format_field_name(category: FieldCategory, key_type: u8) -> &'static str {
    key_type_name(category, key_type)
}

/// Format field value data with context-aware formatting
///
/// Provides specialized formatting for certain field types (e.g., DNSSEC proofs),
/// otherwise falls back to generic hex preview.
pub fn format_field_value(category: FieldCategory, key_type: u8, data: &[u8]) -> String {
    // Special formatting for DNSSEC proof fields
    if category == FieldCategory::Output && key_type == PSBT_OUT_DNSSEC_PROOF {
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
        let end_len = 38; // Last 19 bytes
        format!(
            "{}...{} ({} bytes)",
            &hex[..start_len],
            &hex[hex.len() - end_len..],
            data.len()
        )
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
