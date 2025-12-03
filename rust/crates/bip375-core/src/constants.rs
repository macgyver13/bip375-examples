//! PSBT Field Type Constants
//!
//! BIP-375 specific field type constants and utilities.
//! Standard PSBT field types are provided by the rust-psbt crate.

// TODO: implement bip353
pub const PSBT_OUT_DNSSEC_PROOF: u8 = 0x35;

// Magic bytes for PSBT
pub const PSBT_MAGIC: &[u8] = b"psbt\xff";

// PSBT v2 version number
pub const PSBT_V2_VERSION: u32 = 2;

// Transaction modifiable flags (BIP-370)
pub const TX_MODIFIABLE_INPUTS: u8 = 0x01;
pub const TX_MODIFIABLE_OUTPUTS: u8 = 0x02;
pub const TX_MODIFIABLE_SIGHASH_SINGLE: u8 = 0x04;

/// PSBT field category for disambiguating field types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCategory {
    Global,
    Input,
    Output,
}

/// Get a human-readable name for a PSBT field type based on its category
///
/// Handles specific field types first not handled by rust-psbt
/// field type naming functions for standard fields.
pub fn field_type_name(category: FieldCategory, field_type: u8) -> &'static str {
    // Handle specific fields first
    match category {
        FieldCategory::Input => {
            match field_type {
                _ => {}
            }
        }
        FieldCategory::Output => {
            match field_type {
                PSBT_OUT_DNSSEC_PROOF => return "PSBT_OUT_DNSSEC_PROOF",
                _ => {}
            }
        }
        _ => {}
    }

    // Fall back to rust-psbt's naming for standard fields
    match category {
        FieldCategory::Global => psbt_v2::consts::psbt_global_key_type_value_to_str(field_type),
        FieldCategory::Input => psbt_v2::consts::psbt_in_key_type_value_to_str(field_type),
        FieldCategory::Output => psbt_v2::consts::psbt_out_key_type_value_to_str(field_type),
    }
}
