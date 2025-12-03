//! PSBT Field Type Constants
//!
//! BIP-375 specific field type constants and utilities.
//! Standard PSBT field types are provided by the rust-psbt crate.

// TODO: Remove these 
pub const PSBT_IN_SP_ECDH_SHARE: u8 = 0x1d;
pub const PSBT_IN_SP_DLEQ: u8 = 0x1e;
pub const PSBT_OUT_SP_V0_INFO: u8 = 0x09;
pub const PSBT_OUT_SP_V0_LABEL: u8 = 0x0a;

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
/// Delegates to rust-psbt's field type naming functions for standard fields.
pub fn field_type_name(category: FieldCategory, field_type: u8) -> &'static str {
    match category {
        FieldCategory::Global => psbt_v2::consts::psbt_global_key_type_value_to_str(field_type),
        FieldCategory::Input => psbt_v2::consts::psbt_in_key_type_value_to_str(field_type),
        FieldCategory::Output => psbt_v2::consts::psbt_out_key_type_value_to_str(field_type),
    }
}
