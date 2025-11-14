//! PSBT Field Type Constants
//!
//! Field type constants for PSBT v2 and BIP-375 extensions.
//! Based on BIP-174, BIP-370, and BIP-375 specifications.

// PSBT Global Types (from BIP-370 PSBT v2)
pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
pub const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
pub const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
pub const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
pub const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
pub const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
pub const PSBT_GLOBAL_VERSION: u8 = 0xfb;
pub const PSBT_GLOBAL_PROPRIETARY: u8 = 0xfc;

// BIP-375 Silent Payment Global Fields (Dedicated Field Types)
pub const PSBT_GLOBAL_SP_ECDH_SHARE: u8 = 0x07;
pub const PSBT_GLOBAL_SP_DLEQ: u8 = 0x08;

// PSBT Input Types (from BIP-174 and BIP-370)
pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
pub const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
pub const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
pub const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
pub const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
pub const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
pub const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
pub const PSBT_IN_RIPEMD160: u8 = 0x0a;
pub const PSBT_IN_SHA256: u8 = 0x0b;
pub const PSBT_IN_HASH160: u8 = 0x0c;
pub const PSBT_IN_HASH256: u8 = 0x0d;
pub const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
pub const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
pub const PSBT_IN_SEQUENCE: u8 = 0x10;
pub const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
pub const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
pub const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
pub const PSBT_IN_PROPRIETARY: u8 = 0xfc;

// BIP-375 Silent Payment Input Fields (Dedicated Field Types)
pub const PSBT_IN_SP_ECDH_SHARE: u8 = 0x1d;
pub const PSBT_IN_SP_DLEQ: u8 = 0x1e;

// PSBT Output Types (from BIP-174 and BIP-370)
pub const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
pub const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
pub const PSBT_OUT_AMOUNT: u8 = 0x03;
pub const PSBT_OUT_SCRIPT: u8 = 0x04;
pub const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const PSBT_OUT_TAP_TREE: u8 = 0x06;
pub const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
pub const PSBT_OUT_PROPRIETARY: u8 = 0xfc;

// BIP-375 Silent Payment Output Fields (Dedicated Field Types)
pub const PSBT_OUT_SP_V0_INFO: u8 = 0x09;
pub const PSBT_OUT_SP_V0_LABEL: u8 = 0x0a;

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
pub fn field_type_name(category: FieldCategory, field_type: u8) -> &'static str {
    match (category, field_type) {
        // Global types
        (FieldCategory::Global, PSBT_GLOBAL_UNSIGNED_TX) => "PSBT_GLOBAL_UNSIGNED_TX",
        (FieldCategory::Global, PSBT_GLOBAL_XPUB) => "PSBT_GLOBAL_XPUB",
        (FieldCategory::Global, PSBT_GLOBAL_TX_VERSION) => "PSBT_GLOBAL_TX_VERSION",
        (FieldCategory::Global, PSBT_GLOBAL_FALLBACK_LOCKTIME) => "PSBT_GLOBAL_FALLBACK_LOCKTIME",
        (FieldCategory::Global, PSBT_GLOBAL_INPUT_COUNT) => "PSBT_GLOBAL_INPUT_COUNT",
        (FieldCategory::Global, PSBT_GLOBAL_OUTPUT_COUNT) => "PSBT_GLOBAL_OUTPUT_COUNT",
        (FieldCategory::Global, PSBT_GLOBAL_TX_MODIFIABLE) => "PSBT_GLOBAL_TX_MODIFIABLE",
        (FieldCategory::Global, PSBT_GLOBAL_VERSION) => "PSBT_GLOBAL_VERSION",
        (FieldCategory::Global, PSBT_GLOBAL_PROPRIETARY) => "PSBT_GLOBAL_PROPRIETARY",
        (FieldCategory::Global, PSBT_GLOBAL_SP_ECDH_SHARE) => "PSBT_GLOBAL_SP_ECDH_SHARE",
        (FieldCategory::Global, PSBT_GLOBAL_SP_DLEQ) => "PSBT_GLOBAL_SP_DLEQ",

        // Input types
        (FieldCategory::Input, PSBT_IN_NON_WITNESS_UTXO) => "PSBT_IN_NON_WITNESS_UTXO",
        (FieldCategory::Input, PSBT_IN_WITNESS_UTXO) => "PSBT_IN_WITNESS_UTXO",
        (FieldCategory::Input, PSBT_IN_PARTIAL_SIG) => "PSBT_IN_PARTIAL_SIG",
        (FieldCategory::Input, PSBT_IN_SIGHASH_TYPE) => "PSBT_IN_SIGHASH_TYPE",
        (FieldCategory::Input, PSBT_IN_REDEEM_SCRIPT) => "PSBT_IN_REDEEM_SCRIPT",
        (FieldCategory::Input, PSBT_IN_WITNESS_SCRIPT) => "PSBT_IN_WITNESS_SCRIPT",
        (FieldCategory::Input, PSBT_IN_BIP32_DERIVATION) => "PSBT_IN_BIP32_DERIVATION",
        (FieldCategory::Input, PSBT_IN_FINAL_SCRIPTSIG) => "PSBT_IN_FINAL_SCRIPTSIG",
        (FieldCategory::Input, PSBT_IN_FINAL_SCRIPTWITNESS) => "PSBT_IN_FINAL_SCRIPTWITNESS",
        (FieldCategory::Input, PSBT_IN_POR_COMMITMENT) => "PSBT_IN_POR_COMMITMENT",
        (FieldCategory::Input, PSBT_IN_RIPEMD160) => "PSBT_IN_RIPEMD160",
        (FieldCategory::Input, PSBT_IN_SHA256) => "PSBT_IN_SHA256",
        (FieldCategory::Input, PSBT_IN_HASH160) => "PSBT_IN_HASH160",
        (FieldCategory::Input, PSBT_IN_HASH256) => "PSBT_IN_HASH256",
        (FieldCategory::Input, PSBT_IN_PREVIOUS_TXID) => "PSBT_IN_PREVIOUS_TXID",
        (FieldCategory::Input, PSBT_IN_OUTPUT_INDEX) => "PSBT_IN_OUTPUT_INDEX",
        (FieldCategory::Input, PSBT_IN_SEQUENCE) => "PSBT_IN_SEQUENCE",
        (FieldCategory::Input, PSBT_IN_REQUIRED_TIME_LOCKTIME) => "PSBT_IN_REQUIRED_TIME_LOCKTIME",
        (FieldCategory::Input, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME) => "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
        (FieldCategory::Input, PSBT_IN_TAP_KEY_SIG) => "PSBT_IN_TAP_KEY_SIG",
        (FieldCategory::Input, PSBT_IN_TAP_SCRIPT_SIG) => "PSBT_IN_TAP_SCRIPT_SIG",
        (FieldCategory::Input, PSBT_IN_TAP_LEAF_SCRIPT) => "PSBT_IN_TAP_LEAF_SCRIPT",
        (FieldCategory::Input, PSBT_IN_TAP_BIP32_DERIVATION) => "PSBT_IN_TAP_BIP32_DERIVATION",
        (FieldCategory::Input, PSBT_IN_TAP_INTERNAL_KEY) => "PSBT_IN_TAP_INTERNAL_KEY",
        (FieldCategory::Input, PSBT_IN_TAP_MERKLE_ROOT) => "PSBT_IN_TAP_MERKLE_ROOT",
        (FieldCategory::Input, PSBT_IN_PROPRIETARY) => "PSBT_IN_PROPRIETARY",
        (FieldCategory::Input, PSBT_IN_SP_ECDH_SHARE) => "PSBT_IN_SP_ECDH_SHARE",
        (FieldCategory::Input, PSBT_IN_SP_DLEQ) => "PSBT_IN_SP_DLEQ",

        // Output types
        (FieldCategory::Output, PSBT_OUT_REDEEM_SCRIPT) => "PSBT_OUT_REDEEM_SCRIPT",
        (FieldCategory::Output, PSBT_OUT_WITNESS_SCRIPT) => "PSBT_OUT_WITNESS_SCRIPT",
        (FieldCategory::Output, PSBT_OUT_BIP32_DERIVATION) => "PSBT_OUT_BIP32_DERIVATION",
        (FieldCategory::Output, PSBT_OUT_AMOUNT) => "PSBT_OUT_AMOUNT",
        (FieldCategory::Output, PSBT_OUT_SCRIPT) => "PSBT_OUT_SCRIPT",
        (FieldCategory::Output, PSBT_OUT_TAP_INTERNAL_KEY) => "PSBT_OUT_TAP_INTERNAL_KEY",
        (FieldCategory::Output, PSBT_OUT_TAP_TREE) => "PSBT_OUT_TAP_TREE",
        (FieldCategory::Output, PSBT_OUT_TAP_BIP32_DERIVATION) => "PSBT_OUT_TAP_BIP32_DERIVATION",
        (FieldCategory::Output, PSBT_OUT_PROPRIETARY) => "PSBT_OUT_PROPRIETARY",
        (FieldCategory::Output, PSBT_OUT_SP_V0_INFO) => "PSBT_OUT_SP_V0_INFO",
        (FieldCategory::Output, PSBT_OUT_SP_V0_LABEL) => "PSBT_OUT_SP_V0_LABEL",

        _ => "UNKNOWN_FIELD",
    }
}
