//! Local script/crypto helpers for the demo layer.
//!
//! These were previously provided by `spdk_core::psbt::crypto`. The new standalone
//! `psbt` crate no longer exposes them, so they live here (pure `bitcoin`/`secp256k1`
//! operations used only by the example/demo helpers).

use bitcoin::key::TapTweak;
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Scalar, SecretKey};

/// Build a P2WPKH `scriptPubKey` from a compressed public key.
pub fn pubkey_to_p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
    let pubkey_hash = bitcoin::PublicKey::new(*pubkey)
        .wpubkey_hash()
        .expect("Compressed key");

    ScriptBuf::new_p2wpkh(&pubkey_hash)
}

/// Build a P2TR `scriptPubKey` from an already-tweaked output key
/// (e.g. a BIP-352 silent payment output key).
pub fn tweaked_key_to_p2tr_script(tweaked_output_key: &PublicKey) -> ScriptBuf {
    let xonly = tweaked_output_key.x_only_public_key().0;
    ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked())
}

/// Human-readable script type label for display.
pub fn script_type_string(script: &ScriptBuf) -> &'static str {
    if script.is_p2wpkh() {
        "P2WPKH"
    } else if script.is_p2tr() {
        "P2TR"
    } else if script.is_p2pkh() {
        "P2PKH"
    } else if script.is_p2sh() {
        "P2SH"
    } else if script.is_p2wsh() {
        "P2WSH"
    } else if script.is_op_return() {
        "OP_RETURN"
    } else {
        "Unknown"
    }
}

/// Apply a 32-byte additive tweak to a private key (BIP-352 spend key tweaking).
pub fn apply_tweak_to_privkey(spend_privkey: &SecretKey, tweak: &[u8; 32]) -> Result<SecretKey, String> {
    let tweak_scalar = Scalar::from_be_bytes(*tweak).map_err(|_| "Invalid tweak scalar".to_string())?;

    (*spend_privkey)
        .add_tweak(&tweak_scalar)
        .map_err(|e| format!("Failed to apply tweak: {}", e))
}
