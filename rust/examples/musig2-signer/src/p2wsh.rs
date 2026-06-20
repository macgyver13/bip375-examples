//! P2WSH multisig signing and witness construction.
//!
//! BIP-352 excludes script multisig inputs from eligible input types, so these
//! utilities are not part of the standard bip375-roles crate. They support the
//! sidecar pattern where a P2WSH treasury spends alongside an eligible P2WPKH
//! sidecar input that provides the ECDH key for silent payment derivation.

use anyhow::{bail, Result};
use bitcoin::hashes::Hash;
use bitcoin::{
    opcodes,
    script::Builder,
    sighash::{EcdsaSighashType, SighashCache},
    Amount, PublicKey as BitcoinPubKey, ScriptBuf, Transaction, Witness,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::BTreeMap;

/// Build a sortedmulti redeem script: OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG
///
/// Keys are sorted lexicographically by compressed serialization (BIP-67 / sortedmulti).
pub fn create_sortedmulti_script(threshold: usize, pubkeys: &[PublicKey]) -> ScriptBuf {
    let mut sorted = pubkeys.to_vec();
    sorted.sort_by_key(|pk| pk.serialize());

    let mut builder = Builder::new().push_int(threshold as i64);
    for pk in &sorted {
        builder = builder.push_key(&BitcoinPubKey::new(*pk));
    }
    builder
        .push_int(pubkeys.len() as i64)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script()
}

/// Derive P2WSH script_pubkey from a redeem script: OP_0 <sha256(script)>
pub fn p2wsh_from_redeem(redeem_script: &ScriptBuf) -> ScriptBuf {
    redeem_script.to_p2wsh()
}

/// Sign a P2WSH input with a single key (BIP143 sighash, SIGHASH_ALL).
///
/// Returns a bitcoin::ecdsa::Signature ready for insertion into partial_sigs.
pub fn sign_p2wsh_input(
    secp: &Secp256k1<secp256k1::All>,
    tx: &Transaction,
    input_idx: usize,
    redeem_script: &ScriptBuf,
    amount: Amount,
    privkey: &SecretKey,
) -> Result<bitcoin::ecdsa::Signature> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(input_idx, redeem_script, amount, EcdsaSighashType::All)
        .map_err(|e| anyhow::anyhow!("P2WSH sighash: {e}"))?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, privkey);

    let mut bytes = sig.serialize_der().to_vec();
    bytes.push(EcdsaSighashType::All.to_u32() as u8);

    bitcoin::ecdsa::Signature::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("sig encoding: {e}"))
}

/// Build the P2WSH multisig witness stack.
///
/// Witness: [empty, sig_1, sig_2, ..., sig_threshold, redeem_script]
///
/// Signatures are ordered to match the pubkey order in the redeem script
/// (sortedmulti ensures a canonical ordering that both signer and verifier agree on).
pub fn build_p2wsh_multisig_witness(
    partial_sigs: &BTreeMap<BitcoinPubKey, bitcoin::ecdsa::Signature>,
    redeem_script: &ScriptBuf,
    threshold: usize,
) -> Result<Witness> {
    let ordered_sigs = sigs_in_script_order(partial_sigs, redeem_script, threshold)?;

    let mut witness = Witness::new();
    witness.push([]); // OP_0 dummy required by OP_CHECKMULTISIG
    for sig in &ordered_sigs {
        witness.push(sig.to_vec());
    }
    witness.push(redeem_script.as_bytes());

    Ok(witness)
}

/// Order signatures to match pubkey order in a sortedmulti redeem script.
///
/// Parses compressed pubkeys from the script bytes (each preceded by a 0x21 push)
/// and returns the first `threshold` matching signatures in that order.
fn sigs_in_script_order(
    partial_sigs: &BTreeMap<BitcoinPubKey, bitcoin::ecdsa::Signature>,
    redeem_script: &ScriptBuf,
    threshold: usize,
) -> Result<Vec<bitcoin::ecdsa::Signature>> {
    // Parse pubkeys from script: OP_M [0x21 <33-byte pk>]... OP_N OP_CHECKMULTISIG
    let bytes = redeem_script.as_bytes();
    let mut pubkeys: Vec<BitcoinPubKey> = Vec::new();
    let mut i = 1usize; // skip OP_M
    while i + 33 < bytes.len() {
        if bytes[i] == 0x21 {
            // push 33 bytes
            if let Ok(pk) = BitcoinPubKey::from_slice(&bytes[i + 1..i + 34]) {
                pubkeys.push(pk);
            }
            i += 34;
        } else {
            break;
        }
    }

    let mut result = Vec::new();
    for pk in &pubkeys {
        if let Some(sig) = partial_sigs.get(pk) {
            result.push(*sig);
            if result.len() == threshold {
                break;
            }
        }
    }

    if result.len() < threshold {
        bail!(
            "only {}/{} required signatures matched script pubkey order",
            result.len(),
            threshold
        );
    }

    Ok(result)
}
