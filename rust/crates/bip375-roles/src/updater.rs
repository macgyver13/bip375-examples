//! PSBT Updater Role
//!
//! Adds additional information like BIP32 derivation paths.

use bip375_core::{Error, Result, SilentPaymentPsbt};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::EcdsaSighashType;
use psbt_v2::PsbtSighashType;

/// Add BIP32 derivation information for an input
///
/// Automatically detects the script type and adds derivation to the appropriate field:
/// - For P2TR (Taproot): adds to `tap_key_origins` using x-only pubkey - leaf_hashes omitted for demo
/// - For legacy/SegWit v0 (P2PKH, P2WPKH, P2SH, P2WSH): adds to `bip32_derivations`
///
/// # Arguments
/// * `psbt` - The PSBT to modify
/// * `input_index` - Index of the input
/// * `pubkey` - Full public key (will be converted to x-only for Taproot)
/// * `master_fingerprint` - Master key fingerprint (4 bytes)
/// * `path` - BIP32 derivation path as Vec<u32> with hardening applied
pub fn add_input_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    pubkey: &secp256k1::PublicKey,
    master_fingerprint: [u8; 4],
    path: Vec<u32>,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let fingerprint = Fingerprint::from(master_fingerprint);
    let derivation_path: DerivationPath = path.iter().map(|&i| ChildNumber::from(i)).collect();

    // Detect script type from witness_utxo
    if let Some(ref utxo) = input.witness_utxo {
        if utxo.script_pubkey.is_p2tr() {
            // For Taproot, use tap_key_origins with x-only pubkey
            let xonly_pubkey = bitcoin::key::XOnlyPublicKey::from(*pubkey);
            input
                .tap_key_origins
                .insert(xonly_pubkey, (vec![], (fingerprint, derivation_path)));
        } else {
            // For legacy/SegWit v0, use bip32_derivations
            input
                .bip32_derivations
                .insert(*pubkey, (fingerprint, derivation_path));
        }
    } else {
        // If no witness_utxo, default to bip32_derivations for legacy
        input
            .bip32_derivations
            .insert(*pubkey, (fingerprint, derivation_path));
    }

    Ok(())
}

/// Add BIP32 derivation information for an output
pub fn add_output_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    output_index: usize,
    pubkey: &secp256k1::PublicKey,
    master_fingerprint: [u8; 4],
    path: Vec<u32>,
) -> Result<()> {
    let output = psbt
        .outputs
        .get_mut(output_index)
        .ok_or(Error::InvalidOutputIndex(output_index))?;

    let fingerprint = Fingerprint::from(master_fingerprint);
    let derivation_path: DerivationPath = path.iter().map(|&i| ChildNumber::from(i)).collect();

    output
        .bip32_derivations
        .insert(*pubkey, (fingerprint, derivation_path));

    Ok(())
}

/// Add xpub to the global PSBT section
///
/// Adds PSBT_GLOBAL_XPUB with the extended public key and its origin information.
pub fn add_global_xpub(
    psbt: &mut SilentPaymentPsbt,
    xpub: bitcoin::bip32::Xpub,
    master_fingerprint: [u8; 4],
    path: Vec<u32>,
) -> Result<()> {
    let fingerprint = Fingerprint::from(master_fingerprint);
    let derivation_path: DerivationPath = path.iter().map(|&i| ChildNumber::from(i)).collect();

    psbt.global
        .xpubs
        .insert(xpub, (fingerprint, derivation_path));

    Ok(())
}

/// Add sighash type for an input
pub fn add_input_sighash_type(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    sighash_type: u32,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let sighash = EcdsaSighashType::from_consensus(sighash_type);
    input.sighash_type = Some(PsbtSighashType::from(sighash));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::create_psbt;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_add_input_bip32_derivation() {
        let mut psbt = create_psbt(1, 1).unwrap();
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);

        let fingerprint = [0xAA, 0xBB, 0xCC, 0xDD];
        let path = vec![0x8000002C];

        add_input_bip32_derivation(&mut psbt, 0, &pubkey, fingerprint, path).unwrap();

        // Verify derivation was added
        let input = &psbt.inputs[0];
        assert!(input.bip32_derivations.contains_key(&pubkey));

        let (fp, derivation_path) = input.bip32_derivations.get(&pubkey).unwrap();
        assert_eq!(fp.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(derivation_path.len(), 1);
    }

    #[test]
    fn test_add_sighash_type() {
        let mut psbt = create_psbt(1, 1).unwrap();

        add_input_sighash_type(&mut psbt, 0, 0x01).unwrap(); // SIGHASH_ALL

        let input = &psbt.inputs[0];
        assert!(input.sighash_type.is_some());
        assert_eq!(input.sighash_type.unwrap().to_u32(), 0x01);
    }
}
