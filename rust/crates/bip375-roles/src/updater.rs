//! PSBT Updater Role
//!
//! Adds additional information like BIP32 derivation paths.

use bip375_core::{constants::*, PsbtField, Result, SilentPaymentPsbt};

/// BIP32 derivation information
pub struct Bip32Derivation {
    /// Master fingerprint (4 bytes)
    pub master_fingerprint: [u8; 4],
    /// Derivation path
    pub path: Vec<u32>,
}

impl Bip32Derivation {
    /// Create a new BIP32 derivation
    pub fn new(master_fingerprint: [u8; 4], path: Vec<u32>) -> Self {
        Self {
            master_fingerprint,
            path,
        }
    }

    /// Serialize to PSBT format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Master fingerprint (4 bytes)
        bytes.extend_from_slice(&self.master_fingerprint);
        // Path length as compact size
        // Each path component is 4 bytes
        for component in &self.path {
            bytes.extend_from_slice(&component.to_le_bytes());
        }
        bytes
    }
}

/// Add BIP32 derivation information for an input
pub fn add_input_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    pubkey: &secp256k1::PublicKey,
    derivation: &Bip32Derivation,
) -> Result<()> {
    // Key data is the public key (33 bytes compressed)
    let key_data = pubkey.serialize().to_vec();

    // Value is master fingerprint + derivation path
    let value_data = derivation.to_bytes();

    psbt.add_input_field(
        input_index,
        PsbtField::new(PSBT_IN_BIP32_DERIVATION, key_data, value_data),
    )?;

    Ok(())
}

/// Add BIP32 derivation information for an output
pub fn add_output_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    output_index: usize,
    pubkey: &secp256k1::PublicKey,
    derivation: &Bip32Derivation,
) -> Result<()> {
    // Key data is the public key (33 bytes compressed)
    let key_data = pubkey.serialize().to_vec();

    // Value is master fingerprint + derivation path
    let value_data = derivation.to_bytes();

    psbt.add_output_field(
        output_index,
        PsbtField::new(PSBT_OUT_BIP32_DERIVATION, key_data, value_data),
    )?;

    Ok(())
}

/// Add sighash type for an input
pub fn add_input_sighash_type(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    sighash_type: u32,
) -> Result<()> {
    psbt.add_input_field(
        input_index,
        PsbtField::with_value(PSBT_IN_SIGHASH_TYPE, sighash_type.to_le_bytes().to_vec()),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::create_psbt;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_bip32_derivation() {
        let derivation = Bip32Derivation::new([0x12, 0x34, 0x56, 0x78], vec![0x8000002C, 0x80000000]);

        let bytes = derivation.to_bytes();
        assert_eq!(&bytes[0..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(bytes.len(), 4 + 8); // fingerprint + 2 path components
    }

    #[test]
    fn test_add_input_bip32_derivation() {
        let mut psbt = create_psbt(1, 1).unwrap();
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);

        let derivation = Bip32Derivation::new([0xAA, 0xBB, 0xCC, 0xDD], vec![0x8000002C]);

        add_input_bip32_derivation(&mut psbt, 0, &pubkey, &derivation).unwrap();

        // Verify derivation was added
        let field = psbt.get_input_field(0, PSBT_IN_BIP32_DERIVATION).unwrap();
        assert_eq!(field.key_data, pubkey.serialize());
    }

    #[test]
    fn test_add_sighash_type() {
        let mut psbt = create_psbt(1, 1).unwrap();

        add_input_sighash_type(&mut psbt, 0, 0x01).unwrap(); // SIGHASH_ALL

        let field = psbt.get_input_field(0, PSBT_IN_SIGHASH_TYPE).unwrap();
        assert_eq!(field.value_data, vec![0x01, 0x00, 0x00, 0x00]);
    }
}
