//! BIP-375 Extension Traits for rust-psbt
//!
//! This module provides extension traits that add BIP-375 silent payment functionality
//! to the `psbt_v2::v2::Psbt` type. The design is intended to be upstreamable to rust-psbt
//! in the future.
//!
//! # Design Philosophy
//!
//! - **Non-invasive**: Uses extension traits rather than wrapping types
//! - **Idiomatic**: Follows rust-psbt patterns and conventions
//! - **Upstreamable**: Clean API that could be contributed to rust-psbt
//! - **Type-safe**: Leverages Rust's type system for correctness

use crate::{
    constants::*,
    error::{Error, Result},
    types::{EcdhShare, SilentPaymentAddress},
};
use psbt_v2::{raw::Key, v2::Psbt};
use secp256k1::PublicKey;

/// Extension trait for BIP-375 silent payment fields on PSBT v2
///
/// This trait adds methods to access and modify BIP-375 specific fields:
/// - ECDH shares (global and per-input)
/// - DLEQ proofs (global and per-input)
/// - Silent payment addresses (per-output)
/// - Silent payment labels (per-output)
pub trait Bip375PsbtExt {
    // ===== Global ECDH Shares =====

    /// Get all global ECDH shares
    ///
    /// Global shares are used when one party knows all input private keys.
    /// Field type: PSBT_GLOBAL_SP_ECDH_SHARE (0x07)
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShare>;

    /// Add a global ECDH share
    ///
    /// # Arguments
    /// * `share` - The ECDH share to add
    fn add_global_ecdh_share(&mut self, share: &EcdhShare) -> Result<()>;

    // ===== Per-Input ECDH Shares =====

    /// Get ECDH shares for a specific input
    ///
    /// Returns per-input shares if present, otherwise falls back to global shares.
    /// Field type: PSBT_IN_SP_ECDH_SHARE (0x1d)
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShare>;

    /// Add an ECDH share to a specific input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `share` - The ECDH share to add
    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShare) -> Result<()>;

    // ===== DLEQ Proofs =====

    /// Get global DLEQ proof for a scan key
    ///
    /// Field type: PSBT_GLOBAL_SP_DLEQ (0x08)
    ///
    /// # Arguments
    /// * `scan_key` - The scan key to look up
    fn get_global_dleq_proof(&self, scan_key: &PublicKey) -> Option<[u8; 64]>;

    /// Add a global DLEQ proof
    ///
    /// # Arguments
    /// * `scan_key` - The scan key this proof is for
    /// * `proof` - The 64-byte DLEQ proof
    fn add_global_dleq_proof(&mut self, scan_key: &PublicKey, proof: [u8; 64]) -> Result<()>;

    /// Get DLEQ proof for a specific input and scan key
    ///
    /// Field type: PSBT_IN_SP_DLEQ (0x1e)
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `scan_key` - The scan key to look up
    fn get_input_dleq_proof(&self, input_index: usize, scan_key: &PublicKey)
        -> Option<[u8; 64]>;

    /// Add a DLEQ proof to a specific input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `scan_key` - The scan key this proof is for
    /// * `proof` - The 64-byte DLEQ proof
    fn add_input_dleq_proof(
        &mut self,
        input_index: usize,
        scan_key: &PublicKey,
        proof: [u8; 64],
    ) -> Result<()>;

    // ===== Silent Payment Outputs =====

    /// Get silent payment address for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_INFO (0x09)
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_address(&self, output_index: usize) -> Option<SilentPaymentAddress>;

    /// Set silent payment address for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `address` - The silent payment address
    fn set_output_sp_address(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()>;

    /// Get silent payment label for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_LABEL (0x0a)
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_label(&self, output_index: usize) -> Option<u32>;

    /// Set silent payment label for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `label` - The label value
    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()>;

    // ===== Convenience Methods =====

    /// Get the number of inputs
    fn num_inputs(&self) -> usize;

    /// Get the number of outputs
    fn num_outputs(&self) -> usize;

    /// Get partial signatures for an input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)>;

    // ===== Generic Field Accessors =====

    /// Add a global field (for custom/unknown fields)
    ///
    /// # Arguments
    /// * `field` - The field to add
    fn add_global_field(&mut self, field: crate::field::PsbtField);

    /// Get a global field by type
    ///
    /// # Arguments
    /// * `field_type` - The field type to look up
    fn get_global_field(&self, field_type: u8) -> Option<crate::field::PsbtField>;

    /// Add an input field
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `field` - The field to add
    fn add_input_field(&mut self, input_index: usize, field: crate::field::PsbtField) -> Result<()>;

    /// Get an input field by type
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `field_type` - The field type to look up
    fn get_input_field(&self, input_index: usize, field_type: u8) -> Option<crate::field::PsbtField>;

    /// Add an output field
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `field` - The field to add
    fn add_output_field(&mut self, output_index: usize, field: crate::field::PsbtField) -> Result<()>;

    /// Get an output field by type
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `field_type` - The field type to look up
    fn get_output_field(&self, output_index: usize, field_type: u8) -> Option<crate::field::PsbtField>;
}

impl Bip375PsbtExt for Psbt {
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShare> {
        let mut shares = Vec::new();

        // Access native BIP375 fields from rust-psbt
        for (scan_key_bytes, share_bytes) in &self.global.sp_ecdh_shares {
            if let Ok(scan_key) = PublicKey::from_slice(scan_key_bytes) {
                if let Ok(share_point) = PublicKey::from_slice(share_bytes) {
                    // Look for corresponding DLEQ proof
                    let dleq_proof = self.get_global_dleq_proof(&scan_key);
                    shares.push(EcdhShare::new(scan_key, share_point, dleq_proof));
                }
            }
        }

        shares
    }

    fn add_global_ecdh_share(&mut self, share: &EcdhShare) -> Result<()> {
        // Use native rust-psbt fields
        self.global.sp_ecdh_shares.insert(
            share.scan_key.serialize().to_vec(),
            share.share.serialize().to_vec(),
        );

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            self.add_global_dleq_proof(&share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShare> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut shares = Vec::new();

        // First check for per-input ECDH shares (0x1d)
        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_SP_ECDH_SHARE && key.key.len() == 33 {
                // key format: type_value=0x1d, key=33-byte scan key
                // value format: 33-byte ECDH share
                if value.len() == 33 {
                    if let Ok(scan_key) = PublicKey::from_slice(&key.key) {
                        if let Ok(share_point) = PublicKey::from_slice(value) {
                            // Look for DLEQ proof (input-specific or global)
                            let dleq_proof = self
                                .get_input_dleq_proof(input_index, &scan_key)
                                .or_else(|| self.get_global_dleq_proof(&scan_key));
                            shares.push(EcdhShare::new(scan_key, share_point, dleq_proof));
                        }
                    }
                }
            }
        }

        // If no per-input shares, fall back to global shares
        if shares.is_empty() {
            shares = self.get_global_ecdh_shares();
        }

        shares
    }

    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShare) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Create key: type_value=0x1d, key=33-byte scan key
        let key = Key {
            type_value: PSBT_IN_SP_ECDH_SHARE,
            key: share.scan_key.serialize().to_vec(),
        };

        // Value: 33-byte ECDH share
        let value = share.share.serialize().to_vec();

        input.unknowns.insert(key, value);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            self.add_input_dleq_proof(input_index, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_global_dleq_proof(&self, scan_key: &PublicKey) -> Option<[u8; 64]> {
        // Use native rust-psbt fields
        let scan_key_bytes = scan_key.serialize().to_vec();
        self.global.sp_dleq_proofs.get(&scan_key_bytes).and_then(|value| {
            if value.len() == 64 {
                let mut proof = [0u8; 64];
                proof.copy_from_slice(value);
                Some(proof)
            } else {
                None
            }
        })
    }

    fn add_global_dleq_proof(&mut self, scan_key: &PublicKey, proof: [u8; 64]) -> Result<()> {
        // Use native rust-psbt fields
        self.global.sp_dleq_proofs.insert(
            scan_key.serialize().to_vec(),
            proof.to_vec(),
        );
        Ok(())
    }

    fn get_input_dleq_proof(
        &self,
        input_index: usize,
        scan_key: &PublicKey,
    ) -> Option<[u8; 64]> {
        let input = self.inputs.get(input_index)?;

        // Key format: type_value=0x1e, key=33-byte scan key
        let key = Key {
            type_value: PSBT_IN_SP_DLEQ,
            key: scan_key.serialize().to_vec(),
        };

        input.unknowns.get(&key).and_then(|value| {
            if value.len() == 64 {
                let mut proof = [0u8; 64];
                proof.copy_from_slice(value);
                Some(proof)
            } else {
                None
            }
        })
    }

    fn add_input_dleq_proof(
        &mut self,
        input_index: usize,
        scan_key: &PublicKey,
        proof: [u8; 64],
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Key format: type_value=0x1e, key=33-byte scan key
        let key = Key {
            type_value: PSBT_IN_SP_DLEQ,
            key: scan_key.serialize().to_vec(),
        };

        input.unknowns.insert(key, proof.to_vec());
        Ok(())
    }

    fn get_output_sp_address(&self, output_index: usize) -> Option<SilentPaymentAddress> {
        let output = self.outputs.get(output_index)?;

        // Key format: type_value=0x09, key=empty
        let key = Key {
            type_value: PSBT_OUT_SP_V0_INFO,
            key: vec![],
        };

        output
            .unknowns
            .get(&key)
            .and_then(|value| SilentPaymentAddress::from_bytes(value).ok())
    }

    fn set_output_sp_address(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        // Key format: type_value=0x09, key=empty
        let key = Key {
            type_value: PSBT_OUT_SP_V0_INFO,
            key: vec![],
        };

        // Value: serialized silent payment address
        let value = address.to_bytes();

        output.unknowns.insert(key, value);
        Ok(())
    }

    fn get_output_sp_label(&self, output_index: usize) -> Option<u32> {
        let output = self.outputs.get(output_index)?;

        // Key format: type_value=0x0a, key=empty
        let key = Key {
            type_value: PSBT_OUT_SP_V0_LABEL,
            key: vec![],
        };

        output.unknowns.get(&key).and_then(|value| {
            if value.len() == 4 {
                Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
            } else {
                None
            }
        })
    }

    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        // Key format: type_value=0x0a, key=empty
        let key = Key {
            type_value: PSBT_OUT_SP_V0_LABEL,
            key: vec![],
        };

        // Value: 4-byte little-endian label
        let value = label.to_le_bytes().to_vec();

        output.unknowns.insert(key, value);
        Ok(())
    }

    fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if let Some(input) = self.inputs.get(input_index) {
            input.partial_sigs.iter()
                .map(|(pk, sig)| (pk.inner.serialize().to_vec(), sig.to_vec()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn add_global_field(&mut self, field: crate::field::PsbtField) {
        let key = Key {
            type_value: field.field_type,
            key: field.key_data,
        };
        self.global.unknowns.insert(key, field.value_data);
    }

    fn get_global_field(&self, field_type: u8) -> Option<crate::field::PsbtField> {
        for (key, value) in &self.global.unknowns {
            if key.type_value == field_type {
                return Some(crate::field::PsbtField::new(
                    key.type_value,
                    key.key.clone(),
                    value.clone(),
                ));
            }
        }
        None
    }

    fn add_input_field(&mut self, input_index: usize, field: crate::field::PsbtField) -> Result<()> {
        let input = self.inputs.get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let key = Key {
            type_value: field.field_type,
            key: field.key_data,
        };
        input.unknowns.insert(key, field.value_data);
        Ok(())
    }

    fn get_input_field(&self, input_index: usize, field_type: u8) -> Option<crate::field::PsbtField> {
        let input = self.inputs.get(input_index)?;

        for (key, value) in &input.unknowns {
            if key.type_value == field_type {
                return Some(crate::field::PsbtField::new(
                    key.type_value,
                    key.key.clone(),
                    value.clone(),
                ));
            }
        }
        None
    }

    fn add_output_field(&mut self, output_index: usize, field: crate::field::PsbtField) -> Result<()> {
        let output = self.outputs.get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        let key = Key {
            type_value: field.field_type,
            key: field.key_data,
        };
        output.unknowns.insert(key, field.value_data);
        Ok(())
    }

    fn get_output_field(&self, output_index: usize, field_type: u8) -> Option<crate::field::PsbtField> {
        let output = self.outputs.get(output_index)?;

        for (key, value) in &output.unknowns {
            if key.type_value == field_type {
                return Some(crate::field::PsbtField::new(
                    key.type_value,
                    key.key.clone(),
                    value.clone(),
                ));
            }
        }
        None
    }
}

/// Extension trait for accessing psbt_v2::v2::Global fields
///
/// This trait provides convenient methods to access all standard PSBT v2 global fields
/// in a serialized format suitable for display or further processing.
pub trait GlobalFieldsExt {
    /// Iterator over all standard global fields as (field_type, key_data, value_data) tuples
    ///
    /// Returns fields in the following order:
    /// - PSBT_GLOBAL_VERSION (0x00)
    /// - PSBT_GLOBAL_XPUB (0x01) - Multiple entries possible
    /// - PSBT_GLOBAL_TX_VERSION (0x02)
    /// - PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03) - If present
    /// - PSBT_GLOBAL_TX_MODIFIABLE (0x04)
    /// - PSBT_GLOBAL_INPUT_COUNT (0x05)
    /// - PSBT_GLOBAL_OUTPUT_COUNT (0x06)
    /// - PSBT_GLOBAL_SP_ECDH_SHARE (0x07) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_SP_DLEQ (0x08) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_PROPRIETARY (0xFC) - Multiple entries possible
    /// - Unknown fields from the unknowns map
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        use bitcoin::consensus::Encodable;
        let mut fields = Vec::new();

        // PSBT_GLOBAL_VERSION (0x00) - Always present
        {
            let field_type = 0x00;
            let key_data = vec![];
            let value_data = self.version.to_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_XPUB (0x01) - Can have multiple entries
        for (xpub, key_source) in &self.xpubs {
            let field_type = 0x01;
            // Key is the serialized xpub
            let key_data = xpub.to_string().as_bytes().to_vec();
            // Value is the key source (fingerprint + derivation path)
            let mut value_data = Vec::new();
            // Fingerprint is 4 bytes
            value_data.extend_from_slice(&key_source.0.to_bytes());
            // Derivation path - each ChildNumber is 4 bytes (u32)
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_VERSION (0x02) - Always present
        {
            let field_type = 0x02;
            let key_data = vec![];
            let value_data = self.tx_version.0.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03) - Optional
        if let Some(lock_time) = self.fallback_lock_time {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = lock_time.to_consensus_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_MODIFIABLE (0x04) - Always present
        {
            let field_type = 0x04;
            let key_data = vec![];
            let value_data = vec![self.tx_modifiable_flags];
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_INPUT_COUNT (0x05) - Always present
        {
            let field_type = 0x05;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.input_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_OUTPUT_COUNT (0x06) - Always present
        {
            let field_type = 0x06;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.output_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_SP_ECDH_SHARE (0x07) - BIP-375, can have multiple entries
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            let field_type = 0x07;
            fields.push((field_type, scan_key.clone(), ecdh_share.clone()));
        }

        // PSBT_GLOBAL_SP_DLEQ (0x08) - BIP-375, can have multiple entries  
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            let field_type = 0x08;
            fields.push((field_type, scan_key.clone(), dleq_proof.clone()));
        }

        // PSBT_GLOBAL_PROPRIETARY (0xFC) - Can have multiple entries
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            // Key data is the proprietary key structure
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields from the unknowns map
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn create_test_psbt() -> Psbt {
        // Create a minimal valid PSBT v2
        Psbt {
            global: psbt_v2::v2::Global::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    #[test]
    fn test_global_ecdh_share() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = EcdhShare::without_proof(scan_key, share_point);

        // Add share
        psbt.add_global_ecdh_share(&share).unwrap();

        // Retrieve shares
        let shares = psbt.get_global_ecdh_shares();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].scan_key, scan_key);
        assert_eq!(shares[0].share, share_point);
    }

    #[test]
    fn test_global_dleq_proof() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let proof = [0x42u8; 64];

        // Add proof
        psbt.add_global_dleq_proof(&scan_key, proof).unwrap();

        // Retrieve proof
        let retrieved = psbt.get_global_dleq_proof(&scan_key);
        assert_eq!(retrieved, Some(proof));
    }

    #[test]
    fn test_output_sp_address() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let address = SilentPaymentAddress::without_label(scan_key, spend_key);

        // Set address
        psbt.set_output_sp_address(0, &address).unwrap();

        // Retrieve address
        let retrieved = psbt.get_output_sp_address(0);
        assert_eq!(retrieved, Some(address));
    }

    #[test]
    fn test_output_sp_label() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let label = 42u32;

        // Set label
        psbt.set_output_sp_label(0, label).unwrap();

        // Retrieve label
        let retrieved = psbt.get_output_sp_label(0);
        assert_eq!(retrieved, Some(label));
    }
}
