//! Silent Payment PSBT Implementation
//!
//! Main PSBT v2 structure with BIP-375 silent payment extensions.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::field::PsbtField;
use crate::types::{EcdhShare, SilentPaymentAddress};
use secp256k1::PublicKey;
use std::io::{Cursor, Read, Write};

/// A PSBT v2 with silent payment extensions
#[derive(Debug, Clone)]
pub struct SilentPaymentPsbt {
    /// Global fields
    pub global_fields: Vec<PsbtField>,
    /// Per-input field maps
    pub input_maps: Vec<Vec<PsbtField>>,
    /// Per-output field maps
    pub output_maps: Vec<Vec<PsbtField>>,
}

impl SilentPaymentPsbt {
    /// Create a new empty PSBT
    pub fn new() -> Self {
        Self {
            global_fields: Vec::new(),
            input_maps: Vec::new(),
            output_maps: Vec::new(),
        }
    }

    /// Get the number of inputs
    pub fn num_inputs(&self) -> usize {
        self.input_maps.len()
    }

    /// Get the number of outputs
    pub fn num_outputs(&self) -> usize {
        self.output_maps.len()
    }

    /// Get a global field by type
    pub fn get_global_field(&self, field_type: u8) -> Option<&PsbtField> {
        self.global_fields.iter().find(|f| f.field_type == field_type)
    }

    /// Get a mutable global field by type
    pub fn get_global_field_mut(&mut self, field_type: u8) -> Option<&mut PsbtField> {
        self.global_fields.iter_mut().find(|f| f.field_type == field_type)
    }

    /// Add a global field
    pub fn add_global_field(&mut self, field: PsbtField) {
        self.global_fields.push(field);
    }

    /// Get an input field by type
    pub fn get_input_field(&self, input_index: usize, field_type: u8) -> Option<&PsbtField> {
        self.input_maps
            .get(input_index)?
            .iter()
            .find(|f| f.field_type == field_type)
    }

    /// Add an input field
    pub fn add_input_field(&mut self, input_index: usize, field: PsbtField) -> Result<()> {
        if input_index >= self.input_maps.len() {
            return Err(Error::InvalidInputIndex(input_index));
        }
        self.input_maps[input_index].push(field);
        Ok(())
    }

    /// Get an output field by type
    pub fn get_output_field(&self, output_index: usize, field_type: u8) -> Option<&PsbtField> {
        self.output_maps
            .get(output_index)?
            .iter()
            .find(|f| f.field_type == field_type)
    }

    /// Add an output field
    pub fn add_output_field(&mut self, output_index: usize, field: PsbtField) -> Result<()> {
        if output_index >= self.output_maps.len() {
            return Err(Error::InvalidOutputIndex(output_index));
        }
        self.output_maps[output_index].push(field);
        Ok(())
    }


    /// Get ECDH shares for a specific input
    /// Checks both input-specific fields (0x1d) and global fields (0x07)
    pub fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShare> {
        let Some(input_map) = self.input_maps.get(input_index) else {
            return Vec::new();
        };

        // First, collect input-specific ECDH shares (field type 0x1d)
        let mut shares: Vec<EcdhShare> = input_map
            .iter()
            .filter_map(|field| {
                if field.field_type == PSBT_IN_SP_ECDH_SHARE {
                    // key_data is the 33-byte scan key, value_data is the 33-byte ECDH share
                    if field.key_data.len() == 33 && field.value_data.len() == 33 {
                        if let Ok(scan_key) = PublicKey::from_slice(&field.key_data) {
                            if let Ok(share_point) = PublicKey::from_slice(&field.value_data) {
                                // Look up the corresponding DLEQ proof (input or global)
                                let dleq_proof = self.get_input_dleq_proof(input_index, &scan_key)
                                    .or_else(|| self.get_global_dleq_proof(&scan_key));
                                return Some(EcdhShare::new(scan_key, share_point, dleq_proof));
                            }
                        }
                    }
                }
                None
            })
            .collect();

        // If no input-specific shares, check for global ECDH shares (field type 0x07)
        if shares.is_empty() {
            shares = self.global_fields
                .iter()
                .filter_map(|field| {
                    if field.field_type == PSBT_GLOBAL_SP_ECDH_SHARE {
                        // key_data is the 33-byte scan key, value_data is the 33-byte ECDH share
                        if field.key_data.len() == 33 && field.value_data.len() == 33 {
                            if let Ok(scan_key) = PublicKey::from_slice(&field.key_data) {
                                if let Ok(share_point) = PublicKey::from_slice(&field.value_data) {
                                    // Look up the corresponding DLEQ proof (global)
                                    let dleq_proof = self.get_global_dleq_proof(&scan_key);
                                    return Some(EcdhShare::new(scan_key, share_point, dleq_proof));
                                }
                            }
                        }
                    }
                    None
                })
                .collect();
        }

        shares
    }

    /// Get DLEQ proof for a specific ECDH share in an input
    /// BIP-375 field type 0x1e: key = 33-byte scan key, value = 64-byte DLEQ proof
    pub fn get_input_dleq_proof(&self, input_index: usize, scan_key: &PublicKey) -> Option<[u8; 64]> {
        let input_map = self.input_maps.get(input_index)?;

        for field in input_map {
            if field.field_type == PSBT_IN_SP_DLEQ {
                // key_data is the 33-byte scan key
                if field.key_data == scan_key.serialize() && field.value_data.len() == 64 {
                    let mut proof = [0u8; 64];
                    proof.copy_from_slice(&field.value_data);
                    return Some(proof);
                }
            }
        }

        None
    }

    /// Get global DLEQ proof for a specific scan key
    /// BIP-375 field type 0x08: key = 33-byte scan key, value = 64-byte DLEQ proof
    pub fn get_global_dleq_proof(&self, scan_key: &PublicKey) -> Option<[u8; 64]> {
        for field in &self.global_fields {
            if field.field_type == PSBT_GLOBAL_SP_DLEQ {
                // key_data is the 33-byte scan key
                if field.key_data == scan_key.serialize() && field.value_data.len() == 64 {
                    let mut proof = [0u8; 64];
                    proof.copy_from_slice(&field.value_data);
                    return Some(proof);
                }
            }
        }

        None
    }

    /// Get silent payment address for an output
    /// BIP-375 field type 0x09: key = empty, value = 33-byte scan key + 33-byte spend key
    pub fn get_output_sp_address(&self, output_index: usize) -> Option<SilentPaymentAddress> {
        let output_map = self.output_maps.get(output_index)?;

        for field in output_map {
            if field.field_type == PSBT_OUT_SP_V0_INFO {
                // value_data format: <33 byte scan key><33 byte spend key>
                if let Ok(addr) = SilentPaymentAddress::from_bytes(&field.value_data) {
                    return Some(addr);
                }
            }
        }

        None
    }

    /// Get partial signatures for an input
    /// Returns a vector of (pubkey, signature) pairs
    pub fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if input_index >= self.input_maps.len() {
            return Vec::new();
        }

        self.input_maps[input_index]
            .iter()
            .filter(|field| field.field_type == PSBT_IN_PARTIAL_SIG)
            .map(|field| (field.key_data.clone(), field.value_data.clone()))
            .collect()
    }

    /// Serialize the PSBT to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write magic bytes
        buf.write_all(PSBT_MAGIC)?;

        // Write global fields
        for field in &self.global_fields {
            field.serialize(&mut buf)?;
        }
        buf.write_all(&[0x00])?; // Separator

        // Write input maps
        for input_map in &self.input_maps {
            for field in input_map {
                field.serialize(&mut buf)?;
            }
            buf.write_all(&[0x00])?; // Separator
        }

        // Write output maps
        for output_map in &self.output_maps {
            for field in output_map {
                field.serialize(&mut buf)?;
            }
            buf.write_all(&[0x00])?; // Separator
        }

        Ok(buf)
    }

    /// Deserialize a PSBT from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read and verify magic bytes
        let mut magic = [0u8; 5];
        cursor.read_exact(&mut magic)?;
        if magic != PSBT_MAGIC {
            return Err(Error::InvalidMagic);
        }

        // Read global fields
        let mut global_fields = Vec::new();
        while let Some(field) = PsbtField::deserialize(&mut cursor)? {
            global_fields.push(field);
        }

        // Verify PSBT version
        let version_field = global_fields.iter()
            .find(|f| f.field_type == PSBT_GLOBAL_VERSION)
            .ok_or_else(|| Error::MissingField("PSBT_GLOBAL_VERSION".to_string()))?;

        if version_field.value_data.len() != 4 {
            return Err(Error::InvalidFieldData("Invalid version length".to_string()));
        }

        let version = u32::from_le_bytes([
            version_field.value_data[0],
            version_field.value_data[1],
            version_field.value_data[2],
            version_field.value_data[3],
        ]);

        if version != PSBT_V2_VERSION {
            return Err(Error::InvalidVersion {
                expected: PSBT_V2_VERSION,
                actual: version,
            });
        }

        // Get input and output counts
        let input_count_field = global_fields.iter()
            .find(|f| f.field_type == PSBT_GLOBAL_INPUT_COUNT)
            .ok_or_else(|| Error::MissingField("PSBT_GLOBAL_INPUT_COUNT".to_string()))?;

        let output_count_field = global_fields.iter()
            .find(|f| f.field_type == PSBT_GLOBAL_OUTPUT_COUNT)
            .ok_or_else(|| Error::MissingField("PSBT_GLOBAL_OUTPUT_COUNT".to_string()))?;

        let mut input_count_cursor = Cursor::new(&input_count_field.value_data);
        let input_count = PsbtField::read_compact_size(&mut input_count_cursor)? as usize;

        let mut output_count_cursor = Cursor::new(&output_count_field.value_data);
        let output_count = PsbtField::read_compact_size(&mut output_count_cursor)? as usize;

        // Read input maps
        let mut input_maps = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut input_map = Vec::new();
            while let Some(field) = PsbtField::deserialize(&mut cursor)? {
                input_map.push(field);
            }
            input_maps.push(input_map);
        }

        // Read output maps
        let mut output_maps = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let mut output_map = Vec::new();
            while let Some(field) = PsbtField::deserialize(&mut cursor)? {
                output_map.push(field);
            }
            output_maps.push(output_map);
        }

        Ok(Self {
            global_fields,
            input_maps,
            output_maps,
        })
    }
}

impl Default for SilentPaymentPsbt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_creation() {
        let psbt = SilentPaymentPsbt::new();
        assert_eq!(psbt.num_inputs(), 0);
        assert_eq!(psbt.num_outputs(), 0);
    }

}
