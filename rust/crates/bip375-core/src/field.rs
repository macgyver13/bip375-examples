//! PSBT Field Types
//!
//! Basic building blocks for PSBT data structures.

use crate::error::{Error, Result};
use std::io::{Read, Write};

/// A single PSBT field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtField {
    /// Field type byte
    pub field_type: u8,
    /// Optional key data (everything after field_type in the key)
    pub key_data: Vec<u8>,
    /// Field value data
    pub value_data: Vec<u8>,
}

impl PsbtField {
    /// Create a new PSBT field
    pub fn new(field_type: u8, key_data: Vec<u8>, value_data: Vec<u8>) -> Self {
        Self {
            field_type,
            key_data,
            value_data,
        }
    }

    /// Create a field with no key data
    pub fn with_value(field_type: u8, value_data: Vec<u8>) -> Self {
        Self::new(field_type, vec![], value_data)
    }

    /// Get the full key (field_type + key_data)
    pub fn full_key(&self) -> Vec<u8> {
        let mut key = vec![self.field_type];
        key.extend_from_slice(&self.key_data);
        key
    }

    /// Get the key length (1 + key_data.len())
    pub fn key_len(&self) -> usize {
        1 + self.key_data.len()
    }

    /// Write a compact size integer
    pub fn write_compact_size<W: Write>(w: &mut W, n: u64) -> Result<()> {
        if n < 0xfd {
            w.write_all(&[n as u8])?;
        } else if n <= 0xffff {
            w.write_all(&[0xfd])?;
            w.write_all(&(n as u16).to_le_bytes())?;
        } else if n <= 0xffff_ffff {
            w.write_all(&[0xfe])?;
            w.write_all(&(n as u32).to_le_bytes())?;
        } else {
            w.write_all(&[0xff])?;
            w.write_all(&n.to_le_bytes())?;
        }
        Ok(())
    }

    /// Read a compact size integer
    pub fn read_compact_size<R: Read>(r: &mut R) -> Result<u64> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;

        match buf[0] {
            0xff => {
                let mut buf = [0u8; 8];
                r.read_exact(&mut buf)?;
                Ok(u64::from_le_bytes(buf))
            }
            0xfe => {
                let mut buf = [0u8; 4];
                r.read_exact(&mut buf)?;
                Ok(u32::from_le_bytes(buf) as u64)
            }
            0xfd => {
                let mut buf = [0u8; 2];
                r.read_exact(&mut buf)?;
                Ok(u16::from_le_bytes(buf) as u64)
            }
            n => Ok(n as u64),
        }
    }

    /// Serialize this field to bytes
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        // Write key
        let key = self.full_key();
        Self::write_compact_size(w, key.len() as u64)?;
        w.write_all(&key)?;

        // Write value
        Self::write_compact_size(w, self.value_data.len() as u64)?;
        w.write_all(&self.value_data)?;

        Ok(())
    }

    /// Deserialize a field from bytes
    pub fn deserialize<R: Read>(r: &mut R) -> Result<Option<Self>> {
        // Read key length
        let key_len = match Self::read_compact_size(r) {
            Ok(0) => return Ok(None), // Separator byte
            Ok(len) => len as usize,
            Err(_) => return Ok(None), // End of data
        };

        // Read key
        let mut key = vec![0u8; key_len];
        r.read_exact(&mut key)?;

        if key.is_empty() {
            return Err(Error::Deserialization("Empty key".to_string()));
        }

        let field_type = key[0];
        let key_data = key[1..].to_vec();

        // Read value length
        let value_len = Self::read_compact_size(r)? as usize;

        // Read value
        let mut value_data = vec![0u8; value_len];
        r.read_exact(&mut value_data)?;

        Ok(Some(Self {
            field_type,
            key_data,
            value_data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_size() {
        let mut buf = Vec::new();

        // Test small value
        PsbtField::write_compact_size(&mut buf, 252).unwrap();
        assert_eq!(buf, vec![252]);

        // Test fd
        buf.clear();
        PsbtField::write_compact_size(&mut buf, 253).unwrap();
        assert_eq!(buf, vec![0xfd, 253, 0]);

        // Read back
        let val = PsbtField::read_compact_size(&mut &buf[..]).unwrap();
        assert_eq!(val, 253);
    }

    #[test]
    fn test_field_serialization() {
        let field = PsbtField::new(0x02, vec![0x01, 0x02], vec![0x03, 0x04, 0x05]);

        let mut buf = Vec::new();
        field.serialize(&mut buf).unwrap();

        let deserialized = PsbtField::deserialize(&mut &buf[..]).unwrap().unwrap();
        assert_eq!(field, deserialized);
    }
}
