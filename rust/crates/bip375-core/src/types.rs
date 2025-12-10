//! BIP-375 Type Definitions
//!
//! Core types for silent payments in PSBTs.

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Txid};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// A silent payment address (BIP-352)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilentPaymentAddress {
    /// Scan public key (33 bytes compressed)
    pub scan_key: PublicKey,
    /// Spend public key (33 bytes compressed)
    pub spend_key: PublicKey,
    /// Optional label for change outputs
    pub label: Option<u32>,
}

impl SilentPaymentAddress {
    /// Create a new silent payment address
    pub fn new(scan_key: PublicKey, spend_key: PublicKey, label: Option<u32>) -> Self {
        Self {
            scan_key,
            spend_key,
            label,
        }
    }

    /// Create an address without a label
    pub fn without_label(scan_key: PublicKey, spend_key: PublicKey) -> Self {
        Self::new(scan_key, spend_key, None)
    }

    /// Serialize to bytes (scan_key || spend_key || label?)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66 + if self.label.is_some() { 4 } else { 0 });
        bytes.extend_from_slice(&self.scan_key.serialize());
        bytes.extend_from_slice(&self.spend_key.serialize());
        if let Some(label) = self.label {
            bytes.extend_from_slice(&label.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != 66 && bytes.len() != 70 {
            return Err(crate::Error::InvalidAddress(format!(
                "Invalid length: expected 66 or 70 bytes, got {}",
                bytes.len()
            )));
        }

        let scan_key = PublicKey::from_slice(&bytes[0..33])
            .map_err(|e| crate::Error::InvalidAddress(e.to_string()))?;
        let spend_key = PublicKey::from_slice(&bytes[33..66])
            .map_err(|e| crate::Error::InvalidAddress(e.to_string()))?;

        let label = if bytes.len() == 70 {
            Some(u32::from_le_bytes([
                bytes[66], bytes[67], bytes[68], bytes[69],
            ]))
        } else {
            None
        };

        Ok(Self {
            scan_key,
            spend_key,
            label,
        })
    }
}

/// ECDH share for a silent payment output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhShareData {
    /// Scan public key this share is for (33 bytes)
    pub scan_key: PublicKey,
    /// ECDH share value (33 bytes compressed public key)
    pub share: PublicKey,
    /// Optional DLEQ proof (64 bytes)
    pub dleq_proof: Option<[u8; 64]>,
}

impl EcdhShareData {
    /// Create a new ECDH share
    pub fn new(scan_key: PublicKey, share: PublicKey, dleq_proof: Option<[u8; 64]>) -> Self {
        Self {
            scan_key,
            share,
            dleq_proof,
        }
    }

    /// Create an ECDH share without a DLEQ proof
    pub fn without_proof(scan_key: PublicKey, share: PublicKey) -> Self {
        Self::new(scan_key, share, None)
    }

    /// Serialize share data (scan_key || share)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&self.scan_key.serialize());
        bytes.extend_from_slice(&self.share.serialize());
        bytes
    }

    /// Deserialize share data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != 66 {
            return Err(crate::Error::InvalidEcdhShare(format!(
                "Invalid length: expected 66 bytes, got {}",
                bytes.len()
            )));
        }

        let scan_key = PublicKey::from_slice(&bytes[0..33])
            .map_err(|e| crate::Error::InvalidEcdhShare(e.to_string()))?;
        let share = PublicKey::from_slice(&bytes[33..66])
            .map_err(|e| crate::Error::InvalidEcdhShare(e.to_string()))?;

        Ok(Self {
            scan_key,
            share,
            dleq_proof: None,
        })
    }
}

/// UTXO information for creating PSBTs
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Previous transaction ID
    pub txid: Txid,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: Amount,
    /// ScriptPubKey of the output
    pub script_pubkey: ScriptBuf,
    /// Private key for signing (if available)
    pub private_key: Option<SecretKey>,
    /// Sequence number
    pub sequence: Sequence,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(
        txid: Txid,
        vout: u32,
        amount: Amount,
        script_pubkey: ScriptBuf,
        private_key: Option<SecretKey>,
        sequence: Sequence,
    ) -> Self {
        Self {
            txid,
            vout,
            amount,
            script_pubkey,
            private_key,
            sequence,
        }
    }

    /// Get the outpoint for this UTXO
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

/// Output information for PSBTs
#[derive(Debug, Clone)]
pub struct Output {
    /// Amount in satoshis
    pub amount: Amount,
    /// Script pubkey or silent payment address
    pub recipient: OutputRecipient,
}

/// Output recipient type
#[derive(Debug, Clone)]
pub enum OutputRecipient {
    /// Regular Bitcoin address (script pubkey)
    Address(ScriptBuf),
    /// Silent payment address
    SilentPayment(SilentPaymentAddress),
}

impl Output {
    /// Create a regular output
    pub fn regular(amount: Amount, script_pubkey: ScriptBuf) -> Self {
        Self {
            amount,
            recipient: OutputRecipient::Address(script_pubkey),
        }
    }

    /// Create a silent payment output
    pub fn silent_payment(amount: Amount, address: SilentPaymentAddress) -> Self {
        Self {
            amount,
            recipient: OutputRecipient::SilentPayment(address),
        }
    }

    /// Check if this is a silent payment output
    pub fn is_silent_payment(&self) -> bool {
        matches!(self.recipient, OutputRecipient::SilentPayment(_))
    }
}

/// Transaction data needed for signing
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// Transaction version
    pub version: i32,
    /// Transaction locktime
    pub locktime: u32,
    /// Input data
    pub inputs: Vec<InputData>,
    /// Output data
    pub outputs: Vec<OutputData>,
}

/// Input data for transaction
#[derive(Debug, Clone)]
pub struct InputData {
    /// Previous outpoint
    pub outpoint: OutPoint,
    /// Sequence number
    pub sequence: Sequence,
    /// Witness UTXO (for SegWit)
    pub witness_utxo: Option<WitnessUtxo>,
}

/// Witness UTXO data
#[derive(Debug, Clone)]
pub struct WitnessUtxo {
    /// Amount
    pub amount: Amount,
    /// Script pubkey
    pub script_pubkey: ScriptBuf,
}

/// Output data for transaction
#[derive(Debug, Clone)]
pub struct OutputData {
    /// Amount
    pub amount: Amount,
    /// Script pubkey
    pub script_pubkey: ScriptBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_silent_payment_address_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let addr = SilentPaymentAddress::new(scan_key, spend_key, Some(42));
        let bytes = addr.to_bytes();
        let decoded = SilentPaymentAddress::from_bytes(&bytes).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_ecdh_share_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let ecdh = EcdhShareData::without_proof(scan_key, share);
        let bytes = ecdh.to_bytes();
        let decoded = EcdhShareData::from_bytes(&bytes).unwrap();

        assert_eq!(ecdh.scan_key, decoded.scan_key);
        assert_eq!(ecdh.share, decoded.share);
    }
}
