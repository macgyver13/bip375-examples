// Core data types for UniFFI bindings

use crate::errors::Bip375Error;
use bip375_core as core;
use bip375_core::Bip375PsbtExt;
use std::sync::{Arc, Mutex};

// ============================================================================
// Silent Payment Address
// ============================================================================

#[derive(Clone)]
pub struct SilentPaymentAddress {
    pub scan_key: Vec<u8>,
    pub spend_key: Vec<u8>,
    pub label: Option<u32>,
}

impl SilentPaymentAddress {
    pub fn from_core(addr: &core::types::SilentPaymentAddress) -> Self {
        Self {
            scan_key: addr.scan_key.serialize().to_vec(),
            spend_key: addr.spend_key.serialize().to_vec(),
            label: addr.label,
        }
    }

    pub fn to_core(&self) -> Result<core::types::SilentPaymentAddress, Bip375Error> {
        use secp256k1::PublicKey;

        let scan_key =
            PublicKey::from_slice(&self.scan_key).map_err(|_| Bip375Error::InvalidKey)?;
        let spend_key =
            PublicKey::from_slice(&self.spend_key).map_err(|_| Bip375Error::InvalidKey)?;

        Ok(core::types::SilentPaymentAddress {
            scan_key,
            spend_key,
            label: self.label,
        })
    }
}

// ============================================================================
// ECDH Share
// ============================================================================

#[derive(Clone)]
pub struct EcdhShare {
    pub scan_key: Vec<u8>,
    pub share_point: Vec<u8>,
    pub dleq_proof: Option<Vec<u8>>,
}

impl EcdhShare {
    pub fn from_core(share: &core::types::EcdhShareData) -> Self {
        Self {
            scan_key: share.scan_key.serialize().to_vec(),
            share_point: share.share.serialize().to_vec(),
            dleq_proof: share.dleq_proof.map(|p| p.to_vec()),
        }
    }

    pub fn to_core(&self) -> Result<core::types::EcdhShareData, Bip375Error> {
        use secp256k1::PublicKey;

        let scan_key =
            PublicKey::from_slice(&self.scan_key).map_err(|_| Bip375Error::InvalidKey)?;
        let share =
            PublicKey::from_slice(&self.share_point).map_err(|_| Bip375Error::InvalidKey)?;

        let dleq_proof = if let Some(ref proof_vec) = self.dleq_proof {
            if proof_vec.len() != 64 {
                return Err(Bip375Error::InvalidProof);
            }
            let mut proof_array = [0u8; 64];
            proof_array.copy_from_slice(proof_vec);
            Some(proof_array)
        } else {
            None
        };

        Ok(core::types::EcdhShareData {
            scan_key,
            share,
            dleq_proof,
        })
    }
}

// ============================================================================
// UTXO Input
// ============================================================================

#[derive(Clone)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub private_key: Option<Vec<u8>>,
    pub sequence: Option<u32>,
}

impl Utxo {
    pub fn to_core(&self) -> Result<core::types::Utxo, Bip375Error> {
        use bitcoin::{Amount, Sequence, Txid};
        use secp256k1::SecretKey;
        use std::str::FromStr;

        let txid = Txid::from_str(&self.txid).map_err(|_| Bip375Error::InvalidData)?;

        let private_key = if let Some(ref pk_bytes) = self.private_key {
            Some(SecretKey::from_slice(pk_bytes).map_err(|_| Bip375Error::InvalidKey)?)
        } else {
            None
        };

        let amount = Amount::from_sat(self.amount);
        let sequence = self
            .sequence
            .map(Sequence::from_consensus)
            .unwrap_or(Sequence::ZERO);

        Ok(core::types::Utxo {
            txid,
            vout: self.vout,
            amount,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(self.script_pubkey.clone()),
            private_key,
            sequence,
        })
    }
}

// ============================================================================
// Output (simplified for UniFFI)
// ============================================================================

#[derive(Clone)]
pub struct Output {
    pub amount: u64,
    pub script_pubkey: Option<Vec<u8>>,
    pub sp_address: Option<SilentPaymentAddress>,
}

impl Output {
    pub fn to_core(&self) -> Result<core::types::Output, Bip375Error> {
        use bitcoin::Amount;

        let recipient = if let Some(ref addr) = self.sp_address {
            core::types::OutputRecipient::SilentPayment(addr.to_core()?)
        } else if let Some(ref script) = self.script_pubkey {
            core::types::OutputRecipient::Address(bitcoin::ScriptBuf::from_bytes(script.clone()))
        } else {
            return Err(Bip375Error::InvalidData);
        };

        Ok(core::types::Output {
            amount: Amount::from_sat(self.amount),
            recipient,
        })
    }
}

// ============================================================================
// PSBT Metadata
// ============================================================================

#[derive(Clone, Default)]
pub struct PsbtMetadata {
    pub creator: Option<String>,
    pub stage: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
}

impl PsbtMetadata {
    pub fn from_core(meta: &bip375_io::metadata::PsbtMetadata) -> Self {
        Self {
            creator: meta.creator.clone(),
            stage: meta.stage.clone(),
            description: meta.description.clone(),
            created_at: meta.created_at,
            modified_at: meta.modified_at,
        }
    }

    pub fn to_core(&self) -> bip375_io::metadata::PsbtMetadata {
        bip375_io::metadata::PsbtMetadata {
            creator: self.creator.clone(),
            stage: self.stage.clone(),
            description: self.description.clone(),
            created_at: self.created_at,
            modified_at: self.modified_at,
            num_inputs: None,
            num_outputs: None,
            num_silent_payment_outputs: None,
            ecdh_complete: None,
            signatures_complete: None,
            scripts_computed: None,
            custom: Default::default(),
        }
    }
}

// ============================================================================
// Aggregated Share
// ============================================================================

#[derive(Clone)]
pub struct AggregatedShare {
    pub scan_key: Vec<u8>,
    pub aggregated_point: Vec<u8>,
    pub is_global: bool,
    pub num_inputs: usize,
}

impl AggregatedShare {
    pub fn from_core(share: &core::ecdh_aggregation::AggregatedShare) -> Self {
        Self {
            scan_key: share.scan_key.serialize().to_vec(),
            aggregated_point: share.aggregated_share.serialize().to_vec(),
            is_global: share.is_global,
            num_inputs: share.num_inputs,
        }
    }
}

// ============================================================================
// Silent Payment PSBT (Main Type)
// ============================================================================

pub struct SilentPaymentPsbt {
    inner: Arc<Mutex<bip375_core::SilentPaymentPsbt>>,
}

impl SilentPaymentPsbt {
    pub fn new() -> Self {
        use bitcoin::transaction::Version;
        use psbt_v2::v2::Global;

        let psbt = bip375_core::SilentPaymentPsbt {
            global: Global {
                version: psbt_v2::V2,
                tx_version: Version(2),
                fallback_lock_time: None,
                input_count: 0,
                output_count: 0,
                tx_modifiable_flags: 0,
                sp_dleq_proofs: std::collections::BTreeMap::new(),
                sp_ecdh_shares: std::collections::BTreeMap::new(),
                unknowns: std::collections::BTreeMap::new(),
                xpubs: std::collections::BTreeMap::new(),
                proprietaries: std::collections::BTreeMap::new(),
            },
            inputs: Vec::new(),
            outputs: Vec::new(),
        };

        Self {
            inner: Arc::new(Mutex::new(psbt)),
        }
    }

    // Internal constructor for wrapping a core PSBT
    pub(crate) fn from_core(psbt: bip375_core::SilentPaymentPsbt) -> Self {
        Self {
            inner: Arc::new(Mutex::new(psbt)),
        }
    }

    pub fn deserialize(data: Vec<u8>) -> Result<Self, Bip375Error> {
        let psbt = bip375_core::SilentPaymentPsbt::deserialize(&data)
            .map_err(|_| Bip375Error::SerializationError)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(psbt)),
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        Ok(psbt.serialize())
    }

    pub fn num_inputs(&self) -> u32 {
        let psbt = self.inner.lock().unwrap();
        psbt.num_inputs() as u32
    }

    pub fn get_input_ecdh_shares(&self, input_index: u32) -> Result<Vec<EcdhShare>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = input_index as usize;

        if idx >= psbt.num_inputs() {
            return Err(Bip375Error::InvalidData);
        }

        let shares = psbt.get_input_ecdh_shares(idx);
        Ok(shares.iter().map(EcdhShare::from_core).collect())
    }

    pub fn num_outputs(&self) -> u32 {
        let psbt = self.inner.lock().unwrap();
        psbt.num_outputs() as u32
    }

    pub fn get_output_sp_address(
        &self,
        output_index: u32,
    ) -> Result<Option<SilentPaymentAddress>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = output_index as usize;

        if idx >= psbt.num_outputs() {
            return Err(Bip375Error::InvalidData);
        }

        Ok(psbt
            .get_output_sp_address(idx)
            .map(|addr| SilentPaymentAddress::from_core(&addr)))
    }

    pub fn get_output_script(&self, output_index: u32) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = output_index as usize;

        if idx >= psbt.num_outputs() {
            return Err(Bip375Error::InvalidData);
        }

        // Get the PSBT_OUT_SCRIPT field (0x04)
        const PSBT_OUT_SCRIPT: u8 = 0x04;
        if let Some(field) = psbt.get_output_field(idx, PSBT_OUT_SCRIPT) {
            Ok(field.value_data.clone())
        } else {
            // Return empty if no script has been computed yet
            Ok(Vec::new())
        }
    }

    pub fn get_global_ecdh_shares(&self) -> Result<Vec<EcdhShare>, Bip375Error> {
        // Note: This method doesn't exist in core yet, so we return empty for now
        Ok(Vec::new())
    }

    // Internal access for other modules
    pub(crate) fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut bip375_core::SilentPaymentPsbt) -> R,
    {
        let mut psbt = self.inner.lock().unwrap();
        f(&mut psbt)
    }
}

impl Clone for SilentPaymentPsbt {
    fn clone(&self) -> Self {
        let psbt = self.inner.lock().unwrap();
        Self {
            inner: Arc::new(Mutex::new(psbt.clone())),
        }
    }
}
