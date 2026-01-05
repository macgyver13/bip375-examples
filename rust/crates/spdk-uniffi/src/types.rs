// Core data types for UniFFI bindings

use crate::errors::Bip375Error;
use silentpayments::Network;
use spdk_core::psbt;
use spdk_core::psbt::core;
use spdk_core::psbt::{Bip375PsbtExt, DleqProof, EcdhShareData};
use std::sync::{Arc, Mutex};

// ============================================================================
// Silent Payment Address
// ============================================================================

#[derive(Clone)]
pub struct SilentPaymentAddress {
    pub scan_key: Vec<u8>,
    pub spend_key: Vec<u8>,
}

impl SilentPaymentAddress {
    pub fn from_core(addr: &silentpayments::SilentPaymentAddress) -> Self {
        Self {
            scan_key: addr.get_scan_key().serialize().to_vec(),
            spend_key: addr.get_spend_key().serialize().to_vec(),
        }
    }

    pub fn to_core(&self) -> Result<silentpayments::SilentPaymentAddress, Bip375Error> {
        use secp256k1::PublicKey;

        let scan_pubkey =
            PublicKey::from_slice(&self.scan_key).map_err(|_| Bip375Error::InvalidKey)?;
        let m_pubkey =
            PublicKey::from_slice(&self.spend_key).map_err(|_| Bip375Error::InvalidKey)?;

        // Note: Using Regtest network and version 0 as defaults
        // In production, these should be configurable
        silentpayments::SilentPaymentAddress::new(scan_pubkey, m_pubkey, Network::Mainnet, 0)
            .map_err(|_| Bip375Error::InvalidAddress)
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
    pub fn from_core(share: &EcdhShareData) -> Self {
        Self {
            scan_key: share.scan_key.serialize().to_vec(),
            share_point: share.share.serialize().to_vec(),
            dleq_proof: share.dleq_proof.map(|p| p.as_bytes().to_vec()),
        }
    }

    pub fn to_core(&self) -> Result<EcdhShareData, Bip375Error> {
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
            Some(DleqProof(proof_array))
        } else {
            None
        };

        Ok(EcdhShareData {
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
    /// Convert to PsbtInput (new type)
    pub fn to_psbt_input(&self) -> Result<core::PsbtInput, Bip375Error> {
        use bitcoin::{Amount, OutPoint, Sequence, TxOut, Txid};
        use secp256k1::SecretKey;
        use std::str::FromStr;

        let txid = Txid::from_str(&self.txid).map_err(|_| Bip375Error::InvalidData)?;
        let outpoint = OutPoint::new(txid, self.vout);

        let witness_utxo = TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(self.script_pubkey.clone()),
        };

        let private_key = if let Some(ref pk_bytes) = self.private_key {
            Some(SecretKey::from_slice(pk_bytes).map_err(|_| Bip375Error::InvalidKey)?)
        } else {
            None
        };

        let sequence = self
            .sequence
            .map(Sequence::from_consensus)
            .unwrap_or(Sequence::ZERO);

        Ok(core::PsbtInput::new(
            outpoint,
            witness_utxo,
            sequence,
            private_key,
        ))
    }
}

// ============================================================================
// Output (matches spdk-core PsbtOutput)
// ============================================================================

#[derive(Clone)]
pub enum PsbtOutput {
    Regular {
        amount: u64,
        script_pubkey: Vec<u8>,
    },
    SilentPayment {
        amount: u64,
        address: SilentPaymentAddress,
        label: Option<u32>,
    },
}

impl PsbtOutput {
    /// Convert to core::PsbtOutput
    pub fn to_psbt_output(&self) -> Result<core::PsbtOutput, Bip375Error> {
        use bitcoin::{Amount, TxOut};

        match self {
            PsbtOutput::Regular {
                amount,
                script_pubkey,
            } => Ok(core::PsbtOutput::Regular(TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_pubkey.clone()),
            })),
            PsbtOutput::SilentPayment {
                amount,
                address,
                label,
            } => Ok(core::PsbtOutput::SilentPayment {
                amount: Amount::from_sat(*amount),
                address: address.to_core()?,
                label: *label,
            }),
        }
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
    pub fn from_core(meta: &psbt::io::metadata::PsbtMetadata) -> Self {
        Self {
            creator: meta.creator.clone(),
            stage: meta.stage.clone(),
            description: meta.description.clone(),
            created_at: meta.created_at,
            modified_at: meta.modified_at,
        }
    }

    pub fn to_core(&self) -> psbt::io::metadata::PsbtMetadata {
        psbt::io::metadata::PsbtMetadata {
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
    pub fn from_core(share: &core::shares::AggregatedShare) -> Self {
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
    inner: Arc<Mutex<psbt::SilentPaymentPsbt>>,
}

impl SilentPaymentPsbt {
    pub fn new() -> Self {
        // Use the creator role to create an empty PSBT
        let psbt = psbt::roles::creator::create_psbt(0, 0);
        Self::from_core(psbt)
    }

    pub fn create(num_inputs: u32, num_outputs: u32) -> Result<Self, Bip375Error> {
        let psbt = psbt::roles::creator::create_psbt(num_inputs as usize, num_outputs as usize);
        Ok(Self::from_core(psbt))
    }

    pub fn load(path: String) -> Result<Self, Bip375Error> {
        let (psbt, _metadata) = psbt::io::load_psbt(std::path::Path::new(&path))?;
        Ok(Self::from_core(psbt))
    }

    // Internal constructor for wrapping a core PSBT
    pub(crate) fn from_core(psbt: psbt::SilentPaymentPsbt) -> Self {
        Self {
            inner: Arc::new(Mutex::new(psbt)),
        }
    }

    pub fn deserialize(data: Vec<u8>) -> Result<Self, Bip375Error> {
        let psbt = psbt::SilentPaymentPsbt::deserialize(&data)
            .map_err(|_| Bip375Error::SerializationError)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(psbt)),
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();

        Ok(psbt.serialize())
    }

    pub fn save(&self, path: String, metadata: Option<PsbtMetadata>) -> Result<(), Bip375Error> {
        self.with_inner(|p| {
            let meta = metadata.map(|m| m.to_core());
            psbt::io::save_psbt(p, meta, std::path::Path::new(&path))
        })?;
        Ok(())
    }

    pub fn num_inputs(&self) -> u32 {
        let psbt = self.inner.lock().unwrap();
        psbt.inputs.len() as u32
    }

    pub fn get_input_ecdh_shares(&self, input_index: u32) -> Result<Vec<EcdhShare>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = input_index as usize;

        if idx >= psbt.inputs.len() {
            return Err(Bip375Error::InvalidData);
        }

        let shares = psbt.get_input_ecdh_shares(idx);

        Ok(shares.iter().map(EcdhShare::from_core).collect())
    }

    pub fn num_outputs(&self) -> u32 {
        let psbt = self.inner.lock().unwrap();
        psbt.outputs.len() as u32
    }

    pub fn get_output_sp_address(
        &self,
        output_index: u32,
    ) -> Result<Option<SilentPaymentAddress>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = output_index as usize;

        if idx >= psbt.outputs.len() {
            return Err(Bip375Error::InvalidData);
        }

        // Get the SP info (scan_key, spend_key) and construct address
        Ok(psbt
            .get_output_sp_info_v0(idx)
            .map(|(scan_key, spend_key)| SilentPaymentAddress {
                scan_key: scan_key.serialize().to_vec(),
                spend_key: spend_key.serialize().to_vec(),
            }))
    }

    pub fn get_output_script(&self, output_index: u32) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let idx = output_index as usize;

        if idx >= psbt.outputs.len() {
            return Err(Bip375Error::InvalidData);
        }

        // Get the output script pubkey directly
        if let Some(output) = psbt.outputs.get(idx) {
            Ok(output.script_pubkey.to_bytes())
        } else {
            // Return empty if output doesn't exist
            Ok(Vec::new())
        }
    }

    pub fn get_global_ecdh_shares(&self) -> Result<Vec<EcdhShare>, Bip375Error> {
        // Note: This method doesn't exist in core yet, so we return empty for now
        Ok(Vec::new())
    }

    pub fn add_inputs(&self, inputs: Vec<Utxo>) -> Result<(), Bip375Error> {
        let psbt_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_psbt_input()).collect();
        let psbt_inputs = psbt_inputs?;

        self.with_inner(|p| psbt::roles::constructor::add_inputs(p, &psbt_inputs))?;

        Ok(())
    }

    pub fn add_outputs(&self, outputs: Vec<PsbtOutput>) -> Result<(), Bip375Error> {
        let psbt_outputs: Result<Vec<_>, _> = outputs.iter().map(|o| o.to_psbt_output()).collect();
        let psbt_outputs = psbt_outputs?;

        self.with_inner(|p| psbt::roles::constructor::add_outputs(p, &psbt_outputs))?;

        Ok(())
    }

    pub fn add_ecdh_shares_full(
        &self,
        inputs: Vec<Utxo>,
        scan_keys: Vec<Vec<u8>>,
    ) -> Result<(), Bip375Error> {
        use secp256k1::{PublicKey, Secp256k1};

        let secp = Secp256k1::new();
        let psbt_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_psbt_input()).collect();
        let psbt_inputs = psbt_inputs?;

        let core_scan_keys: Result<Vec<PublicKey>, _> =
            scan_keys.iter().map(|k| PublicKey::from_slice(k)).collect();
        let core_scan_keys = core_scan_keys.map_err(|_| Bip375Error::InvalidKey)?;

        self.with_inner(|p| {
            psbt::roles::signer::add_ecdh_shares_full(&secp, p, &psbt_inputs, &core_scan_keys, true)
        })?;

        Ok(())
    }

    pub fn sign_inputs(&self, inputs: Vec<Utxo>) -> Result<(), Bip375Error> {
        let secp = secp256k1::Secp256k1::new();
        let psbt_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_psbt_input()).collect();
        let psbt_inputs = psbt_inputs?;
        self.with_inner(|p| psbt::roles::signer::sign_inputs(&secp, p, &psbt_inputs))?;

        Ok(())
    }

    pub fn add_ecdh_shares_partial(
        &self,
        input_indices: Vec<u32>,
        inputs: Vec<Utxo>,
        scan_keys: Vec<Vec<u8>>,
        include_dleq: bool,
    ) -> Result<(), Bip375Error> {
        use secp256k1::{PublicKey, Secp256k1};

        let secp = Secp256k1::new();
        let psbt_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_psbt_input()).collect();
        let psbt_inputs = psbt_inputs?;

        let core_scan_keys: Result<Vec<PublicKey>, _> =
            scan_keys.iter().map(|k| PublicKey::from_slice(k)).collect();
        let core_scan_keys = core_scan_keys.map_err(|_| Bip375Error::InvalidKey)?;

        let indices: Vec<usize> = input_indices.iter().map(|&i| i as usize).collect();

        self.with_inner(|p| {
            psbt::roles::signer::add_ecdh_shares_partial(
                &secp,
                p,
                &psbt_inputs,
                &core_scan_keys,
                &indices,
                include_dleq,
            )
        })?;

        Ok(())
    }

    pub fn finalize_inputs(&self) -> Result<(), Bip375Error> {
        let secp = secp256k1::Secp256k1::new();
        self.with_inner(|p| psbt::roles::input_finalizer::finalize_inputs(&secp, p, None))?;
        Ok(())
    }

    pub fn extract_transaction(&self) -> Result<Vec<u8>, Bip375Error> {
        use bitcoin::consensus::serialize;

        let tx = self.with_inner(|p| psbt::roles::extractor::extract_transaction(p))?;
        Ok(serialize(&tx))
    }

    // Internal access for other modules
    pub(crate) fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut psbt::SilentPaymentPsbt) -> R,
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
