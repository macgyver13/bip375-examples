// Core data types for UniFFI bindings.

use crate::errors::Bip375Error;
use bip375_helpers::transaction::{build_psbt, to_sp_v0_info};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
use psbt::roles::{Bip375UpdaterExt, ShareMode, SpSignerExt};
use psbt_v2::{
    Creator, DleqProof, Extractor, Finalizer, GetKey, GetKeyError, Input, Key as PsbtKey,
    KeyRequest, Output, Psbt as CorePsbt, PsbtSighashType, Signer, SpV0Info,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<silentpayments::Network> for Network {
    fn from(value: silentpayments::Network) -> Self {
        match value {
            silentpayments::Network::Mainnet => Network::Mainnet,
            silentpayments::Network::Testnet => Network::Testnet,
            silentpayments::Network::Regtest => Network::Regtest,
        }
    }
}

impl From<Network> for silentpayments::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => silentpayments::Network::Mainnet,
            Network::Testnet => silentpayments::Network::Testnet,
            Network::Regtest => silentpayments::Network::Regtest,
        }
    }
}

#[derive(Clone)]
pub struct SilentPaymentAddress {
    pub scan_key: Vec<u8>,
    pub spend_key: Vec<u8>,
    pub network: Option<Network>,
}

impl SilentPaymentAddress {
    pub fn from_core(code: &silentpayments::SilentPaymentCode) -> Self {
        Self {
            scan_key: code.scan_key().serialize().to_vec(),
            spend_key: code.m_pubkey().serialize().to_vec(),
            network: Some(code.network().into()),
        }
    }

    pub fn to_core(&self) -> Result<silentpayments::SilentPaymentCode, Bip375Error> {
        let scan_pubkey =
            PublicKey::from_slice(&self.scan_key).map_err(|_| Bip375Error::InvalidKey)?;
        let spend_pubkey =
            PublicKey::from_slice(&self.spend_key).map_err(|_| Bip375Error::InvalidKey)?;
        let network = self
            .network
            .map(Into::into)
            .unwrap_or(silentpayments::Network::Mainnet);

        Ok(silentpayments::SilentPaymentCode::new_v0(
            scan_pubkey,
            spend_pubkey,
            network,
        ))
    }
}

#[derive(Clone)]
pub struct EcdhShare {
    pub scan_key: Vec<u8>,
    pub share_point: Vec<u8>,
    pub dleq_proof: Option<Vec<u8>>,
}

fn ecdh_share_from_parts(
    scan_key: &CompressedPublicKey,
    share_point: &CompressedPublicKey,
    dleq_proof: Option<&DleqProof>,
) -> EcdhShare {
    EcdhShare {
        scan_key: scan_key.0.serialize().to_vec(),
        share_point: share_point.0.serialize().to_vec(),
        dleq_proof: dleq_proof.map(|p| p.0.to_vec()),
    }
}

#[derive(Clone)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub sequence: Option<u32>,
    pub public_key: Option<Vec<u8>>,
    pub master_fingerprint: Option<Vec<u8>>,
    pub derivation_path: Option<Vec<u32>>,
}

impl Utxo {
    pub fn to_psbt_input(&self) -> Result<Input, Bip375Error> {
        let txid = Txid::from_str(&self.txid).map_err(|_| Bip375Error::InvalidData)?;
        let outpoint = OutPoint::new(txid, self.vout);
        let mut input = Input::new(&outpoint);
        // Per BIP-370, the Constructor adds only the outpoint (and optionally
        // sequence). The witness UTXO is the Updater responsibility and is set
        // in update_inputs().
        input.sequence = self.sequence.map(Sequence::from_consensus);
        Ok(input)
    }
}

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
    pub fn to_psbt_output(&self) -> Result<Output, Bip375Error> {
        match self {
            PsbtOutput::Regular {
                amount,
                script_pubkey,
            } => Ok(Output::new(TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey.clone()),
            })),
            PsbtOutput::SilentPayment {
                amount,
                address,
                label,
            } => {
                let address = address.to_core()?;
                let mut output = Output::new(TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: ScriptBuf::new(),
                });
                output.sp_v0_info = Some(to_sp_v0_info(&address));
                output.sp_v0_label = *label;
                Ok(output)
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct PsbtMetadata {
    pub creator: Option<String>,
    pub stage: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
}

impl PsbtMetadata {
    pub fn from_core(meta: &bip375_helpers::io::PsbtMetadata) -> Self {
        Self {
            creator: meta.creator.clone(),
            stage: meta.stage.clone(),
            description: meta.description.clone(),
            created_at: meta.created_at,
            modified_at: meta.modified_at,
        }
    }

    pub fn to_core(&self) -> bip375_helpers::io::PsbtMetadata {
        bip375_helpers::io::PsbtMetadata {
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

pub struct Psbt {
    inner: Arc<Mutex<CorePsbt>>,
}

pub type SilentPaymentPsbt = Psbt;

impl Psbt {
    pub fn new() -> Self {
        Self::create(0, 0).expect("empty PSBT construction cannot fail")
    }

    /// Create an empty PSBTv2 with pre-sized input/output maps.
    ///
    /// This constructor is intentionally retained for the external test-vector
    /// generator, which populates maps through raw field setters to create invalid
    /// vectors.
    pub fn create(num_inputs: u32, num_outputs: u32) -> Result<Self, Bip375Error> {
        let mut psbt = Creator::new().psbt();
        psbt.global.input_count = num_inputs as usize;
        psbt.global.output_count = num_outputs as usize;
        psbt.inputs = (0..num_inputs)
            .map(|_| Input::new(&OutPoint::null()))
            .collect();
        psbt.outputs = (0..num_outputs)
            .map(|_| {
                Output::new(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new(),
                })
            })
            .collect();
        Ok(Self::from_core(psbt))
    }

    pub fn create_from_parts(
        inputs: Vec<Utxo>,
        outputs: Vec<PsbtOutput>,
    ) -> Result<Self, Bip375Error> {
        let psbt_inputs: Result<Vec<_>, _> = inputs.iter().map(Utxo::to_psbt_input).collect();
        let psbt_outputs: Result<Vec<_>, _> =
            outputs.iter().map(PsbtOutput::to_psbt_output).collect();
        let psbt = build_psbt(psbt_inputs?, psbt_outputs?).map_err(|_| Bip375Error::PsbtError)?;
        Ok(Self::from_core(psbt))
    }

    pub fn load(path: String) -> Result<Self, Bip375Error> {
        let (psbt, _metadata) = bip375_helpers::io::load_psbt(std::path::Path::new(&path))?;
        Ok(Self::from_core(psbt))
    }

    pub(crate) fn from_core(psbt: CorePsbt) -> Self {
        Self {
            inner: Arc::new(Mutex::new(psbt)),
        }
    }

    pub fn deserialize(data: Vec<u8>) -> Result<Self, Bip375Error> {
        let psbt = CorePsbt::deserialize(&data).map_err(|_| Bip375Error::SerializationError)?;
        Ok(Self::from_core(psbt))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Bip375Error> {
        Ok(self.inner.lock().unwrap().serialize())
    }

    pub fn save(&self, path: String, metadata: Option<PsbtMetadata>) -> Result<(), Bip375Error> {
        self.with_inner(|p| {
            bip375_helpers::io::save_psbt(
                p,
                metadata.map(|m| m.to_core()),
                std::path::Path::new(&path),
            )
        })?;
        Ok(())
    }

    pub fn num_inputs(&self) -> u32 {
        self.inner.lock().unwrap().inputs.len() as u32
    }

    pub fn num_outputs(&self) -> u32 {
        self.inner.lock().unwrap().outputs.len() as u32
    }

    pub fn get_input_ecdh_shares(&self, input_index: u32) -> Result<Vec<EcdhShare>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let input = psbt
            .inputs
            .get(input_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        Ok(input
            .sp_ecdh_shares
            .iter()
            .map(|(scan, share)| ecdh_share_from_parts(scan, share, input.sp_dleq_proofs.get(scan)))
            .collect())
    }

    pub fn get_global_ecdh_shares(&self) -> Result<Vec<EcdhShare>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        Ok(psbt
            .global
            .sp_ecdh_shares
            .iter()
            .map(|(scan, share)| {
                ecdh_share_from_parts(scan, share, psbt.global.sp_dleq_proofs.get(scan))
            })
            .collect())
    }

    pub fn get_output_sp_address(
        &self,
        output_index: u32,
    ) -> Result<Option<SilentPaymentAddress>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let output = psbt
            .outputs
            .get(output_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        let Some(sp_info) = output.sp_v0_info else {
            return Ok(None);
        };
        Ok(Some(SilentPaymentAddress {
            scan_key: sp_info.scan_key().to_bytes().to_vec(),
            spend_key: sp_info.spend_key().to_bytes().to_vec(),
            network: None,
        }))
    }

    pub fn get_output_script(&self, output_index: u32) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap();
        let output = psbt
            .outputs
            .get(output_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        Ok(output.script_pubkey.to_bytes())
    }

    /// Legacy bridge retained for the test-vector generator.
    pub fn add_inputs(&self, inputs: Vec<Utxo>) -> Result<(), Bip375Error> {
        let converted: Result<Vec<_>, _> = inputs.iter().map(Utxo::to_psbt_input).collect();
        self.with_inner(|p| {
            let converted = converted?;
            if !p.inputs.is_empty() && p.inputs.len() != converted.len() {
                return Err(Bip375Error::InvalidData);
            }
            p.inputs = converted;
            p.global.input_count = p.inputs.len();
            Ok(())
        })
    }

    /// Legacy bridge retained for existing Python examples.
    pub fn add_outputs(&self, outputs: Vec<PsbtOutput>) -> Result<(), Bip375Error> {
        let converted: Result<Vec<_>, _> = outputs.iter().map(PsbtOutput::to_psbt_output).collect();
        self.with_inner(|p| {
            let converted = converted?;
            if !p.outputs.is_empty() && p.outputs.len() != converted.len() {
                return Err(Bip375Error::InvalidData);
            }
            p.outputs = converted;
            p.global.output_count = p.outputs.len();
            Ok(())
        })
    }

    pub fn update_inputs(&self, inputs: Vec<Utxo>) -> Result<(), Bip375Error> {
        self.with_inner(|p| {
            for (idx, u) in inputs.iter().enumerate() {
                let Some(input) = p.inputs.get_mut(idx) else {
                    break;
                };
                // The Updater adds the witness UTXO (BIP-370 role separation).
                input.witness_utxo = Some(TxOut {
                    value: Amount::from_sat(u.amount),
                    script_pubkey: ScriptBuf::from_bytes(u.script_pubkey.clone()),
                });
                let Some(pk_bytes) = &u.public_key else {
                    continue;
                };
                let pubkey =
                    PublicKey::from_slice(pk_bytes).map_err(|_| Bip375Error::InvalidKey)?;
                let fingerprint = Fingerprint::from(
                    u.master_fingerprint
                        .as_deref()
                        .and_then(|b| <[u8; 4]>::try_from(b).ok())
                        .unwrap_or([0u8; 4]),
                );
                let path = to_derivation_path(u.derivation_path.clone().unwrap_or_default());
                input.set_bip32_derivation(&pubkey, fingerprint, path);
            }
            Ok(())
        })
    }

    /// Signer role: single-party ECDH share generation (BIP-375 global path).
    pub fn generate_single_signer_ecdh_shares(
        &self,
        spend_key: Vec<u8>,
    ) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        let spend_key = SecretKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
        self.with_inner(|p| {
            p.add_ecdh_shares(&secp, &mut secp256k1::rand::thread_rng(), &spend_key, ShareMode::Global)
                .map(|_| ())
                .map_err(Bip375Error::from)
        })?;
        Ok(())
    }

    /// Signer role: single-party ECDH share generation for inputs held under distinct keys.
    ///
    /// Like `generate_single_signer_ecdh_shares`, but `spend_keys` holds one key per owned input
    /// and the global share covers the sum of them.
    pub fn generate_single_signer_ecdh_shares_with_keys(
        &self,
        spend_keys: Vec<Vec<u8>>,
    ) -> Result<(), Bip375Error> {
        self.add_ecdh_shares_with_keys(spend_keys, ShareMode::Global)
    }

    /// Signer role: multi-party ECDH share generation for a party holding several input keys.
    pub fn generate_multi_signer_ecdh_shares_with_keys(
        &self,
        spend_keys: Vec<Vec<u8>>,
    ) -> Result<(), Bip375Error> {
        self.add_ecdh_shares_with_keys(spend_keys, ShareMode::Partial)
    }

    fn add_ecdh_shares_with_keys(
        &self,
        spend_keys: Vec<Vec<u8>>,
        mode: ShareMode,
    ) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        let keys = spend_keys
            .iter()
            .map(|k| SecretKey::from_slice(k).map_err(|_| Bip375Error::InvalidKey))
            .collect::<Result<Vec<_>, _>>()?;
        self.with_inner(|p| {
            p.add_ecdh_shares(&secp, &mut secp256k1::rand::thread_rng(), &SecretKeySet(keys), mode)
                .map(|_| ())
                .map_err(Bip375Error::from)
        })?;
        Ok(())
    }

    /// Signer role: multi-party ECDH share generation (BIP-375 per-input path).
    pub fn generate_multi_signer_ecdh_shares(&self, spend_key: Vec<u8>) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        let spend_key = SecretKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
        self.with_inner(|p| {
            p.add_ecdh_shares(&secp, &mut secp256k1::rand::thread_rng(), &spend_key, ShareMode::Partial)
                .map(|_| ())
                .map_err(Bip375Error::from)
        })?;
        Ok(())
    }

    pub fn compute_sp_output_scripts(&self) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        self.with_inner(|p| {
            p.commit_sp_outputs(&secp)
                .map_err(Bip375Error::from)
        })?;
        Ok(())
    }

    pub fn sign_silent_payment_inputs(&self, spend_key: Vec<u8>) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        let spend_key = SecretKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
        self.with_inner(|p| {
            p.sign_silent_payment_inputs(&spend_key, &secp)
                .map(|_| ())
                .map_err(|_| Bip375Error::SigningError)
        })?;
        Ok(())
    }

    /// Signer role: sign input `input_index` with `privkey`, ECDSA or taproot key-spend
    /// according to the input's prevout script.
    ///
    /// rust-psbt only signs taproot through `Signer::sign`, which signs every input the key
    /// covers and runs the BIP-174 and BIP-375 signer checks first; only `input_index`'s
    /// signature is kept, so a key shared by several inputs still signs one input per call.
    pub fn sign_input(&self, input_index: u32, privkey: Vec<u8>) -> Result<(), Bip375Error> {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
        let index = input_index as usize;
        self.with_inner(|p| {
            let input = p.inputs.get(index).ok_or(Bip375Error::InvalidData)?;
            if !spent_script(input).is_some_and(|script| script.is_p2tr()) {
                return p
                    .sign_input(index, &privkey, &secp)
                    .map(|_| ())
                    .map_err(|_| Bip375Error::SigningError);
            }

            // Keyed by the even-parity public key, which is how the output key is requested.
            let (output_key, _) = privkey.x_only_public_key(&secp);
            let keystore = std::collections::BTreeMap::from([(
                bitcoin::PublicKey::new(PublicKey::from_x_only_public_key(
                    output_key,
                    bitcoin::key::Parity::Even,
                )),
                bitcoin::PrivateKey::new(privkey, bitcoin::NetworkKind::Main),
            )]);
            let (mut signed, _) = Signer::new(p.clone())
                .map_err(|_| Bip375Error::PsbtError)?
                .sign(&keystore, &secp)
                .map_err(|_| Bip375Error::SigningError)?;
            if let Some(signature) = signed.inputs[index].tap_key_sig.take() {
                p.inputs[index].tap_key_sig = Some(signature);
                p.global.tx_modifiable_flags = signed.global.tx_modifiable_flags;
            }
            Ok(())
        })
    }

    pub fn finalize(&self) -> Result<(), Bip375Error> {
        self.with_inner(finalize)
    }

    pub fn extract_transaction(&self) -> Result<Vec<u8>, Bip375Error> {
        let psbt = self.inner.lock().unwrap().clone();
        let tx = Extractor::new(psbt)
            .map_err(|_| Bip375Error::PsbtError)?
            .extract_tx()
            .map_err(|_| Bip375Error::PsbtError)?;
        Ok(serialize(&tx))
    }

    pub fn set_tx_modifiable(&self, flags: u8) {
        self.with_inner(|p| p.global.tx_modifiable_flags = flags);
    }

    pub(crate) fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut CorePsbt) -> R,
    {
        let mut psbt = self.inner.lock().unwrap();
        f(&mut psbt)
    }
}

/// The scriptPubKey an input spends, from its witness or non-witness UTXO.
fn spent_script(input: &Input) -> Option<&ScriptBuf> {
    match &input.witness_utxo {
        Some(utxo) => Some(&utxo.script_pubkey),
        None => input
            .non_witness_utxo
            .as_ref()?
            .output
            .get(input.spent_output_index as usize)
            .map(|output| &output.script_pubkey),
    }
}

impl Clone for Psbt {
    fn clone(&self) -> Self {
        Self::from_core(self.inner.lock().unwrap().clone())
    }
}

fn to_derivation_path(raw: Vec<u32>) -> DerivationPath {
    DerivationPath::from(raw.into_iter().map(ChildNumber::from).collect::<Vec<_>>())
}

fn finalize(psbt: &mut CorePsbt) -> Result<(), Bip375Error> {
    let secp = Secp256k1::new();
    *psbt = Finalizer::new(psbt.clone())
        .map_err(|_| Bip375Error::ValidationError)?
        .finalize(&secp)
        .map_err(|_| Bip375Error::ValidationError)?;
    Ok(())
}

fn raw_key(type_value: u64, key_data: Vec<u8>) -> PsbtKey {
    PsbtKey {
        type_value,
        key: key_data,
    }
}

pub fn add_raw_global_field(
    psbt: Arc<Psbt>,
    type_value: u64,
    key_data: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        match type_value {
            0x06 if value.len() == 1 => p.global.tx_modifiable_flags = value[0],
            0x07 if key_data.len() == 33 && value.len() == 33 => {
                if let (Ok(scan), Ok(share)) = (
                    PublicKey::from_slice(&key_data),
                    PublicKey::from_slice(&value),
                ) {
                    p.global
                        .sp_ecdh_shares
                        .insert(CompressedPublicKey(scan), CompressedPublicKey(share));
                } else {
                    p.global.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x08 if key_data.len() == 33 && value.len() == 64 => {
                if let Ok(scan) = PublicKey::from_slice(&key_data) {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(&value);
                    p.global
                        .sp_dleq_proofs
                        .insert(CompressedPublicKey(scan), DleqProof(bytes));
                } else {
                    p.global.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            _ => {
                p.global
                    .unknowns
                    .insert(raw_key(type_value, key_data), value);
            }
        }
        Ok(())
    })
}

pub fn add_raw_input_field(
    psbt: Arc<Psbt>,
    input_index: u32,
    type_value: u64,
    key_data: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let input = p
            .inputs
            .get_mut(input_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        match type_value {
            0x00 => {
                if let Ok(tx) = deserialize(&value) {
                    input.non_witness_utxo = Some(tx);
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x01 => {
                if let Ok(txout) = deserialize(&value) {
                    input.witness_utxo = Some(txout);
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x03 if value.len() == 4 => {
                if let Ok(bytes) = <[u8; 4]>::try_from(value.as_slice()) {
                    input.sighash_type = Some(PsbtSighashType::from_u32(u32::from_le_bytes(bytes)));
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x04 => input.redeem_script = Some(ScriptBuf::from_bytes(value)),
            0x05 => input.witness_script = Some(ScriptBuf::from_bytes(value)),
            0x0e if value.len() == 32 => {
                if let Ok(txid) = Txid::from_slice(&value) {
                    input.previous_txid = txid;
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x0f if value.len() == 4 => {
                if let Ok(bytes) = <[u8; 4]>::try_from(value.as_slice()) {
                    input.spent_output_index = u32::from_le_bytes(bytes);
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x10 if value.len() == 4 => {
                if let Ok(bytes) = <[u8; 4]>::try_from(value.as_slice()) {
                    input.sequence = Some(Sequence::from_consensus(u32::from_le_bytes(bytes)));
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x17 if value.len() == 32 => {
                if let Ok(key) = XOnlyPublicKey::from_slice(&value) {
                    input.tap_internal_key = Some(key);
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x1d if key_data.len() == 33 && value.len() == 33 => {
                if let (Ok(scan), Ok(share)) = (
                    PublicKey::from_slice(&key_data),
                    PublicKey::from_slice(&value),
                ) {
                    input
                        .sp_ecdh_shares
                        .insert(CompressedPublicKey(scan), CompressedPublicKey(share));
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x1e if key_data.len() == 33 && value.len() == 64 => {
                if let Ok(scan) = PublicKey::from_slice(&key_data) {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(&value);
                    input
                        .sp_dleq_proofs
                        .insert(CompressedPublicKey(scan), DleqProof(bytes));
                } else {
                    input.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            _ => {
                input.unknowns.insert(raw_key(type_value, key_data), value);
            }
        }
        Ok(())
    })
}

pub fn remove_raw_input_fields_by_type(
    psbt: Arc<Psbt>,
    input_index: u32,
    type_value: u64,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let input = p
            .inputs
            .get_mut(input_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        input.unknowns.retain(|k, _| k.type_value != type_value);
        match type_value {
            0x1d => input.sp_ecdh_shares.clear(),
            0x1e => input.sp_dleq_proofs.clear(),
            _ => {}
        }
        Ok(())
    })
}

pub fn add_raw_output_field(
    psbt: Arc<Psbt>,
    output_index: u32,
    type_value: u64,
    key_data: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let output = p
            .outputs
            .get_mut(output_index as usize)
            .ok_or(Bip375Error::InvalidData)?;
        match type_value {
            0x03 if value.len() == 8 => {
                if let Ok(bytes) = <[u8; 8]>::try_from(value.as_slice()) {
                    output.amount = Amount::from_sat(u64::from_le_bytes(bytes));
                } else {
                    output.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x04 => output.script_pubkey = ScriptBuf::from_bytes(value),
            0x09 if value.len() == 66 => {
                let bytes: [u8; 66] = value.as_slice().try_into().unwrap();
                if let Ok(info) = SpV0Info::from_byte_array(&bytes) {
                    output.sp_v0_info = Some(info);
                } else {
                    output.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            0x0a if value.len() == 4 => {
                if let Ok(bytes) = <[u8; 4]>::try_from(value.as_slice()) {
                    output.sp_v0_label = Some(u32::from_le_bytes(bytes));
                } else {
                    output.unknowns.insert(raw_key(type_value, key_data), value);
                }
            }
            _ => {
                output.unknowns.insert(raw_key(type_value, key_data), value);
            }
        }
        Ok(())
    })
}

/// `SecretKey`'s `GetKey` for several keys: resolves by public key, never by BIP-32 origin.
struct SecretKeySet(Vec<SecretKey>);

impl GetKey for SecretKeySet {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<bitcoin::PrivateKey>, Self::Error> {
        for key in &self.0 {
            if let Some(found) = key.get_key(key_request, secp)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parts_to_new_psbt() {
        let psbt = Psbt::new();
        psbt.add_inputs(vec![Utxo {
            txid: "a".repeat(64),
            vout: 0,
            amount: 100_000,
            script_pubkey: vec![],
            sequence: None,
            public_key: None,
            master_fingerprint: None,
            derivation_path: None,
        }])
        .unwrap();
        psbt.add_outputs(vec![PsbtOutput::Regular {
            amount: 90_000,
            script_pubkey: vec![0x51],
        }])
        .unwrap();

        assert_eq!(psbt.num_inputs(), 1);
        assert_eq!(psbt.num_outputs(), 1);
        assert_eq!(Psbt::deserialize(psbt.serialize().unwrap()).unwrap().num_inputs(), 1);
    }
}
