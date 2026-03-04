// Cryptographic functions for UniFFI bindings

use crate::errors::Bip375Error;
use secp256k1::{PublicKey, SecretKey};
use silentpayments::bitcoin_hashes::Hash as SpHash;
use silentpayments::utils::hash::{InputsHash, LabelHash, SharedSecretHash};
use spdk_core::psbt::crypto;

// ============================================================================
// BIP-352 Functions
// ============================================================================

pub fn bip352_compute_ecdh_share(
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;

    let share = crypto::bip352::compute_ecdh_share(&secp, &sk, &pk)?;
    Ok(share.serialize().to_vec())
}

pub fn bip352_derive_silent_payment_output_pubkey(
    spend_key: Vec<u8>,
    ecdh_secret: Vec<u8>,
    k: u32,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;

    if ecdh_secret.len() != 33 {
        return Err(Bip375Error::InvalidData);
    }
    let mut ecdh_bytes = [0u8; 33];
    ecdh_bytes.copy_from_slice(&ecdh_secret);

    let output_pk =
        crypto::bip352::derive_silent_payment_output_pubkey(&secp, &spend_pk, &ecdh_bytes, k)?;
    Ok(output_pk.serialize().to_vec())
}

pub fn bip352_pubkey_to_p2wpkh_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let script = crypto::bip352::pubkey_to_p2wpkh_script(&pk);
    Ok(script.to_bytes())
}

pub fn bip352_tweaked_key_to_p2tr_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let script = crypto::bip352::tweaked_key_to_p2tr_script(&pk);
    Ok(script.to_bytes())
}

pub fn bip352_apply_label_to_spend_key(
    spend_key: Vec<u8>,
    scan_privkey: Vec<u8>,
    label: u32,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
    let scan_sk = SecretKey::from_slice(&scan_privkey).map_err(|_| Bip375Error::InvalidKey)?;

    let tweak = LabelHash::from_b_scan_and_m(scan_sk, label).to_scalar();
    let tweak_sk = SecretKey::from_slice(&tweak.to_be_bytes()).map_err(|_| Bip375Error::CryptoError)?;
    let tweak_point = PublicKey::from_secret_key(&secp, &tweak_sk);
    let labeled_pk = spend_pk.combine(&tweak_point).map_err(|_| Bip375Error::CryptoError)?;
    Ok(labeled_pk.serialize().to_vec())
}

pub fn bip352_compute_input_hash(
    smallest_outpoint: Vec<u8>,
    summed_pubkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    let pk = PublicKey::from_slice(&summed_pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let outpoint_arr: [u8; 36] = smallest_outpoint
        .try_into()
        .map_err(|_| Bip375Error::InvalidData)?;
    let input_hash = InputsHash::from_outpoint_and_A_sum(&outpoint_arr, pk).to_scalar();
    Ok(input_hash.to_be_bytes().to_vec())
}

pub fn bip352_compute_shared_secret_tweak(
    ecdh_secret: Vec<u8>,
    k: u32,
) -> Result<Vec<u8>, Bip375Error> {
    if ecdh_secret.len() != 33 {
        return Err(Bip375Error::InvalidData);
    }

    let mut ecdh_bytes = [0u8; 33];
    ecdh_bytes.copy_from_slice(&ecdh_secret);

    let ecdh_pubkey = PublicKey::from_slice(&ecdh_bytes).map_err(|_| Bip375Error::InvalidKey)?;
    let tweak_bytes = SpHash::to_byte_array(SharedSecretHash::from_ecdh_and_k(&ecdh_pubkey, k));
    Ok(tweak_bytes.to_vec())
}

// ============================================================================
// BIP-374 DLEQ Proof Functions
// ============================================================================

pub fn dleq_generate_proof(
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
    aux_rand: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;

    if aux_rand.len() != 32 {
        return Err(Bip375Error::InvalidData);
    }

    let mut aux_bytes = [0u8; 32];
    aux_bytes.copy_from_slice(&aux_rand);

    let proof = crypto::dleq::dleq_generate_proof(&secp, &sk, &pk, &aux_bytes, None)?;
    Ok(proof.as_bytes().to_vec())
}

pub fn dleq_verify_proof(
    pubkey_a: Vec<u8>,
    pubkey_b: Vec<u8>,
    pubkey_c: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<bool, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let pk_a = PublicKey::from_slice(&pubkey_a).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_b = PublicKey::from_slice(&pubkey_b).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_c = PublicKey::from_slice(&pubkey_c).map_err(|_| Bip375Error::InvalidKey)?;

    if proof_bytes.len() != 64 {
        return Err(Bip375Error::InvalidData);
    }
    let mut proof_array = [0u8; 64];
    proof_array.copy_from_slice(&proof_bytes);
    let proof = spdk_core::psbt::DleqProof::from(proof_array);

    let result = crypto::dleq::dleq_verify_proof(&secp, &pk_a, &pk_b, &pk_c, &proof, None)?;
    Ok(result)
}

// ============================================================================
// Signing Functions
// ============================================================================

pub fn signing_sign_p2wpkh_input(
    tx: Vec<u8>,
    input_index: u32,
    script_pubkey: Vec<u8>,
    amount: u64,
    privkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    use bitcoin::consensus::deserialize;
    use bitcoin::{Amount, Transaction};

    let secp = secp256k1::Secp256k1::new();
    let transaction: Transaction = deserialize(&tx).map_err(|_| Bip375Error::InvalidData)?;

    let script = bitcoin::ScriptBuf::from_bytes(script_pubkey);
    let sk = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let amount_sats = Amount::from_sat(amount);

    let signature = crypto::signing::sign_p2wpkh_input(
        &secp,
        &transaction,
        input_index as usize,
        &script,
        amount_sats,
        &sk,
    )?;

    Ok(signature.to_vec())
}
