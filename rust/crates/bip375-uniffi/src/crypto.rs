// Cryptographic functions for UniFFI bindings

use crate::errors::Bip375Error;
use bip375_crypto as crypto;
use secp256k1::{PublicKey, SecretKey};

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

// pub fn bip352_derive_silent_payment_output_pubkey(
//     spend_key: Vec<u8>,
//     ecdh_secret: Vec<u8>,
//     k: u32,
// ) -> Result<Vec<u8>, Bip375Error> {
//     let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
//     let ecdh_pk = PublicKey::from_slice(&ecdh_secret).map_err(|_| Bip375Error::InvalidKey)?;

//     let output_pk = crypto::bip352::derive_silent_payment_output_pubkey(&spend_pk, &ecdh_pk, k)?;
//     Ok(output_pk.serialize().to_vec())
// }

// pub fn bip352_pubkey_to_p2wpkh_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
//     let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
//     let script = crypto::bip352::pubkey_to_p2wpkh_script(&pk)?;
//     Ok(script.to_bytes())
// }

// pub fn bip352_tweaked_key_to_p2tr_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
//     let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
//     let script = crypto::bip352::tweaked_key_to_p2tr_script(&pk)?;
//     Ok(script.to_bytes())
// }

// pub fn bip352_compute_label_tweak(scan_key: Vec<u8>, label: u32) -> Result<Vec<u8>, Bip375Error> {
//     let scan_pk = PublicKey::from_slice(&scan_key).map_err(|_| Bip375Error::InvalidKey)?;
//     let tweak = crypto::bip352::compute_label_tweak(&scan_pk, label)?;
//     Ok(tweak.to_vec())
// }

// pub fn bip352_apply_label_to_spend_key(
//     spend_key: Vec<u8>,
//     scan_key: Vec<u8>,
//     label: u32,
// ) -> Result<Vec<u8>, Bip375Error> {
//     let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
//     let scan_pk = PublicKey::from_slice(&scan_key).map_err(|_| Bip375Error::InvalidKey)?;

//     let labeled_pk = crypto::bip352::apply_label_to_spend_key(&spend_pk, &scan_pk, label)?;
//     Ok(labeled_pk.serialize().to_vec())
// }

// pub fn bip352_compute_input_hash(input_pubkeys: Vec<Vec<u8>>) -> Result<Vec<u8>, Bip375Error> {
//     let pubkeys: Result<Vec<PublicKey>, _> = input_pubkeys
//         .iter()
//         .map(|pk_bytes| PublicKey::from_slice(pk_bytes))
//         .collect();

//     let pubkeys = pubkeys.map_err(|_| Bip375Error::InvalidKey)?;
//     let input_hash = crypto::bip352::compute_input_hash(&pubkeys)?;
//     Ok(input_hash.to_vec())
// }

// pub fn bip352_compute_shared_secret_tweak(
//     ecdh_secret: Vec<u8>,
//     input_hash: Vec<u8>,
// ) -> Result<Vec<u8>, Bip375Error> {
//     let ecdh_pk = PublicKey::from_slice(&ecdh_secret).map_err(|_| Bip375Error::InvalidKey)?;

//     if input_hash.len() != 32 {
//         return Err(Bip375Error::InvalidData);
//     }

//     let mut hash_bytes = [0u8; 32];
//     hash_bytes.copy_from_slice(&input_hash);

//     let tweak = crypto::bip352::compute_shared_secret_tweak(&ecdh_pk, &hash_bytes)?;
//     Ok(tweak.to_vec())
// }

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
    Ok(proof.to_vec())
}

pub fn dleq_verify_proof(
    pubkey_a: Vec<u8>,
    pubkey_b: Vec<u8>,
    pubkey_c: Vec<u8>,
    proof: Vec<u8>,
) -> Result<bool, Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let pk_a = PublicKey::from_slice(&pubkey_a).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_b = PublicKey::from_slice(&pubkey_b).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_c = PublicKey::from_slice(&pubkey_c).map_err(|_| Bip375Error::InvalidKey)?;

    if proof.len() != 64 {
        return Err(Bip375Error::InvalidData);
    }

    let mut proof_bytes = [0u8; 64];
    proof_bytes.copy_from_slice(&proof);

    let result = crypto::dleq::dleq_verify_proof(&secp, &pk_a, &pk_b, &pk_c, &proof_bytes, None)?;
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
