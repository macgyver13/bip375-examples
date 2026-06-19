// Cryptographic functions for UniFFI bindings.

use crate::errors::Bip375Error;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use silentpayments::bitcoin_hashes::{sha256, Hash, HashEngine};

fn tagged_hash(tag: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    for chunk in chunks {
        engine.input(chunk);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn scalar_from_hash(bytes: [u8; 32]) -> Result<Scalar, Bip375Error> {
    Scalar::from_be_bytes(bytes).map_err(|_| Bip375Error::CryptoError)
}

pub fn bip352_compute_ecdh_share(
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let share = pk
        .mul_tweak(&secp, &sk.into())
        .map_err(|_| Bip375Error::CryptoError)?;
    Ok(share.serialize().to_vec())
}

pub fn bip352_derive_silent_payment_output_pubkey(
    spend_key: Vec<u8>,
    ecdh_secret: Vec<u8>,
    k: u32,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = Secp256k1::new();
    let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
    if ecdh_secret.len() != 33 {
        return Err(Bip375Error::InvalidData);
    }
    let tweak = tagged_hash(
        b"BIP0352/SharedSecret",
        &[ecdh_secret.as_slice(), &k.to_be_bytes()],
    );
    let tweak = scalar_from_hash(tweak)?;
    let tweak_pk = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&tweak.to_be_bytes()).map_err(|_| Bip375Error::CryptoError)?,
    );
    let output = spend_pk
        .combine(&tweak_pk)
        .map_err(|_| Bip375Error::CryptoError)?;
    Ok(output.serialize().to_vec())
}

pub fn bip352_pubkey_to_p2wpkh_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let script = bip375_helpers::crypto::pubkey_to_p2wpkh_script(&pk);
    Ok(script.to_bytes())
}

pub fn bip352_tweaked_key_to_p2tr_script(pubkey: Vec<u8>) -> Result<Vec<u8>, Bip375Error> {
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let script = bip375_helpers::crypto::tweaked_key_to_p2tr_script(&pk);
    Ok(script.to_bytes())
}

pub fn bip352_apply_label_to_spend_key(
    spend_key: Vec<u8>,
    scan_privkey: Vec<u8>,
    label: u32,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = Secp256k1::new();
    let spend_pk = PublicKey::from_slice(&spend_key).map_err(|_| Bip375Error::InvalidKey)?;
    let scan_sk = SecretKey::from_slice(&scan_privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let label_hash = tagged_hash(
        b"BIP0352/Label",
        &[&scan_sk.secret_bytes(), &label.to_be_bytes()],
    );
    let label_secret = SecretKey::from_slice(&label_hash).map_err(|_| Bip375Error::CryptoError)?;
    let label_pubkey = PublicKey::from_secret_key(&secp, &label_secret);
    let labeled = spend_pk
        .combine(&label_pubkey)
        .map_err(|_| Bip375Error::CryptoError)?;
    Ok(labeled.serialize().to_vec())
}

pub fn bip352_compute_input_hash(
    smallest_outpoint: Vec<u8>,
    summed_pubkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    if smallest_outpoint.len() != 36 {
        return Err(Bip375Error::InvalidData);
    }
    let pk = PublicKey::from_slice(&summed_pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let hash = tagged_hash(
        b"BIP0352/Inputs",
        &[smallest_outpoint.as_slice(), &pk.serialize()],
    );
    let scalar = scalar_from_hash(hash)?;
    Ok(scalar.to_be_bytes().to_vec())
}

pub fn bip352_compute_shared_secret_tweak(
    ecdh_secret: Vec<u8>,
    k: u32,
) -> Result<Vec<u8>, Bip375Error> {
    if ecdh_secret.len() != 33 {
        return Err(Bip375Error::InvalidData);
    }
    Ok(tagged_hash(
        b"BIP0352/SharedSecret",
        &[ecdh_secret.as_slice(), &k.to_be_bytes()],
    )
    .to_vec())
}

pub fn dleq_generate_proof(
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
    aux_rand: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&privkey).map_err(|_| Bip375Error::InvalidKey)?;
    let pk = PublicKey::from_slice(&pubkey).map_err(|_| Bip375Error::InvalidKey)?;
    let aux: [u8; 32] = aux_rand.try_into().map_err(|_| Bip375Error::InvalidData)?;
    let proof = psbt::generate_dleq_proof(&secp, &sk, &pk, &aux, None)
        .map_err(|_| Bip375Error::SigningError)?;
    Ok(proof.as_bytes().to_vec())
}

pub fn dleq_verify_proof(
    pubkey_a: Vec<u8>,
    pubkey_b: Vec<u8>,
    pubkey_c: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<bool, Bip375Error> {
    let secp = Secp256k1::new();
    let pk_a = PublicKey::from_slice(&pubkey_a).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_b = PublicKey::from_slice(&pubkey_b).map_err(|_| Bip375Error::InvalidKey)?;
    let pk_c = PublicKey::from_slice(&pubkey_c).map_err(|_| Bip375Error::InvalidKey)?;
    let proof_array: [u8; 64] = proof_bytes
        .try_into()
        .map_err(|_| Bip375Error::InvalidData)?;
    let proof = psbt::DleqProof::from(proof_array);
    psbt::verify_dleq_proof(&secp, &pk_a, &pk_b, &pk_c, &proof, None)
        .map_err(|_| Bip375Error::InvalidProof)
}

pub fn signing_sign_p2wpkh_input(
    _tx: Vec<u8>,
    _input_index: u32,
    _script_pubkey: Vec<u8>,
    _amount: u64,
    _privkey: Vec<u8>,
) -> Result<Vec<u8>, Bip375Error> {
    Err(Bip375Error::SigningError)
}
