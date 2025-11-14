//! BIP-352 Silent Payment Cryptography
//!
//! Implements cryptographic primitives for BIP-352 silent payments.

use crate::error::{CryptoError, Result};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Compute label tweak for a silent payment address
///
/// BIP 352: hash_BIP0352/Label(ser₂₅₆(scan_privkey) || ser₃₂(label))
/// Uses tagged hash as per BIP 340
pub fn compute_label_tweak(scan_privkey: &SecretKey, label: u32) -> Result<Scalar> {
    // BIP 352 tagged hash: tag_hash || tag_hash || data
    let tag = b"BIP0352/Label";
    let tag_hash = sha256::Hash::hash(tag);
    
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(&scan_privkey.secret_bytes());
    engine.input(&label.to_le_bytes());
    let hash = sha256::Hash::from_engine(engine);

    Scalar::from_be_bytes(hash.to_byte_array())
        .map_err(|_| CryptoError::Other("Failed to create scalar from label tweak".to_string()))
}

/// Compute input hash for BIP-352 silent payments
///
/// BIP 352: hash_BIP0352/Inputs(smallest_outpoint || ser₃₃(A))
/// where A is the sum of all eligible input public keys
/// Uses tagged hash as per BIP 340
pub fn compute_input_hash(smallest_outpoint: &[u8], summed_pubkey: &PublicKey) -> Result<Scalar> {
    // BIP 352 tagged hash: tag_hash || tag_hash || data
    let tag = b"BIP0352/Inputs";
    let tag_hash = sha256::Hash::hash(tag);

    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(smallest_outpoint);
    engine.input(&summed_pubkey.serialize());
    let hash = sha256::Hash::from_engine(engine);

    Scalar::from_be_bytes(hash.to_byte_array())
        .map_err(|_| CryptoError::Other("Failed to create scalar from input hash".to_string()))
}

/// Compute shared secret tweak for output derivation
///
/// BIP 352: hash_BIP0352/SharedSecret(ecdh_secret || ser₃₂(k))
/// Uses tagged hash as per BIP 340
pub fn compute_shared_secret_tweak(ecdh_secret: &[u8; 33], k: u32) -> Result<Scalar> {
    // BIP 352 tagged hash: tag_hash || tag_hash || data
    let tag = b"BIP0352/SharedSecret";
    let tag_hash = sha256::Hash::hash(tag);

    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(ecdh_secret);
    engine.input(&k.to_be_bytes());
    let hash = sha256::Hash::from_engine(engine);

    Scalar::from_be_bytes(hash.to_byte_array())
        .map_err(|_| CryptoError::Other("Failed to create scalar from shared secret tweak".to_string()))
}

/// Apply label to spend public key
///
/// labeled_spend_key = spend_key + label_tweak * G
pub fn apply_label_to_spend_key(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    scan_privkey: &SecretKey,
    label: u32,
) -> Result<PublicKey> {
    let label_tweak = compute_label_tweak(scan_privkey, label)?;
    let label_tweak_key = SecretKey::from_slice(&label_tweak.to_be_bytes())?;
    let label_point = PublicKey::from_secret_key(secp, &label_tweak_key);

    spend_key.combine(&label_point)
        .map_err(|e| CryptoError::Other(format!("Failed to apply label: {}", e)))
}

/// Derive silent payment output public key
///
/// output_pubkey = spend_key + hash(ecdh_secret || ser₃₂(k)) * G
pub fn derive_silent_payment_output_pubkey(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    ecdh_secret: &[u8; 33],
    k: u32,
) -> Result<PublicKey> {
    let tweak = compute_shared_secret_tweak(ecdh_secret, k)?;
    let tweak_key = SecretKey::from_slice(&tweak.to_be_bytes())?;
    let tweak_point = PublicKey::from_secret_key(secp, &tweak_key);

    spend_key.combine(&tweak_point)
        .map_err(|e| CryptoError::Other(format!("Failed to derive output pubkey: {}", e)))
}

/// Convert public key to P2WPKH script
///
/// Returns: OP_0 <20-byte-hash>
pub fn pubkey_to_p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
    let pubkey_hash = bitcoin::PublicKey::new(pubkey.clone())
        .wpubkey_hash()
        .expect("Compressed key");

    ScriptBuf::new_p2wpkh(&pubkey_hash)
}

/// Convert public key to P2TR (Taproot) script
///
/// Returns: OP_1 <32-byte-xonly-pubkey>
pub fn pubkey_to_p2tr_script(pubkey: &PublicKey) -> ScriptBuf {
    let xonly = pubkey.x_only_public_key().0;
    ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked())
}

/// Compute ECDH shared secret
///
/// ecdh_secret = privkey * pubkey
pub fn compute_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    privkey: &SecretKey,
    pubkey: &PublicKey,
) -> Result<PublicKey> {
    // Multiply pubkey by privkey scalar
    let scalar: Scalar = (*privkey).into();
    let shared = pubkey.mul_tweak(secp, &scalar)?;
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_tweak() {
        let _secp = Secp256k1::new();
        let scan_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let label = 42;

        let tweak = compute_label_tweak(&scan_privkey, label).unwrap();
        assert!(tweak.to_be_bytes().len() == 32);
    }

    #[test]
    fn test_shared_secret_tweak() {
        let ecdh_secret = [2u8; 33];
        let k = 0;

        let tweak = compute_shared_secret_tweak(&ecdh_secret, k).unwrap();
        assert!(tweak.to_be_bytes().len() == 32);
    }

    #[test]
    fn test_ecdh_computation() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = compute_ecdh_share(&secp, &privkey, &pubkey).unwrap();
        assert!(share.serialize().len() == 33);
    }

    #[test]
    fn test_p2wpkh_script() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let script = pubkey_to_p2wpkh_script(&pubkey);
        assert_eq!(script.len(), 22); // OP_0 + 20 bytes
    }

    #[test]
    fn test_derive_from_test_vector() {
        let secp = Secp256k1::new();

        // From valid test vector 1
        let spend_key_hex = "024d518353f4bd18d769cf68ff62ef10669b7086246b0a6403fe57bde49211448b";
        let ecdh_secret_hex = "0255164e7926d50d52a09ff990647a5e95c1db1bfc68a616fbc2da213927f98bff";

        let spend_key = PublicKey::from_slice(&hex::decode(spend_key_hex).unwrap()).unwrap();
        let mut ecdh_secret: [u8; 33] = [0; 33];
        ecdh_secret.copy_from_slice(&hex::decode(ecdh_secret_hex).unwrap());

        let output_pubkey = derive_silent_payment_output_pubkey(&secp, &spend_key, &ecdh_secret, 0).unwrap();

        let xonly = output_pubkey.x_only_public_key().0;
        let xonly_hex = hex::encode(xonly.serialize());

        println!("Derived x-only: {}", xonly_hex);
        println!("Expected x-only: ae19fbee2730a1a952d7d2598cc703fddf3b972b25148b1ed1a79ae8739d5e07");

        // This should match the test vector
        assert_eq!(xonly_hex, "ae19fbee2730a1a952d7d2598cc703fddf3b972b25148b1ed1a79ae8739d5e07");
    }

    #[test]
    fn test_p2tr_script_creation() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let script = pubkey_to_p2tr_script(&pubkey);

        // P2TR scripts are 34 bytes: OP_1 (0x51) + PUSH_32 (0x20) + 32-byte x-only key
        assert_eq!(script.len(), 34);
        assert!(script.is_p2tr());

        // Verify script structure
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x51); // OP_1
        assert_eq!(bytes[1], 0x20); // PUSH_32

        // Verify x-only key matches
        let (expected_xonly, _) = pubkey.x_only_public_key();
        assert_eq!(&bytes[2..34], &expected_xonly.serialize()[..]);
    }

    #[test]
    fn test_p2tr_script_compatibility() {
        // Verify that pubkey_to_p2tr_script produces identical results
        // to the manual construction previously used in validation.rs and input_finalizer.rs
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        // New method
        let new_script = pubkey_to_p2tr_script(&pubkey);

        // Old method (manual construction)
        let (xonly, _parity) = pubkey.x_only_public_key();
        let mut script_bytes = Vec::with_capacity(34);
        script_bytes.push(0x51); // OP_1
        script_bytes.push(0x20); // PUSH_32
        script_bytes.extend_from_slice(&xonly.serialize().as_ref());
        let old_script = ScriptBuf::from_bytes(script_bytes);

        // Should be identical
        assert_eq!(new_script, old_script);
    }
}
