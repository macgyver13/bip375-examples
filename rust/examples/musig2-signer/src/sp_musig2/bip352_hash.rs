//! BIP-352 tagged hashes, reimplemented because `silentpayments::utils::hash` is
//! `pub(crate)`. Byte layout matches the upstream crate exactly so that the SP
//! outputs derived here are detectable by a BIP-352 receiver. UPSTREAM CANDIDATE
//! (ideally these would be public in `silentpayments`).

use bitcoin::hashes::{sha256, Hash, HashEngine};
use secp256k1::PublicKey;

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    for p in parts {
        eng.input(p);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// `hash_BIP0352/Inputs(smallest_outpoint(36) || A_sum(33))`.
pub fn input_hash_bytes(smallest_outpoint: &[u8; 36], a_sum: &PublicKey) -> [u8; 32] {
    tagged(b"BIP0352/Inputs", &[smallest_outpoint, &a_sum.serialize()])
}

/// `hash_BIP0352/SharedSecret(serP(ecdh_shared_secret)(33) || k(BE 4))`.
pub fn shared_secret_tweak(ecdh_shared_secret: &PublicKey, k: u32) -> [u8; 32] {
    tagged(
        b"BIP0352/SharedSecret",
        &[&ecdh_shared_secret.serialize(), &k.to_be_bytes()],
    )
}
