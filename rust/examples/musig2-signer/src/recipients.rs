//! Known-seed silent payment recipients shared by the fixture generator (sender) and the
//! `scan-recipient` validator (receiver).
//!
//! Each recipient is defined by a single 32-byte seed. Scan and spend keys are derived
//! deterministically from that seed, so the validator can reconstruct the exact keys and
//! confirm it detects each on-chain output. This is a TEST construct only — a production
//! sender never knows recipient seeds.

use anyhow::Result;
use bitcoin::Amount;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

/// (seed, amount in sats) per recipient. Amounts match the original payroll fixture.
pub const RECIPIENT_SEEDS: [([u8; 32], u64); 5] = [
    ([0xb1; 32], 18_000_000),
    ([0xb2; 32], 16_000_000),
    ([0xb3; 32], 150_000_000),
    ([0xb4; 32], 10_000_000),
    ([0xb5; 32], 20_000_000),
];

/// Deterministically derive (scan_sk, spend_sk) from a recipient seed.
pub fn recipient_keys(seed: &[u8; 32]) -> (SecretKey, SecretKey) {
    (derive_key(seed, b"scan"), derive_key(seed, b"spend"))
}

fn derive_key(seed: &[u8; 32], tag: &[u8]) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(seed);
    let digest = hasher.finalize();
    SecretKey::from_slice(&digest).expect("sha256 output is a valid secret key")
}

/// Build the SP address + amount for every recipient seed.
pub fn recipient_addresses() -> Result<Vec<(SilentPaymentAddress, Amount)>> {
    let secp = Secp256k1::new();
    RECIPIENT_SEEDS
        .iter()
        .map(|(seed, amount)| {
            let (scan_sk, spend_sk) = recipient_keys(seed);
            let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
            let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
            let addr = SilentPaymentAddress::new(scan_pk, spend_pk, SpNetwork::Mainnet, SpVersion::ZERO);
            Ok((addr, Amount::from_sat(*amount)))
        })
        .collect()
}
