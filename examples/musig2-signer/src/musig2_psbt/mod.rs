//! Native psbt-v2 storage accessors for the MuSig2 + Silent-Payment fields.
//!
//! Ported from the old `spdk-core::psbt::core::extensions` (`Bip375PsbtExt`),
//! adapted to operate directly on native `psbt_v2::v2::{Input, Output}`. The old
//! trait already stored everything in native psbt-v2 fields, so these are mostly
//! verbatim. UPSTREAM CANDIDATE.
//!
//! Field map:
//! - participant pubkeys → native `musig2_participant_pubkeys`
//! - pub nonces / partial sigs → native `musig2_pub_nonces` / `musig2_partial_sigs`
//!   (compound key `participant_pk(33) || agg_pk(33)`)
//! - partial ECDH share / DLEQ (proposed `PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE` = 0x21,
//!   `PSBT_IN_MUSIG2_PARTIAL_DLEQ` = 0x22) → `input.unknowns`, key
//!   `scan_key(33) || contributor_pk(33)`, value `share(33)` / `proof(64)`.

use anyhow::{anyhow, bail, Result};
use bitcoin::CompressedPublicKey;
use psbt_v2::raw::Key;
use psbt_v2::v2::dleq::DleqProof;
use psbt_v2::v2::{Input, Output};
use secp256k1::PublicKey;

/// Proposed BIP-375 extension keytype: per-party MuSig2 partial ECDH share.
pub const PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE: u64 = 0x21;
/// Proposed BIP-375 extension keytype: per-party MuSig2 partial DLEQ proof.
pub const PSBT_IN_MUSIG2_PARTIAL_DLEQ: u64 = 0x22;

/// Partial ECDH share contributed by one MuSig2 participant.
///
/// Each participant computes `share = sk_i * scan_key` and a DLEQ proof binding it
/// to its participant pubkey `P_i = sk_i * G`. The final signer sums the weighted
/// shares to obtain the aggregate ECDH share `= a_Q * scan_key`.
#[derive(Debug, Clone)]
pub struct PartialEcdhShareData {
    pub scan_key: PublicKey,
    pub contributor_pk: PublicKey,
    pub share: PublicKey,
    pub dleq_proof: DleqProof,
}

// ===== MuSig2 participant pubkeys (BIP-373) =====

pub fn set_input_musig2_participant_pubkeys(
    input: &mut Input,
    agg_pk: &PublicKey,
    participants: &[PublicKey],
) {
    let mut value = Vec::with_capacity(participants.len() * 33);
    for pk in participants {
        value.extend_from_slice(&pk.serialize());
    }
    input
        .musig2_participant_pubkeys
        .insert(CompressedPublicKey(*agg_pk), value);
}

pub fn get_input_musig2_participant_pubkeys(
    input: &Input,
) -> Result<Vec<(PublicKey, Vec<PublicKey>)>> {
    decode_participant_map(&input.musig2_participant_pubkeys)
}

pub fn set_output_musig2_participant_pubkeys(
    output: &mut Output,
    agg_pk: &PublicKey,
    participants: &[PublicKey],
) {
    let mut value = Vec::with_capacity(participants.len() * 33);
    for pk in participants {
        value.extend_from_slice(&pk.serialize());
    }
    output
        .musig2_participant_pubkeys
        .insert(CompressedPublicKey(*agg_pk), value);
}

fn decode_participant_map(
    map: &std::collections::BTreeMap<CompressedPublicKey, Vec<u8>>,
) -> Result<Vec<(PublicKey, Vec<PublicKey>)>> {
    let mut result = Vec::new();
    for (agg_key_compressed, participants_bytes) in map {
        if participants_bytes.is_empty() || participants_bytes.len() % 33 != 0 {
            bail!(
                "invalid MuSig2 participant list length: {}",
                participants_bytes.len()
            );
        }
        let agg_pk = agg_key_compressed.0;
        let mut participants = Vec::new();
        for chunk in participants_bytes.chunks(33) {
            let pk = PublicKey::from_slice(chunk)
                .map_err(|e| anyhow!("invalid MuSig2 participant public key: {e}"))?;
            if participants.contains(&pk) {
                bail!("duplicate MuSig2 participant public key: {pk}");
            }
            participants.push(pk);
        }
        result.push((agg_pk, participants));
    }
    Ok(result)
}

// ===== MuSig2 public nonces (BIP-373) =====

pub fn add_input_musig2_pub_nonce(
    input: &mut Input,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    nonce: [u8; 66],
) {
    input
        .musig2_pub_nonces
        .insert(compound_key(participant_pk, agg_pk), nonce.to_vec());
}

pub fn get_input_musig2_pub_nonces(input: &Input) -> Result<Vec<(PublicKey, PublicKey, [u8; 66])>> {
    let mut result = Vec::new();
    for (compound, nonce_bytes) in &input.musig2_pub_nonces {
        if compound.len() != 66 || nonce_bytes.len() != 66 {
            bail!(
                "invalid MuSig2 public nonce field lengths: key={}, value={}",
                compound.len(),
                nonce_bytes.len()
            );
        }
        let participant_pk = PublicKey::from_slice(&compound[..33])
            .map_err(|e| anyhow!("invalid nonce participant public key: {e}"))?;
        let agg_pk = PublicKey::from_slice(&compound[33..])
            .map_err(|e| anyhow!("invalid nonce aggregate public key: {e}"))?;
        let mut nonce = [0u8; 66];
        nonce.copy_from_slice(nonce_bytes);
        result.push((participant_pk, agg_pk, nonce));
    }
    Ok(result)
}

// ===== MuSig2 partial signatures (BIP-373) =====

pub fn add_input_musig2_partial_sig(
    input: &mut Input,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    sig: [u8; 32],
) {
    input
        .musig2_partial_sigs
        .insert(compound_key(participant_pk, agg_pk), sig.to_vec());
}

pub fn get_input_musig2_partial_sigs(
    input: &Input,
) -> Result<Vec<(PublicKey, PublicKey, [u8; 32])>> {
    let mut result = Vec::new();
    for (compound, sig_bytes) in &input.musig2_partial_sigs {
        if compound.len() != 66 || sig_bytes.len() != 32 {
            bail!(
                "invalid MuSig2 partial signature field lengths: key={}, value={}",
                compound.len(),
                sig_bytes.len()
            );
        }
        let participant_pk = PublicKey::from_slice(&compound[..33])
            .map_err(|e| anyhow!("invalid signature participant public key: {e}"))?;
        let agg_pk = PublicKey::from_slice(&compound[33..])
            .map_err(|e| anyhow!("invalid signature aggregate public key: {e}"))?;
        let mut sig = [0u8; 32];
        sig.copy_from_slice(sig_bytes);
        result.push((participant_pk, agg_pk, sig));
    }
    Ok(result)
}

fn compound_key(participant_pk: &PublicKey, agg_pk: &PublicKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(66);
    k.extend_from_slice(&participant_pk.serialize());
    k.extend_from_slice(&agg_pk.serialize());
    k
}

// ===== Partial ECDH shares (proposed 0x21 / 0x22) =====

pub fn add_input_partial_ecdh_share(input: &mut Input, partial: &PartialEcdhShareData) {
    // Compound key: scan_key (33B) || contributor_pk (33B)
    let mut compound = Vec::with_capacity(66);
    compound.extend_from_slice(&partial.scan_key.serialize());
    compound.extend_from_slice(&partial.contributor_pk.serialize());

    input.unknowns.insert(
        Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE,
            key: compound.clone(),
        },
        partial.share.serialize().to_vec(),
    );
    input.unknowns.insert(
        Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_DLEQ,
            key: compound,
        },
        partial.dleq_proof.0.to_vec(),
    );
}

pub fn get_input_partial_ecdh_shares(input: &Input) -> Result<Vec<PartialEcdhShareData>> {
    let mut result = Vec::new();
    for (key, value) in &input.unknowns {
        if key.type_value != PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE {
            continue;
        }
        if key.key.len() != 66 || value.len() != 33 {
            bail!(
                "invalid MuSig2 partial ECDH field lengths: key={}, value={}",
                key.key.len(),
                value.len()
            );
        }
        let scan_key = PublicKey::from_slice(&key.key[..33])
            .map_err(|e| anyhow!("invalid partial ECDH scan key: {e}"))?;
        let contributor_pk = PublicKey::from_slice(&key.key[33..])
            .map_err(|e| anyhow!("invalid partial ECDH contributor key: {e}"))?;
        let share =
            PublicKey::from_slice(value).map_err(|e| anyhow!("invalid partial ECDH share: {e}"))?;
        let dleq_key = Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_DLEQ,
            key: key.key.clone(),
        };
        let dleq_bytes = input
            .unknowns
            .get(&dleq_key)
            .ok_or_else(|| anyhow!("partial ECDH share is missing its DLEQ proof"))?;
        let arr = <[u8; 64]>::try_from(dleq_bytes.as_slice()).map_err(|_| {
            anyhow!(
                "invalid MuSig2 partial DLEQ proof length: {}",
                dleq_bytes.len()
            )
        })?;
        result.push(PartialEcdhShareData {
            scan_key,
            contributor_pk,
            share,
            dleq_proof: DleqProof(arr),
        });
    }
    for key in input
        .unknowns
        .keys()
        .filter(|key| key.type_value == PSBT_IN_MUSIG2_PARTIAL_DLEQ)
    {
        if key.key.len() != 66 {
            bail!("invalid MuSig2 partial DLEQ key length: {}", key.key.len());
        }
        let share_key = Key {
            type_value: PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE,
            key: key.key.clone(),
        };
        if !input.unknowns.contains_key(&share_key) {
            bail!("orphan MuSig2 partial DLEQ proof");
        }
    }
    Ok(result)
}

// ===== Silent-payment helpers =====

/// Scan/spend keys from an output's `sp_v0_info` (scan(33) || spend(33)).
pub fn get_output_sp_info(output: &Output) -> Result<Option<(PublicKey, PublicKey)>> {
    let Some(bytes) = output.sp_v0_info.as_ref() else {
        return Ok(None);
    };
    let scan_key = PublicKey::from_slice(&bytes[..33])
        .map_err(|e| anyhow!("invalid silent-payment scan key: {e}"))?;
    let spend_key = PublicKey::from_slice(&bytes[33..])
        .map_err(|e| anyhow!("invalid silent-payment spend key: {e}"))?;
    Ok(Some((scan_key, spend_key)))
}

/// BIP-328 derivation path carried on the input's native SP-spend derivation field,
/// if present. The MuSig2 demo defaults to `[0, 0]` when absent.
pub fn get_input_sp_spend_path(input: &Input) -> Option<Vec<u32>> {
    use psbt::roles::Bip375UpdaterExt;
    let (_pubkey, _fingerprint, path) = input.get_sp_spend_bip32_derivation()?;
    Some(path.into_iter().map(|c| u32::from(*c)).collect())
}

/// BIP-352 outpoint bytes: `txid (internal byte order, 32) || vout (LE, 4)`.
pub fn input_outpoint_bytes(input: &Input) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&input.previous_txid[..]);
    out[32..].copy_from_slice(&input.spent_output_index.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use secp256k1::{Secp256k1, SecretKey};

    fn input() -> Input {
        Input::new(&OutPoint::new(Txid::all_zeros(), 0))
    }

    fn public_key(byte: u8) -> PublicKey {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).expect("valid test key"),
        )
    }

    #[test]
    fn rejects_malformed_nonce_lengths() {
        let mut input = input();
        input.musig2_pub_nonces.insert(vec![1; 65], vec![2; 66]);
        assert!(get_input_musig2_pub_nonces(&input).is_err());
    }

    #[test]
    fn rejects_duplicate_participants() {
        let mut input = input();
        let aggregate = public_key(1);
        let participant = public_key(2);
        set_input_musig2_participant_pubkeys(&mut input, &aggregate, &[participant, participant]);
        assert!(get_input_musig2_participant_pubkeys(&input).is_err());
    }

    #[test]
    fn rejects_share_without_proof() {
        let mut input = input();
        let scan = public_key(3);
        let contributor = public_key(4);
        let mut compound = scan.serialize().to_vec();
        compound.extend_from_slice(&contributor.serialize());
        input.unknowns.insert(
            Key {
                type_value: PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE,
                key: compound,
            },
            public_key(5).serialize().to_vec(),
        );
        assert!(get_input_partial_ecdh_shares(&input).is_err());
    }

    #[test]
    fn rejects_orphan_proof() {
        let mut input = input();
        let scan = public_key(6);
        let contributor = public_key(7);
        let mut compound = scan.serialize().to_vec();
        compound.extend_from_slice(&contributor.serialize());
        input.unknowns.insert(
            Key {
                type_value: PSBT_IN_MUSIG2_PARTIAL_DLEQ,
                key: compound,
            },
            vec![0; 64],
        );
        assert!(get_input_partial_ecdh_shares(&input).is_err());
    }
}
