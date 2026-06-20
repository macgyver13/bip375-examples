//! Silent-payment ECDH share aggregation (BIP-352 + MuSig2 partial shares).
//!
//! Ported from old `spdk-core::psbt::core::shares` (`slznmzkv`), adapted to native
//! `psbt_v2::v2` storage and the new `psbt`/`silentpayments` helpers. UPSTREAM CANDIDATE.

use anyhow::{anyhow, Result};
use secp256k1::{PublicKey, Secp256k1};
use std::collections::{HashMap, HashSet};

use super::finalizer::input_hash_bytes;
use super::keyagg;
use crate::musig2_psbt::{
    get_input_musig2_participant_pubkeys, get_input_partial_ecdh_shares, get_input_sp_spend_path,
    get_output_sp_info, input_outpoint_bytes,
};
use psbt::Psbt;

/// Aggregated ECDH share and input pubkey sum for a single scan key.
#[derive(Debug, Clone)]
pub struct AggregatedShare {
    pub scan_key: PublicKey,
    pub aggregated_share: PublicKey,
    pub input_sum: PublicKey,
}

/// Collection of aggregated shares keyed by scan key.
#[derive(Debug, Clone, Default)]
pub struct AggregatedShares {
    shares: HashMap<PublicKey, AggregatedShare>,
}

impl AggregatedShares {
    pub fn get(&self, scan_key: &PublicKey) -> Option<&AggregatedShare> {
        self.shares.get(scan_key)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &AggregatedShare)> {
        self.shares.iter()
    }
}

/// BIP-352 input public key, or `None` for an ineligible input.
fn input_pubkey(input: &psbt_v2::v2::Input) -> Result<Option<PublicKey>> {
    psbt::roles::signer::extract_eligible_input_pubkey(input)
        .map_err(|e| anyhow!("extract input pubkey: {e}"))
}

/// Collect ECDH shares and input-pubkey sums from a PSBT, grouped by scan key.
///
/// Per-input partial ECDH shares (MuSig2) are synthesized into a single per-input
/// share first (BIP-327 weighting), then summed across inputs along with the
/// eligible input pubkeys.
pub fn aggregate_ecdh_shares(
    psbt: &Psbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<AggregatedShares> {
    if psbt.inputs.is_empty() {
        return Err(anyhow!("cannot aggregate ECDH shares: no inputs"));
    }

    // Discover scan keys from SP outputs.
    let mut scan_keys = Vec::new();
    for output in &psbt.outputs {
        if let Some((scan_key, _)) = get_output_sp_info(output)? {
            if !scan_keys.contains(&scan_key) {
                scan_keys.push(scan_key);
            }
        }
    }

    let synthesized = synthesize_partial_ecdh_shares(psbt, secp)?;

    let mut result = HashMap::new();

    for scan_key in scan_keys {
        // Sum one synthesized MuSig2 share for every eligible input. Ordinary
        // BIP-375 global/per-input shares remain the responsibility of SPDK's
        // `SignerPsbtExt::compute_sp_outputs` and are intentionally not copied here.
        let mut agg_share: Option<PublicKey> = None;
        let mut input_sum: Option<PublicKey> = None;

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            let Some(pubkey) = input_pubkey(input)? else {
                continue;
            };
            let share = synthesized
                .get(&input_idx)
                .and_then(|m| m.get(&scan_key))
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "missing MuSig2 ECDH share for input {input_idx} and scan key {scan_key}"
                    )
                })?;
            agg_share = Some(match agg_share {
                None => share,
                Some(existing) => combine_keys(&existing, &share)?,
            });
            input_sum = Some(match input_sum {
                None => pubkey,
                Some(existing) => combine_keys(&existing, &pubkey)?,
            });
        }

        let aggregated_share = agg_share.ok_or_else(|| anyhow!("no eligible MuSig2 inputs"))?;
        let input_sum = input_sum.ok_or_else(|| anyhow!("no eligible input public keys"))?;
        result.insert(
            scan_key,
            AggregatedShare {
                scan_key,
                aggregated_share,
                input_sum,
            },
        );
    }

    Ok(AggregatedShares { shares: result })
}

/// Compute BIP-352 shared secrets: `shared_secret = aggregated_share * input_hash`
/// where `input_hash = hash_BIP0352/Inputs(smallest_outpoint || input_sum)`.
pub fn compute_sp_shared_secrets(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    aggregated_shares: &AggregatedShares,
) -> Result<HashMap<PublicKey, PublicKey>> {
    let smallest_outpoint: [u8; 36] = psbt
        .inputs
        .iter()
        .map(input_outpoint_bytes)
        .min()
        .ok_or_else(|| anyhow!("no outpoints"))?;

    let mut shared_secrets = HashMap::new();
    for (scan_key, share) in aggregated_shares.iter() {
        let hash_bytes = input_hash_bytes(&smallest_outpoint, &share.input_sum);
        let input_hash = secp256k1::Scalar::from_be_bytes(hash_bytes)
            .map_err(|_| anyhow!("input hash is invalid scalar"))?;
        let shared_secret = share
            .aggregated_share
            .mul_tweak(secp, &input_hash)
            .map_err(|e| anyhow!("failed to multiply ECDH share by input_hash: {e}"))?;
        shared_secrets.insert(*scan_key, shared_secret);
    }

    Ok(shared_secrets)
}

// ===== helpers =====

fn combine_keys(a: &PublicKey, b: &PublicKey) -> Result<PublicKey> {
    a.combine(b)
        .map_err(|e| anyhow!("EC point addition failed: {e}"))
}

/// Synthesize per-input ECDH shares from partial shares (MuSig2).
///
/// For each input with partial shares: verify every contributor's DLEQ proof, then
/// combine the partial shares with the BIP-327 weighting (`aggregate_partial_ecdh_shares`)
/// when MuSig2 participants are registered, else plain EC-sum.
fn synthesize_partial_ecdh_shares(
    psbt: &Psbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<HashMap<usize, HashMap<PublicKey, PublicKey>>> {
    let mut synthesized: HashMap<usize, HashMap<PublicKey, PublicKey>> = HashMap::new();

    for (input_idx, input) in psbt.inputs.iter().enumerate() {
        let partial_shares = get_input_partial_ecdh_shares(input)?;
        if partial_shares.is_empty() {
            continue;
        }

        // Group (contributor_pk, share, proof) by scan key.
        let mut by_scan_key: HashMap<PublicKey, Vec<(PublicKey, PublicKey, _)>> = HashMap::new();
        for partial in &partial_shares {
            by_scan_key.entry(partial.scan_key).or_default().push((
                partial.contributor_pk,
                partial.share,
                partial.dleq_proof,
            ));
        }

        let musig2_info = get_input_musig2_participant_pubkeys(input)?;
        if musig2_info.len() > 1 {
            return Err(anyhow!(
                "input {input_idx} has multiple MuSig2 aggregate key entries"
            ));
        }
        let has_musig2 = !musig2_info.is_empty();

        for (scan_key, entries) in by_scan_key {
            // Verify each contributor's DLEQ proof against its own partial share.
            for (contributor_pk, share, proof) in &entries {
                let rust_proof = psbt::core::utils::to_rust_dleq(*proof);
                let verified = psbt::verify_dleq_proof(
                    secp,
                    contributor_pk,
                    &scan_key,
                    share,
                    &rust_proof,
                    None,
                )
                .map_err(|e| anyhow!("DLEQ verify failed on input {input_idx}: {e:?}"))?;
                if !verified {
                    return Err(anyhow!("invalid DLEQ proof on input {input_idx}"));
                }
            }

            let agg_share = if has_musig2 {
                let (_agg_pk, participants) = &musig2_info[0];
                let expected: HashSet<PublicKey> = participants.iter().copied().collect();
                let actual: HashSet<PublicKey> = entries
                    .iter()
                    .map(|(contributor, _, _)| *contributor)
                    .collect();
                if actual != expected {
                    return Err(anyhow!(
                        "incomplete or unknown MuSig2 contributors on input {input_idx}"
                    ));
                }
                let path = get_input_sp_spend_path(input).unwrap_or_else(|| vec![0, 0]);
                let contributions: Vec<(PublicKey, PublicKey)> =
                    entries.iter().map(|(c, s, _)| (*c, *s)).collect();
                keyagg::aggregate_partial_ecdh_shares(
                    secp,
                    participants,
                    &path,
                    &scan_key,
                    &contributions,
                )?
            } else {
                let mut agg: Option<PublicKey> = None;
                for (_, share, _) in &entries {
                    agg = Some(match agg {
                        None => *share,
                        Some(existing) => combine_keys(&existing, share)?,
                    });
                }
                agg.ok_or_else(|| anyhow!("no shares aggregated"))?
            };

            synthesized
                .entry(input_idx)
                .or_default()
                .insert(scan_key, agg_share);
        }
    }

    Ok(synthesized)
}
