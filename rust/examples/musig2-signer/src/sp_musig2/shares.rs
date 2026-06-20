//! Silent-payment ECDH share aggregation (BIP-352 + MuSig2 partial shares).
//!
//! Ported from old `spdk-core::psbt::core::shares` (`slznmzkv`), adapted to native
//! `psbt_v2::v2` storage and the new `psbt`/`silentpayments` helpers. UPSTREAM CANDIDATE.

use anyhow::{anyhow, Result};
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashMap;

use super::bip352_hash::input_hash_bytes;
use super::keyagg;
use super::psbt_fields::{
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

/// True if the input spends an eligible (BIP-352) script type.
pub fn is_input_eligible(input: &psbt_v2::v2::Input) -> bool {
    match input.funding_utxo() {
        Ok(utxo) => silentpayments::utils::receiving::is_eligible(utxo.script_pubkey.as_bytes()),
        Err(_) => false,
    }
}

/// BIP-352 input public key for an eligible input (taproot output key, P2WPKH key, ...).
fn input_pubkey(input: &psbt_v2::v2::Input) -> Result<PublicKey> {
    psbt::roles::signer::extract_eligible_input_pubkey(input)
        .map_err(|e| anyhow!("extract input pubkey: {e}"))?
        .ok_or_else(|| anyhow!("input is not eligible / missing pubkey fields"))
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
        if let Some((scan_key, _)) = get_output_sp_info(output) {
            if !scan_keys.contains(&scan_key) {
                scan_keys.push(scan_key);
            }
        }
    }

    let synthesized = synthesize_partial_ecdh_shares(psbt, secp)?;

    // Global shares (single-signer path): scan_key -> share.
    let global_shares: HashMap<PublicKey, PublicKey> = psbt
        .global
        .sp_ecdh_shares
        .iter()
        .map(|(scan, share)| (scan.0, share.0))
        .collect();

    let mut result = HashMap::new();

    for scan_key in scan_keys {
        if let Some(&global_share) = global_shares.get(&scan_key) {
            let input_sum = sum_all_eligible_pubkeys(psbt)?;
            result.insert(
                scan_key,
                AggregatedShare {
                    scan_key,
                    aggregated_share: global_share,
                    input_sum,
                },
            );
            continue;
        }

        // Per-input mode: sum shares + pubkeys from contributing inputs.
        let mut agg_share: Option<PublicKey> = None;
        let mut input_sum: Option<PublicKey> = None;

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            let share = synthesized
                .get(&input_idx)
                .and_then(|m| m.get(&scan_key))
                .copied()
                .or_else(|| {
                    input
                        .sp_ecdh_shares
                        .iter()
                        .find(|(scan, _)| scan.0 == scan_key)
                        .map(|(_, share)| share.0)
                });

            let Some(share) = share else { continue };
            if !is_input_eligible(input) {
                continue;
            }

            agg_share = Some(match agg_share {
                None => share,
                Some(existing) => combine_keys(&existing, &share)?,
            });

            if let Ok(pubkey) = input_pubkey(input) {
                input_sum = Some(match input_sum {
                    None => pubkey,
                    Some(existing) => combine_keys(&existing, &pubkey)?,
                });
            }
        }

        if let (Some(agg_share), Some(input_sum)) = (agg_share, input_sum) {
            result.insert(
                scan_key,
                AggregatedShare {
                    scan_key,
                    aggregated_share: agg_share,
                    input_sum,
                },
            );
        }
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

fn sum_all_eligible_pubkeys(psbt: &Psbt) -> Result<PublicKey> {
    let mut sum: Option<PublicKey> = None;
    for input in &psbt.inputs {
        if !is_input_eligible(input) {
            continue;
        }
        if let Ok(pubkey) = input_pubkey(input) {
            sum = Some(match sum {
                None => pubkey,
                Some(existing) => combine_keys(&existing, &pubkey)?,
            });
        }
    }
    sum.ok_or_else(|| anyhow!("no eligible input pubkeys found"))
}

fn combine_keys(a: &PublicKey, b: &PublicKey) -> Result<PublicKey> {
    a.combine(b).map_err(|e| anyhow!("EC point addition failed: {e}"))
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
        let partial_shares = get_input_partial_ecdh_shares(input);
        if partial_shares.is_empty() {
            continue;
        }

        // Group (contributor_pk, share, proof) by scan key.
        let mut by_scan_key: HashMap<PublicKey, Vec<(PublicKey, PublicKey, _)>> = HashMap::new();
        for partial in &partial_shares {
            by_scan_key
                .entry(partial.scan_key)
                .or_default()
                .push((partial.contributor_pk, partial.share, partial.dleq_proof));
        }

        let musig2_info = get_input_musig2_participant_pubkeys(input);
        let has_musig2 = !musig2_info.is_empty();

        for (scan_key, entries) in by_scan_key {
            // Verify each contributor's DLEQ proof against its own partial share.
            for (contributor_pk, share, proof) in &entries {
                let rust_proof = psbt::core::utils::to_rust_dleq(*proof);
                let verified =
                    psbt::verify_dleq_proof(secp, contributor_pk, &scan_key, share, &rust_proof, None)
                        .map_err(|e| anyhow!("DLEQ verify failed on input {input_idx}: {e:?}"))?;
                if !verified {
                    return Err(anyhow!("invalid DLEQ proof on input {input_idx}"));
                }
            }

            let agg_share = if has_musig2 {
                let (_agg_pk, participants) = &musig2_info[0];
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
