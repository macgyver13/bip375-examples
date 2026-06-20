//! MuSig2 key aggregation (BIP-327) and BIP-328 synthetic derivation.
//!
//! Ported from the old `spdk-core::psbt::crypto::musig2` module (revision
//! `slznmzkv`, `musig2-feature` branch) — the new standalone `psbt` crate dropped
//! this functionality. UPSTREAM CANDIDATE.
//!
//! # Byte Boundary Note
//!
//! The `musig2` crate pins `secp256k1 = "0.31"` while the rest of the workspace
//! uses `secp256k1 = "0.29"`. The types are incompatible at the Rust level, so all
//! key material crosses the version boundary via serialized bytes. The conversion
//! helpers are isolated here.
//! TODO: Remove the conversion shims once the workspace upgrades to secp256k1 0.31+.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use musig2::KeyAggContext;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// BIP-328 synthetic-account root chaincode for MuSig2 derivation.
const BIP328_SYNTHETIC_CHAINCODE_HEX: &str =
    "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965";

// ===== Key Aggregation =====

/// Build a MuSig2 key aggregation context from ordered participant public keys.
///
/// Participants are aggregated in the order given; callers must use a consistent
/// order between signing and share synthesis so both derive the same aggregate key.
pub fn build_key_agg_ctx(participants: &[PublicKey]) -> Result<KeyAggContext> {
    // BIP-327 KeySort: aggregate over participants sorted by their 33-byte
    // compressed serialization. The PSBT stores participant keys in plain order,
    // so the aggregator must sort to reproduce the same aggregate key the wallet
    // committed to.
    let mut sorted = participants.to_vec();
    sorted.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

    let points: Vec<musig2::secp256k1::PublicKey> = sorted
        .iter()
        .map(to_musig2_pubkey)
        .collect::<Result<_>>()?;

    KeyAggContext::new(points).map_err(|e| anyhow!("key aggregation failed: {e}"))
}

/// Build the fully tweaked aggregation context for a silent-payment MuSig2 input.
///
/// Applies the BIP-328 plain tweaks derived from `path` and the unspendable
/// taproot tweak, returning the context together with `gacc`: the parity of the
/// aggregate pubkey after the plain tweaks but before the taproot tweak.
pub fn build_tweaked_key_agg_ctx(
    secp: &Secp256k1<secp256k1::All>,
    participants: &[PublicKey],
    path: &[u32],
) -> Result<(KeyAggContext, i8)> {
    let mut ctx = build_key_agg_ctx(participants)?;

    // Apply BIP-328 plain tweaks derived from the synthetic root and PSBT path.
    let base_pk = from_musig2_pubkey(&ctx.aggregated_pubkey())?;
    for tweak in derive_bip328_plain_tweaks(secp, &base_pk, path)? {
        let musig_scalar = musig2::secp256k1::Scalar::from_be_bytes(tweak)
            .map_err(|e| anyhow!("invalid musig tweak scalar: {e}"))?;
        ctx = ctx
            .with_plain_tweak(musig_scalar)
            .map_err(|e| anyhow!("plain tweak failed: {e}"))?;
    }

    let gacc = pubkey_parity(&from_musig2_pubkey(&ctx.aggregated_pubkey())?);

    ctx = ctx
        .with_unspendable_taproot_tweak()
        .map_err(|e| anyhow!("taproot tweak failed: {e}"))?;

    Ok((ctx, gacc))
}

// ===== Partial ECDH Share Aggregation (BIP-327) =====

/// Combine per-participant partial ECDH shares into the aggregate-key ECDH share.
///
/// Each contributor's share is weighted by its BIP-327 key coefficient, the sum is
/// adjusted for the aggregate-key parity, and the accumulated tweak term
/// `(g2 * tacc) * scan_key` is added. `participants` is the ordered MuSig2 key set,
/// `path` the BIP-328 derivation path (from the synthetic root), and `contributions`
/// the `(contributor_pubkey, partial_share)` pairs for the given `scan_key`.
pub fn aggregate_partial_ecdh_shares(
    secp: &Secp256k1<secp256k1::All>,
    participants: &[PublicKey],
    path: &[u32],
    scan_key: &PublicKey,
    contributions: &[(PublicKey, PublicKey)],
) -> Result<PublicKey> {
    if contributions.is_empty() {
        return Err(anyhow!("no partial shares to aggregate"));
    }

    let (ctx, gacc) = build_tweaked_key_agg_ctx(secp, participants, path)?;

    // Parity after the taproot tweak (g2), combined with the pre-taproot parity (gacc).
    let g2 = pubkey_parity(&from_musig2_pubkey(&ctx.aggregated_pubkey())?);
    let c = g2 * gacc;

    let tacc_bytes: [u8; 32] = match ctx.tweak_sum::<musig2::secp::Scalar>() {
        Some(t) => t.into(),
        None => [0u8; 32],
    };

    // Weight each contributor's share by its key coefficient and sum the terms.
    let mut sum: Option<PublicKey> = None;
    for (contributor_pk, share) in contributions {
        let coeff = key_coefficient(&ctx, contributor_pk)?;
        let term = share.mul_tweak(secp, &coeff)?;
        sum = Some(match sum {
            None => term,
            Some(acc) => acc.combine(&term)?,
        });
    }
    let sum = sum.expect("contributions checked non-empty");

    // Apply the parity adjustment c = g2 * gacc.
    let sum_c = if c == 1 { sum } else { negate_pubkey(sum) };

    // Add the (g2 * tacc) * scan_key term when a tweak has accumulated.
    if tacc_bytes == [0u8; 32] {
        return Ok(sum_c);
    }

    let g2_tacc = {
        let sk = SecretKey::from_slice(&tacc_bytes)?;
        if g2 == -1 {
            sk.negate()
        } else {
            sk
        }
    };
    let g2_tacc_scalar = Scalar::from_be_bytes(g2_tacc.secret_bytes())
        .map_err(|e| anyhow!("invalid tacc scalar: {e}"))?;
    let tacc_term = scan_key.mul_tweak(secp, &g2_tacc_scalar)?;

    Ok(sum_c.combine(&tacc_term)?)
}

// ===== Internal Helpers =====

/// Derive BIP-328 plain tweaks by walking `path` from the synthetic-root chaincode.
fn derive_bip328_plain_tweaks(
    secp: &Secp256k1<secp256k1::All>,
    base_pk: &PublicKey,
    path: &[u32],
) -> Result<Vec<[u8; 32]>> {
    let mut chaincode = hex::decode(BIP328_SYNTHETIC_CHAINCODE_HEX)
        .map_err(|e| anyhow!("invalid synthetic chaincode: {e}"))?;
    let mut current_pk = *base_pk;
    let mut tweaks = Vec::with_capacity(path.len());

    for index in path {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&current_pk.serialize());
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chaincode)
            .map_err(|e| anyhow!("HMAC init failed: {e}"))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[0..32].try_into().expect("slice is 32 bytes");
        let ir: [u8; 32] = result[32..64].try_into().expect("slice is 32 bytes");

        let scalar =
            Scalar::from_be_bytes(il).map_err(|e| anyhow!("invalid derivation scalar: {e}"))?;
        current_pk = current_pk.add_exp_tweak(secp, &scalar)?;

        tweaks.push(il);
        chaincode = ir.to_vec();
    }

    Ok(tweaks)
}

/// BIP-327 key coefficient for `contributor`, as a workspace (0.29) scalar.
fn key_coefficient(ctx: &KeyAggContext, contributor: &PublicKey) -> Result<Scalar> {
    let musig_contributor = to_musig2_pubkey(contributor)?;
    let coeff = ctx
        .key_coefficient(musig_contributor)
        .ok_or_else(|| anyhow!("missing key coefficient for contributor"))?;

    let coeff_bytes: [u8; 32] = match coeff {
        musig2::secp::MaybeScalar::Valid(scalar) => scalar.into(),
        musig2::secp::MaybeScalar::Zero => [0u8; 32],
    };
    Scalar::from_be_bytes(coeff_bytes).map_err(|e| anyhow!("invalid coefficient scalar: {e}"))
}

/// Parity sign of a public key: +1 for an even Y, -1 for an odd Y.
fn pubkey_parity(pk: &PublicKey) -> i8 {
    if pk.serialize()[0] == 0x02 {
        1
    } else {
        -1
    }
}

/// Negate a public key by flipping its parity byte.
fn negate_pubkey(pk: PublicKey) -> PublicKey {
    let mut bytes = pk.serialize();
    bytes[0] = if bytes[0] == 0x02 { 0x03 } else { 0x02 };
    PublicKey::from_slice(&bytes).expect("flipping parity yields a valid point")
}

// ===== Byte-Boundary Conversions (secp256k1 0.29 <-> musig2 0.31) =====

pub(crate) fn to_musig2_pubkey(pk: &PublicKey) -> Result<musig2::secp256k1::PublicKey> {
    musig2::secp256k1::PublicKey::from_slice(&pk.serialize())
        .map_err(|e| anyhow!("pubkey 0.29->0.31 conversion failed: {e}"))
}

pub(crate) fn from_musig2_pubkey(pk: &musig2::secp256k1::PublicKey) -> Result<PublicKey> {
    PublicKey::from_slice(&pk.serialize()).map_err(|e| anyhow!("pubkey 0.31->0.29: {e}"))
}

pub(crate) fn from_musig2_xonly(
    xonly: &musig2::secp256k1::XOnlyPublicKey,
) -> Result<secp256k1::XOnlyPublicKey> {
    secp256k1::XOnlyPublicKey::from_slice(&xonly.serialize())
        .map_err(|e| anyhow!("xonly 0.31->0.29: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    /// The ECDH point a contributor publishes: `sk * scan_key`.
    fn ecdh_point(secp: &Secp256k1<secp256k1::All>, sk: &SecretKey, scan_key: &PublicKey) -> PublicKey {
        let scalar = Scalar::from_be_bytes(sk.secret_bytes()).unwrap();
        scan_key.mul_tweak(secp, &scalar).unwrap()
    }

    /// Two MuSig2 participants each publish `sk_i * scan_key`; the synthesized
    /// aggregate share must equal `t * scan_key`, where `t` is the effective
    /// taproot output secret for the tweaked aggregate key (even-Y).
    ///
    /// Oracle: `musig2::aggregated_seckey` computes `t` from the participant secret
    /// keys via an independent (scalar-side) path from our point-side summation.
    #[test]
    fn musig2_partial_shares_aggregate_to_output_secret() {
        let secp = Secp256k1::new();
        let path = vec![0u32, 0u32];

        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let s1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let s2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let p1 = PublicKey::from_secret_key(&secp, &s1);
        let p2 = PublicKey::from_secret_key(&secp, &s2);
        let share1 = ecdh_point(&secp, &s1, &scan_key);
        let share2 = ecdh_point(&secp, &s2, &scan_key);

        // Oracle: effective output secret `t` for the even-Y taproot key. The ctx
        // applies BIP-327 KeySort, so the seckeys handed to `aggregated_seckey` must
        // be ordered the same way (by compressed pubkey).
        let (ctx, _gacc) = build_tweaked_key_agg_ctx(&secp, &[p1, p2], &path).unwrap();
        let mut pairs = [(s1, p1), (s2, p2)];
        pairs.sort_by(|a, b| a.1.serialize().cmp(&b.1.serialize()));
        let seckeys = [
            musig2::secp::Scalar::from_slice(&pairs[0].0.secret_bytes()).unwrap(),
            musig2::secp::Scalar::from_slice(&pairs[1].0.secret_bytes()).unwrap(),
        ];
        let d: musig2::secp::Scalar = ctx.aggregated_seckey(seckeys).unwrap();
        let d_bytes: [u8; 32] = d.into();
        let d_sk = SecretKey::from_slice(&d_bytes).unwrap();
        let q: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
        let q_even = q.serialize()[0] == 0x02;
        let t_sk = if q_even { d_sk } else { d_sk.negate() };
        let t_scalar = Scalar::from_be_bytes(t_sk.secret_bytes()).unwrap();
        let expected = scan_key.mul_tweak(&secp, &t_scalar).unwrap();

        let got = aggregate_partial_ecdh_shares(
            &secp,
            &[p1, p2],
            &path,
            &scan_key,
            &[(p1, share1), (p2, share2)],
        )
        .unwrap();

        assert_eq!(got, expected, "synthesized share must equal t * scan_key");

        let plain_sum = share1.combine(&share2).unwrap();
        assert_ne!(got, plain_sum, "expected BIP-327 weighting, not a plain sum");
    }
}
