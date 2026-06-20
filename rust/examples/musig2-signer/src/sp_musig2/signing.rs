//! MuSig2 signer role (BIP-327 + BIP-373) over native psbt-v2 fields.
//!
//! Ported from old `spdk-core::psbt::roles::musig2_signer` (`slznmzkv`), adapted to
//! operate on `psbt_v2::v2::Input` via [`super::psbt_fields`]. UPSTREAM CANDIDATE.
//!
//! # Byte Boundary Note
//! The `musig2` crate pins `secp256k1 = "0.31"`; the workspace uses `0.29`. All key
//! material crosses via serialized bytes (helpers at the bottom of this module).

use anyhow::{anyhow, Result};
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, BinaryEncoding, CompactSignature,
    KeyAggContext, PartialSignature, PubNonce, SecNonce,
};
use psbt_v2::v2::Input;
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

use super::keyagg::{build_key_agg_ctx, from_musig2_xonly};
use super::psbt_fields::{
    add_input_musig2_partial_sig, add_input_musig2_pub_nonce, get_input_musig2_partial_sigs,
    get_input_musig2_pub_nonces,
};

/// Aggregate participant public keys into a MuSig2 context + the tweaked aggregate
/// x-only key (the P2TR internal key).
pub fn aggregate_musig2_keys(participants: &[PublicKey]) -> Result<(KeyAggContext, XOnlyPublicKey)> {
    let key_agg_ctx = build_key_agg_ctx(participants)?;
    let agg_xonly: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
    let xonly = from_musig2_xonly(&agg_xonly)?;
    Ok((key_agg_ctx, xonly))
}

/// Generate a MuSig2 nonce for one participant and write the public nonce to the
/// input. Returns the `SecNonce` — keep it secret and use it exactly once in
/// [`add_musig2_partial_sig`].
pub fn add_musig2_pub_nonce(
    input: &mut Input,
    participant_sk: &SecretKey,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    nonce_seed: [u8; 32],
) -> Result<SecNonce> {
    let musig2_seckey = sk_029_to_musig2_scalar(participant_sk)?;
    let musig2_agg_pk: musig2::secp::Point = pk_029_to_musig2_point(agg_pk)?;

    let sec_nonce = SecNonce::build(nonce_seed)
        .with_seckey(musig2_seckey)
        .with_aggregated_pubkey(musig2_agg_pk)
        .build();

    let pub_nonce: PubNonce = sec_nonce.public_nonce();
    let nonce_arr: [u8; 66] = BinaryEncoding::to_bytes(&pub_nonce);

    add_input_musig2_pub_nonce(input, participant_pk, agg_pk, nonce_arr);
    Ok(sec_nonce)
}

/// Produce a MuSig2 partial signature and write it to the input. Must be called
/// after every participant's nonce is present. Consumes `sec_nonce`.
pub fn add_musig2_partial_sig(
    input: &mut Input,
    participant_sk: &SecretKey,
    participant_pk: &PublicKey,
    agg_pk: &PublicKey,
    sec_nonce: SecNonce,
    key_agg_ctx: &KeyAggContext,
    message: &[u8; 32],
) -> Result<()> {
    let agg_nonce = collect_agg_nonce(input)?;
    let musig2_seckey = sk_029_to_musig2_scalar(participant_sk)?;

    let partial_sig: PartialSignature = sign_partial(
        key_agg_ctx,
        musig2_seckey,
        sec_nonce,
        &agg_nonce,
        message.as_slice(),
    )
    .map_err(|e| anyhow!("partial signing failed: {e}"))?;

    let sig_bytes: [u8; 32] = partial_sig.serialize();
    add_input_musig2_partial_sig(input, participant_pk, agg_pk, sig_bytes);
    Ok(())
}

/// Aggregate all partial signatures into a 64-byte Schnorr signature and write it
/// to `input.tap_key_sig`. Must be called after every partial signature is present.
pub fn aggregate_musig2_sigs(
    input: &mut Input,
    key_agg_ctx: &KeyAggContext,
    message: &[u8; 32],
    _secp: &Secp256k1<secp256k1::All>,
) -> Result<()> {
    let agg_nonce = collect_agg_nonce(input)?;

    let partial_sigs_raw = get_input_musig2_partial_sigs(input);
    if partial_sigs_raw.is_empty() {
        return Err(anyhow!("no MuSig2 partial signatures present"));
    }

    let partial_sigs: Vec<PartialSignature> = partial_sigs_raw
        .iter()
        .map(|(_, _, sig_bytes)| {
            PartialSignature::from_slice(sig_bytes.as_slice())
                .map_err(|e| anyhow!("invalid partial sig: {e}"))
        })
        .collect::<Result<_>>()?;

    let final_sig: CompactSignature =
        aggregate_partial_signatures(key_agg_ctx, &agg_nonce, partial_sigs, message.as_slice())
            .map_err(|e| anyhow!("signature aggregation failed: {e}"))?;

    let musig2_031_sig: musig2::secp256k1::schnorr::Signature = final_sig.into();
    let sig_bytes = musig2_031_sig.to_byte_array();
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("schnorr sig parse: {e}"))?;

    input.tap_key_sig = Some(bitcoin::taproot::Signature {
        signature: schnorr_sig,
        sighash_type: bitcoin::sighash::TapSighashType::Default,
    });
    Ok(())
}

// ===== internal helpers =====

fn collect_agg_nonce(input: &Input) -> Result<AggNonce> {
    let nonces_raw = get_input_musig2_pub_nonces(input);
    if nonces_raw.is_empty() {
        return Err(anyhow!("no MuSig2 nonces present"));
    }
    let pub_nonces: Vec<PubNonce> = nonces_raw
        .iter()
        .map(|(_, _, nonce_bytes)| {
            PubNonce::from_bytes(nonce_bytes.as_slice())
                .map_err(|e| anyhow!("invalid pub nonce: {e}"))
        })
        .collect::<Result<_>>()?;
    Ok(AggNonce::sum(pub_nonces))
}

fn pk_029_to_musig2_point(pk: &PublicKey) -> Result<musig2::secp::Point> {
    musig2::secp::Point::from_slice(&pk.serialize())
        .map_err(|e| anyhow!("pubkey conversion failed: {e}"))
}

fn sk_029_to_musig2_scalar(sk: &SecretKey) -> Result<musig2::secp::Scalar> {
    musig2::secp::Scalar::from_slice(&sk.secret_bytes())
        .map_err(|e| anyhow!("seckey conversion failed: {e}"))
}
