//! FROST signer/coordinator roles over PSBTv2.
//!
//! Cryptographic operations remain in `frost-secp256k1-tr`; this module only
//! validates round state and moves public commitments/signature shares through
//! the local PSBT extension.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use frost::keys::Tweak;
use frost_secp256k1_tr as frost;
use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar as KScalar};
use psbt::Psbt;
use psbt_v2::{Input, Output, PartialEcdhShareData};
use rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::frost_psbt::{Configuration, FrostInputExt, FrostOutputExt};

/// Construct the base BIP-375 PSBT while the generic upstream builder remains
/// under its historical `musig2` module name.
pub fn build_psbt(inputs: Vec<bitcoin::OutPoint>, outputs: Vec<Output>) -> Result<Psbt> {
    psbt::musig2::build_psbt(inputs, outputs)
}

/// Secret, single-use state returned to a signer in round one.
///
/// Consuming this value in [`sign`] prevents accidental nonce reuse through
/// the normal API.
pub struct Round1Secret {
    identifier: frost::Identifier,
    nonces: frost::round1::SigningNonces,
}

pub fn configure_input(
    input: &mut Input,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    let min_signers = public_key_package
        .min_signers()
        .ok_or_else(|| anyhow!("FROST public key package is missing its threshold"))?;
    let configuration = Configuration {
        min_signers,
        max_signers: public_key_package.max_signers(),
        group_verifying_key: public_key_package
            .verifying_key()
            .serialize()
            .context("serialize FROST group verifying key")?,
    };
    input
        .set_frost_configuration(&configuration)
        .context("set FROST PSBT configuration")?;
    for (identifier, verifying_share) in public_key_package.verifying_shares() {
        input
            .add_frost_verifying_share(
                &identifier.serialize(),
                &verifying_share
                    .serialize()
                    .context("serialize FROST verifying share")?,
            )
            .context("add FROST verifying share")?;
    }
    Ok(())
}

/// Generate and publish one signer's round-one commitment.
pub fn commit<R: RngCore + CryptoRng>(
    input: &mut Input,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
    rng: &mut R,
) -> Result<Round1Secret> {
    validate_key_package(input, key_package, public_key_package)?;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
    let identifier = *key_package.identifier();
    input
        .add_frost_commitment(
            &identifier.serialize(),
            &commitments
                .serialize()
                .context("serialize FROST signing commitments")?,
        )
        .context("add FROST signing commitment")?;
    Ok(Round1Secret { identifier, nonces })
}

/// Build the coordinator package once a threshold of commitments is present.
pub fn signing_package(
    input: &Input,
    message: &[u8],
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<frost::SigningPackage> {
    validate_public_key_package(input, public_key_package)?;
    let configuration = input
        .frost_configuration()
        .context("parse FROST PSBT configuration")?
        .ok_or_else(|| anyhow!("missing FROST PSBT configuration"))?;
    let commitments = parse_commitments(input)?;
    if commitments.len() < usize::from(configuration.min_signers) {
        bail!(
            "insufficient FROST commitments: got {}, need {}",
            commitments.len(),
            configuration.min_signers
        );
    }
    if commitments.len() > usize::from(configuration.max_signers) {
        bail!(
            "too many FROST commitments: got {}, maximum {}",
            commitments.len(),
            configuration.max_signers
        );
    }
    for identifier in commitments.keys() {
        if !public_key_package
            .verifying_shares()
            .contains_key(identifier)
        {
            bail!("FROST commitment supplied by an unknown participant");
        }
    }
    Ok(frost::SigningPackage::new(commitments, message))
}

/// Consume the signer's round-one secret and publish its signature share.
pub fn sign(
    input: &mut Input,
    signing_package: &frost::SigningPackage,
    round1_secret: Round1Secret,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    validate_key_package(input, key_package, public_key_package)?;
    if round1_secret.identifier != *key_package.identifier() {
        bail!("round-one nonce belongs to a different FROST participant");
    }
    let expected = signing_package
        .signing_commitment(key_package.identifier())
        .ok_or_else(|| anyhow!("signer was not selected in the FROST signing package"))?;
    let actual = frost::round1::SigningCommitments::from(&round1_secret.nonces);
    if actual != expected {
        bail!("round-one nonce does not match the published FROST commitment");
    }
    let share =
        frost::round2::sign_with_tweak(signing_package, &round1_secret.nonces, key_package, None)
            .context("create FROST signature share")?;
    input
        .add_frost_signature_share(&round1_secret.identifier.serialize(), &share.serialize())
        .context("add FROST signature share")
}

/// Verify and aggregate all selected signature shares into a Taproot signature.
pub fn aggregate(
    input: &Input,
    signing_package: &frost::SigningPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature> {
    validate_public_key_package(input, public_key_package)?;
    let encoded_shares = input
        .frost_signature_shares()
        .context("parse FROST signature shares")?;
    let mut shares = BTreeMap::new();
    for (identifier_bytes, share_bytes) in encoded_shares {
        let identifier = frost::Identifier::deserialize(&identifier_bytes)
            .context("deserialize FROST signature-share identifier")?;
        if signing_package.signing_commitment(&identifier).is_none() {
            bail!("signature share supplied by an unselected FROST participant");
        }
        let share = frost::round2::SignatureShare::deserialize(&share_bytes)
            .context("deserialize FROST signature share")?;
        shares.insert(identifier, share);
    }
    if shares.len() != signing_package.signing_commitments().len() {
        bail!(
            "incomplete FROST signature shares: got {}, expected {}",
            shares.len(),
            signing_package.signing_commitments().len()
        );
    }
    frost::aggregate_with_tweak(signing_package, &shares, public_key_package, None)
        .context("aggregate FROST signature")
}

/// Add the BIP-375 ECDH share for one selected FROST participant.
///
/// The existing proposed `PSBT_IN_SP_PARTIAL_ECDH_SHARE` and
/// `PSBT_IN_SP_PARTIAL_DLEQ` fields are intentionally reused until their
/// names are generalized upstream.
pub fn add_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    input: &mut Input,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
    scan_key: &PublicKey,
    aux_rand: [u8; 32],
) -> Result<()> {
    validate_key_package(input, key_package, public_key_package)?;
    let tweaked = key_package.clone().tweak::<&[u8]>(None);
    let secret = SecretKey::from_slice(&tweaked.signing_share().serialize())
        .context("convert FROST signing share to secp256k1")?;
    let contributor_pk = PublicKey::from_slice(
        &tweaked
            .verifying_share()
            .serialize()
            .context("serialize FROST verifying share")?,
    )
    .context("convert FROST verifying share to secp256k1")?;
    //FIXME: is the the correct guard or should this be handled elsewhere?
    if input
        .parse_sp_partial_ecdh_shares()
        .context("parse existing FROST partial ECDH shares")?
        .iter()
        .any(|partial| partial.scan_key == *scan_key && partial.contributor_pk == contributor_pk)
    {
        bail!("duplicate FROST partial ECDH contribution");
    }
    let share = scan_key
        .mul_tweak(secp, &Scalar::from(secret))
        .context("compute FROST partial ECDH share")?;
    let proof = psbt::generate_dleq_proof(secp, &secret, scan_key, &aux_rand, None)
        .context("generate FROST partial ECDH DLEQ proof")?;
    input.add_sp_partial_ecdh_share(&PartialEcdhShareData {
        scan_key: *scan_key,
        contributor_pk,
        share,
        dleq_proof: psbt::core::utils::to_psbt_dleq(proof),
    });
    Ok(())
}

/// Verify selected participants' DLEQ proofs and materialize Silent Payment outputs.
pub fn finalize_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    if psbt.inputs.len() != 1 {
        bail!("frost-signer currently requires exactly one eligible input");
    }
    validate_public_key_package(&psbt.inputs[0], public_key_package)?;
    let commitments = parse_commitments(&psbt.inputs[0])?;
    let configuration = psbt.inputs[0]
        .frost_configuration()?
        .ok_or_else(|| anyhow!("missing FROST PSBT configuration"))?;
    if commitments.len() < usize::from(configuration.min_signers) {
        bail!("insufficient selected FROST participants for ECDH aggregation");
    }

    let tweaked_public = public_key_package.clone().tweak::<&[u8]>(None);
    let mut selected = BTreeMap::new();
    for identifier in commitments.keys() {
        let verifying_share = tweaked_public
            .verifying_shares()
            .get(identifier)
            .ok_or_else(|| anyhow!("selected FROST identifier is not in the public key package"))?;
        let public_key = PublicKey::from_slice(
            &verifying_share
                .serialize()
                .context("serialize selected FROST verifying share")?,
        )
        .context("convert selected FROST verifying share")?;
        selected.insert(*identifier, public_key);
    }

    let contributions = psbt.inputs[0]
        .parse_sp_partial_ecdh_shares()
        .context("parse FROST partial ECDH shares")?;
    let mut by_scan: BTreeMap<[u8; 33], BTreeMap<frost::Identifier, PublicKey>> = BTreeMap::new();
    for contribution in contributions {
        let identifier = selected
            .iter()
            .find_map(|(identifier, pk)| {
                (*pk == contribution.contributor_pk).then_some(*identifier)
            })
            .ok_or_else(|| anyhow!("ECDH share belongs to an unselected FROST participant"))?;
        let proof = psbt::core::utils::to_rust_dleq(contribution.dleq_proof);
        let valid = psbt::verify_dleq_proof(
            secp,
            &contribution.contributor_pk,
            &contribution.scan_key,
            &contribution.share,
            &proof,
            None,
        )
        .context("verify FROST partial ECDH DLEQ proof")?;
        if !valid {
            bail!("invalid FROST partial ECDH DLEQ proof");
        }
        if by_scan
            .entry(contribution.scan_key.serialize())
            .or_default()
            .insert(identifier, contribution.share)
            .is_some()
        {
            bail!("duplicate FROST partial ECDH contribution");
        }
    }

    let expected_identifiers: Vec<_> = selected.keys().copied().collect();
    let output_key = PublicKey::from_slice(
        &tweaked_public
            .verifying_key()
            .serialize()
            .context("serialize tweaked FROST group key")?,
    )
    .context("convert tweaked FROST group key")?;
    let (output_xonly, output_parity) = output_key.x_only_public_key();
    let canonical_output_key =
        PublicKey::from_x_only_public_key(output_xonly, secp256k1::Parity::Even);
    let input_hash = input_hash(&psbt.inputs[0].outpoint_bytes(), &canonical_output_key)?;
    let input_scalar = Scalar::from_be_bytes(input_hash)
        .map_err(|_| anyhow!("BIP-352 input hash is not a valid scalar"))?;

    let mut output_indices = BTreeMap::<[u8; 33], u32>::new();
    for output in &mut psbt.outputs {
        let Some(info) = output.sp_v0_info else {
            continue;
        };
        let scan_key = PublicKey::from_slice(&info[..33]).context("parse SP scan key")?;
        let spend_key = PublicKey::from_slice(&info[33..]).context("parse SP spend key")?;
        let shares = by_scan
            .get(&scan_key.serialize())
            .ok_or_else(|| anyhow!("missing FROST ECDH shares for Silent Payment output"))?;
        if shares.keys().copied().collect::<Vec<_>>() != expected_identifiers {
            bail!("incomplete FROST ECDH signer set for Silent Payment output");
        }
        let mut aggregate = interpolate_ecdh_shares(shares)?;
        if output_parity == secp256k1::Parity::Odd {
            aggregate = aggregate.negate(secp);
        }
        let aggregate = aggregate
            .mul_tweak(secp, &input_scalar)
            .context("apply BIP-352 input hash to aggregate ECDH share")?;
        let index = output_indices.entry(scan_key.serialize()).or_default();
        let output_pubkey = derive_silent_payment_output(secp, &spend_key, &aggregate, *index)?;
        let (xonly, _) = output_pubkey.x_only_public_key();
        output.script_pubkey = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );
        *index += 1;
    }
    psbt.global.tx_modifiable_flags = 0;
    Ok(())
}

/// Re-derive every Silent Payment output and reject coordinator tampering.
pub fn verify_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    let expected: Vec<_> = psbt
        .outputs
        .iter()
        .map(|output| output.script_pubkey.clone())
        .collect();
    let mut derived = psbt.clone();
    finalize_sp_outputs(secp, &mut derived, public_key_package)?;
    for (index, (expected, actual)) in expected
        .iter()
        .zip(derived.outputs.iter().map(|output| &output.script_pubkey))
        .enumerate()
    {
        if expected != actual {
            bail!("Silent Payment output {index} does not match the verified FROST ECDH shares");
        }
    }
    Ok(())
}

/// Validate any FROST participant-share output tags against the known group.
///
/// The tag is advisory: outputs without it are ignored. When present, it must
/// match the coordinator's `PublicKeyPackage`, so a change output mislabeled
/// with a foreign participant set is rejected before any share is produced.
pub fn verify_participant_tags(
    psbt: &Psbt,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    let expected_group = public_key_package
        .verifying_key()
        .serialize()
        .context("serialize FROST group verifying key")?;
    let mut expected_shares = public_key_package
        .verifying_shares()
        .values()
        .map(|share| share.serialize().context("serialize FROST verifying share"))
        .collect::<Result<Vec<_>>>()?;
    expected_shares.sort_unstable();

    for output in &psbt.outputs {
        let Some((group, mut shares)) = output
            .frost_participant_shares()
            .context("parse FROST participant-share tag")?
        else {
            continue;
        };
        shares.sort_unstable();
        if group != expected_group || shares != expected_shares {
            bail!("FROST participant-share tag does not match the known group");
        }
    }
    Ok(())
}

fn interpolate_ecdh_shares(shares: &BTreeMap<frost::Identifier, PublicKey>) -> Result<PublicKey> {
    let secp = Secp256k1::verification_only();
    let identifiers: Vec<_> = shares.keys().copied().collect();
    let mut weighted = Vec::with_capacity(shares.len());
    for (identifier, share) in shares {
        let coefficient = lagrange_coefficient(*identifier, &identifiers)?;
        weighted.push(
            share
                .mul_tweak(&secp, &coefficient)
                .context("weight FROST ECDH share")?,
        );
    }
    PublicKey::combine_keys(&weighted.iter().collect::<Vec<_>>())
        .context("combine weighted FROST ECDH shares")
}

fn lagrange_coefficient(
    identifier: frost::Identifier,
    identifiers: &[frost::Identifier],
) -> Result<Scalar> {
    let x_i = scalar_from_bytes(&identifier.serialize())?;
    let mut numerator = KScalar::ONE;
    let mut denominator = KScalar::ONE;
    for other in identifiers
        .iter()
        .copied()
        .filter(|other| *other != identifier)
    {
        let x_j = scalar_from_bytes(&other.serialize())?;
        numerator *= x_j;
        denominator *= x_j - x_i;
    }
    let inverse = Option::<KScalar>::from(denominator.invert())
        .ok_or_else(|| anyhow!("duplicate FROST identifiers"))?;
    Scalar::from_be_bytes((numerator * inverse).to_bytes().into())
        .map_err(|_| anyhow!("invalid FROST Lagrange coefficient"))
}

fn scalar_from_bytes(bytes: &[u8]) -> Result<KScalar> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid FROST identifier length"))?;
    let field_bytes: FieldBytes = array.into();
    // FROST identifiers are always canonical scalars in [1, n); a non-canonical
    // value indicates corruption and must not be silently reduced.
    Option::<KScalar>::from(KScalar::from_repr(field_bytes))
        .ok_or_else(|| anyhow!("non-canonical FROST identifier scalar"))
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub(crate) fn input_hash(outpoint: &[u8; 36], output_key: &PublicKey) -> Result<[u8; 32]> {
    Ok(tagged_hash(
        b"BIP0352/Inputs",
        &[outpoint, &output_key.serialize()],
    ))
}

pub(crate) fn derive_silent_payment_output(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    shared_secret: &PublicKey,
    index: u32,
) -> Result<PublicKey> {
    let tweak = tagged_hash(
        b"BIP0352/SharedSecret",
        &[&shared_secret.serialize(), &index.to_be_bytes()],
    );
    let tweak = SecretKey::from_slice(&tweak).context("invalid Silent Payment output tweak")?;
    spend_key
        .combine(&PublicKey::from_secret_key(secp, &tweak))
        .context("derive Silent Payment output key")
}

fn parse_commitments(
    input: &Input,
) -> Result<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
    let encoded = input
        .frost_commitments()
        .context("parse FROST signing commitments")?;
    let mut commitments = BTreeMap::new();
    for (identifier_bytes, commitment_bytes) in encoded {
        let identifier = frost::Identifier::deserialize(&identifier_bytes)
            .context("deserialize FROST commitment identifier")?;
        let commitment = frost::round1::SigningCommitments::deserialize(&commitment_bytes)
            .context("deserialize FROST signing commitment")?;
        commitments.insert(identifier, commitment);
    }
    Ok(commitments)
}

fn parse_verifying_shares(
    input: &Input,
) -> Result<BTreeMap<frost::Identifier, frost::keys::VerifyingShare>> {
    let encoded = input
        .frost_verifying_shares()
        .context("parse FROST verifying shares")?;
    let mut verifying_shares = BTreeMap::new();
    for (identifier_bytes, share_bytes) in encoded {
        let identifier = frost::Identifier::deserialize(&identifier_bytes)
            .context("deserialize FROST verifying-share identifier")?;
        let verifying_share = frost::keys::VerifyingShare::deserialize(&share_bytes)
            .context("deserialize FROST verifying share")?;
        verifying_shares.insert(identifier, verifying_share);
    }
    Ok(verifying_shares)
}

fn validate_key_package(
    input: &Input,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    validate_public_key_package(input, public_key_package)?;
    let configuration = input
        .frost_configuration()
        .context("parse FROST PSBT configuration")?
        .ok_or_else(|| anyhow!("missing FROST PSBT configuration"))?;
    let verifying_key = key_package
        .verifying_key()
        .serialize()
        .context("serialize signer FROST verifying key")?;
    if verifying_key != configuration.group_verifying_key {
        bail!("FROST key package does not match the PSBT group verifying key");
    }
    if *key_package.min_signers() != configuration.min_signers {
        bail!("FROST key package threshold does not match the PSBT configuration");
    }
    if public_key_package
        .verifying_shares()
        .get(key_package.identifier())
        != Some(key_package.verifying_share())
    {
        bail!("FROST key package does not match the PSBT verifying-share roster");
    }
    Ok(())
}

fn validate_public_key_package(
    input: &Input,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    let configuration = input
        .frost_configuration()
        .context("parse FROST PSBT configuration")?
        .ok_or_else(|| anyhow!("missing FROST PSBT configuration"))?;
    let verifying_key = public_key_package
        .verifying_key()
        .serialize()
        .context("serialize coordinator FROST verifying key")?;
    let verifying_shares = parse_verifying_shares(input)?;
    if verifying_key != configuration.group_verifying_key
        || public_key_package.min_signers() != Some(configuration.min_signers)
        || public_key_package.max_signers() != configuration.max_signers
        || verifying_shares.len() != usize::from(configuration.max_signers)
        || &verifying_shares != public_key_package.verifying_shares()
    {
        bail!("FROST public key package does not match the PSBT configuration and roster");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_psbt::{
        PSBT_IN_FROST_CONFIGURATION, PSBT_IN_FROST_PARTICIPANT_COMMITMENT,
        PSBT_IN_FROST_VERIFYING_SHARE,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use frost::keys::Tweak;
    use psbt_v2::raw;
    use rand::{rngs::StdRng, SeedableRng};

    fn input() -> Input {
        Input::new(&OutPoint::new(Txid::all_zeros(), 0))
    }

    fn packages() -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        packages_with_seed(7)
    }

    fn packages_with_seed(
        seed: u64,
    ) -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let keys = shares
            .into_iter()
            .map(|(identifier, share)| (identifier, share.try_into().unwrap()))
            .collect();
        (keys, public)
    }

    #[test]
    fn every_two_of_three_subset_signs_in_any_order() {
        let (keys, public) = packages();
        let keys: Vec<_> = keys.values().collect();
        for (case, pair) in [[0, 1], [0, 2], [1, 2]].into_iter().enumerate() {
            let mut input = input();
            configure_input(&mut input, &public).unwrap();
            let mut rng = StdRng::seed_from_u64(8 + case as u64);
            let mut selected = Vec::new();
            for index in pair {
                let key = keys[index];
                selected.push((key, commit(&mut input, key, &public, &mut rng).unwrap()));
            }
            let message = [42 + case as u8; 32];
            let package = signing_package(&input, &message, &public).unwrap();
            for (key, secret) in selected.into_iter().rev() {
                sign(&mut input, &package, secret, key, &public).unwrap();
            }
            let signature = aggregate(&input, &package, &public).unwrap();
            let tweaked = public.clone().tweak::<&[u8]>(None);
            tweaked
                .verifying_key()
                .verify(&message, &signature)
                .unwrap();
        }
    }

    #[test]
    fn rejects_fewer_than_threshold_commitments() {
        let (keys, public) = packages();
        let mut input = input();
        configure_input(&mut input, &public).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        commit(&mut input, keys.values().next().unwrap(), &public, &mut rng).unwrap();
        assert!(signing_package(&input, &[1; 32], &public).is_err());
    }

    #[test]
    fn configure_input_writes_complete_verifying_share_roster() {
        let (_, public) = packages();
        let mut input = input();
        configure_input(&mut input, &public).unwrap();

        let expected = public
            .verifying_shares()
            .iter()
            .map(|(identifier, share)| {
                (identifier.serialize().to_vec(), share.serialize().unwrap())
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(input.frost_verifying_shares().unwrap(), expected);
        assert_eq!(
            parse_verifying_shares(&input).unwrap(),
            *public.verifying_shares()
        );
    }

    #[test]
    fn rejects_incomplete_extra_swapped_and_mismatched_rosters() {
        let (keys, public) = packages();
        let mut configured = input();
        configure_input(&mut configured, &public).unwrap();
        let roster_keys = configured
            .unknowns
            .keys()
            .filter(|key| key.type_value == PSBT_IN_FROST_VERIFYING_SHARE)
            .cloned()
            .collect::<Vec<_>>();

        let mut missing = configured.clone();
        missing.unknowns.remove(&roster_keys[0]);
        assert!(validate_public_key_package(&missing, &public).is_err());

        let (foreign_keys, foreign_public) = packages_with_seed(17);
        let foreign_share = foreign_public
            .verifying_shares()
            .values()
            .next()
            .unwrap()
            .serialize()
            .unwrap();
        let mut extra = configured.clone();
        extra.unknowns.insert(
            raw::Key {
                type_value: PSBT_IN_FROST_VERIFYING_SHARE,
                key: frost::Identifier::try_from(4_u16)
                    .unwrap()
                    .serialize()
                    .to_vec(),
            },
            foreign_share.clone(),
        );
        assert!(validate_public_key_package(&extra, &public).is_err());

        let mut swapped = configured.clone();
        let first = swapped.unknowns[&roster_keys[0]].clone();
        let second = swapped.unknowns[&roster_keys[1]].clone();
        swapped.unknowns.insert(roster_keys[0].clone(), second);
        swapped.unknowns.insert(roster_keys[1].clone(), first);
        assert!(validate_public_key_package(&swapped, &public).is_err());

        let mut substituted = configured.clone();
        substituted
            .unknowns
            .insert(roster_keys[0].clone(), foreign_share);
        assert!(validate_public_key_package(&substituted, &public).is_err());

        let mut malformed = configured.clone();
        malformed
            .unknowns
            .insert(roster_keys[0].clone(), vec![0xff; 33]);
        assert!(validate_public_key_package(&malformed, &public).is_err());

        let mut wrong_max = configured.clone();
        let configuration = wrong_max
            .unknowns
            .iter_mut()
            .find(|(key, _)| key.type_value == PSBT_IN_FROST_CONFIGURATION)
            .unwrap()
            .1;
        configuration[2..4].copy_from_slice(&4_u16.to_be_bytes());
        assert!(validate_public_key_package(&wrong_max, &public).is_err());

        let mut rng = StdRng::seed_from_u64(18);
        let mut mismatched_signer = configured.clone();
        assert!(commit(
            &mut mismatched_signer,
            foreign_keys.values().next().unwrap(),
            &public,
            &mut rng,
        )
        .is_err());
        assert!(mismatched_signer
            .unknowns
            .keys()
            .all(|key| key.type_value != PSBT_IN_FROST_PARTICIPANT_COMMITMENT));

        assert!(commit(
            &mut swapped,
            keys.values().next().unwrap(),
            &public,
            &mut rng,
        )
        .is_err());
        assert!(swapped
            .unknowns
            .keys()
            .all(|key| key.type_value != PSBT_IN_FROST_PARTICIPANT_COMMITMENT));
    }
}
