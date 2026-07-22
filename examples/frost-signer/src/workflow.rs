//! Pure 2-of-3 FROST + BIP-375 workflow logic.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use frost::keys::Tweak;
use frost_secp256k1_tr as frost;
use psbt::roles::{ExtractorPsbtExt, InputWitnessFinalizerPsbtExt};
use psbt::Psbt;
use psbt_v2::Output;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

use crate::frost_psbt::FrostOutputExt;
use crate::frost_spdk::{self, Round1Secret};

pub const MIN_SIGNERS: u16 = 2;
pub const MAX_SIGNERS: u16 = 3;

pub const PARTIES: [&str; 3] = ["Alice", "Bob", "Charlie"];

/// Static identifier-to-name bindings for this demo.
const PARTY_IDENTIFIERS: [([u8; 32], &str); 3] = [
    ([0x1a; 32], "Alice"),
    ([0x2b; 32], "Bob"),
    ([0x3c; 32], "Charlie"),
];

/// Deterministic fixtures for the example UI.
///
/// Real deployments must provision authenticated `KeyPackage`s through a
/// trusted-dealer or DKG ceremony and keep them on separate signing devices.
pub struct KeySetup {
    pub key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pub party_ids: BTreeMap<&'static str, frost::Identifier>,
    pub public_key_package: frost::keys::PublicKeyPackage,
    pub internal_key: bitcoin::key::XOnlyPublicKey,
    pub output_key: bitcoin::key::XOnlyPublicKey,
    pub p2tr_script: ScriptBuf,
    pub scan_key: PublicKey,
    pub sp_address: SilentPaymentAddress,
}

pub fn setup_keys() -> Result<KeySetup> {
    let mut rng = StdRng::from_seed([0x37; 32]);

    let party_ids = PARTY_IDENTIFIERS
        .iter()
        .map(|&(identifier_bytes, name)| {
            let identifier = frost::Identifier::deserialize(&identifier_bytes)
                .context("parse static FROST identifier")?;
            Ok((name, identifier))
        })
        .collect::<Result<BTreeMap<&'static str, frost::Identifier>>>()?;
    let identifiers: Vec<_> = party_ids.values().copied().collect();

    let (shares, public_key_package) = frost::keys::generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .context("generate deterministic FROST example fixtures")?;
    let key_packages = shares
        .into_iter()
        .map(|(identifier, share)| {
            let key_package = share
                .try_into()
                .context("verify dealer-generated FROST secret share")?;
            Ok((identifier, key_package))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let internal_bytes = public_key_package
        .verifying_key()
        .serialize()
        .context("serialize FROST internal key")?;
    let internal_full =
        PublicKey::from_slice(&internal_bytes).context("parse FROST internal key")?;
    let (internal_key, _) = internal_full.x_only_public_key();

    let tweaked_public = public_key_package.clone().tweak::<&[u8]>(None);
    let output_bytes = tweaked_public
        .verifying_key()
        .serialize()
        .context("serialize tweaked FROST output key")?;
    let output_full = PublicKey::from_slice(&output_bytes).context("parse FROST output key")?;
    let (output_key, _) = output_full.x_only_public_key();
    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key),
    );

    let secp = Secp256k1::new();
    let scan_secret = SecretKey::from_slice(&[0x11; 32])?;
    let spend_secret = SecretKey::from_slice(&[0x22; 32])?;
    let scan_key = PublicKey::from_secret_key(&secp, &scan_secret);
    let spend_key = PublicKey::from_secret_key(&secp, &spend_secret);
    let sp_address =
        SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Mainnet, SpVersion::ZERO);

    Ok(KeySetup {
        key_packages,
        party_ids,
        public_key_package,
        internal_key,
        output_key,
        p2tr_script,
        scan_key,
        sp_address,
    })
}

pub fn construct_psbt(
    keys: &KeySetup,
    recipients: &[(SilentPaymentAddress, Amount)],
) -> Result<Psbt> {
    let total_payment: u64 = recipients.iter().map(|(_, amount)| amount.to_sat()).sum();
    let change_amount = Amount::from_sat(9_000);
    let fee = Amount::from_sat(1_000);
    let input_amount = Amount::from_sat(total_payment) + change_amount + fee;
    let mut outputs: Vec<Output> = recipients
        .iter()
        .map(|(address, amount)| {
            let mut output = Output::new(TxOut {
                value: *amount,
                script_pubkey: ScriptBuf::new(),
            });
            let mut info = [0; 66];
            info[..33].copy_from_slice(&address.get_scan_key().serialize());
            info[33..].copy_from_slice(&address.get_spend_key().serialize());
            output.sp_v0_info = Some(info);
            output
        })
        .collect();
    outputs.push(Output::new(TxOut {
        value: change_amount,
        script_pubkey: keys.p2tr_script.clone(),
    }));

    let fixture_txid = Txid::from_byte_array([1; 32]);
    let mut psbt = frost_spdk::build_psbt(vec![OutPoint::new(fixture_txid, 0)], outputs)?;
    psbt.inputs[0].sequence = Some(Sequence::MAX);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: input_amount,
        script_pubkey: keys.p2tr_script.clone(),
    });
    psbt.inputs[0].tap_internal_key = Some(keys.internal_key);
    frost_spdk::configure_input(&mut psbt.inputs[0], &keys.public_key_package)?;

    // BIP-373 parallel: tag the non-SP change output with the FROST group's
    // participant set to aid change / self-payment detection.
    let group_key = keys
        .public_key_package
        .verifying_key()
        .serialize()
        .context("serialize FROST group verifying key")?;
    let participant_shares = keys
        .public_key_package
        .verifying_shares()
        .values()
        .map(|share| share.serialize().context("serialize FROST verifying share"))
        .collect::<Result<Vec<_>>>()?;
    for output in psbt.outputs.iter_mut() {
        if output.sp_v0_info.is_none() {
            output
                .set_frost_participant_shares(&group_key, &participant_shares)
                .context("tag FROST change output with participant shares")?;
        }
    }
    Ok(psbt)
}

/// Round one for one selected signer: FROST commitment plus ECDH/DLEQ shares.
pub fn contribute<R: RngCore + rand::CryptoRng>(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
    rng: &mut R,
) -> Result<Round1Secret> {
    let scan_keys: Vec<_> = psbt
        .outputs
        .iter()
        .filter_map(|output| output.sp_v0_info.map(|info| info[..33].to_vec()))
        .map(|bytes| PublicKey::from_slice(&bytes).context("parse Silent Payment scan key"))
        .collect::<Result<_>>()?;
    for scan_key in scan_keys {
        let mut aux_rand = [0; 32];
        rng.fill_bytes(&mut aux_rand);
        frost_spdk::add_ecdh_share(
            secp,
            &mut psbt.inputs[0],
            key_package,
            public_key_package,
            &scan_key,
            aux_rand,
        )?;
    }
    frost_spdk::commit(&mut psbt.inputs[0], key_package, public_key_package, rng)
}

pub fn derive_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    frost_spdk::finalize_sp_outputs(secp, psbt, public_key_package)
}

pub fn compute_sighash(psbt: &Psbt) -> Result<[u8; 32]> {
    let utxo = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or_else(|| anyhow!("input 0 missing witness_utxo"))?;
    compute_tap_sighash(&build_unsigned_tx(psbt), 0, &[utxo])
}

pub fn signing_package(
    psbt: &Psbt,
    message: &[u8; 32],
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<frost::SigningPackage> {
    frost_spdk::signing_package(&psbt.inputs[0], message, public_key_package)
}

pub fn partial_sign(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    signing_package: &frost::SigningPackage,
    secret: Round1Secret,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
    expected_recipients: &[SilentPaymentAddress],
) -> Result<()> {
    verify_recipients(psbt, expected_recipients)?;
    frost_spdk::verify_sp_outputs(secp, psbt, public_key_package)?;
    frost_spdk::verify_participant_tags(psbt, public_key_package)?;
    let expected = compute_sighash(psbt)?;
    if signing_package.message() != expected.as_slice() {
        return Err(anyhow!(
            "FROST signing package message does not match the PSBT sighash"
        ));
    }
    frost_spdk::sign(
        &mut psbt.inputs[0],
        signing_package,
        secret,
        key_package,
        public_key_package,
    )
}

/// Confirm every Silent Payment output pays a recipient the signer authorized.
///
/// `verify_sp_outputs` only proves the output scripts are consistent with the
/// `sp_v0_info` inside the PSBT; a malicious coordinator can still swap that
/// address. The signer must independently authenticate the recipient.
fn verify_recipients(psbt: &Psbt, expected_recipients: &[SilentPaymentAddress]) -> Result<()> {
    for output in &psbt.outputs {
        let Some(info) = output.sp_v0_info else {
            continue;
        };
        let matches = expected_recipients.iter().any(|recipient| {
            recipient.get_scan_key().serialize() == info[..33]
                && recipient.get_spend_key().serialize() == info[33..]
        });
        if !matches {
            return Err(anyhow!(
                "Silent Payment output pays an unauthorized recipient"
            ));
        }
    }
    Ok(())
}

pub fn aggregate_and_extract(
    psbt: &mut Psbt,
    signing_package: &frost::SigningPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<Transaction> {
    let signature = frost_spdk::aggregate(&psbt.inputs[0], signing_package, public_key_package)?;
    let bytes = signature
        .serialize()
        .context("serialize aggregate FROST signature")?;
    let schnorr = secp256k1::schnorr::Signature::from_slice(&bytes)
        .context("convert aggregate FROST signature")?;
    psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
        signature: schnorr,
        sighash_type: TapSighashType::Default,
    });
    *psbt = psbt
        .clone()
        .finalize()
        .map_err(|error| anyhow!("finalize witnesses: {error:?}"))?;
    psbt.clone()
        .extract_tx()
        .map_err(|error| anyhow!("extract transaction: {error:?}"))
}

pub fn build_unsigned_tx(psbt: &Psbt) -> Transaction {
    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: psbt
            .inputs
            .iter()
            .map(|input| TxIn {
                previous_output: OutPoint::new(input.previous_txid, input.spent_output_index),
                script_sig: ScriptBuf::new(),
                sequence: input.sequence.unwrap_or(Sequence::MAX),
                witness: Witness::new(),
            })
            .collect(),
        output: psbt
            .outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect(),
    }
}

pub fn compute_tap_sighash(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map(|hash| hash.to_byte_array())
        .context("compute Taproot key-spend sighash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_psbt::{FrostInputExt, FrostOutputExt};
    use secp256k1::Scalar;

    #[test]
    fn uses_static_party_identifiers() {
        let keys = setup_keys().unwrap();

        for (expected_bytes, name) in PARTY_IDENTIFIERS {
            assert_eq!(keys.party_ids[&name].serialize(), expected_bytes);
        }
    }

    #[test]
    fn full_two_of_three_silent_payment_flow() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x42; 32]);
        let secrets: Vec<_> = selected
            .iter()
            .map(|key| {
                contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut rng).unwrap()
            })
            .collect();

        derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package).unwrap();
        assert!(psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap()
            .script_pubkey
            .is_p2tr());
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &keys.public_key_package).unwrap();
        for (key, secret) in selected.into_iter().zip(secrets) {
            partial_sign(
                &secp,
                &mut psbt,
                &package,
                secret,
                key,
                &keys.public_key_package,
                &[keys.sp_address],
            )
            .unwrap();
        }
        let transaction =
            aggregate_and_extract(&mut psbt, &package, &keys.public_key_package).unwrap();
        let signature = secp256k1::schnorr::Signature::from_slice(
            transaction.input[0].witness.iter().next().unwrap(),
        )
        .unwrap();
        secp.verify_schnorr(
            &signature,
            &secp256k1::Message::from_digest(message),
            &keys.output_key,
        )
        .unwrap();
    }

    #[test]
    fn partitioned_flow_via_serialized_psbt() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();

        // Coordinator constructs the PSBT and ships only its serialized bytes.
        let psbt = construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let mut bytes = psbt.serialize();

        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x48; 32]);

        // Each device loads the bytes, runs round one, and keeps its own
        // single-use Round1Secret locally before shipping the bytes onward.
        let mut secrets = Vec::new();
        for key in &selected {
            let mut device_psbt = Psbt::deserialize(&bytes).unwrap();
            let secret =
                contribute(&secp, &mut device_psbt, key, &keys.public_key_package, &mut rng)
                    .unwrap();
            secrets.push(secret);
            bytes = device_psbt.serialize();
        }

        // Coordinator loads the round-one bytes and derives the SP outputs.
        let mut coordinator_psbt = Psbt::deserialize(&bytes).unwrap();
        derive_sp_outputs(&secp, &mut coordinator_psbt, &keys.public_key_package).unwrap();
        bytes = coordinator_psbt.serialize();

        // Each device loads the derived bytes, independently reconstructs the
        // signing package and sighash from the PSBT alone, and signs using only
        // its own Round1Secret and key package.
        for (key, secret) in selected.into_iter().zip(secrets) {
            let mut device_psbt = Psbt::deserialize(&bytes).unwrap();
            let message = compute_sighash(&device_psbt).unwrap();
            let package = signing_package(&device_psbt, &message, &keys.public_key_package).unwrap();
            partial_sign(
                &secp,
                &mut device_psbt,
                &package,
                secret,
                key,
                &keys.public_key_package,
                &[keys.sp_address],
            )
            .unwrap();
            bytes = device_psbt.serialize();
        }

        // Coordinator loads the fully signed bytes, reconstructs the package, and
        // aggregates into a final transaction.
        let mut final_psbt = Psbt::deserialize(&bytes).unwrap();
        let message = compute_sighash(&final_psbt).unwrap();
        let package = signing_package(&final_psbt, &message, &keys.public_key_package).unwrap();
        let transaction =
            aggregate_and_extract(&mut final_psbt, &package, &keys.public_key_package).unwrap();

        let signature = secp256k1::schnorr::Signature::from_slice(
            transaction.input[0].witness.iter().next().unwrap(),
        )
        .unwrap();
        secp.verify_schnorr(
            &signature,
            &secp256k1::Message::from_digest(message),
            &keys.output_key,
        )
        .unwrap();
    }

    #[test]
    fn signer_rejects_tampered_silent_payment_output() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x43; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| {
                contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut rng).unwrap()
            })
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package).unwrap();
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &keys.public_key_package).unwrap();
        let sp_output = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        sp_output.script_pubkey = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(keys.output_key),
        );
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &keys.public_key_package,
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn signer_rejects_mismatched_signing_message() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x45; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| {
                contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut rng).unwrap()
            })
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package).unwrap();
        // A coordinator that binds the FROST session to a different message than
        // the PSBT sighash must be rejected before any share is produced.
        let package = signing_package(&psbt, &[0xab; 32], &keys.public_key_package).unwrap();
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &keys.public_key_package,
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn signer_rejects_swapped_recipient() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        // Coordinator builds the PSBT toward an attacker's address, but the signer
        // only authorized `keys.sp_address`.
        let attacker_scan =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x51; 32]).unwrap());
        let attacker_spend =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x52; 32]).unwrap());
        let attacker = SilentPaymentAddress::new(
            attacker_scan,
            attacker_spend,
            SpNetwork::Mainnet,
            SpVersion::ZERO,
        );
        let mut psbt = construct_psbt(&keys, &[(attacker, Amount::from_sat(90_000))]).unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x46; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| {
                contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut rng).unwrap()
            })
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package).unwrap();
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &keys.public_key_package).unwrap();
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &keys.public_key_package,
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn recipient_recovers_derived_silent_payment_output() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x47; 32]);
        for key in &selected {
            contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut rng).unwrap();
        }
        derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package).unwrap();
        let derived = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap()
            .script_pubkey
            .clone();

        // Independently recompute the output from the recipient's scan secret,
        // proving the threshold ECDH interpolation reconstructs the correct
        // shared secret rather than merely producing some P2TR script.
        let scan_secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32]).unwrap());
        let output_full = PublicKey::from_slice(
            &keys
                .public_key_package
                .clone()
                .tweak::<&[u8]>(None)
                .verifying_key()
                .serialize()
                .unwrap(),
        )
        .unwrap();
        let (output_xonly, _) = output_full.x_only_public_key();
        let canonical_output_key =
            PublicKey::from_x_only_public_key(output_xonly, secp256k1::Parity::Even);
        let input_hash =
            frost_spdk::input_hash(&psbt.inputs[0].outpoint_bytes(), &canonical_output_key)
                .unwrap();
        let input_scalar = Scalar::from_be_bytes(input_hash).unwrap();
        let shared = canonical_output_key
            .mul_tweak(&secp, &Scalar::from(scan_secret))
            .unwrap()
            .mul_tweak(&secp, &input_scalar)
            .unwrap();
        let expected =
            frost_spdk::derive_silent_payment_output(&secp, &spend_key, &shared, 0).unwrap();
        let (expected_xonly, _) = expected.x_only_public_key();
        let expected_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(expected_xonly),
        );
        assert_eq!(derived, expected_script);
    }

    #[test]
    fn frost_fields_survive_psbt_serialization() {
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let mut rng = StdRng::from_seed([0x44; 32]);
        contribute(
            &Secp256k1::new(),
            &mut psbt,
            keys.key_packages.values().next().unwrap(),
            &keys.public_key_package,
            &mut rng,
        )
        .unwrap();
        let encoded = psbt.serialize();
        let decoded = Psbt::deserialize(&encoded).unwrap();
        assert_eq!(
            decoded.inputs[0].frost_configuration().unwrap(),
            psbt.inputs[0].frost_configuration().unwrap()
        );
        assert_eq!(
            decoded.inputs[0].frost_verifying_shares().unwrap(),
            psbt.inputs[0].frost_verifying_shares().unwrap()
        );
        assert_eq!(
            decoded.inputs[0].frost_commitments().unwrap(),
            psbt.inputs[0].frost_commitments().unwrap()
        );
        assert_eq!(
            decoded.inputs[0]
                .parse_sp_partial_ecdh_shares()
                .unwrap()
                .len(),
            1
        );
        // The FROST output tag round-trips through the top-level keytype in
        // `.unknowns`, confirming 0x20 does not collide with a known keytype.
        let change = decoded
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        assert_eq!(
            change.frost_participant_shares().unwrap(),
            psbt.outputs
                .iter()
                .find(|output| output.sp_v0_info.is_none())
                .unwrap()
                .frost_participant_shares()
                .unwrap()
        );
    }

    #[test]
    fn change_output_is_tagged_and_sp_output_is_not() {
        let keys = setup_keys().unwrap();
        let psbt = construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        let sp = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        let change = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        assert!(sp.frost_participant_shares().unwrap().is_none());
        let (group, shares) = change.frost_participant_shares().unwrap().unwrap();
        assert_eq!(
            group,
            keys.public_key_package.verifying_key().serialize().unwrap()
        );
        assert_eq!(shares.len(), keys.public_key_package.verifying_shares().len());
    }

    #[test]
    fn signer_rejects_mislabeled_participant_tag() {
        let keys = setup_keys().unwrap();
        let mut psbt =
            construct_psbt(&keys, &[(keys.sp_address, Amount::from_sat(90_000))]).unwrap();
        // Overwrite the change output's tag with a foreign participant set.
        let change = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        change.unknowns.clear();
        change
            .set_frost_participant_shares(&[2; 33], &[vec![3; 33], vec![4; 33]])
            .unwrap();
        assert!(frost_spdk::verify_participant_tags(&psbt, &keys.public_key_package).is_err());
    }
}
