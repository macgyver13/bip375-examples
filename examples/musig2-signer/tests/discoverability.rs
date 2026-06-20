//! End-to-end discoverability: the MuSig2-derived silent-payment outputs must be
//! detectable by each recipient scanning the transaction, using only public scan
//! data (no sender/aggregate secrets). This proves the sender-side BIP-352 output
//! derivation (assembled from DLEQ-proven partial ECDH shares) agrees with the
//! standard `silentpayments` receiver path.

use musig2_signer::musig2_psbt::PSBT_IN_MUSIG2_PARTIAL_DLEQ;
use musig2_signer::recipients::{recipient_keys, RECIPIENT_SEEDS};
use musig2_signer::{recipients, workflow};
use psbt::roles::signer::extract_eligible_input_pubkey;
use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::PublicTweakData;
use silentpayments::utils::OutPoint as SpOutPoint;
use silentpayments::{Network, SpVersion, TransactionInputs, TransactionSharedSecret};

#[test]
fn sp_outputs_discoverable_by_recipients() {
    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp).expect("key setup");
    let recipients = recipients::recipient_addresses().expect("recipient addresses");

    let mut psbt = workflow::construct_psbt(&keys, &recipients).expect("construct");
    // Give the input a realistic non-zero outpoint so the BIP-352 input hash is
    // exercised on both sender and receiver sides.
    psbt.inputs[0].previous_txid =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .parse()
            .expect("txid");

    // Each party contributes one DLEQ-proven partial ECDH share per recipient scan key.
    let parties = [
        ("Alice", keys.alice_sk, keys.alice_pk),
        ("Bob", keys.bob_sk, keys.bob_pk),
        ("Charlie", keys.charlie_sk, keys.charlie_pk),
    ];
    let scan_keys: Vec<PublicKey> = recipients.iter().map(|(a, _)| a.get_scan_key()).collect();
    for (name, sk, pk) in &parties {
        for scan in &scan_keys {
            workflow::add_ecdh_share(&secp, &mut psbt, name, sk, pk, scan).expect("ecdh share");
        }
    }

    // Coordinator derives the SP output scripts from the aggregated shares.
    workflow::derive_sp_output(&secp, &mut psbt).expect("derive sp outputs");

    // ---- Receiver side: rebuild the public tweak data and scan. ----
    let mut tx_inputs = TransactionInputs::with_capacity(psbt.inputs.len());
    for input in &psbt.inputs {
        let outpoint = SpOutPoint::from_txid_and_vout(
            input.previous_txid.to_string(),
            input.spent_output_index,
        )
        .expect("outpoint");
        let spk = input
            .witness_utxo
            .as_ref()
            .map(|u| u.script_pubkey.to_bytes())
            .unwrap_or_default();
        let pubkey = extract_eligible_input_pubkey(input).expect("pubkey");
        tx_inputs.push(outpoint, spk, pubkey);
    }
    let tweak_data = PublicTweakData::new(&secp, &tx_inputs).expect("tweak data");

    let candidates: Vec<XOnlyPublicKey> = psbt
        .outputs
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..34]).expect("xonly"))
        .collect();

    for (idx, (seed, _amount)) in RECIPIENT_SEEDS.iter().enumerate() {
        let (scan_sk, spend_sk) = recipient_keys(seed);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        let receiver = Receiver::new(
            SpVersion::ZERO,
            scan_pk,
            spend_pk,
            Label::new(scan_sk, 0),
            Network::Mainnet,
        )
        .expect("receiver");

        let shared =
            TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &scan_sk)
                .expect("shared secret");
        let found = receiver
            .scan_transaction(&shared, &candidates)
            .expect("scan");
        let detected: usize = found.values().map(|m| m.len()).sum();
        assert_eq!(
            detected, 1,
            "recipient[{idx}] should detect exactly one output"
        );
    }
}

#[test]
fn rejects_incomplete_musig2_contributor_set() {
    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp).expect("key setup");
    let recipients = vec![(keys.sp_address.clone(), bitcoin::Amount::from_sat(1_000))];
    let mut psbt = workflow::construct_psbt(&keys, &recipients).expect("construct");
    let scan = keys.sp_address.get_scan_key();

    workflow::add_ecdh_share(
        &secp,
        &mut psbt,
        "Alice",
        &keys.alice_sk,
        &keys.alice_pk,
        &scan,
    )
    .expect("alice share");
    workflow::add_ecdh_share(&secp, &mut psbt, "Bob", &keys.bob_sk, &keys.bob_pk, &scan)
        .expect("bob share");

    assert!(workflow::derive_sp_output(&secp, &mut psbt).is_err());
}

#[test]
fn rejects_invalid_participant_dleq_proof() {
    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp).expect("key setup");
    let recipients = vec![(keys.sp_address.clone(), bitcoin::Amount::from_sat(1_000))];
    let mut psbt = workflow::construct_psbt(&keys, &recipients).expect("construct");
    let scan = keys.sp_address.get_scan_key();

    for (name, sk, pk) in [
        ("Alice", &keys.alice_sk, &keys.alice_pk),
        ("Bob", &keys.bob_sk, &keys.bob_pk),
        ("Charlie", &keys.charlie_sk, &keys.charlie_pk),
    ] {
        workflow::add_ecdh_share(&secp, &mut psbt, name, sk, pk, &scan).expect("share");
    }

    let proof = psbt.inputs[0]
        .unknowns
        .iter_mut()
        .find(|(key, _)| key.type_value == PSBT_IN_MUSIG2_PARTIAL_DLEQ)
        .map(|(_, value)| value)
        .expect("DLEQ proof");
    proof[0] ^= 1;

    assert!(workflow::derive_sp_output(&secp, &mut psbt).is_err());
}

#[test]
fn repeated_scan_key_uses_distinct_output_indices() {
    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp).expect("key setup");
    let recipients = vec![
        (keys.sp_address.clone(), bitcoin::Amount::from_sat(1_000)),
        (keys.sp_address.clone(), bitcoin::Amount::from_sat(2_000)),
    ];
    let mut psbt = workflow::construct_psbt(&keys, &recipients).expect("construct");
    let scan = keys.sp_address.get_scan_key();

    for (name, sk, pk) in [
        ("Alice", &keys.alice_sk, &keys.alice_pk),
        ("Bob", &keys.bob_sk, &keys.bob_pk),
        ("Charlie", &keys.charlie_sk, &keys.charlie_pk),
    ] {
        workflow::add_ecdh_share(&secp, &mut psbt, name, sk, pk, &scan).expect("share");
    }
    workflow::derive_sp_output(&secp, &mut psbt).expect("derive outputs");

    let scripts: Vec<_> = psbt
        .outputs
        .iter()
        .filter(|output| output.sp_v0_info.is_some())
        .map(|output| output.script_pubkey.clone())
        .collect();
    assert_eq!(scripts.len(), 2);
    assert_ne!(scripts[0], scripts[1]);
}
