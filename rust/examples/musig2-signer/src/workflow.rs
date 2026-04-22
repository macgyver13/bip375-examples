//! Pure musig2-signer workflow logic.
//!
//! Each function corresponds to one step in the 10-step MuSig2 + BIP-375
//! silent payment workflow, independent of CLI or GUI concerns.

use anyhow::{bail, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use musig2::SecNonce;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};
use spdk_core::psbt::{
    core::{Bip375PsbtExt, PartialEcdhShareData, PsbtInput, PsbtOutput, SilentPaymentPsbt},
    crypto::{compute_ecdh_share, dleq_generate_proof, dleq_verify_proof},
    roles::{
        add_input_tap_bip32_derivation, add_inputs, add_musig2_partial_sig, add_musig2_pub_nonce,
        add_output_tap_bip32_derivation, add_outputs, aggregate_musig2_keys, aggregate_musig2_sigs,
        create_psbt, extract_transaction, finalize_input_witnesses, finalize_sp_outputs,
        Bip32Derivation,
    },
};

/// Static key material for the demo.
pub struct KeySetup {
    pub alice_sk: SecretKey,
    pub bob_sk: SecretKey,
    pub charlie_sk: SecretKey,
    pub alice_pk: PublicKey,
    pub bob_pk: PublicKey,
    pub charlie_pk: PublicKey,
    pub agg_pk: PublicKey,
    pub agg_xonly: bitcoin::key::XOnlyPublicKey,
    pub key_agg_ctx: musig2::KeyAggContext,
    pub p2tr_script: ScriptBuf,
    pub scan_pk: PublicKey,
    pub scan_sk: SecretKey,
    pub sp_address: SilentPaymentAddress,
}

/// Generate deterministic demo key material and aggregate the MuSig2 key.
pub fn setup_keys(secp: &Secp256k1<secp256k1::All>) -> Result<KeySetup> {
    let alice_sk = SecretKey::from_slice(&[0xaa_u8; 32])?;
    let bob_sk = SecretKey::from_slice(&[0xbb_u8; 32])?;
    let charlie_sk = SecretKey::from_slice(&[0xcc_u8; 32])?;

    let alice_pk = PublicKey::from_secret_key(secp, &alice_sk);
    let bob_pk = PublicKey::from_secret_key(secp, &bob_sk);
    let charlie_pk = PublicKey::from_secret_key(secp, &charlie_sk);

    let participants = vec![alice_pk, bob_pk, charlie_pk];
    let (key_agg_ctx, _untweaked_xonly) = aggregate_musig2_keys(&participants)
        .map_err(|e| anyhow::anyhow!("Key aggregation failed: {e}"))?;

    // Apply BIP-341 taproot tweak (no script tree => unspendable taproot tweak).
    // This updates gacc/tacc in the KeyAggContext so signing math is correct.
    let key_agg_ctx = key_agg_ctx
        .with_unspendable_taproot_tweak()
        .map_err(|e| anyhow::anyhow!("Taproot tweak failed: {e}"))?;

    // Extract the tweaked x-only key (secp256k1 0.31) and convert to 0.29
    let tweaked_xonly_031: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
    let agg_xonly = bitcoin::key::XOnlyPublicKey::from_slice(&tweaked_xonly_031.serialize())?;

    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
    );

    // Construct compressed pubkey from the tweaked x-only key (assume even Y)
    let mut agg_pk_bytes = [0u8; 33];
    agg_pk_bytes[0] = 0x02;
    agg_pk_bytes[1..].copy_from_slice(&agg_xonly.serialize());
    let agg_pk = PublicKey::from_slice(&agg_pk_bytes)?;

    let scan_sk = SecretKey::from_slice(&[0x11_u8; 32])?;
    let spend_sk = SecretKey::from_slice(&[0x22_u8; 32])?;
    let scan_pk = PublicKey::from_secret_key(secp, &scan_sk);
    let spend_pk = PublicKey::from_secret_key(secp, &spend_sk);
    let sp_address =
        SilentPaymentAddress::new(scan_pk, spend_pk, SpNetwork::Mainnet, SpVersion::ZERO);

    Ok(KeySetup {
        alice_sk,
        bob_sk,
        charlie_sk,
        alice_pk,
        bob_pk,
        charlie_pk,
        agg_pk,
        agg_xonly,
        key_agg_ctx,
        p2tr_script,
        scan_pk,
        scan_sk,
        sp_address,
    })
}

/// Create the PSBT with 1 MuSig2 P2TR input and N+1 outputs (N SP recipients + change).
///
/// `recipients` is a slice of (SP address, payment amount) pairs. A change output
/// returning to the same MuSig2 script is appended automatically (9 000 sats).
pub fn construct_psbt(
    keys: &KeySetup,
    recipients: &[(SilentPaymentAddress, Amount)],
) -> Result<SilentPaymentPsbt> {
    let total_payment: u64 = recipients.iter().map(|(_, a)| a.to_sat()).sum();
    let change_amount = Amount::from_sat(9_000);
    let fee = Amount::from_sat(1_000);
    let input_amount = Amount::from_sat(total_payment) + change_amount + fee;

    let num_outputs = recipients.len() + 1; // +1 for change
    let mut psbt = create_psbt(1, num_outputs);

    let psbt_inputs = vec![PsbtInput::new(
        OutPoint::new(Txid::all_zeros(), 0),
        TxOut {
            value: input_amount,
            script_pubkey: keys.p2tr_script.clone(),
        },
        Sequence::MAX,
        None,
    )];

    let mut psbt_outputs: Vec<PsbtOutput> = recipients
        .iter()
        .map(|(addr, amount)| PsbtOutput::silent_payment(*amount, addr.clone(), None))
        .collect();
    psbt_outputs.push(PsbtOutput::regular(change_amount, keys.p2tr_script.clone()));

    add_inputs(&mut psbt, &psbt_inputs)?;
    add_outputs(&mut psbt, &psbt_outputs)?;

    let dummy_derivation = Bip32Derivation::new([0u8; 4], vec![]);
    add_input_tap_bip32_derivation(&mut psbt, 0, &keys.agg_xonly, vec![], &dummy_derivation)?;

    psbt.set_input_musig2_participant_pubkeys(
        0,
        &keys.agg_pk,
        &[keys.alice_pk, keys.bob_pk, keys.charlie_pk],
    )
    .map_err(|e| anyhow::anyhow!("set participant pubkeys: {e}"))?;

    // BIP-373: add PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS + PSBT_OUT_TAP_BIP32_DERIVATION
    // on the change output (last output) to aid in change detection.
    let change_idx = num_outputs - 1;
    psbt.set_output_musig2_participant_pubkeys(
        change_idx,
        &keys.agg_pk,
        &[keys.alice_pk, keys.bob_pk, keys.charlie_pk],
    )
    .map_err(|e| anyhow::anyhow!("set output participant pubkeys: {e}"))?;
    add_output_tap_bip32_derivation(
        &mut psbt,
        change_idx,
        &keys.agg_xonly,
        vec![],
        &dummy_derivation,
    )?;

    Ok(psbt)
}

/// Add one party's partial ECDH share (with DLEQ proof) to the PSBT.
///
/// Returns an error if the DLEQ proof self-check fails.
pub fn add_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    scan_pk: &PublicKey,
) -> Result<()> {
    let partial_share = compute_ecdh_share(secp, party_sk, scan_pk)
        .map_err(|e| anyhow::anyhow!("{party_name} ECDH: {e}"))?;

    let rand_aux = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&party_pk.serialize()[1..]);
        r
    };
    let dleq_proof = dleq_generate_proof(secp, party_sk, scan_pk, &rand_aux, None)
        .map_err(|e| anyhow::anyhow!("{party_name} DLEQ gen: {e}"))?;

    let ok = dleq_verify_proof(secp, party_pk, scan_pk, &partial_share, &dleq_proof, None)
        .map_err(|e| anyhow::anyhow!("{party_name} DLEQ verify: {e}"))?;
    if !ok {
        bail!("{party_name} produced an invalid DLEQ proof");
    }

    let partial = PartialEcdhShareData {
        scan_key: *scan_pk,
        contributor_pk: *party_pk,
        share: partial_share,
        dleq_proof,
    };
    psbt.add_input_partial_ecdh_share(0, &partial)
        .map_err(|e| anyhow::anyhow!("{party_name} add_partial_ecdh: {e}"))?;

    Ok(())
}

/// Combined Round 1: add partial ECDH share + nonce in a single pass.
///
/// BIP-327 allows nonce preprocessing (generating before the message is known).
/// Returns the `SecNonce` that must be consumed exactly once in `partial_sign`.
pub fn contribute(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    scan_pk: &PublicKey,
    agg_pk: &PublicKey,
    key_agg_ctx: &musig2::KeyAggContext,
    nonce_seed: [u8; 32],
) -> Result<SecNonce> {
    add_ecdh_share(secp, psbt, party_name, party_sk, party_pk, scan_pk)?;
    add_nonce(
        psbt,
        party_name,
        party_sk,
        party_pk,
        agg_pk,
        key_agg_ctx,
        nonce_seed,
    )
}

/// Compute the taproot sighash from the current PSBT state.
///
/// Must be called after finalize_inputs so that outputs have their final scripts.
pub fn compute_sighash(psbt: &SilentPaymentPsbt) -> Result<[u8; 32]> {
    let utxo = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("input 0 missing witness_utxo"))?;
    let input_amount = utxo.value;
    let p2tr_script = utxo.script_pubkey.clone();

    let unsigned_tx = build_unsigned_tx(psbt);
    let prevouts = vec![TxOut {
        value: input_amount,
        script_pubkey: p2tr_script,
    }];
    compute_tap_sighash(&unsigned_tx, 0, &prevouts)
}

/// Add one party's public nonce to the PSBT.
///
/// Returns the `SecNonce` that must be stored by the caller and consumed
/// exactly once in the corresponding `partial_sign` call.
pub fn add_nonce(
    psbt: &mut SilentPaymentPsbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    agg_pk: &PublicKey,
    key_agg_ctx: &musig2::KeyAggContext,
    seed: [u8; 32],
) -> Result<SecNonce> {
    let sec_nonce = add_musig2_pub_nonce(psbt, 0, party_sk, party_pk, agg_pk, key_agg_ctx, seed)
        .map_err(|e| anyhow::anyhow!("{party_name} nonce: {e}"))?;
    Ok(sec_nonce)
}

/// Add one party's partial signature to the PSBT.
///
/// Consumes the `SecNonce` returned by `add_nonce`.
pub fn partial_sign(
    psbt: &mut SilentPaymentPsbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    agg_pk: &PublicKey,
    sec_nonce: SecNonce,
    key_agg_ctx: &musig2::KeyAggContext,
    message: &[u8; 32],
) -> Result<()> {
    add_musig2_partial_sig(
        psbt,
        0,
        party_sk,
        party_pk,
        agg_pk,
        sec_nonce,
        key_agg_ctx,
        message,
    )
    .map_err(|e| anyhow::anyhow!("{party_name} partial sig: {e}"))?;
    Ok(())
}

/// Aggregate partial signatures into a Schnorr signature and extract the transaction.
pub fn aggregate_and_extract(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    key_agg_ctx: &musig2::KeyAggContext,
    message: &[u8; 32],
) -> Result<Transaction> {
    aggregate_musig2_sigs(psbt, 0, key_agg_ctx, message, secp)
        .map_err(|e| anyhow::anyhow!("aggregate sigs: {e}"))?;

    finalize_input_witnesses(psbt).map_err(|e| anyhow::anyhow!("finalize witnesses: {e}"))?;

    let tx = extract_transaction(psbt)?;
    Ok(tx)
}

/// Derive the SP output script from the aggregated ECDH shares.
pub fn derive_sp_output(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
) -> Result<()> {
    finalize_sp_outputs(secp, psbt)?;

    Ok(())
}


// =========================================================================
// Helpers (shared with CLI path)
// =========================================================================

pub fn build_unsigned_tx(psbt: &SilentPaymentPsbt) -> Transaction {
    let inputs = psbt
        .inputs
        .iter()
        .map(|i| TxIn {
            previous_output: OutPoint::new(i.previous_txid, i.spent_output_index),
            script_sig: ScriptBuf::new(),
            sequence: i.sequence.unwrap_or(Sequence::MAX),
            witness: Witness::new(),
        })
        .collect();

    let outputs = psbt
        .outputs
        .iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.amount.to_sat()),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: inputs,
        output: outputs,
    }
}

pub fn compute_tap_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| anyhow::anyhow!("taproot sighash: {e}"))?;
    Ok(sighash.to_byte_array())
}
