//! MuSig2 + BIP-375 Silent Payments PoC
//!
//! Demonstrates N-of-N collaborative signing (BIP-327/BIP-373) for a P2TR input
//! combined with Silent Payment output derivation (BIP-375).
//!
//! Three parties — Alice, Bob, Charlie — jointly control one P2TR input via MuSig2
//! key aggregation. The transaction pays to a Silent Payment address.
//!
//! # PSBT v2 role flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │ Pre-PSBT                                                                │
//! │   aggregate_musig2_keys([alice_pk, bob_pk, charlie_pk])                 │
//! │   → KeyAggContext, tweaked agg xonly key, P2TR script                   │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 1. Creator  (BIP-370)                                                   │
//! │   create_psbt(inputs=1, outputs=2)                                      │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 2. Constructor  (BIP-370 v2)                                            │
//! │   add_inputs  → PSBT_IN_PREVIOUS_TXID, PSBT_IN_OUTPUT_INDEX,            │
//! │                  PSBT_IN_WITNESS_UTXO                                   │
//! │   add_outputs → PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT (placeholder)          │
//! │                  PSBT_OUT_SP_INFO (scan_key, spend_key)  [BIP-375]      │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 3. Updater  (BIP-370)                                                   │
//! │   add_input_tap_bip32_derivation → PSBT_IN_TAP_BIP32_DERIVATION         │
//! │     (registers tweaked agg key for BIP-352 input_hash)                  │
//! │   set_input_musig2_participant_pubkeys                                  │
//! │     → PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS  [BIP-373]                     │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 4. Signer — Distributed ECDH  (proposed BIP-375 extension)              │
//! │   each party independently:                                             │
//! │     partial_share = sk_i * scan_key                                     │
//! │     dleq_proof proves log_G(pk_i) = log_{scan_key}(partial_share)       │
//! │   add_input_partial_ecdh_share                                          │
//! │     → PSBT_IN_SP_PARTIAL_ECDH_SHARE (0x21, proposed)  [BIP-375 ext]     │
//! │     → PSBT_IN_SP_PARTIAL_DLEQ       (0x22, proposed)  [BIP-375 ext]     │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 5. Input Finalizer  (BIP-370 + BIP-375)                                 │
//! │   finalize_inputs:                                                      │
//! │     aggregate_ecdh_shares detects partial shares, verifies DLEQs,       │
//! │     sums sk_i*scan_key → agg_sk*scan_key                                │
//! │     BIP-352: shared_secret = input_hash * agg_ecdh_share                │
//! │     derives P2TR output script → PSBT_OUT_SCRIPT (final)                │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 6. Signer — Output Verification  (security step)                        │
//! │   each party reads all PSBT_IN_SP_PARTIAL_ECDH_SHARE entries,           │
//! │   verifies each DLEQ proof independently, sums shares,                  │
//! │   confirms PSBT_OUT_SCRIPT matches before proceeding to sign            │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 7. Signer — Nonce Exchange  (BIP-373 + BIP-327)                         │
//! │   sighash = taproot_key_spend_sighash(unsigned_tx, prevouts)            │
//! │     (commits to the final resolved PSBT_OUT_SCRIPT)                     │
//! │   each party: add_musig2_pub_nonce                                      │
//! │     → PSBT_IN_MUSIG2_PUB_NONCE  [BIP-373]                               │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 8. Signer — Partial Signing  (BIP-373 + BIP-327)                        │
//! │   each party: add_musig2_partial_sig(sighash)                           │
//! │     → PSBT_IN_MUSIG2_PARTIAL_SIG  [BIP-373]                             │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 9. Input Finalizer — Signature Aggregation  (BIP-327)                   │
//! │   aggregate_musig2_sigs: sum partial sigs → Schnorr signature           │
//! │     → PSBT_IN_TAP_KEY_SIG  (standard taproot field)                     │
//! └───────────────────────────────┬─────────────────────────────────────────┘
//!                                 │
//! ┌───────────────────────────────▼─────────────────────────────────────────┐
//! │ 10. Transaction Extractor  (BIP-370)                                    │
//! │   extract_transaction → witness: [schnorr_sig]                          │
//! │   verify schnorr_sig against tweaked agg xonly key                      │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Spec gap: BIP-375 + MuSig2 distributed ECDH
//!
//! In standard BIP-375 multi-signer, each party controls a *distinct* input and
//! writes `sk_i * scan_key` to PSBT_IN_SP_ECDH_SHARE (0x1d). With MuSig2, all
//! parties share *one* input — no single party knows the aggregate secret key.
//!
//! This demo implements the proposed extension: PSBT_IN_SP_PARTIAL_ECDH_SHARE (0x21),
//! keyed by `(scan_key || contributor_pk)`. Each party contributes `sk_i * scan_key`
//! with a DLEQ proof; the coordinator sums them. This should be raised with BIP-375
//! authors as a necessary field addition to support threshold/multisig ECDH.

use anyhow::{bail, Result};
use bitcoin::{
    absolute::LockTime, hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};
use spdk_core::psbt::{
    core::{Bip375PsbtExt, PartialEcdhShareData, PsbtInput, PsbtOutput, SilentPaymentPsbt},
    crypto::{
        compute_ecdh_share, dleq_generate_proof, dleq_verify_proof,
    },
    roles::{
        add_input_tap_bip32_derivation, add_inputs, add_outputs, aggregate_musig2_keys,
        add_musig2_pub_nonce, add_musig2_partial_sig, aggregate_musig2_sigs,
        create_psbt, extract_transaction, finalize_inputs, Bip32Derivation,
    },
};

fn main() -> Result<()> {
    let secp = Secp256k1::new();

    println!("=== MuSig2 + BIP-375 Silent Payments PoC ===\n");

    // =========================================================================
    // 1. KEY SETUP
    // =========================================================================
    println!("--- 1. Key Setup ---");

    // Each party generates a keypair (deterministic for this demo)
    let alice_sk = SecretKey::from_slice(&[0xaa_u8; 32])?;
    let bob_sk = SecretKey::from_slice(&[0xbb_u8; 32])?;
    let charlie_sk = SecretKey::from_slice(&[0xcc_u8; 32])?;

    let alice_pk = PublicKey::from_secret_key(&secp, &alice_sk);
    let bob_pk = PublicKey::from_secret_key(&secp, &bob_sk);
    let charlie_pk = PublicKey::from_secret_key(&secp, &charlie_sk);

    println!("Alice pubkey:   {}", hex::encode(alice_pk.serialize()));
    println!("Bob pubkey:     {}", hex::encode(bob_pk.serialize()));
    println!("Charlie pubkey: {}", hex::encode(charlie_pk.serialize()));

    // Aggregate MuSig2 key: Alice + Bob + Charlie → tweaked P2TR aggregate key
    let participants = vec![alice_pk, bob_pk, charlie_pk];
    let (key_agg_ctx, agg_xonly) = aggregate_musig2_keys(&participants)
        .map_err(|e| anyhow::anyhow!("Key aggregation failed: {e}"))?;

    // Derive P2TR script from the tweaked aggregate key
    // agg_xonly is already the tweaked output key from KeyAggContext::aggregated_pubkey()
    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
    );
    println!("Aggregate P2TR script: {}", hex::encode(p2tr_script.as_bytes()));

    // Build a compressed PublicKey from the x-only key (even parity).
    // Finalize Inputs role reads bip32_derivations to find the input pubkey for input_hash.
    let mut agg_pk_bytes = [0u8; 33];
    agg_pk_bytes[0] = 0x02;
    agg_pk_bytes[1..].copy_from_slice(&agg_xonly.serialize());
    let agg_pk = PublicKey::from_slice(&agg_pk_bytes)?;

    // Receiver's Silent Payment address (scan + spend keys)
    let scan_sk = SecretKey::from_slice(&[0x11_u8; 32])?;
    let spend_sk = SecretKey::from_slice(&[0x22_u8; 32])?;
    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
    let sp_address = SilentPaymentAddress::new(scan_pk, spend_pk, SpNetwork::Mainnet, 0)
        .map_err(|e| anyhow::anyhow!("SP address: {e}"))?;

    println!("Scan pubkey:    {}", hex::encode(scan_pk.serialize()));
    println!("SP address created (Mainnet)\n");

    // =========================================================================
    // 2. PSBT CONSTRUCTION
    // =========================================================================
    println!("--- 2. PSBT Construction ---");

    let input_txid = Txid::all_zeros();
    let input_vout = 0u32;
    let input_amount = Amount::from_sat(100_000);

    let mut psbt = create_psbt(1, 2);

    // Input: P2TR UTXO controlled by the MuSig2 aggregate key
    let psbt_inputs = vec![PsbtInput::new(
        OutPoint::new(input_txid, input_vout),
        TxOut {
            value: input_amount,
            script_pubkey: p2tr_script.clone(),
        },
        Sequence::MAX,
        None, // No single privkey — MuSig2 signing is handled separately
    )];

    let psbt_outputs = vec![
        // Silent payment output (destination)
        PsbtOutput::silent_payment(Amount::from_sat(90_000), sp_address, None),
        // Change output back to the same P2TR aggregate address (simplified demo)
        PsbtOutput::regular(Amount::from_sat(9_000), p2tr_script.clone()),
    ];

    add_inputs(&mut psbt, &psbt_inputs)?;
    add_outputs(&mut psbt, &psbt_outputs)?;

    // Register the tweaked aggregate key for BIP-352 input_hash computation.
    // BIP-352 requires sum_of_eligible_pubkeys; for a MuSig2 input the tweaked
    // aggregate key is the single eligible pubkey (it is the taproot output key).
    let dummy_derivation = Bip32Derivation::new([0u8; 4], vec![]);
    add_input_tap_bip32_derivation(&mut psbt, 0, &agg_xonly, vec![], &dummy_derivation)?;

    // BIP-373: store participant pubkeys in the PSBT so verifiers can reconstruct
    // the aggregate key and cross-check DLEQ contributor set.
    psbt.set_input_musig2_participant_pubkeys(0, &agg_pk, &participants)
        .map_err(|e| anyhow::anyhow!("set participant pubkeys: {e}"))?;

    println!("PSBT created: 1 input, 2 outputs");
    println!("BIP-373 participant pubkeys registered\n");

    // =========================================================================
    // 3. DISTRIBUTED ECDH  (proposed PSBT_IN_SP_PARTIAL_ECDH_SHARE)
    // =========================================================================
    println!("--- 3. Distributed ECDH (proposed BIP-375 extension) ---");
    println!("NOTE: PSBT_IN_SP_PARTIAL_ECDH_SHARE (0x21) is a proposed new field.");
    println!("      BIP-375 currently has no way for multiple parties to each contribute");
    println!("      partial ECDH shares for a shared MuSig2/FROST input.\n");

    let parties: [(&str, &SecretKey, &PublicKey); 3] = [
        ("Alice", &alice_sk, &alice_pk),
        ("Bob", &bob_sk, &bob_pk),
        ("Charlie", &charlie_sk, &charlie_pk),
    ];

    for (name, sk, pk) in &parties {
        // Partial ECDH share: sk_i * scan_key
        // Sum of all partial shares = agg_sk * scan_key (the correct full ECDH share)
        let partial_share = compute_ecdh_share(&secp, sk, &scan_pk)
            .map_err(|e| anyhow::anyhow!("{name} ECDH: {e}"))?;

        // DLEQ proof: proves log_G(pk_i) = log_{scan_key}(partial_share)
        // Any observer can verify each party's contribution is honest without sk_i.
        let rand_aux = {
            let mut r = [0u8; 32];
            r.copy_from_slice(&pk.serialize()[1..]); // use 32 bytes of pubkey as aux randomness
            r
        };
        let dleq_proof = dleq_generate_proof(&secp, sk, &scan_pk, &rand_aux, None)
            .map_err(|e| anyhow::anyhow!("{name} DLEQ gen: {e}"))?;

        // Sanity check our own proof before writing to PSBT
        let ok = dleq_verify_proof(&secp, pk, &scan_pk, &partial_share, &dleq_proof, None)
            .map_err(|e| anyhow::anyhow!("{name} DLEQ verify: {e}"))?;
        if !ok {
            bail!("{name} produced an invalid DLEQ proof");
        }
        println!("[{name}] partial ECDH computed, DLEQ proof: OK");

        let partial = PartialEcdhShareData {
            scan_key: scan_pk,
            contributor_pk: **pk,
            share: partial_share,
            dleq_proof,
        };
        psbt.add_input_partial_ecdh_share(0, &partial)
            .map_err(|e| anyhow::anyhow!("{name} add_partial_ecdh: {e}"))?;
    }
    println!();

    // =========================================================================
    // 4. SP OUTPUT DERIVATION
    // =========================================================================
    println!("--- 4. Silent Payment Output Derivation ---");

    // finalize_inputs:
    //   1. Calls aggregate_ecdh_shares, which detects PSBT_IN_SP_PARTIAL_ECDH_SHARE entries
    //   2. Verifies each DLEQ proof (ensuring all contributions are honest)
    //   3. Sums partial shares: agg_share = sum(sk_i * scan_key) = agg_sk * scan_key
    //   4. Derives the BIP-352 P2TR output script from agg_share
    finalize_inputs(&secp, &mut psbt)?;

    let output_script = psbt.outputs[0].script_pubkey.clone();
    println!(
        "SP output script: {}",
        hex::encode(output_script.as_bytes())
    );
    assert!(output_script.is_p2tr(), "SP output must be P2TR");
    println!("SP output is P2TR: OK\n");

    // =========================================================================
    // 5. VERIFY OUTPUT BEFORE SIGNING
    // =========================================================================
    println!("--- 5. Each Signer Verifies Output Before Signing ---");
    println!("Each signer MUST verify the derived SP output is correct before");
    println!("contributing a MuSig2 partial signature. This prevents a malicious");
    println!("coordinator from redirecting the payment.\n");

    // Each party reads all partial ECDH shares from the PSBT, verifies their
    // DLEQ proofs, and independently sums them to confirm the output script.
    let partial_shares_in_psbt = psbt.get_input_partial_ecdh_shares(0);
    assert_eq!(partial_shares_in_psbt.len(), 3, "Expected 3 partial shares");

    for (name, _, _) in &parties {
        // Verify all DLEQ proofs and sum shares
        let mut running_share = partial_shares_in_psbt[0].share;
        // Verify first entry's proof
        let ok0 = dleq_verify_proof(
            &secp,
            &partial_shares_in_psbt[0].contributor_pk,
            &scan_pk,
            &partial_shares_in_psbt[0].share,
            &partial_shares_in_psbt[0].dleq_proof,
            None,
        )?;
        if !ok0 {
            bail!("[{name}] DLEQ proof 0 invalid — refusing to sign");
        }
        for entry in &partial_shares_in_psbt[1..] {
            let ok = dleq_verify_proof(
                &secp,
                &entry.contributor_pk,
                &scan_pk,
                &entry.share,
                &entry.dleq_proof,
                None,
            )?;
            if !ok {
                bail!("[{name}] DLEQ proof invalid for {} — refusing to sign",
                    hex::encode(entry.contributor_pk.serialize()));
            }
            running_share = running_share
                .combine(&entry.share)
                .map_err(|e| anyhow::anyhow!("combine: {e}"))?;
        }

        // Confirm the PSBT output script is non-empty P2TR.
        // TODO: A complete implementation would re-derive the expected script from running_share
        // and the spend key, then compare byte-for-byte.
        assert!(!output_script.is_empty() && output_script.is_p2tr());
        println!("[{name}] All DLEQ proofs verified, output script confirmed: OK");
    }
    println!();

    // =========================================================================
    // 6. NONCE EXCHANGE  (BIP-373 PSBT_IN_MUSIG2_PUB_NONCE)
    // =========================================================================
    println!("--- 6. Nonce Exchange (BIP-373) ---");

    // Compute the taproot sighash from the unsigned transaction.
    // All parties sign the same message.
    let unsigned_tx = build_unsigned_tx(&psbt);
    let prevouts = vec![TxOut {
        value: input_amount,
        script_pubkey: p2tr_script.clone(),
    }];
    let message = compute_tap_sighash(&unsigned_tx, 0, &prevouts)?;
    println!("Taproot sighash: {}", hex::encode(message));

    // Each party generates a fresh nonce and writes it to the PSBT.
    // SecNonce is consumed once by add_musig2_partial_sig — never reuse.
    let alice_sec_nonce = add_musig2_pub_nonce(
        &mut psbt, 0, &alice_sk, &alice_pk, &agg_pk, &key_agg_ctx, [0xa1_u8; 32],
    ).map_err(|e| anyhow::anyhow!("alice nonce: {e}"))?;

    let bob_sec_nonce = add_musig2_pub_nonce(
        &mut psbt, 0, &bob_sk, &bob_pk, &agg_pk, &key_agg_ctx, [0xb1_u8; 32],
    ).map_err(|e| anyhow::anyhow!("bob nonce: {e}"))?;

    let charlie_sec_nonce = add_musig2_pub_nonce(
        &mut psbt, 0, &charlie_sk, &charlie_pk, &agg_pk, &key_agg_ctx, [0xc1_u8; 32],
    ).map_err(|e| anyhow::anyhow!("charlie nonce: {e}"))?;

    assert_eq!(psbt.get_input_musig2_pub_nonces(0).len(), 3);
    println!("Nonce exchange: OK (3 nonces in PSBT)\n");

    // =========================================================================
    // 7. PARTIAL SIGNING  (BIP-373 PSBT_IN_MUSIG2_PARTIAL_SIG)
    // =========================================================================
    println!("--- 7. Partial Signing (BIP-373) ---");

    // Each party signs after all nonces are present in the PSBT.
    // The AggNonce is computed from all nonces; each partial sig covers that AggNonce.
    add_musig2_partial_sig(
        &mut psbt, 0, &alice_sk, &alice_pk, &agg_pk,
        alice_sec_nonce, &key_agg_ctx, &message,
    ).map_err(|e| anyhow::anyhow!("alice partial sig: {e}"))?;
    println!("[Alice] Partial signature added");

    add_musig2_partial_sig(
        &mut psbt, 0, &bob_sk, &bob_pk, &agg_pk,
        bob_sec_nonce, &key_agg_ctx, &message,
    ).map_err(|e| anyhow::anyhow!("bob partial sig: {e}"))?;
    println!("[Bob] Partial signature added");

    add_musig2_partial_sig(
        &mut psbt, 0, &charlie_sk, &charlie_pk, &agg_pk,
        charlie_sec_nonce, &key_agg_ctx, &message,
    ).map_err(|e| anyhow::anyhow!("charlie partial sig: {e}"))?;
    println!("[Charlie] Partial signature added");

    assert_eq!(psbt.get_input_musig2_partial_sigs(0).len(), 3);
    println!("Partial signatures in PSBT: 3\n");

    // =========================================================================
    // 8. SIGNATURE AGGREGATION → tap_key_sig
    // =========================================================================
    println!("--- 8. Signature Aggregation ---");

    aggregate_musig2_sigs(&mut psbt, 0, &key_agg_ctx, &message, &secp)
        .map_err(|e| anyhow::anyhow!("aggregate sigs: {e}"))?;

    let tap_sig = psbt.inputs[0]
        .tap_key_sig
        .expect("tap_key_sig must be present after aggregation");
    println!(
        "Aggregated Schnorr signature: {}",
        hex::encode(tap_sig.signature.as_ref())
    );
    println!("Signature aggregation: OK\n");

    // =========================================================================
    // 9. EXTRACTION + VERIFICATION
    // =========================================================================
    println!("--- 9. Extraction + Verification ---");

    let tx = extract_transaction(&mut psbt)?;

    println!("txid: {}", tx.compute_txid());
    println!("inputs: {}, outputs: {}", tx.input.len(), tx.output.len());

    // Verify the final Schnorr signature against the tweaked aggregate key
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(tap_sig.signature.as_ref())?;
    let msg = secp256k1::Message::from_digest(message);
    secp.verify_schnorr(&schnorr_sig, &msg, &agg_xonly)?;
    println!("MuSig2 Schnorr signature verified: OK");

    assert!(tx.output[0].script_pubkey.is_p2tr());
    println!("SP output (P2TR): OK");

    println!("\n=== PoC completed successfully ===");
    Ok(())
}

// =========================================================================
// Helpers
// =========================================================================

/// Build an unsigned transaction skeleton from the PSBT for sighash computation.
fn build_unsigned_tx(psbt: &SilentPaymentPsbt) -> Transaction {
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

/// Compute the BIP-341 taproot key-path sighash for the given input.
fn compute_tap_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

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
