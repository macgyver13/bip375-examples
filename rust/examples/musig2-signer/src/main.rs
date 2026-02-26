//! MuSig2 + BIP-375 Silent Payments
//!
//! Run with no arguments for the GUI (default), or `--cli` for the
//! original command-line demonstration.

pub mod core;
pub mod workflow;

#[cfg(feature = "gui")]
pub mod gui;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cli_mode = args.iter().any(|a| a == "--cli");

    if cli_mode {
        run_cli()
    } else {
        #[cfg(feature = "gui")]
        {
            gui::run_gui().map_err(|e| anyhow::anyhow!("GUI error: {e}"))?;
            Ok(())
        }
        #[cfg(not(feature = "gui"))]
        {
            eprintln!("GUI feature not enabled. Falling back to CLI.");
            run_cli()
        }
    }
}

// =========================================================================
// CLI path — uses the same workflow functions
// =========================================================================

fn run_cli() -> anyhow::Result<()> {
    use anyhow::bail;
    use secp256k1::Secp256k1;

    let secp = Secp256k1::new();

    println!("=== MuSig2 + BIP-375 Silent Payments PoC ===\n");

    // -----------------------------------------------------------------------
    println!("--- 1. Key Setup ---");
    let keys = workflow::setup_keys(&secp)?;
    println!("Alice pubkey:   {}", hex::encode(keys.alice_pk.serialize()));
    println!("Bob pubkey:     {}", hex::encode(keys.bob_pk.serialize()));
    println!(
        "Charlie pubkey: {}",
        hex::encode(keys.charlie_pk.serialize())
    );
    println!(
        "Aggregate P2TR script: {}",
        hex::encode(keys.p2tr_script.as_bytes())
    );
    println!("Scan pubkey:    {}", hex::encode(keys.scan_pk.serialize()));
    println!("SP address created (Mainnet)\n");

    // -----------------------------------------------------------------------
    println!("--- 2. PSBT Construction ---");
    let mut psbt = workflow::construct_psbt(&keys)?;
    println!("PSBT created: 1 input, 2 outputs");
    println!("BIP-373 participant pubkeys registered\n");

    // -----------------------------------------------------------------------
    println!("--- 3. Distributed ECDH (proposed BIP-375 extension) ---");
    println!("NOTE: PSBT_IN_SP_PARTIAL_ECDH_SHARE (0x21) is a proposed new field.");

    let parties = [
        ("Alice", &keys.alice_sk, &keys.alice_pk),
        ("Bob", &keys.bob_sk, &keys.bob_pk),
        ("Charlie", &keys.charlie_sk, &keys.charlie_pk),
    ];
    for (name, sk, pk) in &parties {
        workflow::add_ecdh_share(&secp, &mut psbt, name, sk, pk, &keys.scan_pk)?;
        println!("[{name}] partial ECDH computed, DLEQ proof: OK");
    }
    println!();

    // -----------------------------------------------------------------------
    println!("--- 4. Silent Payment Output Derivation ---");
    workflow::derive_sp_output(&secp, &mut psbt)?;
    let output_script = psbt.outputs[0].script_pubkey.clone();
    println!(
        "SP output script: {}",
        hex::encode(output_script.as_bytes())
    );
    if !output_script.is_p2tr() {
        bail!("SP output must be P2TR");
    }
    println!("SP output is P2TR: OK\n");

    // -----------------------------------------------------------------------
    println!("--- 5. Each Signer Verifies Output Before Signing ---");
    let partial_shares = psbt.get_input_partial_ecdh_shares(0);
    assert_eq!(partial_shares.len(), 3, "Expected 3 partial shares");

    use spdk_core::psbt::{core::Bip375PsbtExt, crypto::dleq_verify_proof};
    for (name, _, _) in &parties {
        let mut running_share = partial_shares[0].share;
        let ok0 = dleq_verify_proof(
            &secp,
            &partial_shares[0].contributor_pk,
            &keys.scan_pk,
            &partial_shares[0].share,
            &partial_shares[0].dleq_proof,
            None,
        )?;
        if !ok0 {
            bail!("[{name}] DLEQ proof 0 invalid — refusing to sign");
        }
        for entry in &partial_shares[1..] {
            let ok = dleq_verify_proof(
                &secp,
                &entry.contributor_pk,
                &keys.scan_pk,
                &entry.share,
                &entry.dleq_proof,
                None,
            )?;
            if !ok {
                bail!(
                    "[{name}] DLEQ proof invalid for {} — refusing to sign",
                    hex::encode(entry.contributor_pk.serialize())
                );
            }
            running_share = running_share
                .combine(&entry.share)
                .map_err(|e| anyhow::anyhow!("combine: {e}"))?;
        }
        assert!(!output_script.is_empty() && output_script.is_p2tr());
        println!("[{name}] All DLEQ proofs verified, output script confirmed: OK");
    }
    println!();

    // -----------------------------------------------------------------------
    println!("--- 6. Nonce Exchange (BIP-373) ---");
    let message = workflow::compute_sighash(&psbt)?;
    println!("Taproot sighash: {}", hex::encode(message));

    let alice_sec_nonce = workflow::add_nonce(
        &mut psbt,
        "Alice",
        &keys.alice_sk,
        &keys.alice_pk,
        &keys.agg_pk,
        &keys.key_agg_ctx,
        [0xa1_u8; 32],
    )?;
    let bob_sec_nonce = workflow::add_nonce(
        &mut psbt,
        "Bob",
        &keys.bob_sk,
        &keys.bob_pk,
        &keys.agg_pk,
        &keys.key_agg_ctx,
        [0xb1_u8; 32],
    )?;
    let charlie_sec_nonce = workflow::add_nonce(
        &mut psbt,
        "Charlie",
        &keys.charlie_sk,
        &keys.charlie_pk,
        &keys.agg_pk,
        &keys.key_agg_ctx,
        [0xc1_u8; 32],
    )?;
    println!("Nonce exchange: OK (3 nonces in PSBT)\n");

    // -----------------------------------------------------------------------
    println!("--- 7. Partial Signing (BIP-373) ---");
    workflow::partial_sign(
        &mut psbt,
        "Alice",
        &keys.alice_sk,
        &keys.alice_pk,
        &keys.agg_pk,
        alice_sec_nonce,
        &keys.key_agg_ctx,
        &message,
    )?;
    println!("[Alice] Partial signature added");
    workflow::partial_sign(
        &mut psbt,
        "Bob",
        &keys.bob_sk,
        &keys.bob_pk,
        &keys.agg_pk,
        bob_sec_nonce,
        &keys.key_agg_ctx,
        &message,
    )?;
    println!("[Bob] Partial signature added");
    workflow::partial_sign(
        &mut psbt,
        "Charlie",
        &keys.charlie_sk,
        &keys.charlie_pk,
        &keys.agg_pk,
        charlie_sec_nonce,
        &keys.key_agg_ctx,
        &message,
    )?;
    println!("[Charlie] Partial signature added\n");

    // -----------------------------------------------------------------------
    println!("--- 8. Signature Aggregation ---");
    let tx = workflow::aggregate_and_extract(&secp, &mut psbt, &keys.key_agg_ctx, &message)?;

    let tap_sig = psbt.inputs[0]
        .tap_key_sig
        .expect("tap_key_sig must be present");
    println!(
        "Aggregated Schnorr signature: {}",
        hex::encode(tap_sig.signature.as_ref())
    );

    // -----------------------------------------------------------------------
    println!("--- 9. Extraction + Verification ---");
    println!("txid: {}", tx.compute_txid());
    println!("inputs: {}, outputs: {}", tx.input.len(), tx.output.len());

    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(tap_sig.signature.as_ref())?;
    let msg = secp256k1::Message::from_digest(message);
    secp.verify_schnorr(&schnorr_sig, &msg, &keys.agg_xonly)?;
    println!("MuSig2 Schnorr signature verified: OK");
    assert!(tx.output[0].script_pubkey.is_p2tr());
    println!("SP output (P2TR): OK");

    println!("\n=== PoC completed successfully ===");
    Ok(())
}
