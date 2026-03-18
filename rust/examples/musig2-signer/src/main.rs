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

fn random_nonce_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

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
    // Round 1: Each party contributes ECDH share + nonce in a single pass.
    // BIP-327 allows nonce preprocessing (generating before the message is known).
    println!("--- 3. Round 1: Contribute (ECDH + Nonce) ---");
    println!("NOTE: PSBT_IN_SP_PARTIAL_ECDH_SHARE (0x21) is a proposed new field.");

    let parties = [
        ("Alice", &keys.alice_sk, &keys.alice_pk),
        ("Bob", &keys.bob_sk, &keys.bob_pk),
        ("Charlie", &keys.charlie_sk, &keys.charlie_pk),
    ];
    let alice_sec_nonce = workflow::contribute(
        &secp, &mut psbt, "Alice", &keys.alice_sk, &keys.alice_pk,
        &keys.scan_pk, &keys.agg_pk, &keys.key_agg_ctx, random_nonce_seed(),
    )?;
    println!("[Alice] ECDH share + nonce contributed");
    let bob_sec_nonce = workflow::contribute(
        &secp, &mut psbt, "Bob", &keys.bob_sk, &keys.bob_pk,
        &keys.scan_pk, &keys.agg_pk, &keys.key_agg_ctx, random_nonce_seed(),
    )?;
    println!("[Bob] ECDH share + nonce contributed");
    let charlie_sec_nonce = workflow::contribute(
        &secp, &mut psbt, "Charlie", &keys.charlie_sk, &keys.charlie_pk,
        &keys.scan_pk, &keys.agg_pk, &keys.key_agg_ctx, random_nonce_seed(),
    )?;
    println!("[Charlie] ECDH share + nonce contributed\n");

    // -----------------------------------------------------------------------
    // Coordinator: aggregate ECDH shares and derive SP output
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
    // Round 2 preamble: each signer verifies output before signing
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

    let message = workflow::compute_sighash(&psbt)?;
    println!("Taproot sighash: {}", hex::encode(message));

    // -----------------------------------------------------------------------
    // Round 2: Each party produces a partial MuSig2 signature
    println!("--- 6. Round 2: Partial Signing (BIP-373) ---");
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
    println!("--- 7. Signature Aggregation ---");
    let tx = workflow::aggregate_and_extract(&secp, &mut psbt, &keys.key_agg_ctx, &message)?;

    // Extract Schnorr signature from the finalized witness (tap_key_sig is cleared
    // by finalize_input_witnesses per BIP-174).
    let witness = &tx.input[0].witness;
    let sig_bytes = witness
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("witness empty after finalization"))?;
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)?;
    println!(
        "Aggregated Schnorr signature: {}",
        hex::encode(sig_bytes)
    );

    // -----------------------------------------------------------------------
    println!("--- 8. Extraction + Verification ---");
    println!("txid: {}", tx.compute_txid());
    println!("inputs: {}, outputs: {}", tx.input.len(), tx.output.len());

    let msg = secp256k1::Message::from_digest(message);
    secp.verify_schnorr(&schnorr_sig, &msg, &keys.agg_xonly)?;
    println!("MuSig2 Schnorr signature verified: OK");
    assert!(tx.output[0].script_pubkey.is_p2tr());
    println!("SP output (P2TR): OK");

    println!("\n=== PoC completed successfully ===");
    Ok(())
}
