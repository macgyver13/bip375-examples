//! Finalize Simulator PSBT
//!
//! Takes the r2-charlie.psbt from the Coldcard simulator (which contains
//! all partial signatures and the finalized SP output scripts) and:
//!   1. Computes the final sighash
//!   2. Aggregates all signatures and extracts the final transaction
//! 
//! Writes final musig2-sp-final.psbt and musig2-sp-final-tx.hex to the same 
//! directory as the input PSBT.
//!
//! Usage:
//!   cargo run -p musig2-signer --bin finalize path/to/r2-charlie.psbt

use anyhow::{bail, Context, Result};
use bip375_helpers::crypto::tweaked_key_to_p2tr_script;
use hex;
use musig2_signer::musig2_psbt::{get_output_sp_info, input_outpoint_bytes};
use musig2_signer::musig2_spdk::finalizer::{
    derive_silent_payment_output_pubkey, input_hash_bytes,
};
use musig2_signer::workflow::{self, KeySetup};
use psbt::roles::signer::extract_eligible_input_pubkey;
use psbt::Psbt as SilentPaymentPsbt;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run -p musig2-signer --bin finalize <path_to_r2-charlie.psbt>");
        std::process::exit(1);
    }
    let psbt_path = PathBuf::from(&args[1]);

    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp, workflow::DEMO_SP_INDEX)?;

    // 1. Read the Round 2 PSBT outputted by the simulator
    let psbt_bytes = fs::read(&psbt_path).context("Failed to read PSBT file")?;
    let mut psbt = SilentPaymentPsbt::deserialize(&psbt_bytes).context("Failed to parse PSBT")?;

    println!("Loaded PSBT from {}", psbt_path.display());

    // 2. Compute Sighash (outputs were already finalized by the simulator)
    let message = workflow::compute_sighash(&psbt).context("Failed to compute sighash")?;
    println!("Computed taproot sighash: {}", hex::encode(message));


    // 3. Aggregate Signatures & Extract Transaction
    let tx = workflow::aggregate_and_extract(&secp, &mut psbt, &keys.key_agg_ctx, &message)
        .context("Failed to aggregate signatures and extract tx")?;

    // 4. Independently verify every SP output is discoverable on chain by its recipient.
    verify_outputs_discoverable(&secp, &keys, &psbt, &tx)
        .context("SP output discoverability verification failed")?;

    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);

    println!("\n=== Final Transaction ===");
    println!("txid: {}", tx.compute_txid());
    println!("hex:  {}", tx_hex);

    let out_dir = psbt_path.parent().unwrap_or(std::path::Path::new("."));
    let final_psbt_path = out_dir.join("musig2-sp-final.psbt");
    let final_tx_path = out_dir.join("musig2-sp-final-tx.hex");

    fs::write(&final_psbt_path, psbt.serialize())?;
    fs::write(&final_tx_path, &tx_hex)?;

    println!("\nSaved final PSBT to {}", final_psbt_path.display());
    println!("Saved extracted tx to {}", final_tx_path.display());

    Ok(())
}

/// Reconstruct the aggregate input secret key `a_Q` whose pubkey is the taproot output key
/// `lift_x(Q)` actually being spent. Uses the three participant secret keys + the MuSig2
/// KeyAggContext (coefficients and accumulated tweak), resolving the BIP-327/BIP-341 parity
/// sign by brute-forcing the four combinations against the known `lift_x(Q)`.
fn reconstruct_aggregate_input_secret(
    secp: &Secp256k1<secp256k1::All>,
    keys: &KeySetup,
    lift_x_q: &PublicKey,
) -> Result<SecretKey> {
    // p_sk = Σ sk_i · μ_i, where μ_i is the BIP-327 key-aggregation coefficient.
    let participants = [
        (keys.alice_sk, keys.alice_pk),
        (keys.bob_sk, keys.bob_pk),
        (keys.charlie_sk, keys.charlie_pk),
    ];

    let mut terms: Vec<SecretKey> = Vec::with_capacity(3);
    for (sk, pk) in participants {
        let musig_pk = musig2::secp256k1::PublicKey::from_slice(&pk.serialize())
            .map_err(|e| anyhow::anyhow!("musig pubkey convert: {e}"))?;
        let coeff = keys
            .key_agg_ctx
            .key_coefficient(musig_pk)
            .ok_or_else(|| anyhow::anyhow!("participant not in key_agg_ctx"))?;
        let coeff_bytes: [u8; 32] = match coeff {
            musig2::secp::MaybeScalar::Valid(scalar) => scalar.into(),
            musig2::secp::MaybeScalar::Zero => [0u8; 32],
        };
        let coeff_scalar = Scalar::from_be_bytes(coeff_bytes)?;
        terms.push(sk.mul_tweak(&coeff_scalar)?);
    }

    let mut p_sk = terms[0];
    p_sk = p_sk.add_tweak(&Scalar::from_be_bytes(terms[1].secret_bytes())?)?;
    p_sk = p_sk.add_tweak(&Scalar::from_be_bytes(terms[2].secret_bytes())?)?;

    let tacc_bytes: [u8; 32] = match keys.key_agg_ctx.tweak_sum::<musig2::secp::Scalar>() {
        Some(t) => t.into(),
        None => [0u8; 32],
    };
    let tacc_is_zero = tacc_bytes == [0u8; 32];

    // a_Q = s1·p_sk + s2·tacc; signs (s1, s2) follow the MuSig2 internal parity negations
    // (gacc, g2). Rather than track them out of setup_keys, try all four and keep the one
    // whose pubkey equals lift_x(Q).
    for negate_p in [false, true] {
        for negate_t in [false, true] {
            let mut cand = if negate_p { p_sk.negate() } else { p_sk };
            if !tacc_is_zero {
                let mut tacc_sk = SecretKey::from_slice(&tacc_bytes)?;
                if negate_t {
                    tacc_sk = tacc_sk.negate();
                }
                cand = cand.add_tweak(&Scalar::from_be_bytes(tacc_sk.secret_bytes())?)?;
            }
            if PublicKey::from_secret_key(secp, &cand) == *lift_x_q {
                return Ok(cand);
            }
            if tacc_is_zero {
                break;
            }
        }
    }

    bail!("could not reconstruct aggregate input secret matching lift_x(Q)")
}

/// Verify each SP output script can be independently re-derived as a recipient scanning the
/// chain would, proving the payment is discoverable. Fails on any mismatch.
fn verify_outputs_discoverable(
    secp: &Secp256k1<secp256k1::All>,
    keys: &KeySetup,
    psbt: &SilentPaymentPsbt,
    tx: &bitcoin::Transaction,
) -> Result<()> {
    println!("\n=== Verifying SP output discoverability ===");

    // lift_x(Q): even-Y lift of the taproot output key being spent.
    let mut q_even = [0u8; 33];
    q_even[0] = 0x02;
    q_even[1..].copy_from_slice(&keys.agg_xonly.serialize());
    let lift_x_q = PublicKey::from_slice(&q_even)?;

    let a_q = reconstruct_aggregate_input_secret(secp, keys, &lift_x_q)?;

    // Sanity: the reconstructed secret's pubkey must equal the PSBT's input key on chain.
    let input_pk = extract_eligible_input_pubkey(&psbt.inputs[0])
        .map_err(|e| anyhow::anyhow!("input pubkey: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("input 0 not eligible"))?;
    if PublicKey::from_secret_key(secp, &a_q) != input_pk {
        bail!("reconstructed input secret does not match PSBT input pubkey");
    }
    if input_pk != lift_x_q {
        bail!("PSBT input pubkey does not match lift_x(Q)");
    }
    println!("Reconstructed aggregate input secret matches on-chain input key");

    // BIP-352 input hash from the real transaction inputs.
    let smallest_arr: [u8; 36] = psbt
        .inputs
        .iter()
        .map(input_outpoint_bytes)
        .min()
        .ok_or_else(|| anyhow::anyhow!("no inputs"))?;

    let mut input_pks: Vec<PublicKey> = Vec::new();
    for input in &psbt.inputs {
        if let Some(pk) = extract_eligible_input_pubkey(input)
            .map_err(|e| anyhow::anyhow!("input pubkey: {e:?}"))?
        {
            input_pks.push(pk);
        }
    }
    let input_pk_refs: Vec<&PublicKey> = input_pks.iter().collect();
    let a_sum = PublicKey::combine_keys(&input_pk_refs)
        .map_err(|e| anyhow::anyhow!("combine input pubkeys: {e}"))?;

    let hash_bytes = input_hash_bytes(&smallest_arr, &a_sum);
    let input_hash = Scalar::from_be_bytes(hash_bytes)?;

    let mut scan_key_k: HashMap<PublicKey, u32> = HashMap::new();
    let mut verified = 0usize;

    for i in 0..psbt.outputs.len() {
        let (scan_pk, spend_pk) = match get_output_sp_info(&psbt.outputs[i])? {
            Some(v) => v,
            None => continue, // change / non-SP output
        };

        // Shared secret as the recipient would derive it: a_Q · scan_pk · input_hash
        // (== scan_sk · lift_x(Q) · input_hash, using only the recipient's public scan key).
        let a_q_scalar: Scalar = a_q.into();
        let ecdh = scan_pk
            .mul_tweak(secp, &a_q_scalar)
            .map_err(|e| anyhow::anyhow!("ecdh: {e}"))?;
        let shared_secret = ecdh
            .mul_tweak(secp, &input_hash)
            .map_err(|e| anyhow::anyhow!("apply input hash: {e}"))?;

        let k = *scan_key_k.get(&scan_pk).unwrap_or(&0);
        let output_pk =
            derive_silent_payment_output_pubkey(secp, &spend_pk, &shared_secret.serialize(), k)
                .map_err(|e| anyhow::anyhow!("derive output pubkey: {e}"))?;
        let expected = tweaked_key_to_p2tr_script(&output_pk);

        if psbt.outputs[i].script_pubkey != expected {
            bail!(
                "output {i}: PSBT script {} does not match recipient-derived script {}",
                hex::encode(psbt.outputs[i].script_pubkey.as_bytes()),
                hex::encode(expected.as_bytes())
            );
        }
        if tx.output[i].script_pubkey != expected {
            bail!(
                "output {i}: final tx script {} does not match recipient-derived script {}",
                hex::encode(tx.output[i].script_pubkey.as_bytes()),
                hex::encode(expected.as_bytes())
            );
        }

        println!(
            "  output[{i}] {} -> discoverable",
            hex::encode(expected.as_bytes())
        );
        scan_key_k.insert(scan_pk, k + 1);
        verified += 1;
    }

    if verified == 0 {
        bail!("no SP outputs found to verify (PSBT_OUT_SP_V0_INFO missing?)");
    }
    println!("All {verified} SP output(s) verified discoverable on chain");
    Ok(())
}
