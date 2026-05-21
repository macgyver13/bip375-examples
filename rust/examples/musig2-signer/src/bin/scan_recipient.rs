//! Recipient-side Silent Payment validator.
//!
//! Given a signed round-trip PSBT (e.g. `musig2-sp-final.psbt`), runs the real
//! BIP-352 receiver scanning algorithm for every known-seed recipient and confirms each
//! one detects its on-chain output. Uses ONLY recipient scan keys — no sender or aggregate
//! secrets — exactly as a production wallet scanning the chain would.
//!
//! Usage:
//!   cargo run -p musig2-signer --bin scan-recipient <path_to_musig2-sp-final.psbt>

use anyhow::{bail, Context, Result};
use hex;
use musig2_signer::recipients::{recipient_keys, RECIPIENT_SEEDS};
use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data};
use silentpayments::{Network, SpVersion};
use spdk_core::psbt::core::{Bip375PsbtExt, SilentPaymentPsbt};
use spdk_core::psbt::crypto::is_input_eligible;
use spdk_core::psbt::{get_input_pubkey, get_input_txid, get_input_vout};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run -p musig2-signer --bin scan-recipient <path_to_musig2-sp-final.psbt>");
        std::process::exit(1);
    }
    let psbt_path = PathBuf::from(&args[1]);

    let secp = Secp256k1::new();
    let psbt_bytes = fs::read(&psbt_path).context("Failed to read PSBT file")?;
    let psbt = SilentPaymentPsbt::deserialize(&psbt_bytes).context("Failed to parse PSBT")?;
    println!("Loaded PSBT from {}", psbt_path.display());

    // Recipient-visible input data: input pubkeys (eligible inputs) + all outpoints.
    let mut input_pks: Vec<PublicKey> = Vec::new();
    let mut outpoints: Vec<(String, u32)> = Vec::new();
    for i in 0..psbt.num_inputs() {
        outpoints.push((
            get_input_txid(&psbt, i)
                .map_err(|e| anyhow::anyhow!("input txid: {e}"))?
                .to_string(),
            get_input_vout(&psbt, i).map_err(|e| anyhow::anyhow!("input vout: {e}"))?,
        ));
        if is_input_eligible(&psbt.inputs[i]) {
            input_pks.push(get_input_pubkey(&psbt, i).map_err(|e| anyhow::anyhow!("input pubkey: {e}"))?);
        }
    }
    if input_pks.is_empty() {
        bail!("no eligible inputs to derive tweak data");
    }
    let input_pk_refs: Vec<&PublicKey> = input_pks.iter().collect();
    let tweak_data = calculate_tweak_data(&input_pk_refs, &outpoints)
        .map_err(|e| anyhow::anyhow!("calculate tweak data: {e}"))?;

    // Candidate P2TR outputs to scan against.
    let mut candidates: Vec<(usize, XOnlyPublicKey, u64)> = Vec::new();
    for i in 0..psbt.num_outputs() {
        let spk = &psbt.outputs[i].script_pubkey;
        if spk.is_p2tr() {
            let xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])
                .map_err(|e| anyhow::anyhow!("output {i} x-only: {e}"))?;
            candidates.push((i, xonly, psbt.outputs[i].amount.to_sat()));
        }
    }
    let candidate_xonly: Vec<XOnlyPublicKey> = candidates.iter().map(|(_, x, _)| *x).collect();

    println!(
        "Scanning {} candidate P2TR output(s) for {} known recipient(s)\n",
        candidate_xonly.len(),
        RECIPIENT_SEEDS.len()
    );

    let mut all_detected = true;
    for (idx, (seed, expected_amount)) in RECIPIENT_SEEDS.iter().enumerate() {
        let (scan_sk, spend_sk) = recipient_keys(seed);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let receiver = Receiver::new(SpVersion::ZERO, scan_pk, spend_pk, Label::new(scan_sk, 0), Network::Mainnet)
            .map_err(|e| anyhow::anyhow!("Receiver::new: {e}"))?;

        let ecdh = calculate_ecdh_shared_secret(&tweak_data, &scan_sk);
        let found = receiver
            .scan_transaction(&ecdh, &candidate_xonly)
            .map_err(|e| anyhow::anyhow!("scan_transaction: {e}"))?;

        let detected: Vec<XOnlyPublicKey> =
            found.values().flat_map(|m| m.keys().copied()).collect();

        if detected.is_empty() {
            println!("  recipient[{idx}] (expected {} sats): NOT DETECTED", expected_amount);
            all_detected = false;
            continue;
        }

        for xonly in detected {
            match candidates.iter().find(|(_, x, _)| *x == xonly) {
                Some((out_idx, _, amount)) => {
                    let amount_ok = amount == expected_amount;
                    println!(
                        "  recipient[{idx}] -> output[{out_idx}] {} sats{} (key {})",
                        amount,
                        if amount_ok { "" } else { " [AMOUNT MISMATCH]" },
                        hex::encode(xonly.serialize()),
                    );
                    if !amount_ok {
                        all_detected = false;
                    }
                }
                None => {
                    println!("  recipient[{idx}] -> detected key not among tx outputs");
                    all_detected = false;
                }
            }
        }
    }

    println!();
    if !all_detected {
        bail!("one or more recipients could not detect their output — outputs are NOT discoverable");
    }
    println!("All {} recipient(s) detected their output — outputs are discoverable", RECIPIENT_SEEDS.len());
    Ok(())
}
