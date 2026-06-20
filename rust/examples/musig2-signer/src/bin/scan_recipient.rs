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
use silentpayments::utils::receiving::PublicTweakData;
use silentpayments::utils::OutPoint as SpOutPoint;
use silentpayments::{Network, SpVersion, TransactionInputs, TransactionSharedSecret};
use musig2_signer::sp_musig2::shares::is_input_eligible;
use psbt::roles::signer::extract_eligible_input_pubkey;
use psbt::Psbt as SilentPaymentPsbt;
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

    // Recipient-visible input data: per-vin outpoint, scriptPubKey and (for eligible
    // inputs) the extracted input pubkey — exactly what an indexing server publishes.
    let mut tx_inputs = TransactionInputs::with_capacity(psbt.inputs.len());
    let mut eligible_count = 0usize;
    for input in &psbt.inputs {
        let outpoint = SpOutPoint::from_txid_and_vout(
            input.previous_txid.to_string(),
            input.spent_output_index,
        )
        .map_err(|e| anyhow::anyhow!("outpoint: {e}"))?;
        let spk = input
            .witness_utxo
            .as_ref()
            .map(|u| u.script_pubkey.to_bytes())
            .unwrap_or_default();
        let pubkey = if is_input_eligible(input) {
            eligible_count += 1;
            extract_eligible_input_pubkey(input)
                .map_err(|e| anyhow::anyhow!("input pubkey: {e:?}"))?
        } else {
            None
        };
        tx_inputs.push(outpoint, spk, pubkey);
    }
    if eligible_count == 0 {
        bail!("no eligible inputs to derive tweak data");
    }
    let tweak_data = PublicTweakData::new(&secp, &tx_inputs)
        .map_err(|e| anyhow::anyhow!("calculate tweak data: {e}"))?;

    // Candidate P2TR outputs to scan against.
    let mut candidates: Vec<(usize, XOnlyPublicKey, u64)> = Vec::new();
    for i in 0..psbt.outputs.len() {
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

        let shared_secret =
            TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &scan_sk)
                .map_err(|e| anyhow::anyhow!("shared secret: {e}"))?;
        let found = receiver
            .scan_transaction(&shared_secret, &candidate_xonly)
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
