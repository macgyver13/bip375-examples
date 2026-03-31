//! Multisig SP Payroll Demo — Round Trip
//!
//! Demonstrates two consecutive payroll periods from a P2WSH 3-of-4 multisig
//! treasury alongside a P2WPKH sidecar input to 5 silent payment recipients.
//!
//! Period 1: Bootstrap UTXOs → pays 5 employees → produces treasury + sidecar change.
//! Period 2: Period 1 change outputs → pays same 5 employees again.
//!           Same recipients, different P2TR output scripts (different input hash
//!           from real outpoints = different ECDH shared secret = privacy preserved).
//!
//! BIP-352 excludes script multisig inputs from the ECDH-eligible input set.
//! The sidecar (key S(Sidecar), held by the coordinator) provides the public key for
//! shared secret derivation. Multisig signers verify the coordinator's DLEQ
//! proof before signing — binding spending security (3-of-4) to payment
//! correctness (coordinator cannot forge ECDH shares undetected).
//!
//! Transaction layout (both periods):
//!   Inputs:  [0] wsh(sortedmulti(3,A,B,C,D)) — treasury
//!            [1] P2WPKH (sidecar)             — 5 000 sats
//!   Outputs: [0-N] silent payment outputs     — per-employee amount
//!            [N]   P2WPKH change to sidecar   — 5 000 sats (self-replenishing)
//!            [N+1] Treasury change             — dynamic
//!   Fee:     50 000 sats

mod p2wsh;

use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, PublicKey as BitcoinPubKey, ScriptBuf, Sequence, TxIn,
    TxOut, Txid, Witness,
};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};
use spdk_core::psbt::{
    core::{Bip375PsbtExt, EcdhShareData, PsbtInput, PsbtOutput, SilentPaymentPsbt},
    crypto::{compute_ecdh_share, dleq_generate_proof, pubkey_to_p2wpkh_script},
    roles::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
        extractor::extract_transaction,
        input_finalizer::finalize_sp_outputs,
        signer::sign_inputs,
        updater::{add_input_bip32_derivation, Bip32Derivation},
        validation::{validate_psbt, validate_ready_for_extraction, ValidationLevel},
    },
};

const TREASURY_AMOUNT: u64 = 2_000_000;
const SIDECAR_AMOUNT: u64 = 5_000;
const FEE_AMOUNT: u64 = 50_000;

struct Keys {
    alice_sk: SecretKey,
    _alice_pk: PublicKey,
    bob_sk: SecretKey,
    _bob_pk: PublicKey,
    charlie_sk: SecretKey,
    _charlie_pk: PublicKey,
    dave_sk: SecretKey,
    _dave_pk: PublicKey,
    /// Coordinator sidecar key (private key only needs to be held by coordinator)
    sidecar_sk: SecretKey,
    sidecar_pk: PublicKey,
    sidecar_p2wpkh: ScriptBuf,
    redeem_script: ScriptBuf,
    p2wsh_script: ScriptBuf,
    recipients: Vec<(SilentPaymentAddress, Amount)>,
    scan_keys: Vec<PublicKey>,
}

/// UTXO consumed as a PSBT input.
#[derive(Copy, Clone)]
struct Utxo {
    outpoint: OutPoint,
    amount: Amount,
}

/// Returns the payroll list used for demo purposes.
///
/// Each entry is a (SilentPaymentAddress, Amount) pair.
#[allow(dead_code)]
fn demo_payroll(secp: &Secp256k1<secp256k1::All>) -> Result<Vec<(SilentPaymentAddress, Amount)>> {
    const RECIPIENT_AMOUNTS: [u64; 5] = [180_000, 160_000, 150_000, 140_000, 120_000];

    let mut payroll = Vec::new();
    for i in 0..RECIPIENT_AMOUNTS.len() {
        let scan_sk = SecretKey::from_slice(&[(0x10 + i) as u8; 32])?;
        let spend_sk = SecretKey::from_slice(&[(0x20 + i) as u8; 32])?;
        let scan_pk = PublicKey::from_secret_key(secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(secp, &spend_sk);
        let addr = SilentPaymentAddress::new(scan_pk, spend_pk, SpNetwork::Mainnet, 0)
            .map_err(|e| anyhow::anyhow!("SP address {i}: {e}"))?;
        payroll.push((addr, Amount::from_sat(RECIPIENT_AMOUNTS[i])));
    }

    Ok(payroll)
}

fn real_payroll() -> Result<Vec<(SilentPaymentAddress, Amount)>> {
    let mut payroll = Vec::new();
    payroll.push((SilentPaymentAddress::try_from("sp1qqw5jexmu4358tr090qld3egjxkvwftgnwzg7g2v86wad3gywxkln6qcc0kmh5k03cheul53fd7r7h4lg9y3xkrmz3k00ujulyg2pfcaevu9nurf3")?,
                                Amount::from_sat(180_000)));
    payroll.push((SilentPaymentAddress::try_from("sp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65q5dw5qd6nqjdpw3745tfs44qj8g2d9cwvce7w5d4fsjk353xtk87usyph5m")?,
                                Amount::from_sat(160_000)));
    payroll.push((SilentPaymentAddress::try_from("sp1qqd3kp6zkxyxwt555azlr8lyqwpmac44vsrv4m8x5mk7jzvj7laelwqjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyuxa95mc")?,
                                Amount::from_sat(150_000)));
    payroll.push((SilentPaymentAddress::try_from("sp1qqvw3v3fm82e3x2ktpfduzmxyj6gdsxd9s5n859wdtgryu2s26szejqlpraq2766p7j2tl0p8c3ap0r89wt5t3jng0nr8uy5c29yxrtz7fqjm956u")?,
                                Amount::from_sat(140_000)));
    payroll.push((SilentPaymentAddress::try_from("sp1qq0lc4k44yc3mevn30lr36lkuda27nqukumprfhlsruc85y4j4uwfjqseeexsaan3pta0v2j7mk888x7s2xvgy0n7vmc9maqumr6pp09kv53u7h0t")?,
                                Amount::from_sat(120_000)));
    Ok(payroll)
}

fn setup_keys(
    secp: &Secp256k1<secp256k1::All>,
    payroll: Vec<(SilentPaymentAddress, Amount)>,
) -> Result<Keys> {
    let alice_sk = SecretKey::from_slice(&[0xaa; 32])?;
    let bob_sk = SecretKey::from_slice(&[0xbb; 32])?;
    let charlie_sk = SecretKey::from_slice(&[0xcc; 32])?;
    let dave_sk = SecretKey::from_slice(&[0xdd; 32])?;
    let sidecar_sk = SecretKey::from_slice(&[0xee; 32])?;

    let alice_pk = PublicKey::from_secret_key(secp, &alice_sk);
    let bob_pk = PublicKey::from_secret_key(secp, &bob_sk);
    let charlie_pk = PublicKey::from_secret_key(secp, &charlie_sk);
    let dave_pk = PublicKey::from_secret_key(secp, &dave_sk);
    let sidecar_pk = PublicKey::from_secret_key(secp, &sidecar_sk);

    let sidecar_p2wpkh = pubkey_to_p2wpkh_script(&sidecar_pk);
    let redeem_script =
        p2wsh::create_sortedmulti_script(3, &[alice_pk, bob_pk, charlie_pk, dave_pk]);
    let p2wsh_script = p2wsh::p2wsh_from_redeem(&redeem_script);

    let scan_keys = payroll.iter().map(|(addr, _)| addr.get_scan_key()).collect();

    Ok(Keys {
        alice_sk,
        _alice_pk: alice_pk,
        bob_sk,
        _bob_pk: bob_pk,
        charlie_sk,
        _charlie_pk: charlie_pk,
        dave_sk,
        _dave_pk: dave_pk,
        sidecar_sk,
        sidecar_pk,
        sidecar_p2wpkh,
        redeem_script,
        p2wsh_script,
        recipients: payroll,
        scan_keys,
    })
}

fn build_unsigned_tx(psbt: &SilentPaymentPsbt) -> bitcoin::Transaction {
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
            value: o.amount,
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    bitcoin::Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: inputs,
        output: outputs,
    }
}

/// Run one payroll period: build, sign, and extract a PSBT paying all employees.
///
/// `treasury` and `sidecar` are the input UTXOs for this period. The treasury
/// change (output[N+1]) and sidecar replenishment (output[N]) become the inputs
/// for the next period.
fn run_payroll(
    secp: &Secp256k1<secp256k1::All>,
    keys: &Keys,
    treasury: Utxo,
    sidecar: Utxo,
    signers: &[(&str, SecretKey)],
) -> Result<bitcoin::Transaction> {
    let num_recipients = keys.recipients.len();
    let total_payment: u64 = keys.recipients.iter().map(|(_, a)| a.to_sat()).sum();
    // treasury change = total_in - payments - fee; sidecar self-replenishes at same amount
    let treasury_change_sat = treasury.amount.to_sat() - total_payment - FEE_AMOUNT;

    // ── Create PSBT (Creator + Constructor + Updater) ─────────────────────────
    let mut psbt = create_psbt(2, num_recipients + 2);

    let psbt_inputs = vec![
        // Input[0]: P2WSH multisig treasury (no private key — threshold signed below)
        PsbtInput::new(
            treasury.outpoint,
            TxOut {
                value: treasury.amount,
                script_pubkey: keys.p2wsh_script.clone(),
            },
            Sequence::MAX,
            None,
        ),
        // Input[1]: P2WPKH sidecar — private key used for ECDH shared secret derivation
        PsbtInput::new(
            sidecar.outpoint,
            TxOut {
                value: sidecar.amount,
                script_pubkey: keys.sidecar_p2wpkh.clone(),
            },
            Sequence::MAX,
            Some(keys.sidecar_sk),
        ),
    ];

    let mut psbt_outputs: Vec<PsbtOutput> = keys
        .recipients
        .iter()
        .map(|(addr, amount)| PsbtOutput::silent_payment(*amount, addr.clone(), None))
        .collect();
    // Output[N]: sidecar replenishment — same amount keeps the sidecar funded next period
    psbt_outputs.push(PsbtOutput::regular(
        Amount::from_sat(SIDECAR_AMOUNT),
        keys.sidecar_p2wpkh.clone(),
    ));
    // Output[N+1]: treasury change
    psbt_outputs.push(PsbtOutput::regular(
        Amount::from_sat(treasury_change_sat),
        keys.p2wsh_script.clone(),
    ));

    add_inputs(&mut psbt, &psbt_inputs)?;
    add_outputs(&mut psbt, &psbt_outputs)?;

    // Updater: BIP32 derivation for sidecar input so DLEQ verification can find sidecar_pk
    add_input_bip32_derivation(
        &mut psbt,
        1,
        &keys.sidecar_pk,
        &Bip32Derivation::new([0xde, 0xad, 0xbe, 0xef], vec![0]),
    )?;
    // Updater: witness_script on the P2WSH input for signers to inspect
    psbt.inputs[0].witness_script = Some(keys.redeem_script.clone());

    // ── Sidecar ECDH (Coordinator) ────────────────────────────────────────────
    // Global shares: coordinator computes sidecar_sk * scan_key_i for each recipient.
    // P2WSH is BIP-352 ineligible so global shares bypass the per-input coverage check.
    for (i, scan_key) in keys.scan_keys.iter().enumerate() {
        let share = compute_ecdh_share(secp, &keys.sidecar_sk, scan_key)
            .map_err(|e| anyhow::anyhow!("ECDH share {i}: {e}"))?;
        let mut rand_aux = [0u8; 32];
        OsRng.fill_bytes(&mut rand_aux);
        let dleq_proof =
            dleq_generate_proof(secp, &keys.sidecar_sk, scan_key, &rand_aux, None)
                .map_err(|e| anyhow::anyhow!("DLEQ proof {i}: {e}"))?;
        psbt.add_global_ecdh_share(&EcdhShareData::new(*scan_key, share, Some(dleq_proof)))?;
    }

    // ── Derive SP output scripts ──────────────────────────────────────────────
    finalize_sp_outputs(secp, &mut psbt)?;

    // ── Signing ───────────────────────────────────────────────────────────────
    // Build unsigned tx once — all multisig signers use it for sighash computation
    let unsigned_tx = build_unsigned_tx(&psbt);

    for (name, sk) in signers {
        validate_psbt(secp, &psbt, ValidationLevel::Full)
            .map_err(|e| anyhow::anyhow!("{name} validation failed: {e}"))?;

        let sig = p2wsh::sign_p2wsh_input(
            secp,
            &unsigned_tx,
            0,
            &keys.redeem_script,
            treasury.amount,
            sk,
        )?;
        psbt.inputs[0]
            .partial_sigs
            .insert(BitcoinPubKey::new(PublicKey::from_secret_key(secp, sk)), sig);
        println!("    {name} signed (DLEQ + output scripts verified) ✓");
    }

    // Coordinator signs the P2WPKH sidecar
    sign_inputs(secp, &mut psbt, &psbt_inputs)?;
    println!("    Coordinator signed sidecar (P2WPKH) ✓");

    // ── Witness finalization ──────────────────────────────────────────────────
    // P2WSH: [OP_0, sig_A, sig_B, sig_C, redeem_script]
    let p2wsh_witness = p2wsh::build_p2wsh_multisig_witness(
        &psbt.inputs[0].partial_sigs,
        &keys.redeem_script,
        3,
    )?;
    psbt.inputs[0].final_script_witness = Some(p2wsh_witness);

    // P2WPKH sidecar: [sig, pubkey]
    let sidecar_sigs = psbt.get_input_partial_sigs(1);
    if sidecar_sigs.len() != 1 {
        anyhow::bail!("expected 1 sidecar sig, got {}", sidecar_sigs.len());
    }
    let (pubkey_bytes, sig_bytes) = &sidecar_sigs[0];
    let mut sidecar_witness = Witness::new();
    sidecar_witness.push(sig_bytes);
    sidecar_witness.push(pubkey_bytes);
    psbt.inputs[1].final_script_witness = Some(sidecar_witness);

    // Clear intermediate signing fields (BIP-174 finalizer convention)
    psbt.inputs[0].partial_sigs.clear();
    psbt.inputs[0].witness_script = None;
    psbt.inputs[1].partial_sigs.clear();
    psbt.inputs[1].bip32_derivations.clear();

    // ── Extract transaction ───────────────────────────────────────────────────
    validate_ready_for_extraction(&psbt)?;
    let tx = extract_transaction(&psbt)?;

    Ok(tx)
}

fn print_tx_summary(tx: &bitcoin::Transaction, keys: &Keys, total_in: u64) {
    let num_recipients = keys.recipients.len();
    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    println!("  txid:    {}", tx.compute_txid());
    println!("  inputs:  {} (P2WSH treasury + P2WPKH sidecar)", tx.input.len());
    println!(
        "  outputs: {} ({} SP payments + 1 sidecar change + 1 treasury change)",
        tx.output.len(),
        num_recipients
    );
    for (i, out) in tx.output.iter().enumerate() {
        if i < num_recipients {
            println!(
                "    [{}] {:>10} sats  employee SP (P2TR: {})",
                i,
                out.value.to_sat(),
                out.script_pubkey.is_p2tr()
            );
        } else if out.script_pubkey.is_p2wpkh() {
            println!("    [{}] {:>10} sats  sidecar replenishment", i, out.value.to_sat());
        } else {
            println!("    [{}] {:>10} sats  treasury change", i, out.value.to_sat());
        }
    }
    println!("  fee:     {} sats", total_in - total_out);
}

fn main() -> Result<()> {
    let secp = Secp256k1::new();

    // ── Setup ─────────────────────────────────────────────────────────────────
    // To pay real recipients, replace `demo_payroll` with your own list of
    // (SilentPaymentAddress, Amount) pairs — see the doc comment on demo_payroll.
    let payroll = real_payroll()?;
    // let payroll = demo_payroll(&secp)?;
    let keys = setup_keys(&secp, payroll)?;

    println!("Multisig signers (3-of-4): Alice, Bob, Charlie, Dave");
    println!(
        "Coordinator sidecar key:   {}",
        hex::encode(&keys.sidecar_pk.serialize()[1..5])
    );
    println!("{} SP recipients", keys.recipients.len());

    // ── Period 1: Bootstrap UTXOs ─────────────────────────────────────────────
    println!("\n── Period 1 ─────────────────────────────────────────────────────────────");
    let p1_treasury = Utxo {
        outpoint: OutPoint::new(Txid::all_zeros(), 0),
        amount: Amount::from_sat(TREASURY_AMOUNT),
    };
    let p1_sidecar = Utxo {
        outpoint: OutPoint::new(Txid::all_zeros(), 1),
        amount: Amount::from_sat(SIDECAR_AMOUNT),
    };
    let tx1 = run_payroll(&secp, &keys, p1_treasury, p1_sidecar, &[
        ("Alice",   keys.alice_sk),
        ("Bob",     keys.bob_sk),
        ("Charlie", keys.charlie_sk),
    ])?;
    print_tx_summary(&tx1, &keys, TREASURY_AMOUNT + SIDECAR_AMOUNT);

    // ── Period 2: Inputs are Period 1 change outputs ──────────────────────────
    // Output[N]   = sidecar replenishment (P2WPKH)
    // Output[N+1] = treasury change (P2WSH)
    let sidecar_vout = keys.recipients.len() as u32;
    let treasury_vout = sidecar_vout + 1;
    let tx1_txid = tx1.compute_txid();

    println!("\n── Period 2 ─────────────────────────────────────────────────────────────");
    println!("  Spending from period 1 txid: {tx1_txid}");

    let p2_treasury = Utxo {
        outpoint: OutPoint::new(tx1_txid, treasury_vout),
        amount: tx1.output[treasury_vout as usize].value,
    };
    let p2_sidecar = Utxo {
        outpoint: OutPoint::new(tx1_txid, sidecar_vout),
        amount: tx1.output[sidecar_vout as usize].value,
    };
    let p2_total_in = p2_treasury.amount.to_sat() + p2_sidecar.amount.to_sat();
    let tx2 = run_payroll(&secp, &keys, p2_treasury, p2_sidecar, &[
        ("Dave",  keys.dave_sk),
        ("Bob",   keys.bob_sk),
        ("Alice", keys.alice_sk),
    ])?;
    print_tx_summary(&tx2, &keys, p2_total_in);

    // ── Privacy check: same recipients → different output scripts ─────────────
    println!("\n── SP privacy: same recipients, different outputs per period ────────────");
    for i in 0..keys.recipients.len() {
        let s1 = hex::encode(&tx1.output[i].script_pubkey.as_bytes()[..20]);
        let s2 = hex::encode(&tx2.output[i].script_pubkey.as_bytes()[..20]);
        let changed = if s1 != s2 { "changed" } else { "SAME (unexpected!)" };
        println!("  recipient {i}: {s1}... → {s2}... ({changed})");
    }

    println!("\nRound trip complete.");
    Ok(())
}
