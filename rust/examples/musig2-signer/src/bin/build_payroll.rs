//! MuSig2 + Silent Payments Fixture Generator
//!
//! Produces two PSBTs and a descriptor for Coldcard simulator integration tests.
//! Reuses the workflow helpers from `workflow.rs`. Alice, Bob, and Charlie use the
//! Coldcard simulator's fixed mnemonic with BIP39 passphrases "", "Me", and "Myself".
//! Their account fingerprints and m/48'/1'/0'/2' origins are wired into the PSBT so
//! three independent simulator instances can locate their keys in both signing rounds.
//!
//! Usage:
//!   cargo run -p musig2-signer --bin payroll [OUTPUT_DIR]
//!
//! Output (default: ./output/, which is gitignored):
//!   musig2-sp-round1-in.psbt        — pre-contribution (participant pubkeys registered, no shares)
//!   musig2-sp-cosigner-contrib.psbt — round 1 + Bob and Charlie's static contributions
//!   desc-musig-sp-demo.txt          — tr(musig(A,B,C)) descriptor for Coldcard enrollment

use anyhow::Result;
use bitcoin::{Amount, Txid};
use hex;
use musig2_signer::workflow;
use secp256k1::Secp256k1;
use silentpayments::SilentPaymentAddress;
use spdk_core::psbt::roles::{
    add_input_tap_bip32_derivation, add_output_tap_bip32_derivation, Bip32Derivation
};

/// Account-level BIP-48 derivation path: m/48'/1'/0'/2'.
const BIP48_ACCOUNT_PATH: [u32; 4] = [
    0x80000030, // 48'
    0x80000001, // 1' (testnet)
    0x80000000, // 0'
    0x80000002, // 2'
];

/// Clearly-fake prevout txid for fixture viewing. The fixtures don't reference
/// a real on-chain UTXO; this just gives PSBT viewers a non-zero
/// PSBT_IN_PREVIOUS_TXID so the input renders.
const FIXTURE_PREV_TXID_HEX: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

struct Cosigner {
    label: &'static str,
    /// Master fingerprint bytes (big-endian, as shown in Coldcard xfp field).
    xfp: [u8; 4],
    /// Extended public key at m/48'/1'/0'/2' from the Coldcard simulator fixed seed.
    xpub_str: &'static str,
}

/// First three Coldcard simulator cosigners (Alice, Bob, Charlie).
/// xpubs from testing/data/multisig/ccxp-*.json in the Coldcard firmware repo.
static COSIGNERS_TEST: [Cosigner; 3] = [
    Cosigner {
        label: "Alice",
        xfp: [0x0f, 0x05, 0x69, 0x43],
        xpub_str: "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP",
    },
    Cosigner {
        label: "Bob",
        xfp: [0x6b, 0xa6, 0xcf, 0xd0],
        xpub_str: "tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm",
    },
    Cosigner {
        label: "Charlie",
        xfp: [0x74, 0x7b, 0x69, 0x8e],
        xpub_str: "tpubDExj5FnaUnPAn7sHGUeBqD3buoNH5dqmjAT6884vbDpH1iDYWigb7kFo2cA97dc8EHb54u13TRcZxC4kgRS9gc3Ey2xc8c5urytEzTcp3ac",
    },
];

fn test_nonce_seed(party: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let bytes = party.as_bytes();
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);
    seed
}

fn real_payroll() -> Result<Vec<(SilentPaymentAddress, Amount)>> {
    Ok(vec![
        (
            SilentPaymentAddress::try_from("sp1qqw5jexmu4358tr090qld3egjxkvwftgnwzg7g2v86wad3gywxkln6qcc0kmh5k03cheul53fd7r7h4lg9y3xkrmz3k00ujulyg2pfcaevu9nurf3")?,
            Amount::from_sat(18_000_000),
        ),
        (
            SilentPaymentAddress::try_from("sp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65q5dw5qd6nqjdpw3745tfs44qj8g2d9cwvce7w5d4fsjk353xtk87usyph5m")?,
            Amount::from_sat(16_000_000),
        ),
        (
            SilentPaymentAddress::try_from("sp1qqd3kp6zkxyxwt555azlr8lyqwpmac44vsrv4m8x5mk7jzvj7laelwqjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyuxa95mc")?,
            Amount::from_sat(150_000_000),
        ),
        (
            SilentPaymentAddress::try_from("sp1qqvw3v3fm82e3x2ktpfduzmxyj6gdsxd9s5n859wdtgryu2s26szejqlpraq2766p7j2tl0p8c3ap0r89wt5t3jng0nr8uy5c29yxrtz7fqjm956u")?,
            Amount::from_sat(10_000_000),
        ),
        (
            SilentPaymentAddress::try_from("sp1qq0lc4k44yc3mevn30lr36lkuda27nqukumprfhlsruc85y4j4uwfjqseeexsaan3pta0v2j7mk888x7s2xvgy0n7vmc9maqumr6pp09kv53u7h0t")?,
            Amount::from_sat(20_000_000),
        ),
    ])
}

/// Build the tr(musig(...)) descriptor for Coldcard enrollment.
fn build_descriptor() -> String {
    let parts: Vec<String> = COSIGNERS_TEST
        .iter()
        .map(|c| {
            let xfp_hex = hex::encode(c.xfp);
            format!("[{}/48h/1h/0h/2h]{}", xfp_hex, c.xpub_str)
        })
        .collect();
    format!("tr(musig({})/0/*)", parts.join(","))
}

fn main() -> Result<()> {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| "output".to_string());
    let out_dir = std::path::Path::new(&out_dir);
    std::fs::create_dir_all(out_dir)?;

    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp)?;
    let recipients = musig2_signer::recipients::recipient_addresses()?;
    // let recipients = real_payroll()?;

    println!("MuSig2 + SP fixture generator");
    println!("Participants:");
    for c in &COSIGNERS_TEST {
        println!("  {} [{}]", c.label, hex::encode(c.xfp));
    }
    println!("{} SP recipients\n", recipients.len());

    // Build pre-contribution PSBT with all SP outputs.
    let mut psbt = workflow::construct_psbt(&keys, &recipients)?;

    psbt.inputs[0].previous_txid =
        FIXTURE_PREV_TXID_HEX.parse::<Txid>().expect("static hex");

    // Register BIP32 derivations (xfp, path) for all MuSig2 participants so the
    // hardware device can match the input and change output to its enrolled wallet.
    let participant_pks = [keys.alice_pk, keys.bob_pk, keys.charlie_pk];
    for (i, cosigner) in COSIGNERS_TEST.iter().enumerate() {
        let (xonly, _) = participant_pks[i].x_only_public_key();
        let derivation = Bip32Derivation::new(cosigner.xfp, BIP48_ACCOUNT_PATH.to_vec());

        // Add PSBT_IN_TAP_BIP32_DERIVATION to the MuSig2 input.
        add_input_tap_bip32_derivation(&mut psbt, 0, &xonly, vec![], &derivation)?;

        // Add PSBT_OUT_TAP_BIP32_DERIVATION to the change output.
        let change_idx = psbt.outputs.len() - 1;
        add_output_tap_bip32_derivation(&mut psbt, change_idx, &xonly, vec![], &derivation)?;
    }

    // Add derivation for the aggregate internal key (P) so the simulator can
    // identify the input as part of the enrolled 3-key wallet.
    let mut agg_xfp = [0u8; 4];
    use bitcoin::hashes::{hash160, Hash};

    // Device expects fingerprint of the account-level aggregate with natural even Y parity
    let mut buf = [0u8; 33];
    buf[0] = 0x02; // even Y parity
    buf[1..].copy_from_slice(&keys.untweaked_agg_pk.serialize()[1..]);
    let agg_hash = hash160::Hash::hash(&buf);
    agg_xfp.copy_from_slice(&agg_hash[..4]);

    println!("DBG: Account-level aggregate PK: {}", keys.untweaked_agg_pk);
    println!("Aggregate internal key fingerprint: {}\n", hex::encode(agg_xfp));

    let agg_derivation = Bip32Derivation::new(agg_xfp, vec![0, 0]);
    add_input_tap_bip32_derivation(&mut psbt, 0, &keys.untweaked_agg_xonly, vec![], &agg_derivation)?;

    // Add PSBT_OUT_TAP_BIP32_DERIVATION to the change output.
    let change_idx = psbt.outputs.len() - 1;
    add_output_tap_bip32_derivation(&mut psbt, change_idx, &keys.untweaked_agg_xonly, vec![], &agg_derivation)?;

    // ── Round 1 PSBT: pre-contribution ───────────────────────────────────────
    let round1_bytes = psbt.serialize();
    let round1_path = out_dir.join("musig2-sp-round1-in.psbt");
    std::fs::write(&round1_path, &round1_bytes)?;
    println!("Wrote {} ({} bytes)", round1_path.display(), round1_bytes.len());

    // ── Contribute: all 3 parties × all scan keys ─────────────
    // Each party contributes one ECDH share per scan key (and one nonce total).
    let scan_keys: Vec<_> = recipients.iter().map(|(addr, _)| addr.get_scan_key()).collect();

    let _nonce = workflow::contribute(
        &secp, &mut psbt, "Bob",
        &keys.bob_sk, &keys.bob_pk, &scan_keys[0],
        &keys.agg_pk, &keys.key_agg_ctx, test_nonce_seed("Bob"),
    )?;
    for sk in &scan_keys[1..] {
        workflow::add_ecdh_share(&secp, &mut psbt, "Bob", &keys.bob_sk, &keys.bob_pk, sk)?;
    }

    let _nonce = workflow::contribute(
        &secp, &mut psbt, "Charlie",
        &keys.charlie_sk, &keys.charlie_pk, &scan_keys[0],
        &keys.agg_pk, &keys.key_agg_ctx, test_nonce_seed("Charlie"),
    )?;
    for sk in &scan_keys[1..] {
        workflow::add_ecdh_share(&secp, &mut psbt, "Charlie", &keys.charlie_sk, &keys.charlie_pk, sk)?;
    }

    // ── Cosigner Contrib PSBT: Bob and Charlie only, no Alice ────────────────
    let cosigner_contrib_bytes = psbt.serialize();
    let cosigner_contrib_path = out_dir.join("musig2-sp-cosigner-contrib.psbt");
    std::fs::write(&cosigner_contrib_path, &cosigner_contrib_bytes)?;
    println!("Wrote {} ({} bytes)", cosigner_contrib_path.display(), cosigner_contrib_bytes.len());

    // ── Alice's Contribution ─────────────────────────────────────────────────
    let _nonce = workflow::contribute(
        &secp, &mut psbt, "Alice",
        &keys.alice_sk, &keys.alice_pk, &scan_keys[0],
        &keys.agg_pk, &keys.key_agg_ctx, test_nonce_seed("Alice"),
    )?;
    for sk in &scan_keys[1..] {
        workflow::add_ecdh_share(&secp, &mut psbt, "Alice", &keys.alice_sk, &keys.alice_pk, sk)?;
    }

    // ── Descriptor ───────────────────────────────────────────────────────────
    let desc = build_descriptor();
    let desc_path = out_dir.join("desc-musig-sp-demo.txt");
    std::fs::write(&desc_path, &desc)?;
    println!("Wrote {}", desc_path.display());
    println!("  {desc}");

    // Coordinator: aggregate per-party ECDH shares and derive SP output scripts.
    workflow::derive_sp_output(&secp, &mut psbt)?;

    // Print computed SP output scripts for visual verification.
    println!("\nSP output scripts ({} recipients):", recipients.len());
    for (i, output) in psbt.outputs.iter().enumerate().take(recipients.len()) {
        let (addr, amount) = &recipients[i];
        println!(
            "  [{i}] {} BTC  {}",
            amount.to_btc(),
            hex::encode(output.script_pubkey.as_bytes()),
        );
        println!("       -> {addr}");
    }

    Ok(())
}
