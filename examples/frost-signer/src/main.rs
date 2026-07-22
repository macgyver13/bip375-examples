//! 2-of-3 FROST + BIP-375 Silent Payments signer.
//!
//! Run with no arguments for the GUI (default). Pass `--generate` to run the
//! workflow headless and write a discoverable PSBT to disk for testing with the
//! `validate-outputs` tool.

use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoin::Amount;
use frost_signer::workflow;
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::Secp256k1;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut generate = false;
    let mut out_dir: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--generate" => generate = true,
            "--out-dir" => {
                out_dir = Some(PathBuf::from(
                    args.next().context("--out-dir requires a path")?,
                ))
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    if generate {
        return generate_psbt(
            out_dir.unwrap_or_else(|| PathBuf::from("examples/frost-signer/output")),
        );
    }

    #[cfg(feature = "gui")]
    {
        frost_signer::gui::run_gui().map_err(|error| anyhow::anyhow!("GUI error: {error}"))
    }
    #[cfg(not(feature = "gui"))]
    {
        anyhow::bail!("frost-signer requires the `gui` feature (or pass `--generate`)")
    }
}

/// Run the full 2-of-3 flow headless and write the derived (discoverable) PSBT
/// to `<out_dir>/frost-sp.psbt`, with the recipient address + scan key recorded
/// in `<out_dir>/frost-sp.txt` for the `validate-outputs` tool.
fn generate_psbt(out_dir: PathBuf) -> Result<()> {
    let secp = Secp256k1::new();
    let keys = workflow::setup_keys()?;
    let amount = Amount::from_sat(21_000);
    let mut psbt = workflow::construct_psbt(&keys, &[(keys.sp_address, amount)])?;

    let mut rng = StdRng::from_seed([0x37; 32]);
    for key_package in keys
        .key_packages
        .values()
        .take(workflow::MIN_SIGNERS as usize)
    {
        workflow::contribute(
            &secp,
            &mut psbt,
            key_package,
            &keys.public_key_package,
            &mut rng,
        )
        .context("add FROST contribution")?;
    }
    workflow::derive_sp_outputs(&secp, &mut psbt, &keys.public_key_package)
        .context("derive Silent Payment outputs")?;

    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create output directory {}", out_dir.display()))?;
    let psbt_path = out_dir.join("frost-sp.psbt");
    bip375_helpers::io::save_psbt(&psbt, None, &psbt_path)
        .map_err(|error| anyhow::anyhow!("save PSBT: {error}"))?;

    let scan_key = "11".repeat(32);
    let address = keys.sp_address.to_string();
    let sidecar_path = out_dir.join("frost-sp.txt");
    std::fs::write(&sidecar_path, format!("{address}\n{scan_key}\n"))
        .with_context(|| format!("write {}", sidecar_path.display()))?;

    println!("Wrote {}", psbt_path.display());
    println!("Wrote {}", sidecar_path.display());
    println!(
        "\nValidate discoverability with:\n  cargo r -p validate-outputs -- {} --address {address} --scan-key {scan_key}",
        psbt_path.display()
    );
    Ok(())
}
