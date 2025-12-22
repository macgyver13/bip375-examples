//! Multi-Signer Example - Main Entry Point
//!
//! Demonstrates flexible multi-party signing workflow with progressive ECDH coverage.
//! Supports both GUI and CLI modes.

use bip375_helpers::display::psbt_io::set_use_memory_storage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    set_use_memory_storage(true);

    let args: Vec<String> = std::env::args().collect();

    // Check for --cli flag
    if args.contains(&"--cli".to_string()) {
        // CLI mode
        multi_signer::cli::run_cli()?;
    } else {
        // GUI mode (default)
        #[cfg(feature = "gui")]
        {
            multi_signer::gui::run_gui()?;
        }
        #[cfg(not(feature = "gui"))]
        {
            eprintln!("GUI feature not enabled. Run with --cli flag for CLI mode.");
            eprintln!("Or run with: cargo r --features gui");
            std::process::exit(1);
        }
    }

    Ok(())
}
