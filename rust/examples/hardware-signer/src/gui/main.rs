// BIP-375 Hardware Signer - GUI Binary
// Slint-based graphical interface

use bip375_helpers::display::psbt_io::set_use_memory_storage;
use hardware_signer::gui;

fn main() {
    set_use_memory_storage(true);

    // Parse mnemonic from command line
    let args: Vec<String> = std::env::args().collect();
    let mnemonic = parse_mnemonic_arg(&args).unwrap_or_else(|e| {
        eprintln!("❌ Error: {}", e);
        std::process::exit(1);
    });

    gui::run_gui(mnemonic).unwrap();
}

/// Parse --mnemonic argument from command line
fn parse_mnemonic_arg(args: &[String]) -> Result<Option<String>, String> {
    if let Some(pos) = args.iter().position(|arg| arg == "--mnemonic") {
        if let Some(mnemonic) = args.get(pos + 1) {
            if mnemonic.starts_with("--") {
                return Err("--mnemonic requires a value (12 or 24 word phrase)".to_string());
            }
            // Validate word count (12 or 24 words)
            let word_count = mnemonic.split_whitespace().count();
            if word_count != 12 && word_count != 24 {
                return Err(format!(
                    "Invalid mnemonic: expected 12 or 24 words, got {}",
                    word_count
                ));
            }
            Ok(Some(mnemonic.clone()))
        } else {
            Err("--mnemonic requires a value".to_string())
        }
    } else {
        Ok(None)
    }
}
