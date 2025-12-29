//! PSBT import/export utilities
//!
//! Provides functions for importing PSBTs from various formats (base64, files)
//! and exporting them for sharing or storage.

use spdk_core::psbt::io::{load_psbt_with_metadata, save_psbt_with_metadata, PsbtMetadata};
use spdk_core::psbt::SilentPaymentPsbt;

use std::cell::RefCell;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Import a PSBT from a base64-encoded string
///
/// # Errors
/// Returns an error if the base64 decoding fails or the PSBT parsing fails.
pub fn import_from_base64(base64_str: &str) -> Result<SilentPaymentPsbt, String> {
    // Remove whitespace
    let cleaned = base64_str.trim().replace(['\n', '\r', ' '], "");

    // Decode base64
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // Parse PSBT
    SilentPaymentPsbt::deserialize(&bytes).map_err(|e| format!("PSBT parse error: {:?}", e))
}

/// Export a PSBT to a base64-encoded string
pub fn export_to_base64(psbt: &SilentPaymentPsbt) -> Result<String, String> {
    let bytes = psbt.serialize();

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

/// Export a PSBT to a binary file with a save dialog
///
/// Opens a file save dialog with timestamp-based default naming (export_<timestamp>.psbt)
/// and serializes the PSBT to raw binary format.
///
/// # Arguments
/// * `psbt` - The PSBT to export
///
/// # Returns
/// * `Ok(PathBuf)` - Path where the file was saved
/// * `Err(String)` - Error message if export failed or was cancelled
pub fn export_psbt_with_dialog(psbt: &SilentPaymentPsbt) -> Result<PathBuf, String> {
    // Generate timestamp-based default filename
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs();
    let default_name = format!("export_{}.psbt", timestamp);

    // Open save dialog
    let path = rfd::FileDialog::new()
        .add_filter("PSBT", &["psbt"])
        .set_title("Save PSBT file")
        .set_file_name(&default_name)
        .save_file()
        .ok_or_else(|| "Save cancelled".to_string())?;

    // Serialize PSBT to binary
    let psbt_bytes = psbt.serialize();

    // Write to file
    std::fs::write(&path, psbt_bytes).map_err(|e| format!("Failed to write PSBT file: {}", e))?;

    println!("✅ PSBT exported to {}", path.display());
    Ok(path)
}

/// Load a PSBT from a JSON file
///
/// Uses bip375-io's JSON format with metadata.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file(path: &str) -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>), String> {
    load_psbt_with_metadata(path).map_err(|e| format!("File load error: {}", e))
}

/// Export a PSBT to a JSON file
///
/// Uses bip375-io's JSON format with metadata.
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn export_to_file(psbt: &SilentPaymentPsbt, path: &str) -> Result<(), String> {
    save_psbt_with_metadata(psbt, None, path).map_err(|e| format!("File save error: {}", e))
}

/// Export PSBT to clipboard (platform-specific)
///
/// Currently only supports macOS via pbcopy.
#[cfg(target_os = "macos")]
pub fn export_to_clipboard(base64_str: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn pbcopy: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(base64_str.as_bytes())
            .map_err(|e| format!("Failed to write to pbcopy: {}", e))?;
    }

    child.wait().map_err(|e| format!("pbcopy failed: {}", e))?;

    Ok(())
}

/// Export PSBT to clipboard (non-macOS platforms)
#[cfg(not(target_os = "macos"))]
pub fn export_to_clipboard(_base64_str: &str) -> Result<(), String> {
    Err("Clipboard export not implemented for this platform".to_string())
}

/// PSBT file or memory storage
///
/// File paths for PSBT transfer
pub const TRANSFER_FILE: &str = "output/transfer.json";
pub const FINAL_TX_FILE: &str = "output/final_transaction.hex";

thread_local! {
    // Thread-local memory storage for PSBT (GUI mode)
    static PSBT_MEMORY: RefCell<Option<(SilentPaymentPsbt, Option<PsbtMetadata>)>> = const { RefCell::new(None) };
}

/// Set whether to use in-memory storage (for GUI) or file-based storage (for CLI)
pub fn set_use_memory_storage(use_memory: bool) {
    USE_MEMORY_STORAGE.with(|us| *us.borrow_mut() = use_memory);
}

thread_local! {
    // Thread-local flag to control storage mode
    static USE_MEMORY_STORAGE: RefCell<bool> = const { RefCell::new(false) };
}

/// Save PSBT wrapper - uses memory for GUI, files for CLI
pub fn save_psbt(
    psbt: &SilentPaymentPsbt,
    metadata: Option<PsbtMetadata>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let use_memory = USE_MEMORY_STORAGE.with(|us| *us.borrow());

    if use_memory {
        // Store in thread-local memory
        PSBT_MEMORY.with(|pm| {
            *pm.borrow_mut() = Some((psbt.clone(), metadata));
        });
        Ok(PathBuf::from("memory://transfer.psbt"))
    } else {
        // Save to file (CLI mode)
        let path = PathBuf::from(TRANSFER_FILE);
        std::fs::create_dir_all(path.parent().unwrap())?;
        save_psbt_with_metadata(psbt, metadata, &path)?;
        Ok(path)
    }
}

/// Load PSBT wrapper - uses memory for GUI, files for CLI
pub fn load_psbt() -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>), Box<dyn std::error::Error>>
{
    let use_memory = USE_MEMORY_STORAGE.with(|us| *us.borrow());

    if use_memory {
        // Load from thread-local memory
        PSBT_MEMORY.with(|pm| {
            pm.borrow()
                .clone()
                .ok_or_else(|| "No PSBT in memory".into())
        })
    } else {
        // Load from file (CLI mode)
        let path = PathBuf::from(TRANSFER_FILE);
        load_psbt_with_metadata(&path).map_err(|e| format!("Failed to load PSBT: {}", e).into())
    }
}

// Save final transaction
pub fn save_txn(tx_bytes: &Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let use_memory = USE_MEMORY_STORAGE.with(|us| *us.borrow());
    if !use_memory {
        let tx_hex = hex::encode(tx_bytes);
        fs::write(FINAL_TX_FILE, tx_hex)?;
        println!("  Saved final transaction to: {}\n", FINAL_TX_FILE);
    }
    Ok(())
}

/// Verify a file exists
pub fn verify_file_exists(filename: &str) -> Result<(), String> {
    if !Path::new(filename).exists() {
        return Err(format!("File not found: {}", filename));
    }
    Ok(())
}

/// Reset workflow by removing all generated files
pub fn reset_workflow() -> std::io::Result<()> {
    println!("🧹 Resetting workflow...\n");

    let files = [TRANSFER_FILE, FINAL_TX_FILE];

    let mut removed_count = 0;
    for file in &files {
        if Path::new(file).exists() {
            fs::remove_file(file)?;
            println!(
                "   Removed {}",
                Path::new(file).file_name().unwrap().to_str().unwrap()
            );
            removed_count += 1;
        }
    }

    if removed_count == 0 {
        println!("   No workflow files found - already clean");
    } else {
        println!("\n  Workflow reset complete");
    }

    Ok(())
}
