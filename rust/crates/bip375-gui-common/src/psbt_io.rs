//! PSBT import/export utilities
//!
//! Provides functions for importing PSBTs from various formats (base64, files)
//! and exporting them for sharing or storage.

use bip375_core::SilentPaymentPsbt;
use std::io::Write;

/// Import a PSBT from a base64-encoded string
///
/// # Errors
/// Returns an error if the base64 decoding fails or the PSBT parsing fails.
pub fn import_from_base64(base64_str: &str) -> Result<SilentPaymentPsbt, String> {
    // Remove whitespace
    let cleaned = base64_str.trim().replace(['\n', '\r', ' '], "");

    // Decode base64
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(&cleaned)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // Parse PSBT
    SilentPaymentPsbt::deserialize(&bytes)
        .map_err(|e| format!("PSBT parse error: {:?}", e))
}

/// Export a PSBT to a base64-encoded string
pub fn export_to_base64(psbt: &SilentPaymentPsbt) -> Result<String, String> {
    let bytes = psbt.serialize();

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

/// Load a PSBT from a JSON file
///
/// Uses bip375-io's JSON format with metadata.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file(path: &str) -> Result<(SilentPaymentPsbt, Option<bip375_io::PsbtMetadata>), String> {
    bip375_io::load_psbt_with_metadata(path)
        .map_err(|e| format!("File load error: {}", e))
}

/// Export a PSBT to a JSON file
///
/// Uses bip375-io's JSON format with metadata.
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn export_to_file(psbt: &SilentPaymentPsbt, path: &str) -> Result<(), String> {
    bip375_io::save_psbt_with_metadata(psbt, None, path)
        .map_err(|e| format!("File save error: {}", e))
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
        stdin.write_all(base64_str.as_bytes())
            .map_err(|e| format!("Failed to write to pbcopy: {}", e))?;
    }

    child.wait()
        .map_err(|e| format!("pbcopy failed: {}", e))?;

    Ok(())
}

/// Export PSBT to clipboard (non-macOS platforms)
#[cfg(not(target_os = "macos"))]
pub fn export_to_clipboard(_base64_str: &str) -> Result<(), String> {
    Err("Clipboard export not implemented for this platform".to_string())
}
