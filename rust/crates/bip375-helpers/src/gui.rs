//! GUI helper utilities
//!
//! Shared GUI functionality for BIP-375 applications

use bip375_core::SilentPaymentPsbt;

// Re-export the export function from psbt_io for convenience
pub use crate::display::psbt_io::export_psbt_with_dialog;

/// Export a PSBT with error handling suitable for GUI callbacks
///
/// This is a convenience wrapper around `export_psbt_with_dialog` that
/// prints error messages to stderr and returns nothing, making it suitable
/// for use directly in GUI callback closures.
///
/// # Arguments
/// * `psbt_opt` - Optional PSBT to export
pub fn export_psbt_callback(psbt_opt: Option<&SilentPaymentPsbt>) {
    match psbt_opt {
        Some(psbt) => {
            if let Err(e) = export_psbt_with_dialog(psbt) {
                eprintln!("❌ Export error: {}", e);
            }
        }
        None => {
            eprintln!("❌ No PSBT to export");
        }
    }
}
