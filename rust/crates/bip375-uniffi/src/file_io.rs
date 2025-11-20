// File I/O operations for UniFFI bindings

use crate::errors::Bip375Error;
use crate::types::{PsbtMetadata, SilentPaymentPsbt};
use bip375_io as io;
use std::path::Path;

// ============================================================================
// File I/O Functions
// ============================================================================

pub fn file_io_save_psbt(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    metadata: Option<PsbtMetadata>,
    path: String,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let meta = metadata.map(|m| m.to_core());
        io::file_io::save_psbt(p, meta, Path::new(&path))
    })?;
    Ok(())
}

pub fn file_io_load_psbt(path: String) -> Result<std::sync::Arc<SilentPaymentPsbt>, Bip375Error> {
    let (psbt, _metadata) = io::file_io::load_psbt(Path::new(&path))?;
    Ok(std::sync::Arc::new(SilentPaymentPsbt::from_core(psbt)))
}
