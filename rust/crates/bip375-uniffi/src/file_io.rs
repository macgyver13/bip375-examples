// File I/O operations for UniFFI bindings

use crate::errors::Bip375Error;
use crate::types::{PsbtMetadata, SilentPaymentPsbt};
use bip375_io as io;
use std::path::Path;

// ============================================================================
// File I/O Functions
// ============================================================================

pub fn file_io_save_psbt(
    psbt: &SilentPaymentPsbt,
    path: String,
    metadata: Option<PsbtMetadata>,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let meta = metadata.as_ref().map(|m| m.to_core());
        io::file_io::save_psbt(p, Path::new(&path), meta.as_ref())
    })?;
    Ok(())
}

pub fn file_io_load_psbt(path: String) -> Result<SilentPaymentPsbt, Bip375Error> {
    let psbt = io::file_io::load_psbt(Path::new(&path))?;
    Ok(SilentPaymentPsbt {
        inner: std::sync::Arc::new(std::sync::Mutex::new(psbt)),
    })
}

pub fn file_io_save_psbt_binary(psbt: &SilentPaymentPsbt, path: String) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| io::file_io::save_psbt_binary(p, Path::new(&path)))?;
    Ok(())
}

pub fn file_io_load_psbt_binary(path: String) -> Result<SilentPaymentPsbt, Bip375Error> {
    let psbt = io::file_io::load_psbt_binary(Path::new(&path))?;
    Ok(SilentPaymentPsbt {
        inner: std::sync::Arc::new(std::sync::Mutex::new(psbt)),
    })
}

pub fn file_io_save_psbt_json(
    psbt: &SilentPaymentPsbt,
    path: String,
    metadata: Option<PsbtMetadata>,
) -> Result<(), Bip375Error> {
    psbt.with_inner(|p| {
        let meta = metadata.map(|m| m.to_core()).unwrap_or_default();
        io::file_io::save_psbt_with_metadata(p, Path::new(&path), Some(&meta))
    })?;
    Ok(())
}

pub fn file_io_load_psbt_json(path: String) -> Result<SilentPaymentPsbt, Bip375Error> {
    let psbt = io::file_io::load_psbt(Path::new(&path))?;
    Ok(SilentPaymentPsbt {
        inner: std::sync::Arc::new(std::sync::Mutex::new(psbt)),
    })
}
