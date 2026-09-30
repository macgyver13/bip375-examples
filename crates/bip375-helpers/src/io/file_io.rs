//! File I/O operations for PSBTs

use super::error::{IoError, Result};
use super::metadata::{PsbtFile, PsbtMetadata};
use psbt_v2::Psbt;
use std::fs;
use std::path::Path;

/// Save a PSBT to a file (binary format)
pub fn save_psbt_binary<P: AsRef<Path>>(psbt: &Psbt, path: P) -> Result<()> {
    let bytes = psbt.serialize();
    fs::write(path, bytes)?;
    Ok(())
}

/// Load a PSBT from a file (binary format)
pub fn load_psbt_binary<P: AsRef<Path>>(path: P) -> Result<Psbt> {
    let bytes = fs::read(path)?;
    let psbt = Psbt::deserialize(&bytes)?;
    Ok(psbt)
}

/// Save a PSBT to a JSON file with metadata
pub fn save_psbt_with_metadata<P: AsRef<Path>>(
    psbt: &Psbt,
    metadata: Option<PsbtMetadata>,
    path: P,
) -> Result<()> {
    // Serialize PSBT to base64
    let psbt_bytes = psbt.serialize();
    let psbt_base64 = base64_encode(&psbt_bytes);

    // Create PSBT file structure
    let psbt_file = if let Some(mut meta) = metadata {
        meta.update_timestamps();
        PsbtFile::with_metadata(psbt_base64, meta)
    } else {
        PsbtFile::new(psbt_base64)
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&psbt_file)?;
    fs::write(path, json)?;

    Ok(())
}

/// Load a PSBT from a JSON file (with or without metadata)
pub fn load_psbt_with_metadata<P: AsRef<Path>>(path: P) -> Result<(Psbt, Option<PsbtMetadata>)> {
    let json = fs::read_to_string(path)?;
    let psbt_file: PsbtFile = serde_json::from_str(&json)?;

    // Decode base64 PSBT
    let psbt_bytes = base64_decode(&psbt_file.psbt)?;
    let psbt = Psbt::deserialize(&psbt_bytes)?;

    Ok((psbt, psbt_file.metadata))
}

/// Save a PSBT in the format determined by file extension
///
/// - `.psbt` -> binary format
/// - `.json` -> JSON format with metadata
pub fn save_psbt<P: AsRef<Path>>(
    psbt: &Psbt,
    metadata: Option<PsbtMetadata>,
    path: P,
) -> Result<()> {
    let path_ref = path.as_ref();

    match path_ref.extension().and_then(|s| s.to_str()) {
        Some("json") => save_psbt_with_metadata(psbt, metadata, path),
        Some("psbt") => save_psbt_binary(psbt, path),
        _ => Err(IoError::InvalidFormat(format!(
            "Unsupported file extension: {}",
            path_ref.display()
        ))),
    }
}

/// Load a PSBT from a file (auto-detect format)
///
/// Tries to parse as JSON first, falls back to binary format.
pub fn load_psbt<P: AsRef<Path>>(path: P) -> Result<(Psbt, Option<PsbtMetadata>)> {
    let path_ref = path.as_ref();

    // Try JSON first
    if let Ok((psbt, metadata)) = load_psbt_with_metadata(path_ref) {
        return Ok((psbt, metadata));
    }

    // Fall back to binary
    let psbt = load_psbt_binary(path_ref)?;
    Ok((psbt, None))
}

/// Encode bytes to base64
fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder =
            base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder
            .write_all(data)
            .expect("writing to Vec<u8> should never fail");
    }
    String::from_utf8(buf).expect("base64 encoding always produces valid UTF-8")
}

/// Decode base64 to bytes
fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| IoError::InvalidFormat(format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use psbt_v2::Creator;
    use tempfile::TempDir;

    fn create_test_psbt() -> Psbt {
        Creator::new().psbt()
    }

    #[test]
    fn test_binary_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.psbt");

        let psbt = create_test_psbt();
        save_psbt_binary(&psbt, &path).unwrap();

        let loaded = load_psbt_binary(&path).unwrap();
        assert_eq!(psbt.inputs.len(), loaded.inputs.len());
        assert_eq!(psbt.outputs.len(), loaded.outputs.len());
    }

    #[test]
    fn test_json_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.json");

        let psbt = create_test_psbt();
        let mut metadata = PsbtMetadata::with_description("test-tx-123");
        metadata.set_creator("Alice");

        save_psbt_with_metadata(&psbt, Some(metadata), &path).unwrap();

        let (loaded_psbt, loaded_meta) = load_psbt_with_metadata(&path).unwrap();
        assert_eq!(psbt.inputs.len(), loaded_psbt.inputs.len());
        assert_eq!(psbt.outputs.len(), loaded_psbt.outputs.len());

        let meta = loaded_meta.unwrap();
        assert_eq!(meta.description.as_deref(), Some("test-tx-123"));
        assert_eq!(meta.creator.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_auto_detect_format() {
        let temp_dir = TempDir::new().unwrap();

        // Test .psbt extension
        let binary_path = temp_dir.path().join("test.psbt");
        let psbt = create_test_psbt();
        save_psbt(&psbt, None, &binary_path).unwrap();
        let (loaded, _) = load_psbt(&binary_path).unwrap();
        assert_eq!(psbt.inputs.len(), loaded.inputs.len());

        // Test .json extension
        let json_path = temp_dir.path().join("test.json");
        save_psbt(&psbt, None, &json_path).unwrap();
        let (loaded, _) = load_psbt(&json_path).unwrap();
        assert_eq!(psbt.inputs.len(), loaded.inputs.len());
    }
}
