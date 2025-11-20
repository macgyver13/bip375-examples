use std::fs;
use std::path::PathBuf;

/// Attempts to load test_vectors.json using a fallback strategy
pub fn load_test_vectors() -> Result<String, String> {
    // Strategy 1: Try to load from bundled resource location
    if let Some(bundled_path) = get_bundled_resource_path() {
        if let Ok(contents) = fs::read_to_string(&bundled_path) {
            return Ok(contents);
        }
    }

    // Strategy 2: Use compile-time embedded version as fallback
    const EMBEDDED_TEST_VECTORS: &str = include_str!("../../../../test_vectors.json");
    Ok(EMBEDDED_TEST_VECTORS.to_string())
}

/// Returns the platform-specific bundled resource path if it exists
fn get_bundled_resource_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        // On macOS, check .app bundle Resources folder
        if let Ok(exe_path) = std::env::current_exe() {
            // Example: /Applications/PSBT Viewer.app/Contents/MacOS/psbt-viewer
            // Resource path: /Applications/PSBT Viewer.app/Contents/Resources/test_vectors.json
            if let Some(contents_dir) = exe_path.parent()?.parent() {
                let resource_path = contents_dir.join("Resources/test_vectors.json");
                if resource_path.exists() {
                    return Some(resource_path);
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        // On Linux/Windows, check adjacent to binary
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let resource_path = exe_dir.join("test_vectors.json");
                if resource_path.exists() {
                    return Some(resource_path);
                }
            }
        }
    }

    None
}

/// Opens a file dialog for manual test vector selection
pub fn browse_for_test_vectors() -> Option<String> {
    let file = rfd::FileDialog::new()
        .add_filter("JSON", &["json"])
        .set_title("Select test_vectors.json")
        .pick_file()?;

    fs::read_to_string(file).ok()
}

/// Opens a file dialog for selecting a binary PSBT file
pub fn browse_for_psbt_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("PSBT", &["psbt"])
        .set_title("Select PSBT file")
        .pick_file()
}
