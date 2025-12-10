use bip375_core::SilentPaymentPsbt;
use bip375_io::{load_psbt_with_metadata, save_psbt_with_metadata, PsbtMetadata};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

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

/// Simple wallet for generating deterministic keys from a seed
pub struct SimpleWallet {
    seed: String,
}

impl SimpleWallet {
    pub fn new(seed: &str) -> Self {
        Self {
            seed: seed.to_string(),
        }
    }

    /// Generate a deterministic private key from the seed
    pub fn input_key_pair(&self, index: u32) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        // Match Python's key derivation: f"{seed}_input_{index}"
        let key_material = format!("{}_input_{}", self.seed, index);
        let mut hasher = Sha256::new();
        hasher.update(key_material.as_bytes());
        let hash = hasher.finalize();

        let privkey = SecretKey::from_slice(&hash).expect("valid private key");
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        (privkey, pubkey)
    }

    /// Generate scan key pair
    ///
    /// Must match Python's Wallet.create_key_pair("scan", 0):
    /// data = f"{self.seed}_scan_0".encode()
    pub fn scan_key_pair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        // Match Python's key derivation: f"{seed}_scan_0"
        let key_material = format!("{}_scan_0", self.seed);
        let mut hasher = Sha256::new();
        hasher.update(key_material.as_bytes());
        let scan_hash = hasher.finalize();

        let scan_privkey = SecretKey::from_slice(&scan_hash).expect("valid scan private key");
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_privkey);

        (scan_privkey, scan_pubkey)
    }

    /// Generate spend key pair
    ///
    /// Must match Python's Wallet.create_key_pair("spend", 0):
    /// data = f"{self.seed}_spend_0".encode()
    pub fn spend_key_pair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        // Match Python's key derivation: f"{seed}_spend_0"
        let key_material = format!("{}_spend_0", self.seed);
        let mut hasher = Sha256::new();
        hasher.update(key_material.as_bytes());
        let spend_hash = hasher.finalize();

        let spend_privkey = SecretKey::from_slice(&spend_hash).expect("valid spend private key");
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_privkey);

        (spend_privkey, spend_pubkey)
    }

    /// Get scan and spend public keys (convenience method)
    pub fn scan_spend_keys(&self) -> (PublicKey, PublicKey) {
        (self.scan_key_pair().1, self.spend_key_pair().1)
    }
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
