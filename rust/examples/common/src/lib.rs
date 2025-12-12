use bip375_core::{SilentPaymentPsbt, Utxo};
use bip375_crypto::{pubkey_to_p2tr_script, pubkey_to_p2wpkh_script, script_type_string};
use bip375_io::{load_psbt_with_metadata, save_psbt_with_metadata, PsbtMetadata};
use bitcoin::{hashes::Hash, Amount, Sequence, Txid};
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

// =============================================================================
// Virtual Wallet - Configurable UTXO Selection
// =============================================================================

/// Script type for UTXOs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    P2WPKH,
    P2TR,
}

impl ScriptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptType::P2WPKH => "P2WPKH",
            ScriptType::P2TR => "P2TR",
        }
    }
}

/// Virtual UTXO with metadata for display and selection
#[derive(Debug, Clone)]
pub struct VirtualUtxo {
    pub id: usize,
    pub utxo: Utxo,
    pub script_type: ScriptType,
    pub description: String,
    pub has_sp_tweak: bool,      // Is it a received silent payment?
    pub tweak: Option<[u8; 32]>, // The tweak data if SP output
}

/// Virtual wallet containing a pool of pre-generated UTXOs
pub struct VirtualWallet {
    utxos: Vec<VirtualUtxo>,
    wallet_seed: String,
}

impl VirtualWallet {
    /// Create a new virtual wallet with pre-populated UTXOs
    ///
    /// # Arguments
    /// * `wallet_seed` - Seed for generating deterministic keys
    /// * `utxo_configs` - List of (amount, script_type, has_sp_tweak) configurations
    pub fn new(wallet_seed: &str, utxo_configs: &[(u64, ScriptType, bool)]) -> Self {
        let wallet = SimpleWallet::new(wallet_seed);
        let secp = Secp256k1::new();

        let utxos = utxo_configs
            .iter()
            .enumerate()
            .map(|(idx, &(amount, script_type, has_sp_tweak))| {
                // For Silent Payment UTXOs, use the spend key (not input key)
                // This matches the BIP-352 protocol where SP outputs are created
                // by tweaking the spend public key
                let (privkey, pubkey) = if has_sp_tweak {
                    wallet.spend_key_pair()
                } else {
                    wallet.input_key_pair(idx as u32)
                };

                // If this is a silent payment output, apply a demo tweak to the pubkey
                let (final_pubkey, tweak) = if has_sp_tweak {
                    // Generate a deterministic tweak for this UTXO
                    let tweak = Self::generate_demo_tweak(idx);
                    let tweaked_privkey = bip375_crypto::apply_tweak_to_privkey(&privkey, &tweak)
                        .expect("Valid tweak");
                    let tweaked_pubkey = PublicKey::from_secret_key(&secp, &tweaked_privkey);
                    (tweaked_pubkey, Some(tweak))
                } else {
                    (pubkey, None)
                };

                let script_pubkey = match script_type {
                    ScriptType::P2WPKH => pubkey_to_p2wpkh_script(&final_pubkey),
                    ScriptType::P2TR => pubkey_to_p2tr_script(&final_pubkey),
                };

                let description = match (script_type, has_sp_tweak) {
                    (ScriptType::P2WPKH, false) => "Standard SegWit (P2WPKH)".to_string(),
                    (ScriptType::P2TR, false) => "Taproot (P2TR)".to_string(),
                    (ScriptType::P2TR, true) => "Received Silent Payment (P2TR)".to_string(),
                    (ScriptType::P2WPKH, true) => {
                        "Invalid: P2WPKH cannot be SP".to_string() // SP requires P2TR
                    }
                };

                // Generate a unique TXID for each UTXO
                let txid_bytes = Self::generate_demo_txid(idx);
                let txid = Txid::from_slice(&txid_bytes).expect("valid txid");

                VirtualUtxo {
                    id: idx,
                    utxo: Utxo::new(
                        txid,
                        0,
                        Amount::from_sat(amount),
                        script_pubkey,
                        None, // Private key set later when signing
                        Sequence::from_consensus(0xfffffffe),
                    ),
                    script_type,
                    description,
                    has_sp_tweak,
                    tweak,
                }
            })
            .collect();

        Self {
            utxos,
            wallet_seed: wallet_seed.to_string(),
        }
    }

    /// Create default hardware wallet virtual wallet
    pub fn hardware_wallet_default() -> Self {
        Self::new(
            "hardware_wallet_coldcard_demo",
            &[
                (50_000, ScriptType::P2WPKH, false),  // ID 0
                (100_000, ScriptType::P2TR, true),    // ID 1 - SP
                (150_000, ScriptType::P2WPKH, false), // ID 2
                (200_000, ScriptType::P2TR, true),    // ID 3 - SP
                (75_000, ScriptType::P2WPKH, false),  // ID 4
                (300_000, ScriptType::P2TR, true),    // ID 5 - SP
                (125_000, ScriptType::P2WPKH, false), // ID 6
                (250_000, ScriptType::P2TR, false),   // ID 7
            ],
        )
    }

    /// Create default multi-signer virtual wallet (per-party wallets)
    pub fn multi_signer_wallet(party_seed: &str) -> Self {
        Self::new(
            party_seed,
            &[
                (100_000, ScriptType::P2WPKH, false), // ID 0
                (150_000, ScriptType::P2TR, false),   // ID 1
                (200_000, ScriptType::P2WPKH, false), // ID 2
                (75_000, ScriptType::P2TR, false),    // ID 3
            ],
        )
    }

    /// Get all available UTXOs
    pub fn list_utxos(&self) -> &[VirtualUtxo] {
        &self.utxos
    }

    /// Select UTXOs by IDs and return cloned Utxo objects
    pub fn select_by_ids(&self, ids: &[usize]) -> Vec<Utxo> {
        ids.iter()
            .filter_map(|id| self.utxos.iter().find(|u| u.id == *id))
            .map(|vu| vu.utxo.clone())
            .collect()
    }

    /// Get UTXO by ID
    pub fn get_utxo(&self, id: usize) -> Option<&VirtualUtxo> {
        self.utxos.iter().find(|u| u.id == id)
    }

    /// Get total amount for selected UTXOs
    pub fn total_amount(&self, ids: &[usize]) -> u64 {
        ids.iter()
            .filter_map(|id| self.get_utxo(*id))
            .map(|vu| vu.utxo.amount.to_sat())
            .sum()
    }

    /// Get the wallet seed
    pub fn wallet_seed(&self) -> &str {
        &self.wallet_seed
    }

    /// Get private key for a UTXO ID (for signing)
    pub fn get_privkey(&self, id: usize) -> Option<SecretKey> {
        let wallet = SimpleWallet::new(&self.wallet_seed);
        if id < self.utxos.len() {
            Some(wallet.input_key_pair(id as u32).0)
        } else {
            None
        }
    }

    /// Generate a deterministic tweak for demo purposes
    fn generate_demo_tweak(index: usize) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(format!("demo_sp_tweak_{}", index).as_bytes());
        let hash = hasher.finalize();
        let mut tweak = [0u8; 32];
        tweak.copy_from_slice(&hash);
        tweak
    }

    /// Generate a deterministic TXID for demo purposes
    fn generate_demo_txid(index: usize) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(format!("demo_txid_{}", index).as_bytes());
        let hash = hasher.finalize();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash);
        txid
    }
}

/// Transaction configuration for demos
#[derive(Debug, Clone)]
pub struct TransactionConfig {
    pub selected_utxo_ids: Vec<usize>,
    pub recipient_amount: u64,
    pub change_amount: u64,
    pub fee: u64,
}

impl TransactionConfig {
    /// Create a new transaction configuration
    pub fn new(
        selected_utxo_ids: Vec<usize>,
        recipient_amount: u64,
        change_amount: u64,
        fee: u64,
    ) -> Self {
        Self {
            selected_utxo_ids,
            recipient_amount,
            change_amount,
            fee,
        }
    }

    /// Default configuration for hardware wallet (mimics current behavior)
    pub fn hardware_wallet_auto() -> Self {
        Self {
            selected_utxo_ids: vec![1, 2], // 1 SP + 1 P2WPKH
            recipient_amount: 195_000,
            change_amount: 50_000,
            fee: 5_000,
        }
    }

    /// Default configuration for multi-signer
    pub fn multi_signer_auto() -> Self {
        Self {
            selected_utxo_ids: vec![0], // One input per party
            recipient_amount: 340_000,
            change_amount: 100_000,
            fee: 10_000,
        }
    }

    /// Parse from command-line arguments
    pub fn from_args(args: &[String], default_config: Self) -> Self {
        let mut config = default_config;

        // Parse --utxos flag
        if let Some(pos) = args.iter().position(|arg| arg == "--utxos") {
            if let Some(utxo_str) = args.get(pos + 1) {
                if let Ok(ids) = Self::parse_utxo_ids(utxo_str) {
                    config.selected_utxo_ids = ids;
                }
            }
        }

        // Parse --recipient flag
        if let Some(pos) = args.iter().position(|arg| arg == "--recipient") {
            if let Some(amount_str) = args.get(pos + 1) {
                if let Ok(amount) = amount_str.parse::<u64>() {
                    config.recipient_amount = amount;
                }
            }
        }

        // Parse --change flag
        if let Some(pos) = args.iter().position(|arg| arg == "--change") {
            if let Some(amount_str) = args.get(pos + 1) {
                if let Ok(amount) = amount_str.parse::<u64>() {
                    config.change_amount = amount;
                }
            }
        }

        // Parse --fee flag
        if let Some(pos) = args.iter().position(|arg| arg == "--fee") {
            if let Some(amount_str) = args.get(pos + 1) {
                if let Ok(amount) = amount_str.parse::<u64>() {
                    config.fee = amount;
                }
            }
        }

        config
    }

    /// Parse comma-separated UTXO IDs
    fn parse_utxo_ids(s: &str) -> Result<Vec<usize>, std::num::ParseIntError> {
        s.split(',').map(|id| id.trim().parse::<usize>()).collect()
    }

    /// Validate configuration against virtual wallet
    pub fn validate(&self, wallet: &VirtualWallet) -> Result<(), String> {
        // Check all selected UTXOs exist
        for id in &self.selected_utxo_ids {
            if wallet.get_utxo(*id).is_none() {
                return Err(format!("UTXO ID {} not found in wallet", id));
            }
        }

        // Check amounts balance
        let total_input = wallet.total_amount(&self.selected_utxo_ids);
        let total_output = self.recipient_amount + self.change_amount + self.fee;

        if total_input != total_output {
            return Err(format!(
                "Transaction does not balance: input {} sats != output {} sats",
                total_input, total_output
            ));
        }

        Ok(())
    }

    /// Display configuration summary
    pub fn display(&self, wallet: &VirtualWallet) {
        println!("\n{}", "=".repeat(60));
        println!("  Transaction Configuration");
        println!("{}", "=".repeat(60));

        println!("\nSelected UTXOs:");
        for id in &self.selected_utxo_ids {
            if let Some(vu) = wallet.get_utxo(*id) {
                let sp_indicator = if vu.has_sp_tweak { " [SP]" } else { "" };
                println!(
                    "  [{}] {} sats - {} - {}{}",
                    id,
                    vu.utxo.amount.to_sat(),
                    vu.script_type.as_str(),
                    vu.description,
                    sp_indicator
                );
            }
        }

        let total_input = wallet.total_amount(&self.selected_utxo_ids);
        println!("\nTotal Input:    {:>10} sats", total_input);
        println!("Recipient:      {:>10} sats", self.recipient_amount);
        println!("Change:         {:>10} sats", self.change_amount);
        println!("Fee:            {:>10} sats", self.fee);
        println!(
            "Total Output:   {:>10} sats",
            self.recipient_amount + self.change_amount + self.fee
        );
        println!();
    }
}

/// Interactive configuration builder
pub struct InteractiveConfig;

impl InteractiveConfig {
    /// Build configuration interactively via CLI prompts
    pub fn build(
        wallet: &VirtualWallet,
        default_config: TransactionConfig,
    ) -> Result<TransactionConfig, Box<dyn std::error::Error>> {
        println!("\\n{}", "=".repeat(60));
        println!("  Configure Transaction Inputs");
        println!("{}", "=".repeat(60));

        println!("\\nAvailable UTXOs in your virtual wallet:\\n");
        for vu in wallet.list_utxos() {
            let sp_indicator = if vu.has_sp_tweak { " [SP]" } else { "" };
            println!(
                "  [{}] {:>7} sats - {} - {}{}",
                vu.id,
                vu.utxo.amount.to_sat(),
                vu.script_type.as_str(),
                vu.description,
                sp_indicator
            );
        }

        let default_ids: Vec<String> = default_config
            .selected_utxo_ids
            .iter()
            .map(|id| id.to_string())
            .collect();

        println!("\\nSelect UTXOs to spend (comma-separated, e.g., '1,2,4'):");
        println!("Or press Enter for default [{}]", default_ids.join(","));
        print!("\\n> ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        let selected_ids = if input.is_empty() {
            default_config.selected_utxo_ids.clone()
        } else {
            TransactionConfig::parse_utxo_ids(input).map_err(|_| "Invalid UTXO IDs format")?
        };

        // Validate selection
        for id in &selected_ids {
            if wallet.get_utxo(*id).is_none() {
                return Err(format!("Invalid UTXO ID: {}", id).into());
            }
        }

        let total_input = wallet.total_amount(&selected_ids);

        println!(
            "\\n✓ Selected {} inputs totaling {} sats\\n",
            selected_ids.len(),
            total_input
        );
        for id in &selected_ids {
            if let Some(vu) = wallet.get_utxo(*id) {
                let sp_indicator = if vu.has_sp_tweak { " (SP)" } else { "" };
                println!(
                    "  Input: {} sats [{}]{}",
                    vu.utxo.amount.to_sat(),
                    script_type_string(&vu.utxo.script_pubkey),
                    sp_indicator
                );
            }
        }

        // Use default amounts or prompt (for now just use defaults)
        let config = TransactionConfig::new(
            selected_ids,
            default_config.recipient_amount,
            default_config.change_amount,
            default_config.fee,
        );

        // Auto-adjust amounts to balance
        let total_input = wallet.total_amount(&config.selected_utxo_ids);
        let total_output = config.recipient_amount + config.change_amount + config.fee;

        let final_config = if total_input != total_output {
            println!(
                "\\n⚠  Auto-adjusting amounts to balance (input: {} sats)",
                total_input
            );
            let new_recipient = total_input - config.change_amount - config.fee;
            TransactionConfig::new(
                config.selected_utxo_ids,
                new_recipient,
                config.change_amount,
                config.fee,
            )
        } else {
            config
        };

        final_config.display(wallet);

        Ok(final_config)
    }
}
