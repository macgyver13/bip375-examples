//! Wallet types for examples and demos
//!
//! Provides virtual wallet, UTXO management, and transaction configuration
//! utilities for building BIP-375 demonstration applications.

use spdk_core::psbt::crypto::{
    apply_tweak_to_privkey, internal_key_to_p2tr_script, pubkey_to_p2wpkh_script,
    script_type_string, tweaked_key_to_p2tr_script,
};
use spdk_core::psbt::PsbtInput;

use bip39::{Language, Mnemonic};
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

// ============================================================================
// UTXO Type
// ============================================================================

/// UTXO information for creating PSBTs
///
/// This is a helper type used by the examples' VirtualWallet.
/// For actual PSBT construction, convert to `PsbtInput` using `to_psbt_input()`.
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Previous transaction ID
    pub txid: Txid,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: Amount,
    /// ScriptPubKey of the output
    pub script_pubkey: ScriptBuf,
    /// Private key for signing (if available)
    pub private_key: Option<SecretKey>,
    /// Sequence number
    pub sequence: Sequence,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(
        txid: Txid,
        vout: u32,
        amount: Amount,
        script_pubkey: ScriptBuf,
        private_key: Option<SecretKey>,
        sequence: Sequence,
    ) -> Self {
        Self {
            txid,
            vout,
            amount,
            script_pubkey,
            private_key,
            sequence,
        }
    }

    /// Get the outpoint for this UTXO
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }

    /// Convert to PsbtInput for use with bip375-roles
    pub fn to_psbt_input(&self) -> PsbtInput {
        PsbtInput::new(
            self.outpoint(),
            TxOut {
                value: self.amount,
                script_pubkey: self.script_pubkey.clone(),
            },
            self.sequence,
            self.private_key,
        )
    }
}

/// Derivation path type for BIP32 key generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationPath {
    /// BIP84: m/84'/0'/0' (P2WPKH)
    Bip84,
    /// BIP86: m/86'/0'/0' (P2TR)
    Bip86,
}

impl Default for DerivationPath {
    fn default() -> Self {
        DerivationPath::Bip84 // Default to P2WPKH
    }
}

/// Wallet key source
enum WalletSource {
    /// Simple seed-based derivation (backward compatible)
    Seed(String),
    /// BIP39 mnemonic with BIP32 derivation
    Mnemonic {
        seed: [u8; 64],
        derivation_path: DerivationPath,
    },
}

/// Simple wallet for generating deterministic keys from a seed or mnemonic
pub struct SimpleWallet {
    source: WalletSource,
}

impl SimpleWallet {
    /// Create a wallet from a simple seed string (backward compatible)
    pub fn new(seed: &str) -> Self {
        Self {
            source: WalletSource::Seed(seed.to_string()),
        }
    }

    /// Create a wallet from a BIP39 mnemonic with configurable derivation path
    ///
    /// # Arguments
    /// * `mnemonic_phrase` - 12 or 24 word BIP39 mnemonic
    /// * `derivation_path` - Optional derivation path (defaults to BIP86/P2TR)
    ///
    /// # Errors
    /// Returns error if mnemonic is invalid
    pub fn from_mnemonic(
        mnemonic_phrase: &str,
        derivation_path: Option<DerivationPath>,
    ) -> Result<Self, String> {
        // Parse and validate mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
            .map_err(|e| format!("Invalid BIP39 mnemonic: {}", e))?;

        // Convert to seed (512 bits / 64 bytes)
        let seed = mnemonic.to_seed("");

        Ok(Self {
            source: WalletSource::Mnemonic {
                seed,
                derivation_path: derivation_path.unwrap_or_default(),
            },
        })
    }

    /// Generate a deterministic private key for an input
    ///
    /// For seed-based wallets: Uses SHA256(seed_input_{index})
    /// For mnemonic wallets: Uses BIP32 derivation at m/<purpose>'/0'/0'/0/index
    pub fn input_key_pair(&self, index: u32) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        match &self.source {
            WalletSource::Seed(seed) => {
                // Match Python's key derivation: f"{seed}_input_{index}"
                let key_material = format!("{}_input_{}", seed, index);
                let mut hasher = Sha256::new();
                hasher.update(key_material.as_bytes());
                let hash = hasher.finalize();

                let privkey = SecretKey::from_slice(&hash).expect("valid private key");
                let pubkey = PublicKey::from_secret_key(&secp, &privkey);

                (privkey, pubkey)
            }
            WalletSource::Mnemonic {
                seed,
                derivation_path,
            } => {
                // Use BIP32 derivation: m/<purpose>'/0'/0'/0/index
                let purpose = match derivation_path {
                    DerivationPath::Bip84 => 84, // P2WPKH
                    DerivationPath::Bip86 => 86, // P2TR
                };

                Self::derive_key_bip32(seed, &[purpose, 0, 0, 0, index])
            }
        }
    }

    /// Generate scan key pair
    ///
    /// For seed-based wallets: Uses SHA256(seed_scan_0)
    /// For mnemonic wallets: Uses BIP32 at m/352'/0'/0'/0/0 (BIP352 scan key)
    pub fn scan_key_pair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        match &self.source {
            WalletSource::Seed(seed) => {
                // Match Python's key derivation: f"{seed}_scan_0"
                let key_material = format!("{}_scan_0", seed);
                let mut hasher = Sha256::new();
                hasher.update(key_material.as_bytes());
                let scan_hash = hasher.finalize();

                let scan_privkey =
                    SecretKey::from_slice(&scan_hash).expect("valid scan private key");
                let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_privkey);

                (scan_privkey, scan_pubkey)
            }
            WalletSource::Mnemonic { seed, .. } => {
                // BIP352 scan key path: m/352'/0'/0'/0/0
                Self::derive_key_bip32(seed, &[352, 0, 0, 0, 0])
            }
        }
    }

    /// Generate spend key pair
    ///
    /// For seed-based wallets: Uses SHA256(seed_spend_0)
    /// For mnemonic wallets: Uses BIP32 at m/352'/0'/0'/1/0 (BIP352 spend key)
    pub fn spend_key_pair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();

        match &self.source {
            WalletSource::Seed(seed) => {
                // Match Python's key derivation: f"{seed}_spend_0"
                let key_material = format!("{}_spend_0", seed);
                let mut hasher = Sha256::new();
                hasher.update(key_material.as_bytes());
                let spend_hash = hasher.finalize();

                let spend_privkey =
                    SecretKey::from_slice(&spend_hash).expect("valid spend private key");
                let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_privkey);

                (spend_privkey, spend_pubkey)
            }
            WalletSource::Mnemonic { seed, .. } => {
                // BIP352 spend key path: m/352'/0'/0'/1/0
                Self::derive_key_bip32(seed, &[352, 0, 0, 1, 0])
            }
        }
    }

    /// Get scan and spend public keys (convenience method)
    pub fn scan_spend_keys(&self) -> (PublicKey, PublicKey) {
        (self.scan_key_pair().1, self.spend_key_pair().1)
    }

    /// Get the master fingerprint for BIP32 derivation
    ///
    /// For mnemonic-based wallets: Returns the actual master fingerprint (first 4 bytes of HASH160(master_pubkey))
    /// For seed-based wallets: Returns a placeholder [0u8; 4] since they don't use BIP32
    ///
    /// # Returns
    /// 4-byte master fingerprint as array
    pub fn master_fingerprint(&self) -> [u8; 4] {
        match &self.source {
            WalletSource::Seed(_) => {
                // Seed-based wallets don't use BIP32, return placeholder
                [0u8; 4]
            }
            WalletSource::Mnemonic { seed, .. } => {
                use bitcoin::bip32::Xpriv;
                use bitcoin::Network;

                // Derive master xpriv: m
                let master_xpriv =
                    Xpriv::new_master(Network::Bitcoin, seed).expect("valid master key");

                // Get master xpub
                let secp = Secp256k1::new();
                let master_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &master_xpriv);

                // Return fingerprint: first 4 bytes
                master_xpub.fingerprint().to_bytes()
            }
        }
    }

    /// Get the derivation path used by this wallet
    ///
    /// For mnemonic-based wallets: Returns the configured derivation path
    /// For seed-based wallets: Returns None since they don't use BIP32
    pub fn derivation_path(&self) -> Option<DerivationPath> {
        match &self.source {
            WalletSource::Seed(_) => None,
            WalletSource::Mnemonic {
                derivation_path, ..
            } => Some(*derivation_path),
        }
    }

    /// Get BIP84 (P2WPKH) derivation path for a specific input index
    ///
    /// Returns: m/84'/0'/0'/0/index
    ///
    /// # Arguments
    /// * `index` - The UTXO/input index
    ///
    /// # Returns
    /// Vec of path components as u32 values with hardening applied (0x80000000 bit set)
    pub fn get_p2wpkh_derivation_path(&self, index: u32) -> Vec<u32> {
        vec![0x80000054, 0x80000000, 0x80000000, 0, index] // m/84'/0'/0'/0/index
    }

    /// Get BIP86 (P2TR) derivation path for a specific input index
    ///
    /// Returns: m/86'/0'/0'/0/index
    ///
    /// # Arguments
    /// * `index` - The UTXO/input index
    ///
    /// # Returns
    /// Vec of path components as u32 values with hardening applied (0x80000000 bit set)
    pub fn get_p2tr_derivation_path(&self, index: u32) -> Vec<u32> {
        vec![0x80000056, 0x80000000, 0x80000000, 0, index] // m/86'/0'/0'/0/index
    }

    /// Get BIP352 Silent Payment spend key derivation path
    ///
    /// Returns: m/352'/0'/0'/1/0
    ///
    /// All SP inputs use the same spend key (with different tweaks applied per output).
    ///
    /// # Returns
    /// Vec of path components as u32 values with hardening applied (0x80000000 bit set)
    pub fn get_sp_spend_derivation_path(&self) -> Vec<u32> {
        vec![0x80000160, 0x80000000, 0x80000000, 0x00000001, 0] // m/352'/0'/0'/1/0
    }

    /// Derive a key using BIP32 from a seed
    ///
    /// Uses HMAC-SHA512 for BIP32 derivation with hardened keys
    fn derive_key_bip32(seed: &[u8; 64], path: &[u32]) -> (SecretKey, PublicKey) {
        use bitcoin::bip32::{DerivationPath as Bip32Path, Xpriv};
        use std::str::FromStr;

        let secp = Secp256k1::new();

        // Create master key from seed
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, seed).expect("valid master key");

        // Build derivation path with hardened keys (add 2^31 for hardened)
        let path_str = format!(
            "m/{}",
            path.iter()
                .map(|&i| format!("{}'", i))
                .collect::<Vec<_>>()
                .join("/")
        );

        let derivation_path = Bip32Path::from_str(&path_str).expect("valid derivation path");

        // Derive key
        let derived = master
            .derive_priv(&secp, &derivation_path)
            .expect("valid derivation");

        let privkey = derived.private_key;
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        (privkey, pubkey)
    }
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
    /// * `wallet_seed` - Seed for generating deterministic keys (ignored if wallet provided)
    /// * `utxo_configs` - List of (amount, script_type, has_sp_tweak) configurations
    /// * `wallet` - Optional pre-configured SimpleWallet (for mnemonic support)
    pub fn new(
        wallet_seed: &str,
        utxo_configs: &[(u64, ScriptType, bool)],
        wallet: Option<SimpleWallet>,
    ) -> Self {
        let wallet = wallet.unwrap_or_else(|| SimpleWallet::new(wallet_seed));
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
                    let tweaked_privkey =
                        apply_tweak_to_privkey(&privkey, &tweak).expect("Valid tweak");
                    let tweaked_pubkey = PublicKey::from_secret_key(&secp, &tweaked_privkey);
                    (tweaked_pubkey, Some(tweak))
                } else {
                    (pubkey, None)
                };

                let script_pubkey = match (script_type, has_sp_tweak) {
                    (ScriptType::P2WPKH, _) => pubkey_to_p2wpkh_script(&final_pubkey),
                    (ScriptType::P2TR, true) => {
                        // Silent Payment output - key is already tweaked via BIP-352
                        tweaked_key_to_p2tr_script(&final_pubkey)
                    }
                    (ScriptType::P2TR, false) => {
                        // Regular BIP-86 taproot - needs BIP-341 tweak
                        internal_key_to_p2tr_script(&final_pubkey)
                    }
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
    ///
    /// # Arguments
    /// * `mnemonic` - Optional BIP39 mnemonic phrase
    pub fn hardware_wallet_default(mnemonic: Option<&str>) -> Result<Self, String> {
        let wallet = if let Some(phrase) = mnemonic {
            Some(SimpleWallet::from_mnemonic(phrase, None)?)
        } else {
            None
        };

        Ok(Self::new(
            "hardware_wallet_coldcard_demo",
            &[
                (250_000, ScriptType::P2TR, false),   // ID 0
                (100_000, ScriptType::P2TR, true),    // ID 1 - SP
                (150_000, ScriptType::P2WPKH, false), // ID 2
                (250_000, ScriptType::P2TR, true),    // ID 3 - SP
                (75_000, ScriptType::P2WPKH, false),  // ID 4
                (300_000, ScriptType::P2TR, true),    // ID 5 - SP
                (125_000, ScriptType::P2WPKH, false), // ID 6
                (50_000, ScriptType::P2WPKH, false),  // ID 7
            ],
            wallet,
        ))
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
            None,
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
            recipient_amount: 195_000,
            change_amount: 100_000,
            fee: 5_000,
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
        println!("\n{}", "=".repeat(60));
        println!("  Configure Transaction Inputs");
        println!("{}", "=".repeat(60));

        println!("\nAvailable UTXOs in your virtual wallet:\n");
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

        println!("\nSelect UTXOs to spend (comma-separated, e.g., '1,2,4'):");
        println!("Or press Enter for default [{}]", default_ids.join(","));
        print!("\n> ");
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
