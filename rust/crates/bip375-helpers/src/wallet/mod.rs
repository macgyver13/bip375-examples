//! Wallet utilities for examples and demos
//!
//! Provides virtual wallet and transaction configuration types for building
//! BIP-375 demonstration applications.

pub mod multi_party;
pub mod types;

pub use multi_party::{MultiPartyConfig, PartyConfig};
pub use types::{DerivationPath, SimpleWallet, TransactionConfig, Utxo, VirtualWallet};
