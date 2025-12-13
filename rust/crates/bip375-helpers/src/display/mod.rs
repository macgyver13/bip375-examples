//! PSBT display and visualization utilities
//!
//! Provides functionality for displaying and analyzing PSBTs in GUI applications.

pub mod adapter;
pub mod field_identifier;
pub mod formatting;
pub mod psbt_analyzer;
pub mod psbt_extension;
pub mod psbt_io;

// Re-export commonly used types
pub use field_identifier::{FieldIdentifier, TransactionSummary};
