//! BIP-375 GUI Common Library
//!
//! Shared utilities and types for building BIP-375 PSBT visualization GUIs.
//!
//! This library provides:
//! - Field identification and tracking across PSBT states
//! - PSBT analysis and diff computation
//! - Import/export functionality (base64, files, clipboard)
//! - Display formatting for field data
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use bip375_gui_common::{psbt_analyzer, psbt_io, display_formatting};
//!
//! // Import PSBT from base64
//! let psbt = psbt_io::import_from_base64("cHNidP8BA...")?;
//!
//! // Extract all fields
//! let fields = psbt_analyzer::extract_all_field_identifiers(&psbt);
//!
//! // Format for display
//! for field_id in fields {
//!     let name = display_formatting::format_field_name(category, field_type);
//!     println!("{}", name);
//! }
//! ```

pub mod display_adapter;
pub mod display_formatting;
pub mod field_identifier;
pub mod psbt_analyzer;
pub mod psbt_display_ext;
pub mod psbt_io;

// Re-export commonly used types
pub use field_identifier::{FieldIdentifier, PsbtSnapshot, TransactionSummary};
