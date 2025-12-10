//! BIP-375 PSBT Roles
//!
//! Implements the six PSBT roles defined in BIP-174/370/375:
//! - Creator
//! - Constructor
//! - Updater
//! - Signer
//! - Input Finalizer
//! - Extractor

pub mod constructor;
pub mod creator;
pub mod extractor;
pub mod input_finalizer;
pub mod signer;
pub mod updater;
pub mod validation;

pub use constructor::*;
pub use creator::*;
pub use extractor::*;
pub use input_finalizer::*;
pub use signer::*;
pub use updater::*;
pub use validation::*;
