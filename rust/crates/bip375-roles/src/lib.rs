//! BIP-375 PSBT Roles
//!
//! Implements the six PSBT roles defined in BIP-174/370/375:
//! - Creator
//! - Constructor
//! - Updater
//! - Signer
//! - Input Finalizer
//! - Extractor

pub mod creator;
pub mod constructor;
pub mod updater;
pub mod signer;
pub mod input_finalizer;
pub mod extractor;
pub mod validation;

pub use creator::*;
pub use constructor::*;
pub use updater::*;
pub use signer::*;
pub use input_finalizer::*;
pub use extractor::*;
pub use validation::*;
