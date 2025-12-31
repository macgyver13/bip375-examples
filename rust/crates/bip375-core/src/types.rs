//! BIP-375 Type Definitions
//!
//! Core types for silent payments in PSBTs.

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut};
// use silentpayments::psbt::SilentPaymentOutputInfo;
use secp256k1::SecretKey;


// ============================================================================
// PSBT Construction Helper Types
// ============================================================================

/// Input data for PSBT construction
///
/// Combines bitcoin primitives with optional signing key for BIP-375 workflows.
/// This is a construction helper, not part of the serialized PSBT format.
#[derive(Debug, Clone)]
pub struct PsbtInput {
    /// The previous output being spent
    pub outpoint: OutPoint,
    /// The UTXO being spent (value + script)
    pub witness_utxo: TxOut,
    /// Sequence number for this input
    pub sequence: Sequence,
    /// Optional private key for signing (not serialized)
    pub private_key: Option<SecretKey>,
}

impl PsbtInput {
    /// Create a new PSBT input
    pub fn new(
        outpoint: OutPoint,
        witness_utxo: TxOut,
        sequence: Sequence,
        private_key: Option<SecretKey>,
    ) -> Self {
        Self {
            outpoint,
            witness_utxo,
            sequence,
            private_key,
        }
    }
}

/// Output data for PSBT construction
///
/// Either a regular bitcoin output or a silent payment output.
/// For silent payments, the script is computed during finalization.
#[derive(Debug, Clone)]
pub enum PsbtOutput {
    /// Regular bitcoin output with known script
    Regular(TxOut),
    /// Silent payment output (script computed during finalization)
    SilentPayment {
        /// Amount to send
        amount: Amount,
        /// Silent payment address
        address: SilentPaymentOutputInfo,
    },
}

impl PsbtOutput {
    /// Create a regular output
    pub fn regular(amount: Amount, script_pubkey: ScriptBuf) -> Self {
        Self::Regular(TxOut {
            value: amount,
            script_pubkey,
        })
    }

    /// Create a silent payment output
    pub fn silent_payment(amount: Amount, address: SilentPaymentOutputInfo) -> Self {
        Self::SilentPayment { amount, address }
    }

    /// Check if this is a silent payment output
    pub fn is_silent_payment(&self) -> bool {
        matches!(self, Self::SilentPayment { .. })
    }

    /// Get the amount
    pub fn amount(&self) -> Amount {
        match self {
            Self::Regular(txout) => txout.value,
            Self::SilentPayment { amount, .. } => *amount,
        }
    }
}
