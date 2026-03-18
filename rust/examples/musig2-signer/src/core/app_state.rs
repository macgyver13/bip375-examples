//! Application state for the musig2-signer GUI.

use bip375_helpers::display::field_identifier::{FieldIdentifier, TransactionSummary};
use musig2::SecNonce;
use spdk_core::psbt::SilentPaymentPsbt;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkflowState {
    Init,
    ContributeInProgress(usize), // parties that have contributed (ECDH + nonce)
    OutputDerived,                // all 3 contributed; SP output derived, sighash computed
    SigningInProgress(usize),
    PartialSigningComplete,
    Extracted,
}

impl WorkflowState {
    pub fn as_str(&self) -> String {
        match self {
            WorkflowState::Init => "Init".to_string(),
            WorkflowState::ContributeInProgress(n) => format!("ContributeInProgress({})", n),
            WorkflowState::OutputDerived => "OutputDerived".to_string(),
            WorkflowState::SigningInProgress(n) => format!("SigningInProgress({})", n),
            WorkflowState::PartialSigningComplete => "PartialSigningComplete".to_string(),
            WorkflowState::Extracted => "Extracted".to_string(),
        }
    }
}

pub struct AppState {
    pub workflow_state: WorkflowState,
    pub psbt: Option<SilentPaymentPsbt>,
    /// SecNonce per party — consumed once by partial_sign
    pub sec_nonces: HashMap<String, SecNonce>,
    pub parties_contributed: HashSet<String>,
    pub parties_signed: HashSet<String>,
    /// Fields added by the last operation (for green highlighting)
    pub highlighted_fields: HashSet<FieldIdentifier>,
    pub transaction_summary: Option<TransactionSummary>,
    /// Taproot sighash computed once after SP output is derived
    pub message: Option<[u8; 32]>,
    /// Aggregated Schnorr signature hex (after extraction)
    pub schnorr_sig_hex: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            workflow_state: WorkflowState::Init,
            psbt: None,
            sec_nonces: HashMap::new(),
            parties_contributed: HashSet::new(),
            parties_signed: HashSet::new(),
            highlighted_fields: HashSet::new(),
            transaction_summary: None,
            message: None,
            schnorr_sig_hex: None,
        }
    }
}

impl AppState {
    /// Names of all three parties in order.
    pub fn all_parties() -> [&'static str; 3] {
        ["Alice", "Bob", "Charlie"]
    }

    /// Parties that have not yet contributed (ECDH + nonce).
    pub fn pending_contribute_parties(&self) -> Vec<&'static str> {
        Self::all_parties()
            .into_iter()
            .filter(|&p| !self.parties_contributed.contains(p))
            .collect()
    }

    /// Parties that have not yet partially signed.
    pub fn pending_signing_parties(&self) -> Vec<&'static str> {
        Self::all_parties()
            .into_iter()
            .filter(|&p| !self.parties_signed.contains(p))
            .collect()
    }
}
