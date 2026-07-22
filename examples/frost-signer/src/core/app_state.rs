use std::collections::{HashMap, HashSet};

use anyhow::Result;
use bip375_helpers::display::field_identifier::{FieldIdentifier, TransactionSummary};
use psbt::Psbt;

use crate::frost_spdk::Round1Secret;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowState {
    Init,
    ContributeInProgress(usize),
    OutputDerived,
    SigningInProgress(usize),
    PartialSigningComplete,
    Extracted,
}

impl WorkflowState {
    pub fn as_str(&self) -> String {
        match self {
            Self::Init => "Init".into(),
            Self::ContributeInProgress(count) => format!("ContributeInProgress({count})"),
            Self::OutputDerived => "OutputDerived".into(),
            Self::SigningInProgress(count) => format!("SigningInProgress({count})"),
            Self::PartialSigningComplete => "PartialSigningComplete".into(),
            Self::Extracted => "Extracted".into(),
        }
    }
}

pub struct AppState {
    pub workflow_state: WorkflowState,
    /// Canonical PSBT carrier. The PSBT only ever crosses a phase boundary as
    /// serialized bytes, so every role deserializes it fresh and re-serializes;
    /// nothing but these bytes is shared between the coordinator and the signers.
    pub psbt_bytes: Option<Vec<u8>>,
    /// Device-local, single-use round-one nonce store, keyed by signer name.
    /// These secrets never enter the PSBT and never leave their "device".
    pub round1_secrets: HashMap<String, Round1Secret>,
    pub selected_parties: HashSet<String>,
    pub signed_parties: HashSet<String>,
    pub highlighted_fields: HashSet<FieldIdentifier>,
    pub transaction_summary: Option<TransactionSummary>,
    pub schnorr_sig_hex: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            workflow_state: WorkflowState::Init,
            psbt_bytes: None,
            round1_secrets: HashMap::new(),
            selected_parties: HashSet::new(),
            signed_parties: HashSet::new(),
            highlighted_fields: HashSet::new(),
            transaction_summary: None,
            schnorr_sig_hex: None,
        }
    }
}

impl AppState {
    pub const PARTIES: [&'static str; 3] = crate::workflow::PARTIES;

    /// Deserialize the canonical PSBT bytes for a role step or for display.
    pub fn psbt(&self) -> Result<Option<Psbt>> {
        self.psbt_bytes
            .as_deref()
            .map(Psbt::deserialize)
            .transpose()
            .map_err(|error| anyhow::anyhow!("deserialize PSBT: {error:?}"))
    }

    pub fn pending_parties(&self) -> Vec<&'static str> {
        match self.workflow_state {
            WorkflowState::ContributeInProgress(_) => Self::PARTIES
                .into_iter()
                .filter(|name| !self.selected_parties.contains(*name))
                .collect(),
            WorkflowState::OutputDerived | WorkflowState::SigningInProgress(_) => Self::PARTIES
                .into_iter()
                .filter(|name| {
                    self.selected_parties.contains(*name) && !self.signed_parties.contains(*name)
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}
