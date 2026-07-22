use std::cell::RefCell;

use anyhow::{anyhow, Result};
use bip375_helpers::display::{adapter, psbt_analyzer};
use psbt::Psbt;
use rand::rngs::OsRng;
use secp256k1::Secp256k1;

use super::{AppState, WorkflowState};

pub struct Orchestrator;

impl Orchestrator {
    pub fn execute_reset(state: &mut AppState) {
        *state = AppState::default();
        KEYS.with(|keys| *keys.borrow_mut() = None);
    }

    pub fn execute_create_psbt(state: &mut AppState) -> Result<()> {
        let keys = crate::workflow::setup_keys()?;
        let psbt = crate::workflow::construct_psbt(
            &keys,
            &[(keys.sp_address, bitcoin::Amount::from_sat(90_000))],
        )?;
        state.highlighted_fields = psbt_analyzer::compute_field_diff(None, &psbt);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&psbt));
        store_psbt(state, &psbt);
        state.workflow_state = WorkflowState::ContributeInProgress(0);
        KEYS.with(|stored| *stored.borrow_mut() = Some(keys));
        Ok(())
    }

    pub fn execute_contribute(state: &mut AppState, party_name: &str) -> Result<()> {
        if !matches!(state.workflow_state, WorkflowState::ContributeInProgress(_)) {
            return Err(anyhow!("not in the FROST contribution phase"));
        }
        if state.selected_parties.contains(party_name) {
            return Err(anyhow!("{party_name} has already contributed"));
        }
        // The signer's "device" receives only the serialized PSBT bytes.
        let mut psbt = load_psbt(state)?;
        let before = psbt.clone();
        let secp = Secp256k1::new();
        let secret = KEYS.with(|stored| {
            let borrowed = stored.borrow();
            let keys = borrowed
                .as_ref()
                .ok_or_else(|| anyhow!("keys not initialized"))?;
            let key = party_key(keys, party_name)?;
            crate::workflow::contribute(&secp, &mut psbt, key, &keys.public_key_package, &mut OsRng)
        })?;
        state.round1_secrets.insert(party_name.to_owned(), secret);
        state.selected_parties.insert(party_name.to_owned());
        let count = state.selected_parties.len();
        if count == usize::from(crate::workflow::MIN_SIGNERS) {
            // Coordinator receives the round-one PSBT bytes and derives the
            // Silent Payment outputs before any signature share is produced.
            let mut coordinator_psbt = Psbt::deserialize(&psbt.serialize())
                .map_err(|error| anyhow!("deserialize PSBT: {error:?}"))?;
            KEYS.with(|stored| {
                let borrowed = stored.borrow();
                let keys = borrowed
                    .as_ref()
                    .ok_or_else(|| anyhow!("keys not initialized"))?;
                crate::workflow::derive_sp_outputs(
                    &secp,
                    &mut coordinator_psbt,
                    &keys.public_key_package,
                )
            })?;
            store_psbt(state, &coordinator_psbt);
            state.workflow_state = WorkflowState::OutputDerived;
        } else {
            store_psbt(state, &psbt);
            state.workflow_state = WorkflowState::ContributeInProgress(count);
        }
        update_display(state, before);
        Ok(())
    }

    pub fn execute_partial_sign(state: &mut AppState, party_name: &str) -> Result<()> {
        if !matches!(
            state.workflow_state,
            WorkflowState::OutputDerived | WorkflowState::SigningInProgress(_)
        ) {
            return Err(anyhow!("not in the FROST signing phase"));
        }
        let secret = state
            .round1_secrets
            .remove(party_name)
            .ok_or_else(|| anyhow!("no single-use nonce stored for {party_name}"))?;
        // The signer's device loads the PSBT bytes and reconstructs the signing
        // package and sighash from them alone -- no coordinator state is shared.
        let mut psbt = load_psbt(state)?;
        let before = psbt.clone();
        KEYS.with(|stored| {
            let borrowed = stored.borrow();
            let keys = borrowed
                .as_ref()
                .ok_or_else(|| anyhow!("keys not initialized"))?;
            let message = crate::workflow::compute_sighash(&psbt)?;
            let package =
                crate::workflow::signing_package(&psbt, &message, &keys.public_key_package)?;
            crate::workflow::partial_sign(
                &Secp256k1::new(),
                &mut psbt,
                &package,
                secret,
                party_key(keys, party_name)?,
                &keys.public_key_package,
                &[keys.sp_address],
            )
        })?;
        store_psbt(state, &psbt);
        state.signed_parties.insert(party_name.to_owned());
        let count = state.signed_parties.len();
        state.workflow_state = if count == usize::from(crate::workflow::MIN_SIGNERS) {
            WorkflowState::PartialSigningComplete
        } else {
            WorkflowState::SigningInProgress(count)
        };
        update_display(state, before);
        Ok(())
    }

    pub fn execute_extract(state: &mut AppState) -> Result<()> {
        if state.workflow_state != WorkflowState::PartialSigningComplete {
            return Err(anyhow!("FROST signature shares are incomplete"));
        }
        // The coordinator loads the fully signed PSBT bytes and independently
        // reconstructs the signing package to aggregate the shares.
        let mut psbt = load_psbt(state)?;
        let before = psbt.clone();
        let transaction = KEYS.with(|stored| {
            let borrowed = stored.borrow();
            let keys = borrowed
                .as_ref()
                .ok_or_else(|| anyhow!("keys not initialized"))?;
            let message = crate::workflow::compute_sighash(&psbt)?;
            let package =
                crate::workflow::signing_package(&psbt, &message, &keys.public_key_package)?;
            crate::workflow::aggregate_and_extract(&mut psbt, &package, &keys.public_key_package)
        })?;
        store_psbt(state, &psbt);
        state.schnorr_sig_hex = transaction.input[0].witness.iter().next().map(hex::encode);
        state.workflow_state = WorkflowState::Extracted;
        update_display(state, before);
        Ok(())
    }
}

/// Deserialize the canonical PSBT bytes into a working copy for a role step.
fn load_psbt(state: &AppState) -> Result<Psbt> {
    state.psbt()?.ok_or_else(|| anyhow!("no PSBT"))
}

/// Store a role's PSBT back as the canonical serialized bytes.
fn store_psbt(state: &mut AppState, psbt: &Psbt) {
    state.psbt_bytes = Some(psbt.serialize());
}

fn party_key<'a>(
    keys: &'a crate::workflow::KeySetup,
    name: &str,
) -> Result<&'a frost_secp256k1_tr::keys::KeyPackage> {
    let identifier = keys
        .party_ids
        .get(name)
        .ok_or_else(|| anyhow!("unknown party: {name}"))?;
    keys.key_packages
        .get(identifier)
        .ok_or_else(|| anyhow!("missing key package for {name}"))
}

fn update_display(state: &mut AppState, before: Psbt) {
    if let Ok(Some(after)) = state.psbt() {
        state.highlighted_fields = psbt_analyzer::compute_field_diff(Some(&before), &after);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&after));
    }
}

pub fn extract_display_fields_from_state(
    state: &AppState,
) -> Option<(
    Vec<adapter::DisplayField>,
    Vec<adapter::DisplayField>,
    Vec<adapter::DisplayField>,
)> {
    state
        .psbt()
        .ok()
        .flatten()
        .map(|psbt| adapter::extract_display_fields(&psbt, &state.highlighted_fields))
}

thread_local! {
    static KEYS: RefCell<Option<crate::workflow::KeySetup>> = const { RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the refactored orchestrator end to end. Every phase deserializes the
    /// PSBT from the canonical bytes and re-serializes it, so a signature can only
    /// be produced if each role works from bytes plus its own device-local state.
    #[test]
    fn partitioned_orchestrator_flow_produces_signature() {
        let mut state = AppState::default();
        Orchestrator::execute_create_psbt(&mut state).unwrap();
        Orchestrator::execute_contribute(&mut state, "Alice").unwrap();
        Orchestrator::execute_contribute(&mut state, "Bob").unwrap();
        assert_eq!(state.workflow_state, WorkflowState::OutputDerived);
        Orchestrator::execute_partial_sign(&mut state, "Alice").unwrap();
        Orchestrator::execute_partial_sign(&mut state, "Bob").unwrap();
        Orchestrator::execute_extract(&mut state).unwrap();
        assert_eq!(state.workflow_state, WorkflowState::Extracted);
        assert!(state.schnorr_sig_hex.is_some());
    }
}
