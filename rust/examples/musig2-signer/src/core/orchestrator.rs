//! Workflow orchestration for the musig2-signer GUI.
//!
//! Each `execute_*` method mutates `AppState` and drives the underlying
//! workflow logic from `crate::workflow`.

use super::app_state::{AppState, WorkflowState};
use bip375_helpers::display::{adapter, psbt_analyzer};
use secp256k1::Secp256k1;

pub struct Orchestrator;

impl Orchestrator {
    /// Reset to initial state.
    pub fn execute_reset(state: &mut AppState) {
        *state = AppState::default();
    }

    /// Steps 1–3: create PSBT with 1 MuSig2 input.
    pub fn execute_create_psbt(state: &mut AppState) -> Result<(), String> {
        let secp = Secp256k1::new();
        let keys = crate::workflow::setup_keys(&secp).map_err(|e| e.to_string())?;
        let psbt = crate::workflow::construct_psbt(&keys).map_err(|e| e.to_string())?;

        state.highlighted_fields = psbt_analyzer::compute_field_diff(None, &psbt);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&psbt));

        // Store all key material in thread-local (avoids partial-move issues
        // since KeySetup fields are not Clone/Copy).
        KEYS.with(|k| *k.borrow_mut() = Some(keys));

        state.psbt = Some(psbt);
        state.workflow_state = WorkflowState::EcdhInProgress(0);
        Ok(())
    }

    /// Add one party's partial ECDH share.
    ///
    /// If this is the last share (all 3 parties done), automatically runs
    /// `finalize_inputs` and transitions to `OutputDerived`.
    pub fn execute_add_ecdh(state: &mut AppState, party_name: &str) -> Result<(), String> {
        let secp = Secp256k1::new();
        let psbt = state.psbt.as_mut().ok_or("No PSBT")?;
        let before = psbt.clone();

        KEYS.with(|k| -> Result<(), String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            let (sk, pk) = party_keys(keys, party_name)?;
            crate::workflow::add_ecdh_share(&secp, psbt, party_name, sk, pk, &keys.scan_pk)
                .map_err(|e| e.to_string())
        })?;

        state.parties_ecdh_done.insert(party_name.to_string());
        let n = state.parties_ecdh_done.len();

        if n == 3 {
            // All ECDH shares present — derive SP output automatically.
            let secp2 = Secp256k1::new();
            crate::workflow::derive_sp_output(&secp2, psbt).map_err(|e| e.to_string())?;

            // Compute sighash now that output scripts are final.
            let msg = crate::workflow::compute_sighash(psbt).map_err(|e| e.to_string())?;
            state.message = Some(msg);
            state.workflow_state = WorkflowState::OutputDerived;
        } else {
            state.workflow_state = WorkflowState::EcdhInProgress(n);
        }

        let after = psbt.clone();
        state.highlighted_fields = psbt_analyzer::compute_field_diff(Some(&before), &after);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&after));
        Ok(())
    }

    /// Add one party's public nonce.
    pub fn execute_add_nonce(state: &mut AppState, party_name: &str) -> Result<(), String> {
        let psbt = state.psbt.as_mut().ok_or("No PSBT")?;
        let before = psbt.clone();

        let seed = nonce_seed_for(party_name);

        let sec_nonce = KEYS.with(|k| -> Result<musig2::SecNonce, String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            let (sk, pk) = party_keys(keys, party_name)?;
            crate::workflow::add_nonce(
                psbt,
                party_name,
                sk,
                pk,
                &keys.agg_pk,
                &keys.key_agg_ctx,
                seed,
            )
            .map_err(|e| e.to_string())
        })?;

        state.sec_nonces.insert(party_name.to_string(), sec_nonce);
        state.parties_nonce_done.insert(party_name.to_string());
        let n = state.parties_nonce_done.len();

        state.workflow_state = if n == 3 {
            WorkflowState::NonceComplete
        } else {
            WorkflowState::NonceInProgress(n)
        };

        let after = psbt.clone();
        state.highlighted_fields = psbt_analyzer::compute_field_diff(Some(&before), &after);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&after));
        Ok(())
    }

    /// Add one party's partial signature.
    pub fn execute_partial_sign(state: &mut AppState, party_name: &str) -> Result<(), String> {
        let message = state.message.ok_or("Sighash not computed")?;
        let psbt = state.psbt.as_mut().ok_or("No PSBT")?;
        let before = psbt.clone();

        let sec_nonce = state
            .sec_nonces
            .remove(party_name)
            .ok_or(format!("No nonce stored for {party_name}"))?;

        KEYS.with(|k| -> Result<(), String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            let (sk, pk) = party_keys(keys, party_name)?;
            crate::workflow::partial_sign(
                psbt,
                party_name,
                sk,
                pk,
                &keys.agg_pk,
                sec_nonce,
                &keys.key_agg_ctx,
                &message,
            )
            .map_err(|e| e.to_string())
        })?;

        state.parties_signed.insert(party_name.to_string());
        let n = state.parties_signed.len();

        state.workflow_state = if n == 3 {
            WorkflowState::PartialSigningComplete
        } else {
            WorkflowState::SigningInProgress(n)
        };

        let after = psbt.clone();
        state.highlighted_fields = psbt_analyzer::compute_field_diff(Some(&before), &after);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&after));
        Ok(())
    }

    /// Aggregate partial signatures and extract transaction.
    pub fn execute_extract(state: &mut AppState) -> Result<(), String> {
        let secp = Secp256k1::new();
        let message = state.message.ok_or("Sighash not computed")?;
        let psbt = state.psbt.as_mut().ok_or("No PSBT")?;
        let before = psbt.clone();

        KEYS.with(|k| -> Result<(), String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            crate::workflow::aggregate_and_extract(&secp, psbt, &keys.key_agg_ctx, &message)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })?;

        // Capture aggregated Schnorr sig hex for display.
        if let Some(tap_sig) = psbt.inputs[0].tap_key_sig {
            state.schnorr_sig_hex = Some(hex::encode(tap_sig.signature.as_ref()));
        }

        state.workflow_state = WorkflowState::Extracted;

        let after = psbt.clone();
        state.highlighted_fields = psbt_analyzer::compute_field_diff(Some(&before), &after);
        state.transaction_summary = Some(psbt_analyzer::compute_transaction_summary(&after));
        Ok(())
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Deterministic nonce seeds for the demo.
fn nonce_seed_for(party_name: &str) -> [u8; 32] {
    match party_name {
        "Alice" => [0xa1_u8; 32],
        "Bob" => [0xb1_u8; 32],
        "Charlie" => [0xc1_u8; 32],
        _ => [0x00_u8; 32],
    }
}

/// Look up a party's (sk, pk) from the cached KeySetup.
fn party_keys<'a>(
    keys: &'a crate::workflow::KeySetup,
    name: &str,
) -> Result<(&'a secp256k1::SecretKey, &'a secp256k1::PublicKey), String> {
    match name {
        "Alice" => Ok((&keys.alice_sk, &keys.alice_pk)),
        "Bob" => Ok((&keys.bob_sk, &keys.bob_pk)),
        "Charlie" => Ok((&keys.charlie_sk, &keys.charlie_pk)),
        _ => Err(format!("Unknown party: {name}")),
    }
}

// Thread-local storage for KeySetup (avoids needing Clone on SecretKey).
use std::cell::RefCell;
thread_local! {
    static KEYS: RefCell<Option<crate::workflow::KeySetup>> = const { RefCell::new(None) };
}

/// Helper used by gui::sync_state_to_ui.
pub fn extract_display_fields_from_state(
    state: &AppState,
) -> Option<(
    Vec<adapter::DisplayField>,
    Vec<adapter::DisplayField>,
    Vec<adapter::DisplayField>,
)> {
    state
        .psbt
        .as_ref()
        .map(|psbt| adapter::extract_display_fields(psbt, &state.highlighted_fields))
}
