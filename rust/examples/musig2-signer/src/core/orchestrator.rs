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
        state.workflow_state = WorkflowState::ContributeInProgress(0);
        Ok(())
    }

    /// Contribute one party's ECDH share + nonce (combined Round 1).
    ///
    /// If this is the last party (all 3 done), automatically derives the SP
    /// output and computes the sighash, transitioning to `OutputDerived`.
    pub fn execute_contribute(state: &mut AppState, party_name: &str) -> Result<(), String> {
        let secp = Secp256k1::new();
        let psbt = state.psbt.as_mut().ok_or("No PSBT")?;
        let before = psbt.clone();

        let seed = random_nonce_seed();

        let sec_nonce = KEYS.with(|k| -> Result<musig2::SecNonce, String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            let (sk, pk) = party_keys(keys, party_name)?;
            crate::workflow::contribute(
                &secp, psbt, party_name, sk, pk,
                &keys.scan_pk, &keys.agg_pk, &keys.key_agg_ctx, seed,
            )
            .map_err(|e| e.to_string())
        })?;

        state.sec_nonces.insert(party_name.to_string(), sec_nonce);
        state.parties_contributed.insert(party_name.to_string());
        let n = state.parties_contributed.len();

        if n == 3 {
            // All contributions present — derive SP output + compute sighash.
            crate::workflow::derive_sp_output(&secp, psbt).map_err(|e| e.to_string())?;
            let msg = crate::workflow::compute_sighash(psbt).map_err(|e| e.to_string())?;
            state.message = Some(msg);
            state.workflow_state = WorkflowState::OutputDerived;
        } else {
            state.workflow_state = WorkflowState::ContributeInProgress(n);
        }

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

        let tx = KEYS.with(|k| -> Result<bitcoin::Transaction, String> {
            let keys_ref = k.borrow();
            let keys = keys_ref.as_ref().ok_or("Keys not initialised")?;
            crate::workflow::aggregate_and_extract(&secp, psbt, &keys.key_agg_ctx, &message)
                .map_err(|e| e.to_string())
        })?;

        // Extract Schnorr sig from the finalized witness (tap_key_sig is
        // cleared by finalize_input_witnesses per BIP-174).
        if let Some(sig_bytes) = tx.input[0].witness.iter().next() {
            state.schnorr_sig_hex = Some(hex::encode(sig_bytes));
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

/// Generate a random nonce seed from a CSPRNG (BIP-327 NonceGen requirement).
fn random_nonce_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
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
