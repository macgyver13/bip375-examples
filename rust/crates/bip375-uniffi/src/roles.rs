// PSBT role functions for UniFFI bindings

use crate::errors::Bip375Error;
use crate::types::{Output, SilentPaymentPsbt, Utxo};
use bip375_roles as roles;
use secp256k1::PublicKey;

// ============================================================================
// Creator Role
// ============================================================================

pub fn roles_create_psbt(
    inputs: Vec<Utxo>,
    outputs: Vec<Output>,
) -> Result<std::sync::Arc<SilentPaymentPsbt>, Bip375Error> {
    let core_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_core()).collect();
    let core_inputs = core_inputs?;

    let core_outputs: Result<Vec<_>, _> = outputs.iter().map(|o| o.to_core()).collect();
    let core_outputs = core_outputs?;

    let psbt = roles::creator::create_psbt(core_inputs.len(), core_outputs.len())?;

    Ok(std::sync::Arc::new(SilentPaymentPsbt::from_core(psbt)))
}

// ============================================================================
// Constructor Role
// ============================================================================

pub fn roles_add_inputs(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    inputs: Vec<Utxo>,
) -> Result<(), Bip375Error> {
    let core_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_core()).collect();
    let core_inputs = core_inputs?;

    psbt.with_inner(|p| roles::constructor::add_inputs(p, &core_inputs))?;
    Ok(())
}

pub fn roles_add_outputs(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    outputs: Vec<Output>,
) -> Result<(), Bip375Error> {
    let core_outputs: Result<Vec<_>, _> = outputs.iter().map(|o| o.to_core()).collect();
    let core_outputs = core_outputs?;

    psbt.with_inner(|p| roles::constructor::add_outputs(p, &core_outputs))?;
    Ok(())
}

// ============================================================================
// Signer Role
// ============================================================================

pub fn roles_add_ecdh_shares_full(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    inputs: Vec<Utxo>,
    scan_keys: Vec<Vec<u8>>,
) -> Result<(), Bip375Error> {
    let secp = secp256k1::Secp256k1::new();

    // Convert UniFFI inputs to core types
    let core_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_core()).collect();
    let core_inputs = core_inputs?;

    // Convert byte vectors to PublicKey objects
    let core_scan_keys: Result<Vec<PublicKey>, _> =
        scan_keys.iter().map(|k| PublicKey::from_slice(k)).collect();
    let core_scan_keys = core_scan_keys.map_err(|_| Bip375Error::InvalidKey)?;

    psbt.with_inner(|p| {
        roles::signer::add_ecdh_shares_full(&secp, p, &core_inputs, &core_scan_keys, true)
    })?;
    Ok(())
}

pub fn roles_add_ecdh_shares_partial(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    input_indices: Vec<u32>,
    inputs: Vec<Utxo>,
    scan_keys: Vec<Vec<u8>>,
    include_dleq: bool,
) -> Result<(), Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let core_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_core()).collect();
    let core_inputs = core_inputs?;

    let core_scan_keys: Result<Vec<PublicKey>, _> =
        scan_keys.iter().map(|k| PublicKey::from_slice(k)).collect();
    let core_scan_keys = core_scan_keys.map_err(|_| Bip375Error::InvalidKey)?;

    let indices: Vec<usize> = input_indices.iter().map(|&i| i as usize).collect();

    psbt.with_inner(|p| {
        roles::signer::add_ecdh_shares_partial(
            &secp,
            p,
            &core_inputs,
            &core_scan_keys,
            &indices,
            include_dleq,
        )
    })?;
    Ok(())
}

pub fn roles_sign_inputs(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
    inputs: Vec<Utxo>,
) -> Result<(), Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    let core_inputs: Result<Vec<_>, _> = inputs.iter().map(|u| u.to_core()).collect();
    let core_inputs = core_inputs?;
    psbt.with_inner(|p| roles::signer::sign_inputs(&secp, p, &core_inputs))?;
    Ok(())
}

// ============================================================================
// Input Finalizer Role
// ============================================================================

pub fn roles_finalize_inputs(psbt: std::sync::Arc<SilentPaymentPsbt>) -> Result<(), Bip375Error> {
    let secp = secp256k1::Secp256k1::new();
    psbt.with_inner(|p| roles::input_finalizer::finalize_inputs(&secp, p, None))?;
    Ok(())
}

// ============================================================================
// Extractor Role
// ============================================================================

pub fn roles_extract_transaction(
    psbt: std::sync::Arc<SilentPaymentPsbt>,
) -> Result<Vec<u8>, Bip375Error> {
    use bitcoin::consensus::serialize;

    let tx = psbt.with_inner(|p| roles::extractor::extract_transaction(p))?;
    Ok(serialize(&tx))
}
