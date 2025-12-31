use bip375_helpers::display::psbt_io::{load_psbt, save_psbt};
use bip375_helpers::transaction::{
    build_inputs_from_multi_party_config, build_outputs, validate_transaction_balance,
};
use bip375_helpers::wallet::{MultiPartyConfig, PartyConfig, SimpleWallet};
use bitcoin::Transaction;
use secp256k1::{Secp256k1, SecretKey};
use silentpayments::{Network, SilentPaymentAddress};
use spdk_core::psbt::crypto::script_type_string;
use spdk_core::psbt::io::PsbtMetadata;
use spdk_core::psbt::roles::{
    constructor::{add_inputs, add_outputs},
    creator::create_psbt,
    extractor::extract_transaction,
    input_finalizer::finalize_inputs,
    signer::{add_ecdh_shares_partial, sign_inputs},
    validation::{self, ValidationLevel},
};
use spdk_core::psbt::{PsbtInput, SilentPaymentPsbt};
use std::collections::HashMap;

/// Create a new PSBT with inputs and outputs (no ECDH shares, no signatures)
pub fn create_psbt_only(config: &MultiPartyConfig) -> Result<SilentPaymentPsbt, String> {
    let num_inputs = config.get_total_inputs();
    let num_outputs = 2;

    let mut psbt = create_psbt(num_inputs, num_outputs);

    let inputs = build_inputs_from_multi_party_config(config)?;

    add_inputs(&mut psbt, &inputs).map_err(|e| format!("Failed to add inputs: {}", e))?;

    let recipient_wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (scan_key, spend_key) = recipient_wallet.scan_spend_keys();
    let recipient_address = SilentPaymentAddress::new(scan_key, spend_key, Network::Mainnet, 0)
        .map_err(|e| format!("Failed to create recipient address: {}", e))?;

    let change_wallet = SimpleWallet::new("change_address_for_multi_signer_test");

    let recipient_amount = config.get_recipient_amount();
    let change_amount = config.get_change_amount();

    let outputs = build_outputs(
        recipient_amount,
        change_amount,
        &recipient_address,
        &change_wallet,
    )?;

    add_outputs(&mut psbt, &outputs).map_err(|e| format!("Failed to add outputs: {}", e))?;

    validate_transaction_balance(&inputs, &outputs, config.total_fee)?;

    Ok(psbt)
}

pub fn sign_inputs_for_party(
    psbt: &mut SilentPaymentPsbt,
    party: &PartyConfig,
    config: &MultiPartyConfig,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Vec<usize>, String> {
    let recipient_wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (scan_key, _) = recipient_wallet.scan_spend_keys();

    validation::validate_psbt(secp, psbt, ValidationLevel::DleqOnly)
        .map_err(|e| format!("Validation failed: {}", e))?;

    let private_key = get_party_private_key(&party.name)?;

    let inputs = build_inputs_from_multi_party_config(config)?;

    let inputs_with_keys: Vec<PsbtInput> = inputs
        .into_iter()
        .enumerate()
        .map(|(idx, mut input)| {
            if party.controlled_input_indices.contains(&idx) {
                input.private_key = Some(private_key);
            }
            input
        })
        .collect();

    add_ecdh_shares_partial(
        secp,
        psbt,
        &inputs_with_keys,
        &[scan_key],
        &party.controlled_input_indices,
        true,
    )
    .map_err(|e| format!("Failed to add ECDH shares: {}", e))?;

    sign_inputs(secp, psbt, &inputs_with_keys)
        .map_err(|e| format!("Failed to sign inputs: {}", e))?;

    Ok(party.controlled_input_indices.clone())
}

pub fn finalize_and_extract(
    psbt: &mut SilentPaymentPsbt,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Transaction, String> {
    let recipient_wallet = SimpleWallet::new("recipient_silent_payment_test_seed");
    let (_scan_key, _) = recipient_wallet.scan_spend_keys();

    validation::validate_psbt(secp, psbt, ValidationLevel::Full)
        .map_err(|e| format!("Final validation failed: {}", e))?;

    finalize_inputs(secp, psbt, None).map_err(|e| format!("Finalization failed: {}", e))?;

    let tx = extract_transaction(psbt).map_err(|e| format!("Extraction failed: {}", e))?;

    Ok(tx)
}

pub fn get_party_private_key(party_name: &str) -> Result<SecretKey, String> {
    let wallet = SimpleWallet::new(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ));
    Ok(wallet.input_key_pair(0).0)
}

pub fn create_input_assignments_metadata(config: &MultiPartyConfig) -> HashMap<usize, String> {
    let mut assignments = HashMap::new();
    for party in &config.parties {
        for &input_idx in &party.controlled_input_indices {
            assignments.insert(input_idx, party.name.clone());
        }
    }
    assignments
}

pub fn save_psbt_with_metadata(
    psbt: &SilentPaymentPsbt,
    description: impl Into<String>,
) -> Result<(), String> {
    let mut metadata = PsbtMetadata::with_description(description);
    metadata.set_counts(psbt.inputs.len(), psbt.outputs.len());
    metadata.update_timestamps();

    save_psbt(psbt, Some(metadata)).map_err(|e| format!("Failed to save PSBT: {:?}", e))?;
    Ok(())
}

pub fn load_psbt_with_metadata() -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>), String> {
    load_psbt().map_err(|e| format!("Failed to load PSBT: {:?}", e))
}

pub fn print_transaction_summary(config: &MultiPartyConfig, inputs: &[PsbtInput]) {
    println!("Multi-Signer Silent Payment Transaction");
    println!("{}", "=".repeat(50));
    println!("  Configuration:");
    println!("   • Creator: {}", config.get_creator().name);
    println!("   • Total Inputs: {}", inputs.len());
    println!("   • Total Parties: {}", config.parties.len());
    println!();

    println!("  Input Assignments:");
    for (idx, input) in inputs.iter().enumerate() {
        let party = config
            .parties
            .iter()
            .find(|p| p.controlled_input_indices.contains(&idx))
            .map(|p| p.name.as_str())
            .unwrap_or("Unassigned");

        let input_type = script_type_string(&input.witness_utxo.script_pubkey);
        println!(
            "   Input {} ({}): {} sats [{}]",
            idx,
            party,
            input.witness_utxo.value.to_sat(),
            input_type
        );
    }

    let total_input: u64 = inputs.iter().map(|i| i.witness_utxo.value.to_sat()).sum();
    println!("   Total: {} sats", total_input);
    println!();

    println!("  Outputs:");
    println!(
        "   Recipient: {} sats (Silent Payment)",
        config.get_recipient_amount()
    );
    println!("   Change: {} sats", config.get_change_amount());
    println!("   Fee: {} sats", config.total_fee);
    println!("{}", "=".repeat(50));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip375_helpers::wallet::TransactionConfig;

    #[test]
    fn test_get_party_private_key() {
        let result = get_party_private_key("Alice");
        assert!(result.is_ok());

        let result = get_party_private_key("Bob");
        assert!(result.is_ok());

        let result = get_party_private_key("Charlie");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_input_assignments_metadata() {
        let alice_config = TransactionConfig::multi_signer_auto();
        let alice = PartyConfig::new("Alice", alice_config).with_controlled_inputs(vec![0]);

        let bob_config = TransactionConfig::multi_signer_auto();
        let bob = PartyConfig::new("Bob", bob_config).with_controlled_inputs(vec![1]);

        let config = MultiPartyConfig::new(
            vec![alice, bob],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        let assignments = create_input_assignments_metadata(&config);

        assert_eq!(assignments.get(&0), Some(&"Alice".to_string()));
        assert_eq!(assignments.get(&1), Some(&"Bob".to_string()));
    }
}
