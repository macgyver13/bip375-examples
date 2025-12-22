pub mod assignment;

use crate::wallet::{MultiPartyConfig, SimpleWallet, TransactionConfig, VirtualWallet};
use bip375_core::{PsbtInput, PsbtOutput, SilentPaymentAddress};
use bip375_crypto::pubkey_to_p2wpkh_script;
use bitcoin::Amount;

pub use assignment::{assign_inputs_to_parties, validate_assignments, InputAssignment};

pub fn build_inputs_from_configs(
    configs: &[(&TransactionConfig, &VirtualWallet)]
) -> Result<Vec<PsbtInput>, String> {
    let mut inputs = Vec::new();

    for (config, wallet) in configs {
        let utxos = wallet.select_by_ids(&config.selected_utxo_ids);

        if utxos.len() != config.selected_utxo_ids.len() {
            return Err(format!(
                "Wallet has {} UTXOs but config specifies {} IDs",
                utxos.len(),
                config.selected_utxo_ids.len()
            ));
        }

        inputs.extend(utxos.into_iter().map(|u| u.to_psbt_input()));
    }

    Ok(inputs)
}

pub fn build_inputs_from_multi_party_config(
    config: &MultiPartyConfig
) -> Result<Vec<PsbtInput>, String> {
    let mut inputs = Vec::new();

    for party in &config.parties {
        let wallet = VirtualWallet::multi_signer_wallet(&format!(
            "{}_multi_signer_silent_payment_test_seed",
            party.name.to_lowercase()
        ));

        let utxos = wallet.select_by_ids(&party.tx_config.selected_utxo_ids);

        if utxos.len() != party.tx_config.selected_utxo_ids.len() {
            return Err(format!(
                "Party '{}' wallet has {} UTXOs but config specifies {} IDs",
                party.name,
                utxos.len(),
                party.tx_config.selected_utxo_ids.len()
            ));
        }

        inputs.extend(utxos.into_iter().map(|u| u.to_psbt_input()));
    }

    Ok(inputs)
}

pub fn build_outputs(
    recipient_amount: u64,
    change_amount: u64,
    recipient_address: &SilentPaymentAddress,
    change_wallet: &SimpleWallet,
) -> Result<Vec<PsbtOutput>, String> {
    let change_pubkey = change_wallet.input_key_pair(0).1;
    let change_script = pubkey_to_p2wpkh_script(&change_pubkey);

    Ok(vec![
        PsbtOutput::regular(Amount::from_sat(change_amount), change_script),
        PsbtOutput::silent_payment(Amount::from_sat(recipient_amount), recipient_address.clone()),
    ])
}

pub fn validate_transaction_balance(
    inputs: &[PsbtInput],
    outputs: &[PsbtOutput],
    fee: u64,
) -> Result<(), String> {
    let total_input: u64 = inputs.iter().map(|i| i.witness_utxo.value.to_sat()).sum();

    let total_output: u64 = outputs
        .iter()
        .map(|o| match o {
            PsbtOutput::SilentPayment { amount, .. } => amount.to_sat(),
            PsbtOutput::Regular(txout) => txout.value.to_sat(),
        })
        .sum();

    if total_input != total_output + fee {
        return Err(format!(
            "Transaction imbalanced: input {} != output {} + fee {}",
            total_input, total_output, fee
        ));
    }

    Ok(())
}

pub fn get_party_wallet(party_name: &str) -> VirtualWallet {
    VirtualWallet::multi_signer_wallet(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ))
}

pub fn get_party_simple_wallet(party_name: &str) -> SimpleWallet {
    SimpleWallet::new(&format!(
        "{}_multi_signer_silent_payment_test_seed",
        party_name.to_lowercase()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_inputs_from_configs() {
        let wallet1 = VirtualWallet::multi_signer_wallet("alice_multi_signer_silent_payment_test_seed");
        let wallet2 = VirtualWallet::multi_signer_wallet("bob_multi_signer_silent_payment_test_seed");

        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let inputs = build_inputs_from_configs(&[
            (&config1, &wallet1),
            (&config2, &wallet2),
        ]);

        assert!(inputs.is_ok());
        assert_eq!(inputs.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_transaction_balance() {
        let wallet = VirtualWallet::multi_signer_wallet("test_seed");
        let config = TransactionConfig::multi_signer_auto();

        let inputs = build_inputs_from_configs(&[(&config, &wallet)]).unwrap();

        let recipient = SimpleWallet::new("recipient_test_seed");
        let (scan_key, spend_key) = recipient.scan_spend_keys();
        let address = SilentPaymentAddress::new(scan_key, spend_key, None);

        let change_wallet = SimpleWallet::new("change_test_seed");

        let outputs = build_outputs(50_000, 35_000, &address, &change_wallet).unwrap();

        let result = validate_transaction_balance(&inputs, &outputs, 15_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transaction_imbalanced() {
        let wallet = VirtualWallet::multi_signer_wallet("test_seed");
        let config = TransactionConfig::multi_signer_auto();

        let inputs = build_inputs_from_configs(&[(&config, &wallet)]).unwrap();

        let recipient = SimpleWallet::new("recipient_test_seed");
        let (scan_key, spend_key) = recipient.scan_spend_keys();
        let address = SilentPaymentAddress::new(scan_key, spend_key, None);

        let change_wallet = SimpleWallet::new("change_test_seed");

        let outputs = build_outputs(50_000, 40_000, &address, &change_wallet).unwrap();

        let result = validate_transaction_balance(&inputs, &outputs, 15_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("imbalanced"));
    }
}
