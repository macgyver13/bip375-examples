pub mod assignment;

use crate::crypto::pubkey_to_p2wpkh_script;
use crate::wallet::{MultiPartyConfig, SimpleWallet, TransactionConfig, VirtualWallet};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use silentpayments::SilentPaymentAddress;
use psbt::roles::ConstructorPsbtExt;
use psbt::Psbt;
use psbt_v2::{Input, Output};

/// Assemble a PSBT from built inputs and outputs using the new Constructor role.
///
/// The constructor's `add_inputs` only carries outpoints, so witness_utxo and
/// sequence from the built inputs are re-applied afterwards. (Outputs are shuffled
/// by `create_new_transaction`, per BIP-375; SP vs change is distinguished by
/// `sp_v0_info`, not position.)
pub fn build_psbt(inputs: Vec<Input>, outputs: Vec<Output>) -> Result<Psbt, String> {
    let outpoints: Vec<OutPoint> = inputs
        .iter()
        .map(|i| OutPoint::new(i.previous_txid, i.spent_output_index))
        .collect();

    let psbt = Psbt::create_new_transaction(outputs).map_err(|e| e.to_string())?;
    let mut psbt = psbt.add_inputs(outpoints).map_err(|e| e.to_string())?;

    for (slot, built) in psbt.inputs.iter_mut().zip(inputs.into_iter()) {
        slot.witness_utxo = built.witness_utxo;
        slot.sequence = built.sequence;
    }

    Ok(psbt)
}

/// Build the 66-byte `PSBT_OUT_SP_V0_INFO` payload (scan_key || spend_key)
/// for a silent payment output.
fn sp_v0_info_bytes(address: &SilentPaymentAddress) -> [u8; 66] {
    let mut bytes = [0u8; 66];
    bytes[..33].copy_from_slice(&address.get_scan_key().serialize());
    bytes[33..].copy_from_slice(&address.get_spend_key().serialize());
    bytes
}

pub use assignment::{assign_inputs_to_parties, validate_assignments, InputAssignment};

pub fn build_inputs_from_configs(
    configs: &[(&TransactionConfig, &VirtualWallet)],
) -> Result<Vec<Input>, String> {
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
    config: &MultiPartyConfig,
) -> Result<Vec<Input>, String> {
    let mut inputs = Vec::new();

    for party in &config.parties {
        let wallet = VirtualWallet::multi_signer_wallet(&format!(
            "{}_multi_signer_silent_payment_test_seed",
            party.name.to_lowercase()
        ));

        let mut utxos = wallet.select_by_ids(&party.tx_config.selected_utxo_ids);

        if utxos.len() != party.tx_config.selected_utxo_ids.len() {
            return Err(format!(
                "Party '{}' wallet has {} UTXOs but config specifies {} IDs",
                party.name,
                utxos.len(),
                party.tx_config.selected_utxo_ids.len()
            ));
        }

        // If custom input amounts are provided, override the default wallet amounts
        if let Some(ref custom_amounts) = party.input_amounts {
            if custom_amounts.len() != utxos.len() {
                return Err(format!(
                    "Party '{}' has {} custom amounts but {} UTXOs",
                    party.name,
                    custom_amounts.len(),
                    utxos.len()
                ));
            }

            for (utxo, &custom_amount) in utxos.iter_mut().zip(custom_amounts.iter()) {
                utxo.amount = bitcoin::Amount::from_sat(custom_amount);
            }
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
) -> Result<Vec<Output>, String> {
    let change_pubkey = change_wallet.input_key_pair(0).1;
    let change_script = pubkey_to_p2wpkh_script(&change_pubkey);

    // Regular change output: script set at construction time.
    let change_output = Output::new(TxOut {
        value: Amount::from_sat(change_amount),
        script_pubkey: change_script,
    });

    // Silent payment recipient output: script is computed later by the Signer,
    // so it starts empty; PSBT_OUT_SP_V0_INFO carries the scan/spend keys.
    let mut sp_output = Output::new(TxOut {
        value: Amount::from_sat(recipient_amount),
        script_pubkey: ScriptBuf::new(),
    });
    sp_output.sp_v0_info = Some(sp_v0_info_bytes(recipient_address));

    Ok(vec![change_output, sp_output])
}

pub fn validate_transaction_balance(
    inputs: &[Input],
    outputs: &[Output],
    fee: u64,
) -> Result<(), String> {
    let total_input: u64 = inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().map_or(0, |u| u.value.to_sat()))
        .sum();

    let total_output: u64 = outputs.iter().map(|o| o.amount.to_sat()).sum();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_inputs_from_configs() {
        let wallet1 =
            VirtualWallet::multi_signer_wallet("alice_multi_signer_silent_payment_test_seed");
        let wallet2 =
            VirtualWallet::multi_signer_wallet("bob_multi_signer_silent_payment_test_seed");

        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let inputs = build_inputs_from_configs(&[(&config1, &wallet1), (&config2, &wallet2)]);

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
        let address = SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, silentpayments::SpVersion::ZERO);

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
        let address = SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, silentpayments::SpVersion::ZERO);

        let change_wallet = SimpleWallet::new("change_test_seed");

        let outputs = build_outputs(50_000, 40_000, &address, &change_wallet).unwrap();

        let result = validate_transaction_balance(&inputs, &outputs, 15_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("imbalanced"));
    }
}
