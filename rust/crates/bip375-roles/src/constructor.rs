//! PSBT Constructor Role
//!
//! Adds inputs and outputs to the PSBT.

use bip375_core::{
    Error, Output, OutputRecipient, Result, SilentPaymentPsbt, Utxo,
    Bip375PsbtExt,
};

/// Add inputs to the PSBT
pub fn add_inputs(psbt: &mut SilentPaymentPsbt, inputs: &[Utxo]) -> Result<()> {
    if psbt.num_inputs() != inputs.len() {
        return Err(Error::Other(format!(
            "PSBT has {} input slots but {} inputs provided",
            psbt.num_inputs(),
            inputs.len()
        )));
    }

    for (i, utxo) in inputs.iter().enumerate() {
        let psbt_input = &mut psbt.inputs[i];
        
        psbt_input.previous_txid = utxo.txid;
        psbt_input.spent_output_index = utxo.vout;
        psbt_input.sequence = Some(utxo.sequence);
        
        // Add PSBT_IN_WITNESS_UTXO (required for SegWit inputs)
        let witness_utxo = psbt_v2::bitcoin::TxOut {
            value: psbt_v2::bitcoin::Amount::from_sat(utxo.amount.to_sat()),
            script_pubkey: psbt_v2::bitcoin::ScriptBuf::from(utxo.script_pubkey.to_bytes()),
        };

        psbt_input.witness_utxo = Some(witness_utxo);
        psbt_input.final_script_witness = None; // Clear any existing witness
    }

    Ok(())
}

/// Add outputs to the PSBT
pub fn add_outputs(psbt: &mut SilentPaymentPsbt, outputs: &[Output]) -> Result<()> {
    if psbt.num_outputs() != outputs.len() {
        return Err(Error::Other(format!(
            "PSBT has {} output slots but {} outputs provided",
            psbt.num_outputs(),
            outputs.len()
        )));
    }

    for (i, output) in outputs.iter().enumerate() {
        // Set standard fields
        {
            let psbt_output = &mut psbt.outputs[i];
            // Convert between potentially different bitcoin::Amount types
            psbt_output.amount = psbt_v2::bitcoin::Amount::from_sat(output.amount.to_sat());

            // Only set script_pubkey for regular address outputs
            // For SilentPayment outputs, script_pubkey is computed during finalization
            if let OutputRecipient::Address(script) = &output.recipient {
                psbt_output.script_pubkey = script.clone();
            }
            // Note: SilentPayment outputs will have empty script_pubkey here,
            // which is handled by BIP-375 compatible deserialization
        }

        // Set BIP-375 fields
        if let OutputRecipient::SilentPayment(sp_addr) = &output.recipient {
            psbt.set_output_sp_address(i, sp_addr)?;

            if let Some(label) = sp_addr.label {
                psbt.set_output_sp_label(i, label)?;
            }
        }
    }

    Ok(())
}

/// Add both inputs and outputs to the PSBT (convenience function)
pub fn construct_psbt(
    psbt: &mut SilentPaymentPsbt,
    inputs: &[Utxo],
    outputs: &[Output],
) -> Result<()> {
    add_inputs(psbt, inputs)?;
    add_outputs(psbt, outputs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::create_psbt;
    use bitcoin::{hashes::Hash, Amount, ScriptBuf, Sequence, Txid};
    use bip375_core::constants::*;

    #[test]
    fn test_add_inputs() {
        let mut psbt = create_psbt(2, 1).unwrap();

        let inputs = vec![
            Utxo::new(
                Txid::all_zeros(),
                0,
                Amount::from_sat(50000),
                ScriptBuf::new(),
                None,
                Sequence::MAX,
            ),
            Utxo::new(
                Txid::all_zeros(),
                1,
                Amount::from_sat(30000),
                ScriptBuf::new(),
                None,
                Sequence::MAX,
            ),
        ];

        add_inputs(&mut psbt, &inputs).unwrap();

        // Verify inputs were added
        assert_eq!(psbt.inputs[0].previous_txid, inputs[0].txid);
        assert_eq!(psbt.inputs[0].spent_output_index, inputs[0].vout);
        assert_eq!(psbt.inputs[1].previous_txid, inputs[1].txid);
    }

    #[test]
    fn test_add_outputs() {
        let mut psbt = create_psbt(1, 2).unwrap();

        let outputs = vec![
            Output::regular(Amount::from_sat(40000), ScriptBuf::new()),
            Output::regular(Amount::from_sat(10000), ScriptBuf::new()),
        ];

        add_outputs(&mut psbt, &outputs).unwrap();

        // Verify outputs were added
        assert_eq!(psbt.outputs[0].amount, Amount::from_sat(40000));
        assert!(psbt.outputs[0].script_pubkey.len() == 0); // Empty script in test
        assert_eq!(psbt.outputs[1].amount, Amount::from_sat(10000));
    }

    #[test]
    fn test_construct_psbt() {
        let mut psbt = create_psbt(1, 1).unwrap();

        let inputs = vec![Utxo::new(
            Txid::all_zeros(),
            0,
            Amount::from_sat(50000),
            ScriptBuf::new(),
            None,
            Sequence::MAX,
        )];

        let outputs = vec![Output::regular(Amount::from_sat(49000), ScriptBuf::new())];

        construct_psbt(&mut psbt, &inputs, &outputs).unwrap();

        // Verify both inputs and outputs were added
        assert_eq!(psbt.inputs[0].previous_txid, inputs[0].txid);
        assert_eq!(psbt.outputs[0].amount, Amount::from_sat(49000));
    }
}
