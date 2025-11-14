//! PSBT Constructor Role
//!
//! Adds inputs and outputs to the PSBT.

use bip375_core::{
    constants::*, Error, Output, OutputRecipient, PsbtField, Result,
    SilentPaymentPsbt, Utxo,
};
use bitcoin::hashes::Hash;

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
        // Add PSBT_IN_PREVIOUS_TXID
        psbt.add_input_field(
            i,
            PsbtField::with_value(PSBT_IN_PREVIOUS_TXID, utxo.txid.to_byte_array().to_vec()),
        )?;

        // Add PSBT_IN_OUTPUT_INDEX
        psbt.add_input_field(
            i,
            PsbtField::with_value(PSBT_IN_OUTPUT_INDEX, utxo.vout.to_le_bytes().to_vec()),
        )?;

        // Add PSBT_IN_SEQUENCE
        psbt.add_input_field(
            i,
            PsbtField::with_value(PSBT_IN_SEQUENCE, utxo.sequence.to_consensus_u32().to_le_bytes().to_vec()),
        )?;

        // Add PSBT_IN_WITNESS_UTXO (required for SegWit inputs)
        let mut witness_utxo_bytes = Vec::new();
        // Amount (8 bytes little-endian)
        witness_utxo_bytes.extend_from_slice(&utxo.amount.to_sat().to_le_bytes());
        // Script length (compact size)
        PsbtField::write_compact_size(&mut witness_utxo_bytes, utxo.script_pubkey.len() as u64)?;
        // Script
        witness_utxo_bytes.extend_from_slice(utxo.script_pubkey.as_bytes());

        psbt.add_input_field(i, PsbtField::with_value(PSBT_IN_WITNESS_UTXO, witness_utxo_bytes))?;
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
        // Add PSBT_OUT_AMOUNT
        let mut amount_bytes = Vec::new();
        PsbtField::write_compact_size(&mut amount_bytes, output.amount.to_sat())?;
        psbt.add_output_field(i, PsbtField::with_value(PSBT_OUT_AMOUNT, amount_bytes))?;

        match &output.recipient {
            OutputRecipient::Address(script_pubkey) => {
                // Regular output - add script directly
                psbt.add_output_field(
                    i,
                    PsbtField::with_value(PSBT_OUT_SCRIPT, script_pubkey.to_bytes()),
                )?;
            }
            OutputRecipient::SilentPayment(sp_address) => {
                // Silent payment output - add SP address (BIP-375 field type 0x09)
                // PSBT_OUT_SP_V0_INFO: 33-byte scan key + 33-byte spend key (66 bytes total)
                let mut sp_info = Vec::with_capacity(66);
                sp_info.extend_from_slice(&sp_address.scan_key.serialize());
                sp_info.extend_from_slice(&sp_address.spend_key.serialize());
                
                psbt.add_output_field(
                    i,
                    PsbtField::with_value(PSBT_OUT_SP_V0_INFO, sp_info),
                )?;

                // Add PSBT_OUT_SP_V0_LABEL if present (separate field per BIP-375)
                if let Some(label) = sp_address.label {
                    psbt.add_output_field(
                        i,
                        PsbtField::with_value(PSBT_OUT_SP_V0_LABEL, label.to_le_bytes().to_vec()),
                    )?;
                }

                // Note: Output script will be computed by Input Finalizer after ECDH is complete
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
        assert!(psbt.get_input_field(0, PSBT_IN_PREVIOUS_TXID).is_some());
        assert!(psbt.get_input_field(0, PSBT_IN_OUTPUT_INDEX).is_some());
        assert!(psbt.get_input_field(1, PSBT_IN_PREVIOUS_TXID).is_some());
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
        assert!(psbt.get_output_field(0, PSBT_OUT_AMOUNT).is_some());
        assert!(psbt.get_output_field(0, PSBT_OUT_SCRIPT).is_some());
        assert!(psbt.get_output_field(1, PSBT_OUT_AMOUNT).is_some());
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
        assert!(psbt.get_input_field(0, PSBT_IN_PREVIOUS_TXID).is_some());
        assert!(psbt.get_output_field(0, PSBT_OUT_AMOUNT).is_some());
    }
}
