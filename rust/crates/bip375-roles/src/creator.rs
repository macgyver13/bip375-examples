//! PSBT Creator Role
//!
//! Creates the initial PSBT structure.

use bip375_core::{PsbtField, Result, SilentPaymentPsbt};
use bip375_core::constants::*;

/// Create a new PSBT v2 with the specified number of inputs and outputs
pub fn create_psbt(num_inputs: usize, num_outputs: usize) -> Result<SilentPaymentPsbt> {
    let mut psbt = SilentPaymentPsbt::new();

    // Add PSBT version (required for v2)
    psbt.add_global_field(PsbtField::with_value(
        PSBT_GLOBAL_VERSION,
        PSBT_V2_VERSION.to_le_bytes().to_vec(),
    ));

    // Add transaction version (default to 2)
    psbt.add_global_field(PsbtField::with_value(
        PSBT_GLOBAL_TX_VERSION,
        2u32.to_le_bytes().to_vec(),
    ));

    // Add input count
    let mut input_count_bytes = Vec::new();
    PsbtField::write_compact_size(&mut input_count_bytes, num_inputs as u64)?;
    psbt.add_global_field(PsbtField::with_value(
        PSBT_GLOBAL_INPUT_COUNT,
        input_count_bytes,
    ));

    // Add output count
    let mut output_count_bytes = Vec::new();
    PsbtField::write_compact_size(&mut output_count_bytes, num_outputs as u64)?;
    psbt.add_global_field(PsbtField::with_value(
        PSBT_GLOBAL_OUTPUT_COUNT,
        output_count_bytes,
    ));

    // Add TX modifiable flag (allow signer to modify inputs/outputs)
    psbt.add_global_field(PsbtField::with_value(
        PSBT_GLOBAL_TX_MODIFIABLE,
        vec![TX_MODIFIABLE_INPUTS | TX_MODIFIABLE_OUTPUTS],
    ));

    // Initialize empty input and output maps
    for _ in 0..num_inputs {
        psbt.input_maps.push(Vec::new());
    }
    for _ in 0..num_outputs {
        psbt.output_maps.push(Vec::new());
    }

    Ok(psbt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_psbt() {
        let psbt = create_psbt(2, 3).unwrap();

        assert_eq!(psbt.num_inputs(), 2);
        assert_eq!(psbt.num_outputs(), 3);

        // Check version field
        let version = psbt.get_global_field(PSBT_GLOBAL_VERSION).unwrap();
        assert_eq!(version.value_data, PSBT_V2_VERSION.to_le_bytes());
    }
}
