use crate::wallet::PartyConfig;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct InputAssignment {
    pub input_index: usize,
    pub party_name: String,
    pub utxo_source: String,
}

impl InputAssignment {
    pub fn new(
        input_index: usize,
        party_name: impl Into<String>,
        utxo_source: impl Into<String>,
    ) -> Self {
        Self {
            input_index,
            party_name: party_name.into(),
            utxo_source: utxo_source.into(),
        }
    }
}

pub fn assign_inputs_to_parties(configs: &[PartyConfig]) -> Result<Vec<InputAssignment>, String> {
    let mut assignments = Vec::new();
    let mut input_index = 0;

    for config in configs {
        for &utxo_id in &config.tx_config.selected_utxo_ids {
            let assignment = InputAssignment::new(
                input_index,
                config.name.clone(),
                format!("{}_utxo_{}", config.name, utxo_id),
            );
            assignments.push(assignment);
            input_index += 1;
        }
    }

    validate_assignments(&assignments, input_index)?;

    Ok(assignments)
}

pub fn validate_assignments(
    assignments: &[InputAssignment],
    num_inputs: usize,
) -> Result<(), String> {
    if assignments.is_empty() {
        return Err("No input assignments provided".to_string());
    }

    let mut seen_indices = HashSet::new();

    for assignment in assignments {
        if assignment.input_index >= num_inputs {
            return Err(format!(
                "Input index {} out of bounds (have {} inputs)",
                assignment.input_index, num_inputs
            ));
        }

        if !seen_indices.insert(assignment.input_index) {
            return Err(format!(
                "Input {} assigned to multiple parties",
                assignment.input_index
            ));
        }
    }

    for i in 0..num_inputs {
        if !seen_indices.contains(&i) {
            return Err(format!("Input {} has no assignment", i));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::TransactionConfig;

    #[test]
    fn test_assign_inputs_to_parties() {
        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let party1 = PartyConfig::new("Alice", config1);
        let party2 = PartyConfig::new("Bob", config2);

        let assignments = assign_inputs_to_parties(&[party1, party2]);

        assert!(assignments.is_ok());
        let assignments = assignments.unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].party_name, "Alice");
        assert_eq!(assignments[1].party_name, "Bob");
    }

    #[test]
    fn test_validate_assignments_duplicate() {
        let assignments = vec![
            InputAssignment::new(0, "Alice", "alice_utxo_0"),
            InputAssignment::new(0, "Bob", "bob_utxo_0"),
        ];

        let result = validate_assignments(&assignments, 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("assigned to multiple parties"));
    }

    #[test]
    fn test_validate_assignments_missing() {
        let assignments = vec![InputAssignment::new(0, "Alice", "alice_utxo_0")];

        let result = validate_assignments(&assignments, 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has no assignment"));
    }

    #[test]
    fn test_validate_assignments_out_of_bounds() {
        let assignments = vec![InputAssignment::new(5, "Alice", "alice_utxo_0")];

        let result = validate_assignments(&assignments, 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }
}
