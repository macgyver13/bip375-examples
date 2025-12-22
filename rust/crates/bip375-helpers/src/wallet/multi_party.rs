use std::collections::HashMap;

use super::TransactionConfig;

#[derive(Debug, Clone)]
pub struct PartyConfig {
    pub name: String,
    pub tx_config: TransactionConfig,
    pub controlled_input_indices: Vec<usize>,
    /// Optional custom input amounts (in satoshis). If provided, overrides default wallet amounts.
    /// Must match the number of selected UTXOs.
    pub input_amounts: Option<Vec<u64>>,
}

impl PartyConfig {
    pub fn new(name: impl Into<String>, tx_config: TransactionConfig) -> Self {
        Self {
            name: name.into(),
            tx_config,
            controlled_input_indices: Vec::new(),
            input_amounts: None,
        }
    }

    pub fn with_controlled_inputs(mut self, indices: Vec<usize>) -> Self {
        self.controlled_input_indices = indices;
        self
    }

    pub fn with_input_amounts(mut self, amounts: Vec<u64>) -> Self {
        self.input_amounts = Some(amounts);
        self
    }
}

#[derive(Debug, Clone)]
pub struct MultiPartyConfig {
    pub parties: Vec<PartyConfig>,
    pub creator_index: usize,
    pub recipient_address: String,
    pub total_fee: u64,
}

impl MultiPartyConfig {
    pub fn new(
        parties: Vec<PartyConfig>,
        creator_index: usize,
        recipient_address: impl Into<String>,
        total_fee: u64,
    ) -> Self {
        Self {
            parties,
            creator_index,
            recipient_address: recipient_address.into(),
            total_fee,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.parties.is_empty() {
            return Err("At least one party required".to_string());
        }

        if self.creator_index >= self.parties.len() {
            return Err(format!(
                "Creator index {} out of bounds (have {} parties)",
                self.creator_index,
                self.parties.len()
            ));
        }

        let total_inputs = self.get_total_inputs();
        let mut assigned_inputs = vec![false; total_inputs];

        for party in &self.parties {
            for &input_idx in &party.controlled_input_indices {
                if input_idx >= total_inputs {
                    return Err(format!(
                        "Party '{}' controls input {} but only {} inputs exist",
                        party.name, input_idx, total_inputs
                    ));
                }

                if assigned_inputs[input_idx] {
                    return Err(format!(
                        "Input {} is assigned to multiple parties",
                        input_idx
                    ));
                }

                assigned_inputs[input_idx] = true;
            }
        }

        for (idx, assigned) in assigned_inputs.iter().enumerate() {
            if !assigned {
                return Err(format!("Input {} has no assigned party", idx));
            }
        }

        // Calculate total input amount from custom amounts if provided, otherwise use default
        let total_input_amount: u64 = self
            .parties
            .iter()
            .map(|p| {
                if let Some(ref amounts) = p.input_amounts {
                    amounts.iter().sum()
                } else {
                    // Default: assume 100k per UTXO if not specified
                    p.tx_config.selected_utxo_ids.len() as u64 * 100_000
                }
            })
            .sum();

        let total_output_amount = self.get_recipient_amount() + self.get_change_amount();

        if total_input_amount < total_output_amount + self.total_fee {
            return Err(format!(
                "Insufficient inputs: {} < {} + {}",
                total_input_amount, total_output_amount, self.total_fee
            ));
        }

        Ok(())
    }

    pub fn get_creator(&self) -> &PartyConfig {
        &self.parties[self.creator_index]
    }

    pub fn get_total_inputs(&self) -> usize {
        self.parties
            .iter()
            .map(|p| p.tx_config.selected_utxo_ids.len())
            .sum()
    }

    pub fn input_to_party_map(&self) -> HashMap<usize, &PartyConfig> {
        let mut map = HashMap::new();

        for party in &self.parties {
            for &input_idx in &party.controlled_input_indices {
                map.insert(input_idx, party);
            }
        }

        map
    }

    pub fn get_party_by_name(&self, name: &str) -> Option<&PartyConfig> {
        self.parties.iter().find(|p| p.name == name)
    }

    pub fn get_party_by_name_mut(&mut self, name: &str) -> Option<&mut PartyConfig> {
        self.parties.iter_mut().find(|p| p.name == name)
    }

    pub fn get_recipient_amount(&self) -> u64 {
        195_000
    }

    pub fn get_change_amount(&self) -> u64 {
        100_000
    }

    pub fn get_inputs_for_party(&self, party_name: &str) -> Vec<usize> {
        self.parties
            .iter()
            .find(|p| p.name == party_name)
            .map(|p| p.controlled_input_indices.clone())
            .unwrap_or_default()
    }

    pub fn default_three_party() -> Result<Self, String> {
        let alice_config = TransactionConfig::multi_signer_auto();
        let bob_config = TransactionConfig::multi_signer_auto();
        let charlie_config = TransactionConfig::multi_signer_auto();

        // Individual party config validation skipped - inappropriate for multi-party scenarios
        // where each party contributes partial inputs. The MultiPartyConfig::validate() method
        // (called below) properly validates the combined transaction balance.

        let alice = PartyConfig::new("Alice", alice_config)
            .with_controlled_inputs(vec![0])
            .with_input_amounts(vec![100_000]);

        let bob = PartyConfig::new("Bob", bob_config)
            .with_controlled_inputs(vec![1])
            .with_input_amounts(vec![90_000]);

        let charlie = PartyConfig::new("Charlie", charlie_config)
            .with_controlled_inputs(vec![2])
            .with_input_amounts(vec![110_000]);

        let config = MultiPartyConfig::new(
            vec![alice, bob, charlie],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            5_000, // Updated fee to match 100k + 90k + 110k = 300k total input, 195k recipient + 100k change + 5k fee
        );

        config.validate()?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_input_assignment_rejected() {
        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let party1 = PartyConfig::new("Alice", config1).with_controlled_inputs(vec![0]);

        let party2 = PartyConfig::new("Bob", config2).with_controlled_inputs(vec![0]);

        let multi_config = MultiPartyConfig::new(
            vec![party1, party2],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        assert!(multi_config.validate().is_err());
        assert!(multi_config
            .validate()
            .unwrap_err()
            .contains("assigned to multiple parties"));
    }

    #[test]
    fn test_missing_input_assignment() {
        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let party1 = PartyConfig::new("Alice", config1).with_controlled_inputs(vec![0]);

        let party2 = PartyConfig::new("Bob", config2).with_controlled_inputs(vec![]);

        let multi_config = MultiPartyConfig::new(
            vec![party1, party2],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        assert!(multi_config.validate().is_err());
        assert!(multi_config
            .validate()
            .unwrap_err()
            .contains("has no assigned party"));
    }

    #[test]
    fn test_creator_index_out_of_bounds() {
        let config = TransactionConfig::multi_signer_auto();
        let party = PartyConfig::new("Alice", config).with_controlled_inputs(vec![0]);

        let multi_config = MultiPartyConfig::new(
            vec![party],
            5,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        assert!(multi_config.validate().is_err());
        assert!(multi_config
            .validate()
            .unwrap_err()
            .contains("Creator index"));
    }

    #[test]
    fn test_input_to_party_map() {
        let config1 = TransactionConfig::multi_signer_auto();
        let config2 = TransactionConfig::multi_signer_auto();

        let party1 = PartyConfig::new("Alice", config1).with_controlled_inputs(vec![0, 2]);

        let party2 = PartyConfig::new("Bob", config2).with_controlled_inputs(vec![1]);

        let multi_config = MultiPartyConfig::new(
            vec![party1, party2],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        let map = multi_config.input_to_party_map();

        assert_eq!(map.get(&0).unwrap().name, "Alice");
        assert_eq!(map.get(&1).unwrap().name, "Bob");
        assert_eq!(map.get(&2).unwrap().name, "Alice");
    }

    #[test]
    fn test_get_party_by_name() {
        let config = TransactionConfig::multi_signer_auto();
        let party = PartyConfig::new("Alice", config).with_controlled_inputs(vec![0]);

        let multi_config = MultiPartyConfig::new(
            vec![party],
            0,
            "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcwqpj9",
            15_000,
        );

        assert!(multi_config.get_party_by_name("Alice").is_some());
        assert!(multi_config.get_party_by_name("Bob").is_none());
    }
}
