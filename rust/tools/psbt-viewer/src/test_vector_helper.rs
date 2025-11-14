use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorFile {
    pub description: String,
    pub version: String,
    #[serde(default)]
    pub invalid: Vec<TestVectorEntry>,
    #[serde(default)]
    pub valid: Vec<TestVectorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorEntry {
    pub description: String,
    pub psbt: String, // Base64 PSBT
    #[serde(default)]
    pub comment: String,
}

impl TestVectorFile {
    /// Parse test vectors from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Convert to Slint-compatible format
    pub fn to_slint_vectors(&self) -> Vec<crate::TestVector> {
        let mut vectors = Vec::new();

        // Add all valid test vectors first
        for entry in &self.valid {
            vectors.push(crate::TestVector {
                description: entry.description.clone().into(),
                is_valid: true,
                comment: entry.comment.clone().into(),
                psbt_base64: entry.psbt.clone().into(),
            });
        }

        // Then add all invalid test vectors
        for entry in &self.invalid {
            vectors.push(crate::TestVector {
                description: entry.description.clone().into(),
                is_valid: false,
                comment: entry.comment.clone().into(),
                psbt_base64: entry.psbt.clone().into(),
            });
        }

        vectors
    }
}
