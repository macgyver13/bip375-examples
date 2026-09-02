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

/// Filter test vectors by case-insensitive description substring.
pub fn filter_vectors_by_description(
    vectors: &[crate::TestVector],
    filter: &str,
) -> Vec<crate::TestVector> {
    let filter = filter.trim().to_lowercase();

    if filter.is_empty() {
        return vectors.to_vec();
    }

    vectors
        .iter()
        .filter(|vector| vector.description.to_lowercase().contains(&filter))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::filter_vectors_by_description;

    fn vector(description: &str, comment: &str) -> crate::TestVector {
        crate::TestVector {
            description: description.into(),
            is_valid: true,
            comment: comment.into(),
            psbt_base64: "cHNidP8=".into(),
        }
    }

    #[test]
    fn empty_filter_returns_all_vectors() {
        let vectors = vec![vector("alpha", ""), vector("beta", "")];

        let filtered = filter_vectors_by_description(&vectors, "");

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn matches_description_case_insensitively() {
        let vectors = vec![vector("Missing PSBT_OUT_SP_V0_INFO field", "")];

        let filtered = filter_vectors_by_description(&vectors, "missing psbt_out");

        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn matches_description_substrings() {
        let vectors = vec![
            vector("psbt structure: missing output info", ""),
            vector("wallet flow: valid ecdh shares", ""),
        ];

        let filtered = filter_vectors_by_description(&vectors, "missing output");

        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].description,
            "psbt structure: missing output info"
        );
    }

    #[test]
    fn comments_are_not_matched() {
        let vectors = vec![vector("unrelated description", "needle")];

        let filtered = filter_vectors_by_description(&vectors, "needle");

        assert!(filtered.is_empty());
    }
}
