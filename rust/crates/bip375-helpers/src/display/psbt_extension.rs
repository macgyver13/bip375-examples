//! PSBT Display Extension Traits
//!
//! Provides traits for extracting and serializing PSBT fields for display purposes.
//! These traits are used exclusively by the GUI and analysis tools to inspect PSBT contents.

// use bitcoin::CompressedPublicKey;

/// Extension trait for accessing psbt_v2::v2::Global fields
///
/// This trait provides convenient methods to access all standard PSBT v2 global fields
/// in a serialized format suitable for display or further processing.
pub trait GlobalFieldsExt {
    /// Iterator over all standard global fields as (field_type, key_data, value_data) tuples
    ///
    /// Returns fields in the following order:
    /// - PSBT_GLOBAL_XPUB (0x01) - Multiple entries possible
    /// - PSBT_GLOBAL_TX_VERSION (0x02)
    /// - PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03) - If present
    /// - PSBT_GLOBAL_INPUT_COUNT (0x04)
    /// - PSBT_GLOBAL_OUTPUT_COUNT (0x05)
    /// - PSBT_GLOBAL_TX_MODIFIABLE (0x06)
    /// - PSBT_GLOBAL_SP_ECDH_SHARE (0x07) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_SP_DLEQ (0x08) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_VERSION (0xFB)
    /// - PSBT_GLOBAL_PROPRIETARY (0xFC) - Multiple entries possible
    /// - Unknown fields from the unknowns map
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_GLOBAL_XPUB = 0x01 - Can have multiple entries
        for (xpub, key_source) in &self.xpubs {
            let field_type = 0x01;
            // Key is the serialized xpub
            let key_data = xpub.to_string().as_bytes().to_vec();
            // Value is the key source (fingerprint + derivation path)
            let mut value_data = Vec::new();
            // Fingerprint is 4 bytes
            value_data.extend_from_slice(&key_source.0.to_bytes());
            // Derivation path - each ChildNumber is 4 bytes (u32)
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_VERSION = 0x02 - Always present
        {
            let field_type = 0x02;
            let key_data = vec![];
            let value_data = self.tx_version.0.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03 - Optional
        if let Some(lock_time) = self.fallback_lock_time {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = lock_time.to_consensus_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_INPUT_COUNT = 0x04 - Always present
        {
            let field_type = 0x04;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.input_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_OUTPUT_COUNT = 0x05 - Always present
        {
            let field_type = 0x05;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.output_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_MODIFIABLE = 0x06 - Always present
        {
            let field_type = 0x06;
            let key_data = vec![];
            let value_data = vec![self.tx_modifiable_flags];
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_SP_ECDH_SHARE = 0x07 - BIP-375, can have multiple entries
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            let field_type = 0x07;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                ecdh_share.to_bytes().to_vec(),
            ));
        }

        // PSBT_GLOBAL_SP_DLEQ = 0x08 - BIP-375, can have multiple entries
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            let field_type = 0x08;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                dleq_proof.as_bytes().to_vec(),
            ));
        }

        // PSBT_GLOBAL_VERSION = 0xFB - Always present
        {
            let field_type = 0xFB;
            let key_data = vec![];
            let value_data = self.version.to_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_PROPRIETARY = 0xFC - Can have multiple entries
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            // Key data is the proprietary key structure
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields from the unknowns map
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}

/// Extension trait for accessing psbt_v2::v2::Input fields
///
/// This trait provides convenient methods to access all standard PSBT v2 input fields
/// in a serialized format suitable for display or further processing.
pub trait InputFieldsExt {
    /// Iterator over all standard input fields as (field_type, key_data, value_data) tuples
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl InputFieldsExt for psbt_v2::v2::Input {
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_IN_NON_WITNESS_UTXO (0x00) - Optional
        if let Some(ref tx) = self.non_witness_utxo {
            use bitcoin::consensus::Encodable;
            let field_type = 0x00;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = tx.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_WITNESS_UTXO (0x01) - Optional
        if let Some(ref utxo) = self.witness_utxo {
            use bitcoin::consensus::Encodable;
            let field_type = 0x01;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = utxo.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_PARTIAL_SIG (0x02) - Multiple entries possible
        for (pubkey, sig) in &self.partial_sigs {
            let field_type = 0x02;
            let key_data = pubkey.inner.serialize().to_vec();
            let value_data = sig.to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SIGHASH_TYPE (0x03) - Optional
        if let Some(sighash_type) = self.sighash_type {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = (sighash_type.to_u32()).to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_REDEEM_SCRIPT (0x04) - Optional
        if let Some(ref script) = self.redeem_script {
            let field_type = 0x04;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_WITNESS_SCRIPT (0x05) - Optional
        if let Some(ref script) = self.witness_script {
            let field_type = 0x05;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_BIP32_DERIVATION (0x06) - Multiple entries possible
        for (pubkey, key_source) in &self.bip32_derivations {
            let field_type = 0x06;
            let key_data = pubkey.serialize().to_vec();
            let mut value_data = Vec::new();
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_FINAL_SCRIPTSIG (0x07) - Optional
        if let Some(ref script) = self.final_script_sig {
            let field_type = 0x07;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_FINAL_SCRIPTWITNESS (0x08) - Optional
        if let Some(ref witness) = self.final_script_witness {
            use bitcoin::consensus::Encodable;
            let field_type = 0x08;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = witness.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_PREVIOUS_TXID (0x0e) - Always present
        {
            use bitcoin::consensus::Encodable;
            let field_type = 0x0e;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = self.previous_txid.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_OUTPUT_INDEX (0x0f) - Always present
        {
            let field_type = 0x0f;
            let key_data = vec![];
            let value_data = self.spent_output_index.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SEQUENCE (0x10) - Optional
        if let Some(sequence) = self.sequence {
            let field_type = 0x10;
            let key_data = vec![];
            let value_data = sequence.to_consensus_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_TAP_BIP32_DERIVATION (0x16) - Multiple entries possible
        for (xonly_pubkey, (leaf_hashes, key_source)) in &self.tap_key_origins {
            let field_type = 0x16;
            let key_data = xonly_pubkey.serialize().to_vec();
            let mut value_data = Vec::new();

            // Encode leaf_hashes (compact size + hashes)
            value_data.push(leaf_hashes.len() as u8);
            for leaf_hash in leaf_hashes {
                value_data.extend_from_slice(leaf_hash.as_ref());
            }

            // Encode key_source (fingerprint + derivation path)
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }

            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SP_ECDH_SHARE (0x1d) - BIP-375, multiple entries possible
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            let field_type = 0x1d;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                ecdh_share.to_bytes().to_vec(),
            ));
        }

        // PSBT_IN_SP_DLEQ (0x1e) - BIP-375, multiple entries possible
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            let field_type = 0x1e;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                dleq_proof.as_bytes().to_vec(),
            ));
        }

        // PSBT_IN_PROPRIETARY (0xFC) - Multiple entries possible
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}

/// Extension trait for accessing psbt_v2::v2::Output fields
///
/// This trait provides convenient methods to access all standard PSBT v2 output fields
/// in a serialized format suitable for display or further processing.
pub trait OutputFieldsExt {
    /// Iterator over all standard output fields as (field_type, key_data, value_data) tuples
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl OutputFieldsExt for psbt_v2::v2::Output {
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_OUT_REDEEM_SCRIPT (0x00) - Optional
        if let Some(ref script) = self.redeem_script {
            let field_type = 0x00;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_WITNESS_SCRIPT (0x01) - Optional
        if let Some(ref script) = self.witness_script {
            let field_type = 0x01;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_BIP32_DERIVATION (0x02) - Multiple entries possible
        for (pubkey, key_source) in &self.bip32_derivations {
            let field_type = 0x02;
            let key_data = pubkey.serialize().to_vec();
            let mut value_data = Vec::new();
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_AMOUNT (0x03) - Always present
        {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = self.amount.to_sat().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_SCRIPT (0x04) - Always present
        {
            let field_type = 0x04;
            let key_data = vec![];
            let value_data = self.script_pubkey.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_SP_V0_INFO (0x09) - BIP-375, optional
        if let Some(ref sp_info) = self.sp_v0_info {
            let field_type = 0x09;
            let key_data = vec![];
            fields.push((field_type, key_data, sp_info.clone()));
        }

        // PSBT_OUT_SP_V0_LABEL (0x0a) - BIP-375, optional
        if let Some(label) = self.sp_v0_label {
            let field_type = 0x0a;
            let key_data = vec![];
            let value_data = label.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_PROPRIETARY (0xFC) - Multiple entries possible
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}
