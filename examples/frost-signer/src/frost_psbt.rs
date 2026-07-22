//! PSBT representations that are not yet provided by upstream `rust-psbt`.
//!
//! These fields use custom top-level PSBT keytypes until a FROST PSBT extension
//! is standardized. Secret signing nonces and key packages must never be stored
//! in a PSBT.

use std::collections::{BTreeMap, BTreeSet};

use psbt_v2::{raw, Input, Output};
use thiserror::Error;

/// Top-level FROST PSBT keytypes. Input fields occupy the `0x3x` range; the
/// FROST output field occupies the `0x2x` range to keep the two maps separate.
pub const PSBT_IN_FROST_CONFIGURATION: u64 = 0x30;
pub const PSBT_IN_FROST_PARTICIPANT_COMMITMENT: u64 = 0x31;
pub const PSBT_IN_FROST_SIGNATURE_SHARE: u64 = 0x32;
pub const PSBT_IN_FROST_VERIFYING_SHARE: u64 = 0x33;
pub const PSBT_OUT_FROST_PARTICIPANT_SHARES: u64 = 0x20;

/// Human-readable name for a FROST PSBT keytype.
pub fn field_name(key_type: u64) -> Option<&'static str> {
    match key_type {
        PSBT_IN_FROST_CONFIGURATION => Some("PSBT_IN_FROST_CONFIGURATION"),
        PSBT_IN_FROST_PARTICIPANT_COMMITMENT => Some("PSBT_IN_FROST_PARTICIPANT_COMMITMENT"),
        PSBT_IN_FROST_SIGNATURE_SHARE => Some("PSBT_IN_FROST_SIGNATURE_SHARE"),
        PSBT_IN_FROST_VERIFYING_SHARE => Some("PSBT_IN_FROST_VERIFYING_SHARE"),
        PSBT_OUT_FROST_PARTICIPANT_SHARES => Some("PSBT_OUT_FROST_PARTICIPANT_SHARES"),
        _ => None,
    }
}

/// Public parameters shared by every participant in a FROST signing session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub min_signers: u16,
    pub max_signers: u16,
    pub group_verifying_key: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid FROST threshold {min_signers}-of-{max_signers}")]
    InvalidThreshold { min_signers: u16, max_signers: u16 },
    #[error("invalid FROST {field} field")]
    Malformed { field: &'static str },
    #[error("duplicate FROST {field} for participant {identifier}")]
    Duplicate {
        field: &'static str,
        identifier: String,
    },
    #[error("conflicting FROST configuration already exists")]
    ConflictingConfiguration,
}

/// Input-map accessors for the local FROST PSBT extension.
pub trait FrostInputExt {
    fn set_frost_configuration(&mut self, configuration: &Configuration) -> Result<(), Error>;
    fn frost_configuration(&self) -> Result<Option<Configuration>, Error>;
    fn add_frost_verifying_share(
        &mut self,
        identifier: &[u8],
        verifying_share: &[u8],
    ) -> Result<(), Error>;
    fn frost_verifying_shares(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>;
    fn add_frost_commitment(&mut self, identifier: &[u8], commitment: &[u8]) -> Result<(), Error>;
    fn frost_commitments(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>;
    fn add_frost_signature_share(&mut self, identifier: &[u8], share: &[u8]) -> Result<(), Error>;
    fn frost_signature_shares(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>;
}

/// Output-map accessors for the local FROST PSBT extension.
pub trait FrostOutputExt {
    fn set_frost_participant_shares(
        &mut self,
        group_verifying_key: &[u8],
        verifying_shares: &[Vec<u8>],
    ) -> Result<(), Error>;
    fn frost_participant_shares(&self) -> Result<Option<(Vec<u8>, Vec<Vec<u8>>)>, Error>;
}

impl FrostInputExt for Input {
    fn set_frost_configuration(&mut self, configuration: &Configuration) -> Result<(), Error> {
        validate_configuration(configuration)?;
        let mut value = Vec::with_capacity(4 + configuration.group_verifying_key.len());
        value.extend_from_slice(&configuration.min_signers.to_be_bytes());
        value.extend_from_slice(&configuration.max_signers.to_be_bytes());
        value.extend_from_slice(&configuration.group_verifying_key);
        let key = field_key(PSBT_IN_FROST_CONFIGURATION, &[]);
        if let Some(existing) = self.unknowns.get(&key) {
            if existing == &value {
                return Ok(());
            }
            return Err(Error::ConflictingConfiguration);
        }
        self.unknowns.insert(key, value);
        Ok(())
    }

    fn frost_configuration(&self) -> Result<Option<Configuration>, Error> {
        let Some(value) = self
            .unknowns
            .get(&field_key(PSBT_IN_FROST_CONFIGURATION, &[]))
        else {
            return Ok(None);
        };
        if value.len() < 5 {
            return Err(Error::Malformed {
                field: "configuration",
            });
        }
        let configuration = Configuration {
            min_signers: u16::from_be_bytes([value[0], value[1]]),
            max_signers: u16::from_be_bytes([value[2], value[3]]),
            group_verifying_key: value[4..].to_vec(),
        };
        validate_configuration(&configuration)?;
        Ok(Some(configuration))
    }

    fn add_frost_verifying_share(
        &mut self,
        identifier: &[u8],
        verifying_share: &[u8],
    ) -> Result<(), Error> {
        if identifier.len() != 32 || verifying_share.len() != 33 {
            return Err(Error::Malformed {
                field: "verifying share",
            });
        }
        if self
            .frost_verifying_shares()?
            .values()
            .any(|existing| existing == verifying_share)
        {
            return Err(Error::Duplicate {
                field: "verifying share",
                identifier: hex::encode(identifier),
            });
        }
        insert_participant_field(
            self,
            PSBT_IN_FROST_VERIFYING_SHARE,
            "verifying share",
            identifier,
            verifying_share,
        )
    }

    fn frost_verifying_shares(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        let fields = participant_fields(self, PSBT_IN_FROST_VERIFYING_SHARE, "verifying share")?;
        let mut seen = BTreeSet::new();
        for (identifier, verifying_share) in &fields {
            if identifier.len() != 32 || verifying_share.len() != 33 {
                return Err(Error::Malformed {
                    field: "verifying share",
                });
            }
            if !seen.insert(verifying_share) {
                return Err(Error::Duplicate {
                    field: "verifying share",
                    identifier: hex::encode(identifier),
                });
            }
        }
        Ok(fields)
    }

    fn add_frost_commitment(&mut self, identifier: &[u8], commitment: &[u8]) -> Result<(), Error> {
        insert_participant_field(
            self,
            PSBT_IN_FROST_PARTICIPANT_COMMITMENT,
            "commitment",
            identifier,
            commitment,
        )
    }

    fn frost_commitments(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        participant_fields(self, PSBT_IN_FROST_PARTICIPANT_COMMITMENT, "commitment")
    }

    fn add_frost_signature_share(&mut self, identifier: &[u8], share: &[u8]) -> Result<(), Error> {
        insert_participant_field(
            self,
            PSBT_IN_FROST_SIGNATURE_SHARE,
            "signature share",
            identifier,
            share,
        )
    }

    fn frost_signature_shares(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        participant_fields(self, PSBT_IN_FROST_SIGNATURE_SHARE, "signature share")
    }
}

impl FrostOutputExt for Output {
    fn set_frost_participant_shares(
        &mut self,
        group_verifying_key: &[u8],
        verifying_shares: &[Vec<u8>],
    ) -> Result<(), Error> {
        if group_verifying_key.is_empty()
            || verifying_shares.is_empty()
            || verifying_shares.iter().any(|share| share.len() != 33)
        {
            return Err(Error::Malformed {
                field: "participant shares",
            });
        }
        // Sort for a canonical encoding independent of the caller's ordering.
        let mut sorted: Vec<&[u8]> = verifying_shares.iter().map(Vec::as_slice).collect();
        sorted.sort_unstable();
        let mut value = Vec::with_capacity(sorted.len() * 33);
        for share in sorted {
            value.extend_from_slice(share);
        }
        let key = field_key(PSBT_OUT_FROST_PARTICIPANT_SHARES, group_verifying_key);
        if let Some(existing) = self.unknowns.get(&key) {
            if existing == &value {
                return Ok(());
            }
            return Err(Error::ConflictingConfiguration);
        }
        self.unknowns.insert(key, value);
        Ok(())
    }

    fn frost_participant_shares(&self) -> Result<Option<(Vec<u8>, Vec<Vec<u8>>)>, Error> {
        for (key, value) in &self.unknowns {
            if key.type_value != PSBT_OUT_FROST_PARTICIPANT_SHARES {
                continue;
            }
            if value.is_empty() || value.len() % 33 != 0 {
                return Err(Error::Malformed {
                    field: "participant shares",
                });
            }
            let shares = value.chunks(33).map(<[u8]>::to_vec).collect();
            return Ok(Some((key.key.clone(), shares)));
        }
        Ok(None)
    }
}

fn validate_configuration(configuration: &Configuration) -> Result<(), Error> {
    if configuration.min_signers < 2
        || configuration.min_signers > configuration.max_signers
        || configuration.group_verifying_key.is_empty()
    {
        return Err(Error::InvalidThreshold {
            min_signers: configuration.min_signers,
            max_signers: configuration.max_signers,
        });
    }
    Ok(())
}

fn insert_participant_field(
    input: &mut Input,
    key_type: u64,
    field: &'static str,
    identifier: &[u8],
    value: &[u8],
) -> Result<(), Error> {
    if identifier.is_empty() || value.is_empty() {
        return Err(Error::Malformed { field });
    }
    let key = field_key(key_type, identifier);
    if input.unknowns.contains_key(&key) {
        return Err(Error::Duplicate {
            field,
            identifier: hex::encode(identifier),
        });
    }
    input.unknowns.insert(key, value.to_vec());
    Ok(())
}

fn participant_fields(
    input: &Input,
    key_type: u64,
    field: &'static str,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
    let mut fields = BTreeMap::new();
    for (key, value) in &input.unknowns {
        if key.type_value != key_type {
            continue;
        }
        let identifier = key.key.clone();
        if identifier.is_empty() || value.is_empty() {
            return Err(Error::Malformed { field });
        }
        fields.insert(identifier, value.clone());
    }
    Ok(fields)
}

fn field_key(type_value: u64, key: &[u8]) -> raw::Key {
    raw::Key {
        type_value,
        key: key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    fn input() -> Input {
        Input::new(&OutPoint::new(Txid::all_zeros(), 0))
    }

    fn output() -> Output {
        Output::new(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        })
    }

    #[test]
    fn configuration_round_trips() {
        let mut input = input();
        let configuration = Configuration {
            min_signers: 2,
            max_signers: 3,
            group_verifying_key: vec![2; 33],
        };
        input.set_frost_configuration(&configuration).unwrap();
        assert_eq!(input.frost_configuration().unwrap(), Some(configuration));
    }

    #[test]
    fn rejects_invalid_threshold() {
        let mut input = input();
        let configuration = Configuration {
            min_signers: 3,
            max_signers: 2,
            group_verifying_key: vec![2; 33],
        };
        assert_eq!(
            input.set_frost_configuration(&configuration),
            Err(Error::InvalidThreshold {
                min_signers: 3,
                max_signers: 2
            })
        );
    }

    #[test]
    fn participant_fields_round_trip_and_reject_duplicates() {
        let mut input = input();
        input.add_frost_commitment(&[1], &[2; 66]).unwrap();
        assert_eq!(
            input.frost_commitments().unwrap().get(&vec![1]),
            Some(&vec![2; 66])
        );
        assert!(matches!(
            input.add_frost_commitment(&[1], &[3; 66]),
            Err(Error::Duplicate { .. })
        ));
    }

    #[test]
    fn verifying_shares_round_trip_in_identifier_order() {
        let mut roster_input = input();
        let first_identifier = [1; 32];
        let second_identifier = [2; 32];
        let first_share = [3; 33];
        let second_share = [4; 33];
        roster_input
            .add_frost_verifying_share(&second_identifier, &second_share)
            .unwrap();
        roster_input
            .add_frost_verifying_share(&first_identifier, &first_share)
            .unwrap();
        let mut reverse = input();
        reverse
            .add_frost_verifying_share(&first_identifier, &first_share)
            .unwrap();
        reverse
            .add_frost_verifying_share(&second_identifier, &second_share)
            .unwrap();

        assert_eq!(
            roster_input
                .frost_verifying_shares()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![
                (first_identifier.to_vec(), first_share.to_vec()),
                (second_identifier.to_vec(), second_share.to_vec()),
            ]
        );
        assert_eq!(roster_input.unknowns, reverse.unknowns);
    }

    #[test]
    fn verifying_shares_reject_malformed_and_duplicate_entries() {
        let mut roster_input = input();
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[1; 31], &[2; 33]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[1; 33], &[2; 33]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[1; 32], &[2; 32]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[1; 32], &[2; 34]),
            Err(Error::Malformed { .. })
        ));

        roster_input
            .add_frost_verifying_share(&[1; 32], &[2; 33])
            .unwrap();
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[1; 32], &[3; 33]),
            Err(Error::Duplicate { .. })
        ));
        assert!(matches!(
            roster_input.add_frost_verifying_share(&[4; 32], &[2; 33]),
            Err(Error::Duplicate { .. })
        ));

        let mut malformed = input();
        malformed.unknowns.insert(
            field_key(PSBT_IN_FROST_VERIFYING_SHARE, &[1; 31]),
            vec![2; 33],
        );
        assert!(matches!(
            malformed.frost_verifying_shares(),
            Err(Error::Malformed { .. })
        ));

        let mut duplicate = input();
        duplicate.unknowns.insert(
            field_key(PSBT_IN_FROST_VERIFYING_SHARE, &[1; 32]),
            vec![2; 33],
        );
        duplicate.unknowns.insert(
            field_key(PSBT_IN_FROST_VERIFYING_SHARE, &[3; 32]),
            vec![2; 33],
        );
        assert!(matches!(
            duplicate.frost_verifying_shares(),
            Err(Error::Duplicate { .. })
        ));
    }

    #[test]
    fn ignores_unrelated_unknown_fields() {
        let mut input = input();
        input.unknowns.insert(
            raw::Key {
                type_value: 0xaa,
                key: vec![1],
            },
            vec![2],
        );
        assert!(input.frost_commitments().unwrap().is_empty());
    }

    #[test]
    fn participant_shares_round_trip_and_sort() {
        let mut output = output();
        let group = vec![2; 33];
        let a = vec![3; 33];
        let b = vec![4; 33];
        // Insert unsorted; expect the canonical sorted order on read-back.
        output
            .set_frost_participant_shares(&group, &[b.clone(), a.clone()])
            .unwrap();
        let (got_group, shares) = output.frost_participant_shares().unwrap().unwrap();
        assert_eq!(got_group, group);
        assert_eq!(shares, vec![a, b]);
    }

    #[test]
    fn participant_shares_reject_bad_length() {
        let mut output = output();
        assert!(matches!(
            output.set_frost_participant_shares(&[2; 33], &[vec![1; 32]]),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn participant_shares_reject_conflict() {
        let mut output = output();
        output
            .set_frost_participant_shares(&[2; 33], &[vec![3; 33]])
            .unwrap();
        assert!(matches!(
            output.set_frost_participant_shares(&[2; 33], &[vec![4; 33]]),
            Err(Error::ConflictingConfiguration)
        ));
    }

    #[test]
    fn names_frost_fields() {
        for (key_type, expected) in [
            (PSBT_IN_FROST_CONFIGURATION, "PSBT_IN_FROST_CONFIGURATION"),
            (
                PSBT_IN_FROST_PARTICIPANT_COMMITMENT,
                "PSBT_IN_FROST_PARTICIPANT_COMMITMENT",
            ),
            (
                PSBT_IN_FROST_SIGNATURE_SHARE,
                "PSBT_IN_FROST_SIGNATURE_SHARE",
            ),
            (
                PSBT_IN_FROST_VERIFYING_SHARE,
                "PSBT_IN_FROST_VERIFYING_SHARE",
            ),
            (
                PSBT_OUT_FROST_PARTICIPANT_SHARES,
                "PSBT_OUT_FROST_PARTICIPANT_SHARES",
            ),
        ] {
            assert_eq!(field_name(key_type), Some(expected));
        }
        assert_eq!(field_name(0xaa), None);
    }
}
