// ECDH aggregation for UniFFI bindings

use crate::errors::Bip375Error;
use crate::types::{AggregatedShare, SilentPaymentPsbt};
use bip375_core::ecdh_aggregation;
use secp256k1::PublicKey;

// ============================================================================
// Aggregated Shares Collection
// ============================================================================

pub struct AggregatedShares {
    inner: ecdh_aggregation::AggregatedShares,
}

// impl AggregatedShares {
//     pub fn get_share_point(&self, scan_key: Vec<u8>) -> Result<Option<Vec<u8>>, Bip375Error> {
//         let pk = PublicKey::from_slice(&scan_key).map_err(|_| Bip375Error::InvalidKey)?;

//         Ok(self
//             .inner
//             .get_share(&pk)
//             .map(|share| share.serialize().to_vec()))
//     }

//     pub fn scan_keys(&self) -> Vec<Vec<u8>> {
//         self.inner
//             .shares
//             .iter()
//             .map(|share| share.scan_key.serialize().to_vec())
//             .collect()
//     }

//     pub fn all_shares(&self) -> Vec<AggregatedShare> {
//         self.inner
//             .shares
//             .iter()
//             .map(AggregatedShare::from_core)
//             .collect()
//     }
// }

// ============================================================================
// Aggregation Function
// ============================================================================

pub fn aggregation_aggregate_ecdh_shares(psbt: &SilentPaymentPsbt) -> Result<AggregatedShares, Bip375Error> {
    let aggregated = psbt.with_inner(|p| ecdh_aggregation::aggregate_ecdh_shares(p))?;

    Ok(AggregatedShares { inner: aggregated })
}
