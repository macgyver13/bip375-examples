//! MuSig2 + Silent-Payment PSBT subsystem (UPSTREAM CANDIDATE).
//!
//! Ported from the old `spdk-core::psbt` MuSig2-feature subsystem (revision
//! `slznmzkv`), which the new standalone `psbt` crate dropped. Implements the
//! proposed BIP-375 extension where each MuSig2 party contributes a DLEQ-proven
//! partial ECDH share (`PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE` = 0x21 /
//! `PSBT_IN_MUSIG2_PARTIAL_DLEQ` = 0x22), and the final signer assembles the
//! aggregate-key ECDH share `a_Q * B_scan` via BIP-327/328/341 accumulators.
//!
//! All storage is native `psbt_v2::v2` (proposed fields live in `input.unknowns`).

pub mod bip352_hash;
pub mod keyagg;
pub mod outputs;
pub mod psbt_fields;
pub mod shares;
pub mod signing;
