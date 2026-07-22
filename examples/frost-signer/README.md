# Silent Payments from a 2-of-3 FROST Treasury

This example spends a Taproot output controlled by any two of three FROST
participants and creates a BIP-352 Silent Payment output. It is the threshold
counterpart to `musig2-signer`, with a GUI that exposes each PSBT round and the
fields added by each selected signer.

## Security model

No participant holds the group secret. For a signing session, exactly two
participants are selected from Alice, Bob, and Charlie:

1. Each selected signer publishes a FROST round-one commitment. Secret signing
   nonces remain local and are represented by a single-use Rust value.
2. Each selected signer also publishes one ECDH share per recipient scan key and
   a BIP-374 DLEQ proof binding that share to the signer's Taproot-tweaked FROST
   verifying share.
3. Once the threshold is present, the coordinator verifies every DLEQ proof,
   interpolates the selected Shamir shares with their Lagrange coefficients,
   and derives the Silent Payment output scripts.
4. Before producing a FROST signature share, every signer independently repeats
   the DLEQ verification, interpolation, and output derivation, and rejects any
   `script_pubkey` that does not match the ECDH shares. This detects a coordinator
   that tampers with a derived output script, but it does not by itself prove the
   recipient is the intended one: the derivation reads the recipient scan/spend
   keys from the PSBT's `sp_v0_info`. Each signer must therefore authenticate
   `sp_v0_info` against a recipient it approved out of band (the example passes the
   authorized `SilentPaymentAddress` into `partial_sign`).
5. Each signer also confirms that the FROST session message equals the sighash of
   the PSBT it inspected, so a coordinator cannot have the group sign a different
   transaction than the one whose outputs were verified.
6. The two signature shares are verified and aggregated into a standard 64-byte
   BIP-340 signature. The PSBT is finalized as a Taproot key-path spend.

The GUI uses deterministic dealer-generated keys only as reproducible fixtures.
A deployment must provision authenticated `KeyPackage`s using an appropriate
trusted-dealer or DKG ceremony, establish a consistent `PublicKeyPackage`, and
keep each key package on its own signer. Key generation and authenticated
transport are intentionally outside this transaction-signing example; they are
not replaced with an insecure application protocol.

## PSBT compatibility modules

Upstream `rust-psbt` has no FROST signing fields, so the crate keeps the missing
surface local:

- `frost_psbt` encodes the public group configuration, the authoritative
  identifier-to-verification-share roster, FROST signing commitments, and
  FROST signature shares as local PSBT fields. The input roster is checked
  against each signer's authenticated `PublicKeyPackage`; the separate output
  participant-share tag remains advisory change-detection metadata. Secret
  nonces and secret key packages are never stored in the PSBT.
- `frost_spdk` implements validated FROST signer/coordinator roles, threshold
  ECDH interpolation, DLEQ verification, Silent Payment derivation, and
  independent output verification. It handles exactly one eligible input, because
  the BIP-352 `input_hash` (smallest outpoint) and summed input key `A` are
  computed for the single-input case; multi-input support is out of scope here.

The existing proposed fields named
`PSBT_IN_SP_PARTIAL_ECDH_SHARE` and
`PSBT_IN_SP_PARTIAL_DLEQ` are deliberately reused for FROST ECDH shares.
They are structurally suitable and are expected to receive generalized names
upstream. No duplicate FROST-only ECDH field numbers are introduced here.

## Protocol boundary

The crypto implementation is
[`frost-secp256k1-tr` 3.0](https://crates.io/crates/frost-secp256k1-tr), which
produces BIP-340-compatible signatures. This example does not claim wire or
test-vector compatibility with the separate draft BIP-445 FROST3 protocol.

The FROST group key represented by the fixtures is the exact Taproot internal
wallet key for the demonstrated UTXO. Unlike the MuSig2 example, this crate does
not silently apply BIP-328 synthetic child derivation to independently created
shares. Wallet derivation and share provisioning must agree before a PSBT is
accepted; the BIP-341 Taproot tweak is then applied exactly once by the upstream
FROST implementation.

## Run and test

From `rust/`:

```text
just frost
cargo test -p frost-signer --all-targets --all-features
```

The tests cover proprietary-field validation and PSBT serialization, 2-of-3
signing, insufficient commitments, the full BIP-375 transaction flow, final
BIP-340 verification through `rust-secp256k1`, and refusal to sign a tampered
Silent Payment output.
