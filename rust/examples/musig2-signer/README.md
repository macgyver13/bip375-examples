# Silent Payments from a MuSig2 Treasury

## Background

A grant organization wants to pay grantees using Silent Payments to avoid the operational burden of managing unique addresses for each payroll. The treasury holding the funds is secured by an aggregated MuSig2 wallet (e.g. 3-of-3), with keys held on hardware signing devices.

## The Challenge

Silent Payments (BIP-352) require the spending transaction to include at least one input with a single, extractable public key. The sender uses the corresponding input private key(s) to compute an ECDH shared secret with the recipient's scan key, deriving a unique output for each payment. A MuSig2-aggregated key can serve as an input key, but because no single party holds the aggregate secret, the ECDH share must be assembled from per-party partial shares - each carrying a DLEQ proof (the same technique BIP-375 uses) to prove it was constructed honestly.

## The Solution: MuSig Aggregated Key + Two-Round PSBT

Because each party only knows its own share of the aggregate secret key `a_Q`, the ECDH share must be computed in pieces: each party contributes a partial share `shareᵢ` derived from its partial secret `skᵢ`, the key that normally feeds into KeyAgg. Shares are recombined using the public KeyAgg coefficients (`aᵢ`), parity accumulators (`gacc`, `gᵥ`), and accumulated tweak (`tacc`) - see [Output Derivation Comparison](#output-derivation-comparison) for the exact construction. To prove the partial shares were computed honestly, each party attaches a DLEQ proof (BIP-374) binding its partial share to its participant public key (mirroring the BIP-375 approach).

The COLDCARD implementation signs the `tr(musig(A,B,C)/0/*)` descriptor. The synthetic `/0/*` step is a tweak on the *aggregate* key, not a per-device derivation. Each device exposes only its account-level participant key. The `/0/*` index is carried on the aggregate internal key's `PSBT_IN_TAP_BIP32_DERIVATION` entry in the PSBT; a signer recovers it by subtracting the enrolled descriptor's bare aggregate-fingerprint prefix from that path. The per-participant account-level entries leave an empty suffix, so only the aggregate entry yields the synthetic derivation, then reuses the canonical `tr(musig(…)/0/*)` code path to validate the scriptPubKey and reconstruct `tacc`.

To keep the total number of PSBT rounds to a minimum the MuSig2 nonce and ECDH share collection are combined in the first round:

- **Round 1 - Contribute** - Partial ECDH share, DLEQ proof, and fresh MuSig2 pubnonce from every signer (last signer computes Silent Payment output scripts from the aggregated ECDH share).
- **Round 2 - Sign** - Each signer independently re-verifies Silent Payment output scripts then contributes partial MuSig2 signature completing the MuSig2 aggregation and PSBT finalization as normal.

### Proposed PSBT Extensions

| Name | \<keytype> | \<keydata> | \<keydata> Description | \<valuedata> | \<valuedata> Description | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MuSig2 Partial Silent Payment Input ECDH Share | `PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE` = 0x21 | <33 byte scankey> <33 byte participant pubkey> | The pairing of scan key and MuSig2 participant public key that this ECDH share is for. | <33 byte share> | Each party's partial ECDH share computed as `skᵢ * B_scan` | | 0 | 2 |
| MuSig2 Partial Silent Payment Input DLEQ Proof | `PSBT_IN_MUSIG2_PARTIAL_DLEQ` = 0x22 | <33 byte scankey> <33 byte participant pubkey> | The pairing of scan key and MuSig2 participant public key that this DLEQ proof is for. | <64 byte proof> | Each party's partial DLEQ proof (`dleqᵢ`) | | 0 | 2 |

### Notation

#### BIP-352 Terms

| Symbol | Meaning |
| --- | --- |
| `B_scan` | The recipient's scan public key |
| `B_spend` | The recipient's spend public key |
| `input_hash` | The BIP-352 input hash over `outpoint_L` (smallest outpoint) and the input public key |
| `Pₖ` | The derived Silent Payment output public key for index `k` |

#### Per-party (`i = 1..N`)

| Symbol | Meaning |
| --- | --- |
| `skᵢ` | The i-th party's account-level participant secret key (e.g. `m/48'/1'/0'/2'`) |
| `aᵢ` | The i-th party's KeyAgg coefficient (BIP-327) |
| `shareᵢ` | The i-th party's partial ECDH share, computed as `skᵢ * B_scan` |
| `dleqᵢ` | The i-th party's DLEQ proof (BIP-374) binding `shareᵢ` to its participant public key |

#### KeyAgg & tweak accumulators (BIP-327 / BIP-328 / BIP-341)

| Symbol | Meaning |
| --- | --- |
| `gacc` | The running parity accumulator after BIP-328 synthetic derivation |
| `gᵥ` | The parity factor from the BIP-341 taproot tweak step |
| `tacc` | The accumulated tweak (BIP-328 synthetic derivation + BIP-341 taproot tweak) |
| `P` | The taproot internal key tweaking `P` yields `Q` |
| `Q` | The aggregate output public key (the P2TR input key) |
| `a_Q` | The aggregate tweaked secret - see [Output Derivation Comparison](#output-derivation-comparison) for its construction |

### Single-Party vs MuSig2 Taproot Input Comparison

| Component | Single-Party Taproot | MuSig2-Taproot (Generalization) |
| --- | --- | --- |
| On-Chain Input Key | A | Q (Aggregate Key) |
| Input Secret | a (Tweaked Secret) | a_Q (Tweaked Agg. Secret) |
| ECDH Share Point | a \* B_scan | a_Q \* B_scan |

#### Output Derivation Comparison

**Traditional BIP-352** sums the eligible input secret keys, `a = Σ aᵢ` with `A = a · G`:

    input_hash = hashBIP0352/Inputs(outpoint_L || A)
    Pₖ = B_spend + hash( serP(input_hash * a * B_scan) || k ) * G

**MuSig2 Generalization** replaces the on-chain input key `A` with the aggregate
output key `Q` and the secret `a` with the aggregate tweaked secret `a_Q`
(`a_Q = gᵥ * (gacc * Σ aᵢ * skᵢ + tacc)`):

> *Note:* The `a_Q` scalar in this generalization is shown only to demonstrate that the MuSig2 spend is algebraically identical to the single-party case. No one party knows skᵢ by MuSig2 design.

    input_hash = hashBIP0352/Inputs(outpoint_L || Q)
    Pₖ = B_spend + hash( serP(input_hash * a_Q * B_scan) || k ) * G

The output formula depends on the input side only through the discrete log of the on-chain input key. Since `Q` is the spendable input key, `a_Q` plays the identical algebraic role as `a`, so `input_hash * a_Q * B_scan` is the correct ECDH shared secret. No party knows `a_Q`, so `a_Q * B_scan` is never formed directly - it is assembled from DLEQ-proven per-party shares as `(gᵥ * gacc) * Σ(aᵢ * shareᵢ) + (gᵥ * tacc) * B_scan`.

## The Signing Flow

### Coordinator

#### 1. Construction

The coordinator builds a PSBT with one MuSig2 P2TR input and N SP recipients + 1 change output. The recipient's scan public and spend public keys are recorded in `PSBT_OUT_SP_V0_INFO`. The participant keys are recorded on the input in `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` so every signer can see the exact set being aggregated. `PSBT_IN_TAP_INTERNAL_KEY` holds the taproot internal key `P` — the bare aggregate after BIP-328 synthetic derivation but before the taproot tweak.

`PSBT_IN_TAP_BIP32_DERIVATION` carries two kinds of entries: each participant's x-only key mapped to its account-level origin (`m/48'/1'/0'/2'`), and the aggregate key `P` mapped to the aggregate fingerprint with a `/0/<index>` path. That index selects the address — and therefore the UTXO — this input spends.

### Each signer (Round 1)

#### 2. Contribute - shares + nonce

Each party independently computes a partial ECDH share `shareᵢ = skᵢ * B_scan` from its account-level participant secret `skᵢ`, and writes it to `PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE`. A DLEQ proof binding that share to its account-level participant pubkey is written to `PSBT_IN_MUSIG2_PARTIAL_DLEQ`.

Additionally, the MuSig2 nonce is written to `PSBT_IN_MUSIG2_PUB_NONCE`.

### Final signer (Round 1)

#### 3. Silent Payment output derivation

All DLEQ proofs are verified against the account-level participant keys listed in `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS`. The signer combines the partial shares into the aggregate ECDH point `a_Q * B_scan` (see [Output Derivation Comparison](#output-derivation-comparison)), applies the `input_hash` factor to yield the ECDH shared secret, and derives the target output public keys, placing them in `PSBT_OUT_SCRIPT`.

### Each signer (Round 2)

#### 4. Independent verification

Before signing, each signer device re-verifies every DLEQ proof, re-aggregates the shares, re-derives the Silent Payment output script, and refuses to continue if the derived script does not match `PSBT_OUT_SCRIPT`. This is what protects the signers from a malicious coordinator and/or signer from redirecting funds.

#### 5. Partial signing

A taproot key spend sighash is computed over the unsigned transaction. Each party then uses its stored secret nonce, the aggregated pubnonce, and the sighash to emit a partial MuSig2 signature into `PSBT_IN_MUSIG2_PARTIAL_SIG`.

### Final signer (Round 2)

#### 6. Aggregation + finalize

The partial signatures are combined with the aggregated pubnonce and sighash into a single 64-byte Schnorr signature, written into the standard `PSBT_IN_TAP_KEY_SIG` field. The finalizer then turns the aggregated signature into the input's key-path witness and the extractor produces a broadcastable transaction.

## Security Properties

| Property | Mechanism |
| --- | --- |
| N-of-N authorization | MuSig2 aggregation requires all N partial signatures to produce a valid Schnorr signature |
| Rogue-key resistance | BIP-327 key aggregation coefficients bind each key to the specific participant set |
| DLEQ-proofed ECDH share | Zero-knowledge proof that the partial share uses the same secret as the participant's public key |
| Independent output verification | Each signer re-derives the Silent Payment output before signing |

## Open Concerns / Improvements

- Validate SecNonce Msg safety - session_digest uses sp_v0_info for SP outputs instead of full script, all other randomness properties follow MuSig2 nonce generation
- Signer order / sequence - test PSBT partial contributions with multiple signers in random order
- Partial secret safety - Do ECDH shares or DLEQ proofs leak secret key information for account-level secret keys?

### Coordinator Implementation Notes

- Spot checking a SP address on hardware signer is prone to error - display a checksum to simplify comparison
- The payroll list must be unforgeable - implement an out-of-band exchange by treasury signers any time the grantee list / amounts are altered
- **secp256k1 version shim** - The `musig2` crate uses secp256k1 0.31 while the rest of the workspace uses 0.29; byte-level converters in `spdk-core/src/psbt/roles/musig2_signer.rs` bridge the two and should be removed once the workspace upgrades.
