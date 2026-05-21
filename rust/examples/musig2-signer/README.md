# Silent Payments from a Musig2 Treasury

## Background

A grant organization wants to pay grantees using Silent Payments to avoid the operational burden of managing unique addresses for each payroll. The treasury holding the funds is secured by an aggregated MuSig2 wallet (e.g. 3-of-3), with keys held on hardware signing devices.

## The Challenge

Silent Payments (BIP-352) require the spending transaction to include at least one input with a single, extractable public key. The sender uses the corresponding input private key(s) to compute an ECDH shared secret with the recipient's scan key, deriving a unique output for each payment. A MuSig2-aggregated key can serve as an input key, but because no single party holds the aggregate secret, the ECDH share must be assembled from per-party partial shares - each carrying a DLEQ proof (the same technique BIP-375 uses) to prove it was constructed honestly.

## The Solution: MuSig Aggregated Key + Two-Round PSBT

Because each party only knows its own share of the aggregate secret key, the ECDH share must be computed in pieces: each party contributes `share_i = x_i × B_scan`, where `x_i` is its **account-level** participant secret. A plain EC sum of the shares is *not* correct: the on-chain key is `a_Q = g₂ * (gacc * Σ μᵢ * xᵢ + tacc)`, not `Σ xᵢ`, so summing the raw shares yields an output the recipient cannot detect or spend. To prove those pieces were computed honestly, each party attaches a DLEQ proof (BIP-374) binding its partial share to its participant public key (mirroring the BIP-375 approach).

To keep the total number of PSBT rounds to a minimum the MuSig2 nonce and ECDH share collection are combined in the first round:

- **Round 1 - Contribute** - Partial ECDH share, DLEQ proof, and fresh MuSig2 pubnonce from every signer.
- **Round 2 - Sign** - After the Silent Payment output script is derived from the aggregated ECDH share and independently re-verified by every signer, each signer emits a partial MuSig2 signature. The partial signatures are then aggregated into a single Schnorr signature that unlocks the P2TR UTXO.

## The Signing Flow

**Coordinator:**

1. **Key aggregation** - Pre-PSBT, the participant public keys are aggregated under BIP-327 and tweaked with BIP-328 synthetic derivation and then a key-path only BIP-341 taproot tweak. The resulting x-only key is the output key for the shared P2TR UTXO.
2. **Construction** - The coordinator builds a PSBT with one input — the aggregated P2TR UTXO — and two outputs: a placeholder for the Silent Payment recipient and a change output back to the same aggregated key. The recipient's scan and spend keys are recorded in `PSBT_OUT_SP_V0_INFO` (BIP-375). The participant keys are recorded on the input in `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (BIP-373, 0x1a) so every signer can see the exact set being aggregated.

   **Derivation-path layout.** Participant keys are recorded in `PSBT_IN_TAP_BIP32_DERIVATION` at their **account-level** origin (e.g. `m/48'/1'/0'/2'`). The synthetic `/0/*` index lives on the **aggregate internal key's** entry (under the aggregate's synthetic fingerprint), not on the participants. Signers recover the synthetic derivation from that aggregate entry — matching how a canonical (non-SP) `tr(musig(…)/0/*)` keyspend is built — so the same code path validates the scriptPubKey and reconstructs `tacc`.

**Each signer (Round 1):**

3. **Contribute Partial Shares** - Each party independently, and without coordination, computes:  - a partial ECDH share `share_i = sk_i * B_scan`, where `sk_i` is the party's **account-level** participant secret (the key that feeds KeyAgg, *not* the BIP-328 `/0/*`-derived child — the synthetic derivation is folded into `tacc`, not applied per-share), written to `PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE` (proposed BIP extension, 0x21); - a DLEQ proof binding that share to its (account-level) participant pubkey, written to `PSBT_IN_MUSIG2_PARTIAL_DLEQ` (proposed BIP extension, 0x22); - a fresh MuSig2 pubnonce, written to `PSBT_IN_MUSIG2_PUB_NONCE` (BIP-373, 0x1b).

**Final signer (Round 1):**

4. **Silent Payment output derivation** - All DLEQ proofs are verified against the **account-level** participant keys listed in `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (BIP-373, 0x1a). The signer reconstructs the public factors from the PSBT — the KeyAgg coefficients `μᵢ` (BIP-327), the parity accumulators `gacc` (after BIP-328 synthetic derivation) and `g₂` (after the BIP-341 taproot tweak), and the accumulated tweak `tacc` (synthetic + taproot) — and combines the shares as `(g₂ * gacc) * Σ(μᵢ * shareᵢ) + (g₂ * tacc) * B_scan = a_Q * B_scan`. For a MuSig2 input the only ECDH artifacts carried on the PSBT are the per-signer partial shares (`PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE`, 0x21) and their DLEQ proofs (`PSBT_IN_MUSIG2_PARTIAL_DLEQ`, 0x22).
The aggregate point `a_Q * B_scan` is unhashed. To calculate the final `PSBT_OUT_SCRIPT`, the signer computes the BIP-352 input_hash from the transaction's lexicographically smallest outpoint and the aggregate public key, then multiplies the input_hash scalar by `a_Q * B_scan` to yield the `ecdh_shared_secret`, from which the target output public keys `P_mn` are derived and placed in `PSBT_OUT_SCRIPT`.

**Each signer (Round 2):**

5. **Independent verification** - Before signing, each party re-verifies every DLEQ proof, re-aggregates the shares, re-derives the Silent Payment output script, and refuses to continue if the derived script does not match `PSBT_OUT_SCRIPT`. This is what protects the signers from a malicious or buggy coordinator redirecting funds.
6. **Partial signing** - A BIP-341 taproot key-spend sighash is computed over the unsigned transaction. Each party then uses its stored secret nonce, the aggregated pubnonce, and the sighash to emit a 32-byte partial MuSig2 signature into `PSBT_IN_MUSIG2_PARTIAL_SIG` (BIP-373, 0x1c).

**Coordinator:**

7. **Aggregation and extraction** - The partial signatures are combined with the aggregated pubnonce and sighash into a single 64-byte Schnorr signature, written into the standard `PSBT_IN_TAP_KEY_SIG` field. The finalizer turns that into the input's witness and the extractor produces a broadcastable transaction.

## Security Properties

| Property | Mechanism |
| --- | --- |
| N-of-N authorization | MuSig2 aggregation requires all N partial signatures to produce a valid Schnorr signature |
| Rogue-key resistance | BIP-327 key aggregation coefficients bind each key to the specific participant set |
| DLEQ-proofed ECDH share | Zero-knowledge proof that the partial share uses the same secret as the participant's public key |
| Independent output verification | Each signer re-derives the Silent Payment output before signing |
| Nonce freshness | A new MuSig2 `SecNonce` is generated per session and consumed by value |

## Open Concerns / Improvements

- Validate SecNonce Msg safety - session_digest uses sp_v0_info for SP outputs instead of full script, all other randomness properties follow Musig2 nonce generation
- Signer order / sequence - test PSBT partial contributions with multiple signers in random order
- Partial secret safety - Do ECDH shares or DLEQ proofs leak secret key information for aggregated keys?

### Coordinator Implementation Notes

- Spot checking a SP address on hardware signer is prone to error - display a checksum to simplify comparison
- The payroll list must be unforgeable - implement an out-of-band exchange by treasury signers any time the grantee list / amounts are altered
- **secp256k1 version shim** - The `musig2` crate uses secp256k1 0.31 while the rest of the workspace uses 0.29; byte-level converters in `spdk-core/src/psbt/roles/musig2_signer.rs` bridge the two and should be removed once the workspace upgrades.