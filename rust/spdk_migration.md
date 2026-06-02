# Migrate bip375-examples to the new spdk `psbt` crate

## Context

`bip375-examples/rust` was built against spdk revision `slznmzkv` (bookmark
`musig2-feature`), where all PSBT functionality lived under `spdk_core::psbt::*`
with rich custom wrapper types (`Psbt`, `PsbtInput`, `PsbtOutput`,
`Bip375PsbtExt`), a `crypto` module, and many role free-functions
(`create_psbt`, `add_inputs/outputs`, `add_musig2_*`, `finalize_*`).

The migration **target** is `~/src/spdk @ = xztlowrz` (`psbt_definitive@fork-sosthene`).
There, PSBT functionality was extracted into a **standalone `psbt` crate** that is
a ground-up rewrite delegating to `psbt_v2` (Sosthene's `rust-psbt` fork,
`taproot_sign` branch, `silent-payments` feature). Consequences:

- `psbt::core::Psbt` is now just a re-export of `psbt_v2::v2::Psbt`; inputs/outputs
  are native `psbt_v2::v2::{Input, Output}`. The custom `PsbtInput`/`PsbtOutput`
  (enum `Regular`/`SilentPayment`) wrapper types are **gone**.
- The API is now extension traits on the native PSBT: `ConstructorPsbtExt`,
  `Bip375UpdaterExt`, `SignerPsbtExt`, `ExtractorPsbtExt`,
  `InputWitnessFinalizerPsbtExt`.
- **Dropped** from the public surface: the entire `crypto` module, the standalone
  `creator`/`musig2_signer` roles, `add_musig2_*`/`aggregate_musig2_sigs`,
  `AggregatedShares`/`PartialEcdhShareData`, the free accessors
  (`get_input_pubkey/txid/vout`). The old helpers still exist only inside
  `psbt/src/roles/validation.rs`, which is **commented out** of `roles/mod.rs`
  (not public API).

Goal: get `bip375-helpers`, `psbt-viewer`, and the three examples
(`hardware-signer`, `multi-signer`, `musig2-signer`) compiling and working
against the new crate. Per direction: **musig2 PSBT support is deferred /
out of scope** (musig2-signer's signing path is parked); decisions about where
dropped functionality lives are made **case-by-case** below.

## Decision posture (per the user)

- Scope: helpers + viewer + **all three examples** (musig2 only for its
  non-musig2 paths; its musig2 signing flow is deferred).
- Where dropped code lands: **case-by-case**, recommendations in the table below.
- Target: `psbt_definitive@fork-sosthene` (`xztlowrz`).
- `crates/spdk-uniffi` is **out of scope** (not a workspace member — commented
  out — and a binding layer). It is the most spdk-coupled crate; tracked as a
  follow-up, not migrated here.

## Phase 0 — Workspace wiring

`rust/Cargo.toml`:
- Keep `psbt = { path = "/Users/ron/src/spdk/psbt" }`,
  `silentpayments = { path = "/Users/ron/src/spdk/silentpayments" }`.
- Add the dependencies the examples now need directly:
  - `psbt-v2 = { git = "https://github.com/Sosthene00/rust-psbt.git", branch = "taproot_sign", features = ["silent-payments"] }`
    (examples now construct/inspect native `Input`/`Output`).
  - `rust-dleq` (only if a non-deferred path needs DLEQ; currently only musig2 ⇒
    likely **not** needed now).
- Uncomment the example members and `crates/spdk-uniffi` stays commented.
- Remove every `spdk-core.workspace = true` from example `Cargo.toml`s; replace
  with `psbt.workspace = true` (+ `psbt-v2` where native types are touched).
  This matches the already-WIP `musig2-signer/Cargo.toml` conflict resolution
  (it drops `spdk-core`, adds `psbt`).

## Case-by-case API mapping (old `spdk_core::psbt` → new)

| Old symbol | New location | Action / where it should live |
|---|---|---|
| `Psbt` | `psbt::Psbt` (= `psbt_v2::v2::Psbt`) | Swap import. Field access changes (native v2). |
| `PsbtInput` | `psbt_v2::v2::Input` | Replace type; update field access in helpers/examples. |
| `PsbtOutput` (enum `Regular`/`SilentPayment`) | **gone** → `psbt_v2::v2::Output` | Biggest semantic change. The Regular/SP distinction must move into **bip375-helpers** (e.g. a local `OutputKind` helper or a function that classifies a v2 `Output`). Reused by `transaction/mod.rs`, examples' `shared_utils`. |
| `Bip375PsbtExt` | split traits: `SignerPsbtExt`, `Bip375UpdaterExt`, `ConstructorPsbtExt`, `ExtractorPsbtExt`, `InputWitnessFinalizerPsbtExt` | Re-point each method call to its new trait. |
| `roles::creator::create_psbt(n_in, n_out)` | `ConstructorPsbtExt::create_new_transaction(outputs)` + `add_inputs(outpoints)` | Paradigm change (count-based → outputs/outpoints). Used in `file_io.rs` test + examples. Rewrite call sites. |
| `roles::{add_inputs, add_outputs}` | `ConstructorPsbtExt` | Map to `create_new_transaction`/`add_inputs`. |
| `roles::signer::sign_inputs`, `add_ecdh_shares_partial` | `SignerPsbtExt::{aggregate_ecdh_shares, compute_sp_outputs, set_sp_scriptpubkey, sign_sp_inputs}` | Signing flow restructured. Rework hardware-signer/multi-signer signing sequences against the 4 new methods. **Needs API discovery during impl** (semantics differ). |
| `roles::input_finalizer::finalize_sp_outputs` | SP output finalization is now `compute_sp_outputs` + `set_sp_scriptpubkey` (signer); `finalize_sp_outputs` named only in a doc comment, no impl file | Treat as **investigate-first**: confirm whether SP-output finalize is a signer step now. |
| `roles::finalize_input_witnesses` | `InputWitnessFinalizerPsbtExt::finalize` | Swap. |
| `roles::extract_transaction` | `ExtractorPsbtExt::extract_tx` | Swap. |
| `roles::updater::{add_output_bip32_derivation, update_input_derivation, Bip32Derivation}` | `Bip375UpdaterExt::{set_bip32_derivation, set_sp_spend_bip32_derivation, set_sp_tweak, get_*}` | `Bip32Derivation` struct gone — pass `(PublicKey, Fingerprint, DerivationPath)` tuples. Rewrite `hardware-signer/shared_utils.rs:579-708`. **Honest-path only — not used by the attack scenarios** (see Attack-mode viability below). |
| `crypto::pubkey_to_p2wpkh_script` | **not public** (only in disabled `validation.rs`) | **Re-implement in bip375-helpers** (trivial `bitcoin` script build). Reused by `transaction/mod.rs`, `multi-signer/shared_utils.rs`. |
| `crypto::tweaked_key_to_p2tr_script` | same | **bip375-helpers** local helper. |
| `crypto::script_type_string` | same | **bip375-helpers** display helper (pure display; clearly belongs in the demo layer). |
| `crypto::derive_silent_payment_output_pubkey` | same | **bip375-helpers** via `silentpayments` crate primitives, or recommend upstream re-export. Used by `hardware-signer/attack_mode.rs`. |
| `core::{AggregatedShares, PartialEcdhShareData}` | **gone** | Used by `hardware-signer/attack_mode.rs:295,321`. Determine new ECDH-share representation in `psbt_v2`; adapt attack code. **Investigate-first.** |
| `crypto::{compute_ecdh_share, dleq_generate_proof, dleq_verify_proof}`, `is_input_eligible`, `get_input_pubkey/txid/vout`, `add_musig2_*`, `aggregate_musig2_sigs` | **gone** | All on the **musig2-signer** path ⇒ **deferred / out of scope**. Park `workflow.rs` + `scan_recipient.rs` behind a `#[cfg(feature)]`/`compile_error!` stub or exclude those bins so the rest of the workspace builds. |
| `roles::validation::{validate_psbt, ValidationLevel}` | exists but **commented out** of `roles/mod.rs` | Used by `tests/test_vectors.rs:15`. Recommend **upstream**: re-enable/finish `validation` in the new psbt crate (it already contains the logic). If upstream can't land in time, port a thin validator into the test crate. **Upstream-leaning.** |
| `psbt::Error` (+ variants) | `psbt::Error` | Variant set mostly preserved; `MissingWitnessUtxo` and `UnsupportedScriptType` dropped. Update `io/error.rs` `#[from]` and any matches. |

### Items recommended for **spdk upstream** (not local)
- `roles::validation` re-enable (logic already present, just disabled).
- A public, supported home for SP-output script derivation if `compute_sp_outputs`
  / `set_sp_scriptpubkey` don't fully cover the old `finalize_sp_outputs`.
- Re-export of a SP-output pubkey derivation helper (used by attack demos) if the
  intent is for consumers not to reach into `silentpayments` directly.

### Items recommended for **bip375-examples** (local)
- Output Regular/SP classification (replacing `PsbtOutput` enum).
- Script builders (`pubkey_to_p2wpkh_script`, `tweaked_key_to_p2tr_script`).
- `script_type_string` display helper.
- The virtual-wallet / multi-party / metadata layers already live here and stay.

## Attack-mode viability (hardware-signer)

The four attack variants in `examples/hardware-signer/src/attack_mode.rs` mostly
**survive** the migration, because they manipulate raw SP output bytes that exist
natively in `psbt_v2::v2::Output`:

- **Attacks 2/3/4** (wrong scan key / substitute spend key / strip SP fields)
  write `psbt.outputs[i].sp_v0_info = Some(..)/None` directly. Native `Output`
  already exposes `sp_v0_info` (the new `SignerPsbtExt::aggregate_ecdh_shares`
  reads it), so these map with no behavioral change.
- **`prepare_scan_keys`** uses the dropped `Bip375PsbtExt::get_output_scan_keys()`.
  Reimplement locally as `sp_v0_info[..33]` — the same slice the new signer uses.
- **Attack 1 (`sign_inputs_malicious`)** is the only real rework. It poisons the
  spdk-only `PsbtInput.private_key` field and calls the removed
  `sign_inputs(secp, psbt, &inputs)`. Native `Input` has no `private_key`, and the
  new signer takes the key as a parameter: `SignerPsbtExt::sign_sp_inputs(secp,
  attacker_spend_key)`. The attack becomes simpler (pass the wrong key) but must be
  rewritten — not a blocker.

**Regular/Taproot input signing — resolved:** `SignerPsbtExt::sign_sp_inputs`
only covers SP inputs, but the psbt_v2 `taproot_sign` branch provides native
keystore-based signing for the rest: `psbt_v2::v2::Psbt::sign<C, K: GetKey>(self,
k, secp) -> Result<(Psbt, SigningKeys), ..>`, which handles **both ECDSA (P2WPKH)
and Schnorr (P2TR)** inputs per `signing_algorithm()`. So honest non-SP signing in
hardware-signer/multi-signer uses `Psbt::sign(&keystore, secp)`; SP inputs use
`sign_sp_inputs`. Note `sign` takes `self` by value and returns the signed PSBT.
Malicious Attack 1 supplies the **attacker's key via the `GetKey` keystore** for
non-SP inputs (and `sign_sp_inputs(attacker_key)` for SP) — cleaner than poisoning
a per-input field.

## IMPLEMENTATION STATUS (checkpoint)

Done and verified:
- **Phase 0 wiring** — `psbt-v2` (Sosthene `taproot_sign`) added to workspace deps;
  example `Cargo.toml`s swapped `spdk-core` → `psbt`/`psbt-v2`. Examples are
  currently **commented out of `members`** (staged) so `cargo build --workspace`
  stays green; re-enable each as migrated.
- **Phase 2 — `bip375-helpers`** — builds, 26 tests pass. New
  `src/crypto.rs` (script/tweak helpers, pure bitcoin/secp), native
  `psbt_v2::v2::{Input, Output}` throughout, SP outputs encoded via `sp_v0_info`
  (`transaction::sp_v0_info_bytes`), `SilentPaymentAddress::new` API drift fixed.
- **`transaction::build_psbt(inputs, outputs)`** — assembles a PSBT via the new
  Constructor role and re-applies witness_utxo/sequence (constructor only carries
  outpoints). Reusable by both examples.
- **`src/sp_signer.rs`** — UPSTREAM CANDIDATE. Isolated reimplementation of the
  removed per-input ECDH share + DLEQ proof *generation*
  (`add_input_ecdh_share`): computes `share = privkey*scan_key`, DLEQ-proves it,
  writes `input.sp_ecdh_shares` + `input.sp_dleq_proofs` — exactly what the new
  `SignerPsbtExt::aggregate_ecdh_shares` consumes/verifies. Intended to move into
  the spdk `psbt` signer role.
- **Phase 3 — `psbt-viewer`** — builds.

## HANDOFF: remaining example migration (mechanical, mappings pinned)

Apply across `multi-signer`, then `hardware-signer` (incl. `attack_mode.rs`),
then `musig2-signer` (non-musig2 only). Files per example: `shared_utils.rs`,
`workflow_actions.rs`/`workflow.rs`, `core/` orchestrator, `main.rs`.

Old → new (all confirmed against the new crates):
- `spdk crypto::{pubkey_to_p2wpkh_script, tweaked_key_to_p2tr_script, script_type_string}` → `bip375_helpers::crypto::{…}`.
- `PsbtInput`/`PsbtOutput` → native `psbt_v2::v2::{Input, Output}`. Classify outputs by `output.sp_v0_info.is_some()`. `input.witness_utxo` is now `Option<TxOut>`; outpoint via `input.previous_txid`/`input.spent_output_index` (no `.outpoint`). Display code that read `PsbtOutput::SilentPayment{address,..}` must parse scan/spend keys from `sp_v0_info[..33]`/`[33..]`.
- `create_psbt`+`add_inputs`+`add_outputs` → `bip375_helpers::transaction::build_psbt(inputs, outputs)`.
- `update_input_derivation`/`Bip32Derivation` → `psbt::roles::Bip375UpdaterExt::set_bip32_derivation(&pubkey, fingerprint, path)` on `psbt.inputs[i]` (Fingerprint + `bitcoin::bip32::DerivationPath`, not `Vec<u32>`).
- `add_ecdh_shares_partial` → `bip375_helpers::sp_signer::add_input_ecdh_share(secp, &mut psbt.inputs[i], i, &privkey, &scan_key)` per controlled input.
- `finalize_sp_outputs` → `psbt.aggregate_ecdh_shares(secp)?` → `let m = psbt.compute_sp_outputs(secp)?` → `psbt.set_sp_scriptpubkey(m)?` (all `SignerPsbtExt`).
- `sign_inputs` (non-SP) → `let (psbt, _keys) = psbt.sign(&party_secret_key, secp).map_err(|(_, e)| e)?;` (psbt_v2 `Psbt::sign`, `impl GetKey for SecretKey`). SP-input spends → `SignerPsbtExt::sign_sp_inputs(secp, spend_key)`.
- `finalize_input_witnesses` → `psbt::roles::InputWitnessFinalizerPsbtExt::finalize(&mut psbt)`.
- `extract_transaction` → `psbt::roles::ExtractorPsbtExt::extract_tx(psbt)`.
- `validation::validate_psbt`/`ValidationLevel` → **drop** (disabled upstream).

attack_mode.rs specifics (already analyzed in Attack-mode viability above):
- Attacks 2/3/4 keep working via `psbt.outputs[i].sp_v0_info = Some/None`.
- `get_output_scan_keys()` → local helper reading `sp_v0_info[..33]`.
- `sign_inputs_malicious` → sign with attacker key via `psbt.sign(&attacker_key, secp)` / `sign_sp_inputs(attacker_key)`; native `Input` has no `private_key`.
- `core::{AggregatedShares, PartialEcdhShareData}` gone → use `psbt.global.sp_ecdh_shares` / per-input `sp_ecdh_shares` (native maps).

Watch-outs:
- `create_new_transaction` **shuffles outputs** (BIP-375). Fine functionally (SP keyed by `sp_v0_info`), but fix any order-dependent demo/test assertions.
- `validation` is commented out in the upstream `psbt` crate → `tests/test_vectors.rs` (Phase 7) is blocked until it's re-enabled upstream (recommended) or a thin validator is ported locally.
- `derive_silent_payment_output_pubkey` / `apply_label_to_spend_pubkey` (hardware-signer) were not ported yet — add to `bip375_helpers::crypto` when migrating Phase 5 (verify `silentpayments::utils::*` visibility; the spdk signer imports `silentpayments::utils::common::*`, so the needed items are public).

Verify each example by **running** it (per `rust/justfile`) through finalize/extract,
not just compiling — the signer sequencing and ECDSA tx_modifiable clearing need
runtime confirmation.

## Phased execution

1. **Phase 0 wiring** (above) → verify: `cargo metadata` resolves; nothing builds yet.
2. **bip375-helpers core** → verify: `cargo build -p bip375-helpers`.
   - `io/error.rs`: new `Error` import + variants.
   - `transaction/mod.rs`: native `Input`/`Output`, local script helper, local
     output classification, `validate_transaction_balance` reads v2 fields.
   - `io/file_io.rs` test: `create_psbt` → `ConstructorPsbtExt`.
   - Add the local helpers (`scripts`, `output_kind`, `script_type_string`).
3. **psbt-viewer** → verify: `cargo build -p psbt-viewer`, launches and renders a
   test vector. Should need only transitive changes (it already avoids spdk-core),
   plus any helper signature changes from step 2.
4. **multi-signer** → verify: `cargo build -p multi-signer`; run its workflow.
   - `shared_utils.rs`, `workflow_actions.rs`: constructor/signer/extractor traits,
     local script helpers.
5. **hardware-signer** → verify: `cargo build -p hardware-signer`; run signing +
   attack-mode demo.
   - `hw_device.rs`, `shared_utils.rs`, `wallet_coordinator.rs`, `attack_mode.rs`:
     signer/updater/finalizer traits; resolve `AggregatedShares` representation.
6. **musig2-signer (non-musig2 only)** → verify: `cargo build -p musig2-signer`
   for the main bin with musig2 paths stubbed/deferred; document deferred work.
   - Finish the already-WIP `Cargo.toml` conflict (drop `spdk-core`, add `psbt`).
7. **tests/test_vectors.rs** → verify: `cargo test` (gated on the validation
   decision above).

## Verification (end-to-end)

- `cd rust && cargo build --workspace` (musig2 signing paths deferred/stubbed).
- `cargo test -p bip375-helpers` and the `tests/` vectors (after validation call).
- Run `psbt-viewer` and load a bundled test vector; confirm fields + summary render.
- Run `multi-signer` and `hardware-signer` demo workflows (per `rust/justfile`)
  through to PSBT finalize/extract; confirm a valid transaction is produced.
- Reference BIPs in `~/src/bips` (375/376/352/370) when adapting field semantics.

## Open risks / investigate-first during implementation

- New **signer** semantics (`aggregate_ecdh_shares` / `compute_sp_outputs` /
  `set_sp_scriptpubkey` / `sign_sp_inputs`) vs old `sign_inputs` +
  `add_ecdh_shares_partial` — map the exact sequence before rewriting.
- New ECDH-share representation in `psbt_v2` (old `AggregatedShares` /
  `PartialEcdhShareData` gone) — needed for hardware-signer attack mode.
- Non-SP signing path now uses `psbt_v2::v2::Psbt::sign` (GetKey keystore,
  ECDSA+Schnorr) rather than spdk's `sign_inputs` — resolved capability-wise, but
  the call sites consume/return the PSBT by value, so signing helpers in the
  examples need restructuring (see Attack-mode viability).
- Whether SP-output finalize is fully covered by the signer methods.
- `validation` upstream decision blocks the test crate.
