# BIP-375 Reference Examples

This repository exercises [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki): Sending Silent Payments with PSBTs. It provides Rust signing examples and a Python API generated with UniFFI for building BIP-375 test vectors and exploring SPDK's PSBT workflows. The examples also use BIP-352 silent-payment operations and BIP-374 DLEQ proofs.

## Project Layout

```
crates/
├── bip375-helpers/  # Shared example, display, I/O, and wallet utilities
└── spdk-uniffi/     # UniFFI bindings, exposed to Python as spdk_psbt
examples/
├── hardware-signer/ # Air-gapped hardware-wallet simulation
└── multi-signer/    # Multi-party signing workflow
tools/
└── psbt-viewer/     # Visual PSBT reader
deprecated/python/   # Unmaintained pure-Python implementation
```

The workspace pins SPDK's `psbt` and `silentpayments` crates and a separate `psbt-v2` crate from rust-psbt in [Cargo.toml](Cargo.toml). SPDK supplies the BIP-375 roles and silent-payment operations; rust-psbt supplies the PSBT v2 types and signing used by the examples. `bip375-helpers` contains shared example code, and `spdk-uniffi` exposes PSBT and cryptographic operations to Python. The pinned revisions let this repository exercise development across SPDK and rust-psbt together.

## Run an Example

### Multi-Signer

```bash
# GUI (default)
cargo run -p multi-signer

# CLI workflow
cargo run -p multi-signer -- --cli
```

### Hardware Signer

```bash
# Interactive CLI
cargo run -p hardware-signer

# Automated demo
cargo run -p hardware-signer -- --demo-flow --auto-read --auto-approve

# GUI demo
cargo run -p hardware-signer --bin hardware-signer --features=gui
```

Add `--attack` to the automated demo to simulate a malicious device.

### PSBT Viewer

The viewer embeds the upstream BIP-375 JSON vectors at compile time. Place a `bips` checkout next to this repository so `../bips/bip-0375/bip375_test_vectors.json` exists before building it:

```bash
git clone https://github.com/bitcoin/bips.git ../bips
```

```bash
cargo run -p psbt-viewer
```

## Python Bindings

The supported Python API is `spdk_psbt`, built from [`crates/spdk-uniffi`](crates/spdk-uniffi/README.md).

```bash
pip install -e 'crates/spdk-uniffi[dev]'
python crates/spdk-uniffi/examples/simple_example.py
pytest crates/spdk-uniffi/tests -v
```

### Test Vector Generation

Use `spdk_psbt.SilentPaymentPsbt.create_from_parts(...)` to build valid PSBTs from inputs and outputs. The UniFFI API also exposes `SilentPaymentPsbt.create(input_count, output_count)` and `add_raw_global_field`, `add_raw_input_field`, `remove_raw_input_fields_by_type`, and `add_raw_output_field` to construct intentionally invalid cases. Serialize each PSBT with `serialize()`, base64-encode the bytes in Python, and place them in the upstream JSON format's `valid` or `invalid` array (each entry has a `description` and `psbt`). See the [binding API](crates/spdk-uniffi/src/spdk_psbt.udl) and [upstream vectors](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json) for fields and examples.

There is no maintained UniFFI vector-generator command in this checkout yet. The former pure-Python `psbt_sp` implementation and generator remain in [deprecated/python](deprecated/python/) for historical reference; they are not maintained for new work.

## Tests and Further Reading

```bash
cargo test -p spdk-uniffi
```

Use `just` for additional shortcuts, including `just multi`, `just multi-cli`, and `just uniffi`.

Read [REFERENCE.md](REFERENCE.md) for an implementation-oriented guide to BIP-375 concepts and security properties.

The repository no longer bundles test vectors; use the [upstream BIP-375 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json).
