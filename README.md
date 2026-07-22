# BIP-375 Reference Examples

This repository provides a Rust implementation of [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki): Sending Silent Payments with PSBTs. It includes BIP-352 silent-payment operations, BIP-374 DLEQ proofs, interactive examples, and Python bindings generated with UniFFI.

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

Core PSBT and silent-payment functionality is supplied by the upstream `spdk-core` and `silentpayments` dependencies.

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

```bash
cargo run -p psbt-viewer
```

## Python Bindings

The supported Python API is `spdk_psbt`, built from [`crates/spdk-uniffi`](crates/spdk-uniffi/README.md).

```bash
pip install -e crates/spdk-uniffi
python crates/spdk-uniffi/examples/simple_example.py
pytest crates/spdk-uniffi/tests -v
```

The former pure-Python `psbt_sp` implementation is retained in [deprecated/python](deprecated/python/README.md) for historical reference only. It is not maintained and should not be used for new work.

## Tests and Further Reading

```bash
cargo test -p spdk-uniffi
```

Use `just` for additional shortcuts, including `just multi`, `just multi-cli`, and `just uniffi`.

Read [REFERENCE.md](REFERENCE.md) for an implementation-oriented guide to BIP-375 concepts and security properties.

The repository no longer bundles test vectors; see the [upstream BIP-375 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json).
