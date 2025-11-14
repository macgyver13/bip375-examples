# BIP-375 Reference Examples

This repository contains reference implementations for BIP 375: Sending Silent Payments with PSBTs.

## Quick Start

New to BIP375? Start here:

1. Read [GETTING_STARTED.md](GETTING_STARTED.md) for a quick introduction
2. Run the multi-signer example to see BIP375 in action
3. Review [REFERENCE.md](REFERENCE.md) for concepts and terminology

## Repository Overview

- PSBTv2 Libraries (Python and Rust)
- Examples demonstrating BIP375 workflows
- Rust Overview [README.md](rust/README.md)

## Libraries

- Python
  - **`psbt_sp/`** - Package to PSBT v2 for Silent Payments
    - Full role-based implementation (Creator, Constructor, Updater, Signer, Input Finalizer, Extractor)
    - Serialization, crypto utilities, and BIP 352 integration
  - **`dleq_374.py`** - BIP 374 DLEQ proof implementation
  - **`secp256k1_374.py`** - secp256k1 implementation
- Rust
  - **`crates/`** - Crates to support PSBTv2 for Silent Payments

## **Examples**

### Single User Wallet + Hardware Device

*Hardware wallet integration*
Demonstrates silent payments spending with wallet coordinator + hd signer 
- Additionally demonstrates detection of malicious hardware device using DLEQ proofs

- Python
  - [Hardware Signer](python/examples/hardware-signer/README.md)
- Rust
  - Hardware Signer - rust/examples/hardware-signer/

### Multi Signer

*Collaborative signing workflow*
Alice, Bob and Charlie create, sign, finalize a silent payments spending transaction

- Python
  - [Multi Party Signer](python/examples/multi-signer/README.md)
- Rust
  - [Multi Party Signer](rust/examples/multi-signer/README.md)

### PSBT Viewer

*Tool for decoding and viewing PSBT fields*

- Rust
  - PSBT Viewer - rust/tools/psbt-viewer

### Testing Python Examples
  **`tests/validate_tests_examples.py`** - Validate python examples

## **BIP-0375 Reference**

[bips/bip-0375](https://github.com/bitcoin/bips/)
- [test vectors](bips/bip-0375/test_vectors.json) - cloned in this repo for convienence
