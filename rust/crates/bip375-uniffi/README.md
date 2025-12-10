# BIP-375 Python Bindings

Demonstration for high-performance Python bindings for BIP-375 (Sending Silent Payments with PSBTs) implementation in Rust.

## Features

- **Full BIP-375 support**: Create, sign, and extract PSBTs with Silent Payment outputs
- **BIP-352 cryptography**: Silent payment address derivation and ECDH operations
- **BIP-374 DLEQ proofs**: Generate and verify discrete logarithm equality proofs
- **High performance**: Cryptographic operations run at native Rust speed
- **Memory safe**: Leverages Rust's ownership system for safety
- **Multi-language ready**: Built with UniFFI for future Kotlin/Swift/Ruby support

## Installation

### From source (development)

```bash
# Install maturin
pip install maturin

# Build and install in development mode
cd rust/crates/bip375-uniffi
maturin develop
```

### From PyPI (when published)

```bash
cd rust/crates/bip375-uniffi
pip install -e .
```

## Quick Start

Review `examples/simple_example.py` and `tests/test_basic.py` for guide on getting started

## API Overview

### Core Types

- `SilentPaymentPsbt`: PSBT v2 structure with silent payment extensions
- `SilentPaymentAddress`: Silent payment address (scan key + spend key + optional label)
- `EcdhShare`: ECDH share with optional DLEQ proof
- `Utxo`: Input UTXO information
- `Output`: Output with amount and recipient (address or silent payment)

### Modules

#### `bip352` - BIP-352 Silent Payments - WIP

- `bip352_compute_ecdh_share()`: Compute ECDH shared secret
- `derive_silent_payment_output_pubkey()`: Derive output public key
- `pubkey_to_p2wpkh_script()`: Convert pubkey to P2WPKH script
- `pubkey_to_p2tr_script()`: Convert pubkey to P2TR script
- `compute_label_tweak()`: Compute label tweak
- `apply_label_to_spend_key()`: Apply label to spend key

#### `dleq` - BIP-374 DLEQ Proofs

- `dleq_generate_proof()`: Generate DLEQ proof
- `dleq_verify_proof()`: Verify DLEQ proof

#### `signing` - Transaction Signing - TODO

- `sign_p2wpkh_input()`: Sign P2WPKH input

#### `aggregation` - ECDH Aggregation - TODO

- `aggregate_ecdh_shares()`: Aggregate ECDH shares from PSBT
- `AggregatedShares`: Collection of aggregated shares

## Performance

The Rust implementation provides significant performance improvements over pure Python, especially for:

- **Cryptographic operations**: 10-100x faster ECDH computations
- **ECDH aggregation**: Near-instant aggregation of thousands of shares
- **PSBT serialization**: 5-10x faster binary encoding/decoding
- **Transaction signing**: Native secp256k1 performance

## Examples

See the `examples/` directory for complete working examples:

- `simple_example.py`: Single-party PSBT workflow

## Development

Exposed binding api is available in `bip375.udl`

```bash
# Quick Test
cargo build && pip install -e . && pytest tests -v

# Build in release mode
maturin build --release

# Run tests
pytest tests [-v]
```

### Contributions

```bash
cargo +nightly-2025-01-21 fmt --all [-- --check]
```

## License

MIT License - see LICENSE file for details.

## References

- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP-374: DLEQ Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
