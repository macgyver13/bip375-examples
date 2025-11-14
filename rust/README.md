# BIP-375 Rust Implementation

Rust implementation of BIP-375 (Sending Silent Payments with PSBTs).

## Overview

This is a Rust implementation of BIP-375, providing:

- PSBT v2 support with silent payment extensions
- Role-based architecture (Creator, Constructor, Updater, Signer, Input Finalizer, Extractor)
- BIP-352 silent payment cryptography
- BIP-374 DLEQ proof generation and verification
- Test vector compatibility

## Project Structure

```
rust/
├── crates/
│   ├── bip375-core/      # Core PSBT v2 data structures
│   ├── bip375-crypto/    # Cryptographic primitives
│   ├── bip375-io/        # Serialization and I/O
│   └── bip375-roles/     # Role-based PSBT operations
├── examples/
│   ├── hardware-signer/  # Air-gapped hardware wallet simulation
│   └── multi-signer/     # Multi-party signing workflow
├── tests/                # Test vector runner
└-- tools/
    └── psbt-viewer/      # Visual PSBT reader
```

## Running Examples

### Hardware Signer Example

```bash
cargo run -p hardware-signer
# alias
cargo run -p hardware-signer -- [--auto-read] [--auto-approve]
```

#### Skip interactive menu

```bash
cargo run -p hardware-signer -- --demo-flow [--attack]
```

#### Launch GUI Demo

```bash
cargo run -p hardware-signer --bin hardware-signer --features=gui
# alias
cargo hardware-signer
```

### Multi-Signer Example

```bash
cargo run -p multi-signer --bin alice-creates
cargo run -p multi-signer --bin bob-signs
cargo run -p multi-signer --bin charlie-finalizes
```

#### Launch GUI Demo

```bash
cargo run -p multi-signer --features=gui

cargo multi-signer
```

### PSBT Viewer
```bash
cargo run -p psbt-viewer
```

## Testing

Run all tests including test vector validation:

```bash
cargo test
```
### Verify test vectors
```bash
# Valid
cargo test test_valid_vectors -- --no-capture
# Invalid
cargo test test_invalid_vectors -- --no-capture
```

## Packaging

### Hardware Signer

```bash
cargo build -r -p hardware-signer
pushd examples/hardware-signer
cargo bundle -r -p hardware-signer --bin hardware-signer --features=gui
popd
```

### Multi Signer

```bash
cargo build -r -p multi-signer
pushd examples/multi-signer
cargo bundle -r -p multi-signer --bin multi-signer --features=gui
popd
```

### PSBT Viewer

```bash
cargo build -r -p psbt-viewer
cargo bundle -r -p psbt-viewer 
```