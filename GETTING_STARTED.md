# Getting Started with BIP375 Examples

## What is BIP375?

For full specification details, see [BIP375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki).

## Quick Start

The multi-signer example demonstrates three parties collaborating to create a silent payment transaction.

### Python Example

```bash
cd python/examples/multi-signer
python3 alice_creates.py
python3 bob_signs.py
python3 charlie_finalizes.py
```

You'll see Alice create a PSBT and sign input 0, Bob verify and sign input 1, and Charlie complete the ECDH coverage, compute output scripts, and extract the final transaction.

### Rust Example

```bash
cd rust
cargo run -p multi-signer --bin alice-creates
cargo run -p multi-signer --bin bob-signs
cargo run -p multi-signer --bin charlie-finalizes
```

### What Just Happened?

The workflow demonstrates BIP375's key features:

1. **Per-input ECDH**: Each party computes ECDH shares only for inputs they control
2. **DLEQ Proofs**: Each party generates proofs that others verify (prevents malicious hardware attacks)
3. **Progressive Coverage**: ECDH shares accumulate until all inputs are covered
4. **Output Scripts**: Computed only when ECDH coverage is complete
5. **Signing**: Inputs signed only after output scripts are computed

## Next Steps

- Try the [hardware signer example](python/examples/hardware-signer/README.md) to see DLEQ proof validation in action
- Read [REFERENCE.md](REFERENCE.md) for concepts and terminology
- Explore the library code in`python/psbt_sp/` or`rust/crates/`

## Troubleshooting

**Build errors (Rust)**: Ensure you have Rust 1.88+ with `rustc --version`

**DLEQ verification failures**: The example uses hardcoded keys - modifications to input keys will cause verification to fail