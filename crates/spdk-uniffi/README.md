# BIP-375 Python Bindings

This crate exposes SPDK's BIP-375 PSBT workflows and BIP-352/BIP-374 operations to Python through UniFFI. The package imports as `spdk_psbt`. Its API is defined in [spdk_psbt.udl](src/spdk_psbt.udl).

## Install and Run

From the repository root:

```bash
pip install -e 'crates/spdk-uniffi[dev]'
python crates/spdk-uniffi/examples/simple_example.py
pytest crates/spdk-uniffi/tests -v
```

The [simple example](examples/simple_example.py) creates a PSBT with a silent-payment output, adds input metadata and an ECDH share, computes the output script, signs, finalizes, and saves the result. It writes `output/transfer.json` relative to the working directory.

## Building BIP-375 Test Vectors

`SilentPaymentPsbt.create_from_parts(inputs, outputs)` builds a PSBT from `Utxo` and `PsbtOutput` values. Use `update_inputs` to attach input metadata, then generate single-signer or multi-signer ECDH shares, compute the silent-payment output scripts, and sign only after all output scripts are present.

For invalid vectors, `SilentPaymentPsbt.create(input_count, output_count)` creates pre-sized PSBT maps. The `add_raw_global_field`, `add_raw_input_field`, `remove_raw_input_fields_by_type`, and `add_raw_output_field` functions let a Python generator alter individual fields. `serialize()` returns PSBT bytes, which the generator can base64-encode for the [upstream vector format](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json). The bindings provide these primitives; this checkout does not contain a maintained UniFFI generator script.

See [test_basic.py](tests/test_basic.py) for examples of construction, share generation, serialization, and file I/O. The deprecated pure-Python generator is in [deprecated/python/tests/test_generator.py](../../deprecated/python/tests/test_generator.py) for historical reference.

## Dependencies

The workspace [Cargo.toml](../../Cargo.toml) pins SPDK's `psbt` and `silentpayments` crates and rust-psbt's `psbt-v2` crate. This binding uses those pinned revisions when exercising PSBT roles. Run Cargo commands from the repository root; for example:

```bash
cargo test -p spdk-uniffi
```
