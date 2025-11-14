# Multi-Signer Silent Payment Example (Rust)

Demonstrates a 3-of-3 multi-signer silent payment workflow following BIP375. Three parties (Alice, Bob, Charlie) collaborate to create a silent payment transaction, each contributing ECDH shares and signatures for inputs they control.

## Running the Example

Execute the workflow in order:

```bash
# From the rust/ directory
cargo run --bin alice-creates
cargo run --bin bob-signs
cargo run --bin charlie-finalizes
```

## Files

Output files are generated in the working directory:

- `transfer.psbt` - Shared transfer file for passing psbt between actors
  - psbt - encoded PSBT - required data
  - metadata - optional data - supports coordinating examples
  - psbt_json - optional data - human readable representation of PSBT
- `final_transaction.hex` - Completed transaction ready for broadcast

## Details

For detailed workflow explanation, see the [Python multi-signer README](/python/examples/multi-signer/README.md).
