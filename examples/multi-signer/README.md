# Multi-Signer Silent Payment Example

This example lets Alice, Bob, and Charlie contribute ECDH shares and signatures for the inputs they control in a BIP-375 PSBT.

## Run

From the repository root:

```bash
cargo run -p multi-signer
```

The GUI is the default. For the interactive CLI:

```bash
cargo run -p multi-signer -- --cli
```

## Workflow

1. Create a PSBT with the participants' inputs and a silent-payment output.
2. Have each party add ECDH shares and DLEQ proofs. Once every eligible input is covered, the example computes the silent-payment output scripts.
3. Have each party sign their inputs after the output scripts are present.
4. Finalize the signed inputs and extract the transaction.

The CLI includes an export option for the current PSBT. Its default path is `output/psbt_export.json`; choose another filename at the prompt if needed. See the repository [reference guide](../../REFERENCE.md) for the BIP-375 concepts behind the workflow.
