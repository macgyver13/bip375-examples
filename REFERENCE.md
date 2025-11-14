# BIP375 Reference

## What is BIP375?

BIP375 extends PSBT v2 (BIP370) to support Silent Payments (BIP352). It defines new PSBT fields and workflows for coordinating silent payment transactions across multiple signers.

Silent Payments allow receiving payments to a static address without on-chain address reuse. The sender derives a unique output script using ECDH (Elliptic Curve Diffie-Hellman) with the recipient's public keys.

## Why BIP375 Exists

Creating silent payment transactions requires coordination between signers:

1. Each signer must compute ECDH shares for their inputs
2. Output scripts can only be computed when all ECDH shares are present
3. Signers must verify each other's ECDH computations

BIP375 provides the PSBT fields and workflow to make this coordination possible in a trustless manner.

## Key Concepts

### ECDH Shares

Each input contributes an ECDH share computed as `private_key * recipient_scan_key`. These shares are combined to derive the final output script.

### DLEQ Proofs

Discrete Log Equality (DLEQ) proofs allow signers to prove their ECDH computation is correct without revealing their private key. This prevents malicious hardware devices from redirecting funds to attacker-controlled addresses.

See [BIP374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) for DLEQ proof specification.

### Per-Input Approach

BIP375 uses a per-input ECDH approach where:

- Each signer computes shares only for inputs they control
- ECDH coverage builds progressively across signers
- Output scripts are computed when all inputs have ECDH shares
- TX_MODIFIABLE flags prevent modification after finalization

### PSBT Roles

BIP375 uses PSBT v2 roles:

- **Creator**: Initializes empty PSBT
- **Constructor**: Adds inputs and outputs
- **Updater**: Adds metadata and keys
- **Signer**: Computes ECDH shares, generates DLEQ proofs, signs inputs
- **Input Finalizer**: Finalizes witness data
- **Extractor**: Creates final transaction

For silent payments, the Signer role is extended with ECDH computation and DLEQ proof generation.

## Workflow

### Hardware-Signer Workflow

1. Wallet Coordinator Creator creates PSBT, adds inputs and outputs
2. Wallet Coordinator Constructor adds inputs and outputs
3. Signer computes ECDH shares for all inputs
4. Signer computes output scripts
5. Signer signs all inputs
6. Extractor creates final transaction

### Multi-Signer Workflow

1. First signer (Creator + Constructor) creates PSBT structure
2. First signer computes ECDH shares for their inputs AND signs their inputs
3. Subsequent signers verify previous DLEQ proofs
4. Subsequent signers add ECDH shares for their inputs AND sign their inputs
5. Final signer completes ECDH coverage, computes output scripts, AND signs their inputs
6. Extractor creates final transaction

## BIP375 PSBT Fields

New fields defined by BIP375:

- **PSBT_IN_PROPRIETARY_ECDH_SHARE**: ECDH share for an input
- **PSBT_IN_PROPRIETARY_DLEQ_PROOF**: DLEQ proof for ECDH share
- **PSBT_OUT_SCRIPT**: Output script (set after ECDH complete)

See [BIP375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) for complete field specifications.

## Security Considerations

### DLEQ Proof Verification

All signers must verify DLEQ proofs from other signers before adding their own ECDH shares. Skipping verification allows malicious signers to redirect funds.

### Output Script Timing

Output scripts must not be computed until all inputs have ECDH shares. Computing scripts early can lead to invalid transactions.

### Signature Timing

Inputs must not be signed until output scripts are computed. Otherwise signatures will be invalid.

### Modifiable Flags

TX_MODIFIABLE flags prevent modification after output scripts are computed. This ensures signatures remain valid.

## Examples in This Repository

### Multi-Signer Example

Demonstrates three parties collaborating to create a silent payment transaction. Shows progressive ECDH coverage and cross-party DLEQ verification.

Best for understanding the multi-party workflow and ECDH share accumulation.

### Hardware Signer Example

Demonstrates air-gapped hardware wallet workflow with attack simulation. Shows how DLEQ proof verification prevents malicious hardware from redirecting funds.

Best for understanding DLEQ proof security and air-gapped signing.

## Related BIPs

- [BIP352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP370: PSBT Version 2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [BIP374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
