# BIP-375 Concepts

This document explains the BIP-375 concepts used by this repository. It is not a replacement for the normative BIP specifications.

## What is BIP-375?

BIP-375 extends PSBT v2 (BIP-370) to support Silent Payments (BIP-352). It defines new PSBT fields and workflows for coordinating silent payment transactions across multiple signers.

Silent Payments allow receiving payments to a static address without on-chain address reuse. The sender derives a unique output script using ECDH (Elliptic Curve Diffie-Hellman) with the recipient's public keys.

## Why BIP-375 Exists

Creating silent payment transactions requires coordination between signers:

1. Signers contribute ECDH shares for eligible inputs they control, or a signer with all eligible keys can contribute a global share
2. Signers verify shares from other signers using DLEQ proofs
3. Output scripts can be computed when every eligible input is covered for each recipient scan key

BIP-375 provides the PSBT fields and workflow to make this coordination possible in a trustless manner.

## Key Concepts

### ECDH Shares

Each eligible input can contribute an ECDH share computed as `input_private_key * recipient_scan_key`. A signer holding all eligible input keys can instead provide a global share. The shares are used to derive the final output script.

### DLEQ Proofs

Discrete Log Equality (DLEQ) proofs allow signers to prove their ECDH computation is correct without revealing their private key. This prevents malicious hardware devices from redirecting funds to attacker-controlled addresses.

See [BIP374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) for DLEQ proof specification.

### Per-Input Approach

BIP-375 supports per-input ECDH shares, as used by the multi-signer example:

- Each signer computes shares only for inputs they control
- ECDH coverage builds progressively across signers
- Output scripts are computed when all eligible inputs are covered for each scan key
- The signer clears the inputs and outputs modifiable flags when it computes missing output scripts

### PSBT Roles

BIP-375 uses PSBT v2 roles:

- **Creator**: Initializes empty PSBT
- **Constructor**: Adds inputs and outputs
- **Updater**: Adds metadata and keys
- **Signer**: Computes ECDH shares, generates DLEQ proofs, signs inputs
- **Input Finalizer**: Finalizes witness data
- **Extractor**: Creates final transaction

For silent payments, the Signer role is extended with ECDH computation and DLEQ proof generation.

## Workflow

### Hardware-Signer Workflow

1. Wallet coordinator creates the PSBT with inputs and outputs
2. Hardware signer computes ECDH shares for eligible inputs
3. Hardware signer computes output scripts and signs inputs
4. Wallet coordinator verifies proofs and output scripts, then finalizes inputs
5. Extractor creates the final transaction

### Multi-Signer Workflow

1. Create the PSBT with inputs and outputs
2. Each signer adds ECDH shares and DLEQ proofs for eligible inputs they control, verifying other signers' proofs
3. Once shares cover every eligible input for each scan key, compute the output scripts and clear the inputs and outputs modifiable flags
4. Each signer verifies the computed outputs and signs their inputs
5. Finalize the signed inputs and extract the transaction

## BIP-375 PSBT Fields

See [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) for complete field specifications.

## Security Considerations

### DLEQ Proof Verification

Signers should verify DLEQ proofs for shares from other signers before relying on those shares to compute or accept output scripts. Skipping verification can allow an incorrect output script to go undetected.

### Output Script Timing

Output scripts must not be computed until every eligible input has an ECDH share for each recipient scan key, or a valid global share covers all eligible inputs. Computing scripts early can lead to invalid transactions.

### Signature Timing

Inputs must not be signed until output scripts are computed. Otherwise signatures will be invalid.

### Modifiable Flags

When a signer sets missing silent-payment output scripts, it must clear the inputs and outputs modifiable flags before signatures are added.

## Examples in This Repository

### Multi-Signer Example

Demonstrates three parties collaborating to create a silent payment transaction. Shows progressive ECDH coverage and cross-party DLEQ verification.

Best for understanding the multi-party workflow and ECDH share accumulation.

### Hardware Signer Example

Demonstrates air-gapped hardware wallet workflow with attack simulation. Shows how DLEQ proof verification prevents malicious hardware from redirecting funds.

Best for understanding DLEQ proof security and air-gapped signing.

## Related BIPs

- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP-370: PSBT Version 2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [BIP-374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
