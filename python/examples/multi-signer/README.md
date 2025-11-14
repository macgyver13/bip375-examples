# Multi-Signer Silent Payment Example

This directory demonstrates a realistic 3-of-3 multi-signer silent payment workflow compliant with BIP 375. Three separate parties (Alice, Bob, and Charlie) collaborate to create a silent payment transaction, each contributing ECDH shares and signatures for inputs they control.

## Quick Start

Run the three-party workflow:

```bash
cd python/examples/multi-signer
python3 alice_creates.py
python3 bob_signs.py
python3 charlie_finalizes.py
```

Each script processes one party's inputs and passes the PSBT to the next party. The final transaction appears in `output/final_transaction.hex`.

## Overview

### Scenario

- **3 inputs** controlled by different parties:
  - Input 0: Alice (100,000 sats)
  - Input 1: Bob (150,000 sats)
  - Input 2: Charlie (200,000 sats)
- **2 outputs**:
  - Regular change output (100,000 sats)
  - Silent payment output (340,000 sats)
- **Transaction fee**: 10,000 sats

### Key Features

- **Per-input ECDH approach**: Each party computes ECDH shares only for inputs they control
- **File-based handoffs**: Parties pass PSBTs via JSON files with metadata
- **Cross-party DLEQ verification**: Each party verifies proofs from previous signers
- **Progressive workflow**: ECDH coverage builds incrementally until complete
- **BIP 375 compliance**: Follows exact multi-signer requirements

## Files

### Scripts (run in order)

1. **`alice_creates.py`** - Alice creates PSBT and processes input 0
2. **`bob_signs.py`** - Bob verifies Alice's work and processes input 1
3. **`charlie_finalizes.py`** - Charlie completes ECDH coverage, computes output scripts, and extracts transaction

### Utilities

- **`shared_utils.py`** - Common data, transaction inputs/outputs, and utility functions

### Generated Files (in `output/` directory)

- **`transfer.psbt`** - Current working PSBT (shared by all parties)
- **`final_transaction.hex`** - Completed transaction ready for broadcast

## Usage

### Running the Workflow

#### Fresh Demonstration

For a clean demonstration, simply start with Alice (she automatically resets any previous files):

1. **Start with Alice** (CREATOR + CONSTRUCTOR + partial SIGNER):

```bash
cd examples/multi-signer
python3 alice_creates.py
```

2. **Continue with Bob** (partial SIGNER):

```bash
python3 bob_signs.py
```

3. **Finalize with Charlie** (final SIGNER + EXTRACTOR):

```bash
python3 charlie_finalizes.py
```

### Expected Output

#### Step 1: Alice Creates

```
============================================================
Step 1: Alice Creates PSBT
Party: Alice
============================================================
...
  CREATOR: Setting up PSBT structure...
 CONSTRUCTOR: Adding transaction inputs and outputs...
   Created PSBT with 3 inputs and 2 outputs
   Set Alice's private key for input 0
 SIGNER (Alice): Processing input 0...
   Computing ECDH share and DLEQ proof for input 0
   Verifying DLEQ proofs from other signers (none yet)
   Checking ECDH coverage for output script computation
 SIGNER (partial): Processing 1 controlled input(s)
   Found 1 unique scan key(s)
   Verifying existing DLEQ proofs from other signers...
     Verified 0 DLEQ proof(s) from other signers
   Computing ECDH shares for controlled inputs [0]...
     Added ECDH share for input 0, scan key 02d029ff96de2cbcf782be4359c48620ea92bcdd6bef032b95158b91a1693fb4f8
   ECDH shares and DLEQ proofs computed for controlled inputs
   ECDH coverage: 1/3 inputs covered
   Checking if we can sign controlled inputs...
⚠️  Some outputs missing scripts - cannot sign yet
   Signing controlled inputs [0] for partial workflow...
 Signed input 0
     Successfully signed 1 input(s)
   Partial signatures added successfully
 SIGNER (partial): Completed successfully
   ECDH Coverage: 1/3 inputs
   Covered inputs: [0]
   Complete: ❌ NO
Saved PSBT to output/transfer.psbt
```

#### Step 2: Bob Signs

```
============================================================
Step 2: Bob Signs PSBT
Party: Bob
============================================================
...
 Loaded previous work:
   Step: 1
   Completed by: alice
   Previous controlled inputs: [0]
   Description: Alice created PSBT and processed input 0
   Set Bob's private key for input 1

 Current ECDH coverage (before Bob):
   ECDH Coverage: 1/3 inputs
   Covered inputs: [0]
   Complete: ❌ NO
 SIGNER (Bob): Processing input 1...
   Computing ECDH share and DLEQ proof for input 1
 SIGNER (partial): Processing 1 controlled input(s)
   Found 1 unique scan key(s)
   Verifying existing DLEQ proofs from other signers...
     Input 0 DLEQ proof verification passed
     Verified 1 DLEQ proof(s) from other signers
   Computing ECDH shares for controlled inputs [1]...
     Added ECDH share for input 1, scan key 02d029ff96de2cbcf782be4359c48620ea92bcdd6bef032b95158b91a1693fb4f8
   ECDH shares and DLEQ proofs computed for controlled inputs
   ECDH coverage: 2/3 inputs covered
   Checking if we can sign controlled inputs...
⚠️  Some outputs missing scripts - cannot sign yet
   Signing controlled inputs [1] for partial workflow...
 Signed input 1
     Successfully signed 1 input(s)
   Partial signatures added successfully
 SIGNER (partial): Completed successfully

 Updated ECDH coverage (after Bob):
   ECDH Coverage: 2/3 inputs
   Covered inputs: [0, 1]
   Complete: ❌ NO
Saved PSBT to output/transfer.psbt
```

#### Step 3: Charlie Finalizes

```
============================================================
Step 3: Charlie Finalizes PSBT
Party: Charlie
============================================================

Loaded previous work:
   Step: 2
   Completed by: bob
   Inputs with ECDH: [0, 1]
   Inputs with signatures: [0, 1]
   Description: Bob verified Alice's work and processed input 1
   Set Charlie's private key for input 2

 Current ECDH coverage (before Charlie):
   ECDH Coverage: 2/3 inputs
   Covered inputs: [0, 1]
   Complete: ❌ NO

 SIGNER (Charlie): Processing final input 2...
   Computing ECDH share and DLEQ proof for input 2
   This will complete ECDH coverage!
 SIGNER (partial): Processing 1 controlled input(s)
   Found 1 unique scan key(s)
   Verifying existing DLEQ proofs from other signers...
     Input 0 DLEQ proof verification passed
     Input 1 DLEQ proof verification passed
     Verified 2 DLEQ proof(s) from other signers
   Computing ECDH shares for controlled inputs [2]...
     Added ECDH share for input 2, scan key 02d029ff96de2cbcf782be4359c48620ea92bcdd6bef032b95158b91a1693fb4f8
   ECDH shares and DLEQ proofs computed for controlled inputs
   ECDH coverage: 3/3 inputs covered
   Complete ECDH coverage achieved! Computing output scripts...
 Found ECDH shares for 1 scan key(s)
 Computed output script for output 1
Set TX_MODIFIABLE flags to 0x00
 Successfully computed 1 output script(s)
   Output scripts computed successfully
   Checking if we can sign controlled inputs...
   All outputs have scripts - signing controlled inputs [2]...
 Signed input 2
     Successfully signed 1 input(s)
   Signatures added successfully
 SIGNER (partial): Completed successfully

 Final ECDH coverage (after Charlie):
   ECDH Coverage: 3/3 inputs
   Covered inputs: [0, 1, 2]
   Complete: ✅ YES

 Complete ECDH coverage achieved!
    Silent payment output scripts computed
    Modifiable flags set to False
    All inputs signed

 EXTRACTOR: Creating final transaction...
Extracting transaction with 3 inputs and 2 outputs
 Transaction extracted (518 bytes)
 Transaction ID: 5f1f871ee1a40dce65c524af1314c81cd4720d6811ee712f2cf5dc77ad772b8d
Saved transaction to output/final_transaction.hex
 Multi-signer silent payment transaction complete!
```

## Technical Details

### BIP 375 Multi-Signer Implementation

This example implements the full BIP 375 multi-signer specification:

1. **Per-Input ECDH Computation**: Each signer computes ECDH shares only for inputs they control
2. **DLEQ Proof Generation**: Each input gets its own DLEQ proof for trustless verification
3. **Cross-Party Verification**: Each signer verifies DLEQ proofs from previous signers
4. **Output Script Timing**: Scripts computed only when all ECDH shares present
5. **Modifiable Flags**: Set to False when output scripts computed
6. **Signature Timing**: Inputs signed only after all outputs have scripts
7. **Finalization Protection**: TX_MODIFIABLE flags prevent modification once finalized

### Finalized PSBT Protection

The implementation includes protection against modifying finalized PSBTs:

- **TX_MODIFIABLE Tracking**: PSBTs track modifiable state via`TX_MODIFIABLE` field
- **Initial State**:`0x03` (both inputs and outputs modifiable)
- **Final State**:`0x00` (neither inputs nor outputs modifiable)
- **Validation**:`signer_role_partial()` checks modifiability before making changes
- **Error Handling**: Clear error messages when attempting to modify finalized PSBTs

**Test the protection**:

```bash
# Complete a full workflow
python3 alice_creates.py && python3 bob_signs.py && python3 charlie_finalizes.py

```

### File Format

The JSON files contain:

```json
{
  "psbt": "cHNidP8BAH0CAA...",
  "metadata": {
  },
  "psbt_json": {
    "global": [...],
    "inputs": [...],
    "outputs": [...]
  }
}
```

### ECDH Coverage Progression

| Step | Party   | Input 0    | Input 1    | Input 2    | Coverage | Output Scripts |
| ---- | ------- | ---------- | ---------- | ---------- | -------- | -------------- |
| 1    | Alice   | ECDH + Sig | ...        | ...        | 1/3      | NO             |
| 2    | Bob     | YES        | ECDH + Sig | ...        | 2/3      | NO             |
| 3    | Charlie | YES        | YES        | ECDH + Sig | 3/3      | YES            |

## Security Considerations

### Verification Requirements

- Each party MUST verify DLEQ proofs from other signers
- ECDH shares MUST be verified before adding new ones
- Output scripts MUST NOT be computed until complete ECDH coverage
- Inputs MUST NOT be signed until all outputs have scripts

### Trust Model

- **No trusted coordinator**: Fully peer-to-peer workflow
- **Cryptographic verification**: DLEQ proofs ensure honesty
- **Progressive validation**: Each step validates previous work
- **File integrity**: JSON metadata provides workflow tracking

## Troubleshooting

### Common Issues

**DLEQ verification failures**: Check that input private keys match the expected public keys

**Incomplete ECDH coverage**: Verify all three scripts complete successfully

**Trying to modify finalized PSBT**: If you see "PSBT is no longer modifiable (transaction already finalized)", this means Charlie has already completed the workflow and set the TX_MODIFIABLE flags to 0x00. Start fresh with `alice_creates.py`.

### Debugging

Add debugging output by modifying the scripts:

```python
# Enable more verbose output
psbt.pretty_print()  # Shows PSBT structure
print(f"Metadata: {metadata}")  # Shows file metadata
```

### Resetting Between Demonstrations

**Automatic Reset**: Alice's script automatically cleans up previous files when starting a new demonstration.

**Files that get cleaned up**:

- `output/transfer.psbt`
- `output/final_transaction.hex` - Final transaction

## References

- [BIP 375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
- [BIP 352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP 370: PSBT v2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [BIP 374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
