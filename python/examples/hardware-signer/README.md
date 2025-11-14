# Hardware Signer Air-Gapped Workflow

This directory demonstrates a realistic air-gapped hardware wallet workflow for BIP 375 silent payment transactions. Two separate scripts simulate communication between an online wallet coordinator and an offline hardware device, with all data transfers happening manually (copy/paste or file-based).

## Overview

### Scenario

- **Wallet Coordinator** (online computer): Creates PSBT, verifies signatures, broadcasts transaction
- **Hardware Device** (air-gapped): Securely stores private keys, signs transactions, generates DLEQ proofs
- **Communication**: Manual data transfer simulating QR codes or USB transfers

### Transaction Details

- **2 inputs** controlled by hardware device (100,000 + 200,000 = 300,000 sats)
- **2 outputs**:
  - Change output: 50,000 sats
  - Silent payment output: 245,000 sats
- **Transaction fee**: 5,000 sats

## Examples

### Interactive Scripts (Run These)

#### Multi Step Demo - Optional Attack Scenario

1. **`wallet_coordinator.py`** - Online wallet that creates and finalizes PSBTs
2. **`hw_device.py`** - Air-gapped hardware device that signs PSBTs

##### Generated Files (in `output/` directory)

- **`transfer.psbt`** - Shared transfer file for passing psbt between actors
  - psbt - encoded PSBT - required data
  - metadata - optional data - supports coordinating examples
  - psbt_json - optional data - human readable representation of PSBT
- **`final_transaction.hex`** - Completed transaction ready for broadcast

#### Quick Demo

**`hardware_wallet_flow.py`** - Basic multi step hardware signing demo

### Support Files

- **`shared_hw_utils.py`** - Common utilities, transaction data, and display helpers

## Attack Simulation

### Malicious Hardware Attack Demo

This example includes an **attack simulation mode** that demonstrates how DLEQ proof validation protects against compromised hardware wallets. The attack simulates a malicious hardware device that attempts to redirect funds to an attacker-controlled address.

#### How to Trigger Attack Simulation

**Step 1**: Create PSBT (normal)

```bash
python3 wallet_coordinator.py
```

**Step 2**: Simulate malicious hardware

```bash
python3 hw_device.py
# Choose: read
# When prompted for approval, type: ATTACK
```

**Step 3**: Coordinator detects attack

```bash
python3 wallet_coordinator.py
# Choose: read
# Validation will FAIL and transaction will be REJECTED
```

#### What the Attack Does

**Malicious Hardware Behavior**:

1. **[OK] Displays correct transaction details** (appears legitimate to user)
2. **[OK] Signs inputs with correct private keys** (signatures are valid)
3. **[ATTACK] Computes ECDH shares with attacker's scan key** (redirects funds)
4. **[ATTACK] Generates DLEQ proofs for wrong scan key** (proves malicious computation)

**Attack Goal**: Redirect silent payment funds to attacker while maintaining valid signatures

**Why Attack Attempts This**:

- User sees legitimate transaction details and approves
- Transaction has valid signatures (appears normal)
- Funds would go to attacker instead of intended recipient
- Without DLEQ proofs, this attack would succeed

#### How DLEQ Proofs Prevent the Attack

**Protection Mechanism**:

1. **Hardware generates proof**:`DLEQ(a, G, B_attacker, A, C_malicious)`
2. **Coordinator verifies proof**: Checks that`C = a * B_recipient`
3. **Proof verification fails**: Hardware used`B_attacker` instead of`B_recipient`
4. **Transaction rejected**: Coordinator detects malicious behavior

**Zero-Trust Security**:

- Coordinator doesn't trust hardware device
- All ECDH computations are cryptographically verified
- Private keys never leave hardware device
- Malicious hardware cannot steal funds

#### Expected Output During Attack

**Hardware Device (Attack Mode)**:

```
⚠️  ATTACK MODE ENABLED - Simulating malicious hardware!
   Hardware will compute ECDH shares with wrong scan key
   Coordinator should detect this via DLEQ proof verification

──────────────────────────────────────────────────────────────────────


 SIGNER: Processing transaction with hardware keys...

🚨 ATTACK MODE: Using malicious scan key!
   Real recipient scan key would be used in honest mode
   Legitimate scan key:  031e6c6b3424fd2767aec379ad4cda41b59a769ce42164cda453476a28465a2a7e
   Malicious scan key:   02920eb00a9cd342ff7e6e9f8dbf6e21a3a7179164d7fada2ee16e6f52a7a70a46
   ⚠️  Funds would go to attacker if this succeeds!

   Hardware wallet controls inputs: [0, 1]
   Set private keys for inputs [0, 1]

   🚨 Computing ECDH shares with MALICIOUS scan key...
   🚨 Generating DLEQ proofs for WRONG scan key...
    Signing inputs with CORRECT private keys...

   ⚠️  This attack tries to redirect funds while maintaining valid signatures
   ⚠️  The coordinator should detect this via DLEQ proof verification!
```

**Wallet Coordinator (Detection)**:

```
 VALIDATING SIGNED PSBT
======================================================================

 Checking ECDH coverage...
   PASSED: Complete ECDH coverage (2/2 inputs)

 Verifying DLEQ proofs...
   🚨 ATTACK DETECTED: DLEQ proofs for unexpected scan keys!
      Unexpected: 02920eb00a9cd342ff7e6e9f8dbf6e21a3a7179164d7fada2ee16e6f52a7a70a46
   ⚠️ CRITICAL: Hardware device used attacker's scan key!
    Hardware device computed ECDH shares with incorrect scan key
    This could indicate firmware corruption or malicious modification

  Verifying output scripts...
   PASSED: Output scripts present

  Verifying signatures...
   PASSED: All inputs signed (2/2)

  Checking TX_MODIFIABLE flags...
   INFO: TX_MODIFIABLE check not available

  Validating transaction amounts...
   Total input:  300,000 sats
   Total output: 295,000 sats
   Fee:          5,000 sats
   PASSED: Amounts valid

======================================================================
❌ VALIDATION FAILED - TRANSACTION NOT SAFE TO BROADCAST
======================================================================

⚠️  DO NOT broadcast this transaction!
   One or more critical validations failed.
   The hardware device may be compromised or malfunctioning.

======================================================================
❌ WORKFLOW INCOMPLETE
======================================================================
```

#### Security Analysis

**What Makes This Attack Realistic**:

- Hardware appears to work normally (correct transaction display)
- User approval process is identical to legitimate transactions
- Signatures are completely valid
- Only the ECDH computation is malicious

**Why the Attack Fails**:

- **DLEQ proofs are mathematically binding** to the scan key used
- **Coordinator cryptographically verifies** all ECDH computations
- **Cannot forge proofs** for different scan keys
- **Zero-trust model** - software doesn't trust hardware

**Attack Scenarios This Protects Against**:

1. **Supply chain attacks** - Compromised hardware from manufacturer
2. **Firmware corruption** - Malware infection of hardware device
3. **Malicious updates** - Attacker pushes malicious firmware
4. **Physical tampering** - Device modified by attacker
5. **Insider threats** - Malicious hardware manufacturer

#### Real-World Implications

**Without DLEQ Proofs**:

- Users would have no way to detect malicious hardware
- Attackers could steal funds while maintaining plausible deniability
- Hardware wallets would be vulnerable to supply chain attacks

**With DLEQ Proofs (BIP 375)**:

- Mathematical proof of correct computation
- Trustless verification of hardware behavior
- Attack detection is automatic and cryptographically certain
- Users protected even from sophisticated attacks

#### Demonstrating Zero-Trust Security

This attack simulation proves that BIP 375 achieves **true zero-trust security**:

1. **Don't trust hardware manufacturer** → DLEQ proofs verify computation
2. **Don't trust software coordinator** → Hardware retains private keys
3. **Don't trust communication channel** → Proofs detect tampering
4. **Don't trust user verification** → Cryptographic validation supplements human verification

The attack fails not because the user detected something wrong, but because the cryptographic verification automatically detected the malicious behavior.

## Usage

### Quick Start (File-Based Transfer)

This is the fastest way to see the workflow:

```bash
# Terminal 1 (or run sequentially)
cd examples/hardware-signer

# Step 1: Create PSBT
python3 wallet_coordinator.py
# When prompted, press Enter (file will be saved automatically)

# Step 2: Sign on hardware device
python3 hw_device.py
# Choose: read
# Verify transaction details
# Type: YES

# Step 3: Finalize transaction
python3 wallet_coordinator.py
# Choose: read
# Transaction complete!
```

### Manual Copy/Paste (More Realistic)

Simulates QR code scanning or manual data entry:

```bash
# Step 1: Create PSBT
python3 wallet_coordinator.py
# Copy the PSBT base64 string displayed in the box

# Step 2: Sign on hardware device (different terminal/computer)
python3 hw_device.py
# Choose: paste
# Paste the PSBT data, then press Ctrl+D (or Ctrl+Z on Windows)
# Verify transaction details
# Type: YES
# Copy the signed PSBT base64 string

# Step 3: Finalize transaction
python3 wallet_coordinator.py
# Choose: paste
# Paste the signed PSBT data, then press Ctrl+D (or Ctrl+Z on Windows)
# Transaction complete!
```

### Two-Terminal Workflow (Best Simulation)

Open two terminal windows to better simulate the air-gap:

**Terminal 1 (Online Computer):**

```bash
cd examples/hardware-signer
python3 wallet_coordinator.py
# Note the transfer file location or copy the PSBT data
```

**Terminal 2 (Air-Gapped Device):**

```bash
cd examples/hardware-signer
python3 hw_device.py
# Type: read (or paste the PSBT data)
# Verify and approve transaction
```

**Terminal 1 (Online Computer):**

```bash
python3 wallet_coordinator.py
# Type: read (or paste the signed PSBT)
# Transaction finalized!
```

## Workflow Details

### Step 1: Wallet Coordinator Creates PSBT

**Role**: CREATOR + CONSTRUCTOR

**Actions**:

- Creates PSBTv2 structure with inputs and outputs
- Displays transaction details for verification
- Outputs PSBT in two formats:
  1. Base64 text (copy/paste)
  2. File:`output/transfer.psbt` (file transfer)

**Output**:

```
╔═════════════════════════════════════════════════════════════════╗
║                    COPY THIS PSBT DATA                          ║
╠═════════════════════════════════════════════════════════════════╣
║ cHNidP8BAH0CAAAAAQI...                                          ║
║ ...                                                             ║
║ Length: 1234 characters                                         ║
╚═════════════════════════════════════════════════════════════════╝
```

### Step 2: Hardware Device Signs PSBT

**Role**: SIGNER

**Actions**:

1. Receives PSBT (via copy/paste or file read)
2. Displays transaction details on "secure display"
3. Prompts user to verify and approve
4. Computes ECDH shares for all hardware-controlled inputs
5. Generates DLEQ proofs for cryptographic verification
6. Signs inputs with private keys
7. Computes output scripts (full ECDH coverage achieved)
8. Outputs signed PSBT

**User Verification Display**:

```
TRANSACTION DETAILS (Verify these match on both sides)
──────────────────────────────────────────────────────────────────

INPUTS:
  Input 0:
    Amount:     100,000 sats
    TXID:       a1b2c3d4e5f67890...34567a
    ...

OUTPUTS:
  Output 0:
    Amount:     50,000 sats
    Type:       Silent Payment CHANGE (Label 0)
  Output 1:
    Amount:     245,000 sats
    Type:       Silent Payment
    ...

  Fee:          5,000 sats
```

**Security Prompt**:

```
SECURITY PROMPT:
Type 'YES' to approve this transaction:
```

### Step 3: Wallet Coordinator Finalizes

**Role**: SIGNER (verification) + EXTRACTOR

**Actions**:

1. Receives signed PSBT from hardware device
2. Runs comprehensive validation checks (see below)
3. Extracts final transaction if all checks pass
4. Saves to`output/final_transaction.hex`
5. Ready for broadcast!

**Comprehensive Validation Process**:

The coordinator performs 6 critical validation checks before finalizing:

```
 VALIDATING SIGNED PSBT
======================================================================

 Checking ECDH coverage...
   PASSED: Complete ECDH coverage (2/2 inputs)

 Verifying DLEQ proofs...
 Input 0 DLEQ proof verified for scan key 03f86c31bd5ef4008ee53a843a54a787e4581a5b262ee61f87fb4437c90370278c
 Input 0 DLEQ proof verified for scan key 031e6c6b3424fd2767aec379ad4cda41b59a769ce42164cda453476a28465a2a7e
 Input 1 DLEQ proof verified for scan key 03f86c31bd5ef4008ee53a843a54a787e4581a5b262ee61f87fb4437c90370278c
 Input 1 DLEQ proof verified for scan key 031e6c6b3424fd2767aec379ad4cda41b59a769ce42164cda453476a28465a2a7e
 All DLEQ proofs verified successfully
   PASSED: All DLEQ proofs verified for 2 scan keys
      Change scan key:    03f86c31bd5ef4008ee53a843a54a787e4581a5b262ee61f87fb4437c90370278c
      Recipient scan key: 031e6c6b3424fd2767aec379ad4cda41b59a769ce42164cda453476a28465a2a7e

  Verifying output scripts...
   PASSED: Output scripts present

  Verifying signatures...
   PASSED: All inputs signed (2/2)

  Checking TX_MODIFIABLE flags...
   INFO: TX_MODIFIABLE check not available

  Validating transaction amounts...
   Total input:  300,000 sats
   Total output: 295,000 sats
   Fee:          5,000 sats
   PASSED: Amounts valid

======================================================================
ALL VALIDATIONS PASSED
======================================================================

Transaction is safe to broadcast
```

**What Each Validation Checks**:

1. **ECDH Coverage**: All inputs have ECDH shares for silent payment computation
2. **DLEQ Proofs**: Cryptographically verifies hardware computed ECDH shares correctly (prevents malicious hardware from stealing funds)
3. **Output Scripts**: Silent payment output scripts were computed and are present
4. **Signatures**: All inputs have valid signatures from the hardware device
5. **TX_MODIFIABLE**: PSBT is properly finalized and cannot be modified further
6. **Amounts**: Transaction amounts are sane (inputs ≥ outputs + fee, reasonable fee)

**Final Broadcast Confirmation**:

After all validations pass, the coordinator prompts for final confirmation:

```
[WARNING] BROADCAST CONFIRMATION
[WARNING] This will broadcast the transaction to the Bitcoin network.
[WARNING] Once broadcast, the transaction CANNOT be reversed!

Please verify:
   • Transaction details match what you approved on hardware device
   • Recipient address is correct
   • Amounts and fee are acceptable

[WARNING] Type 'BROADCAST' to confirm and broadcast, or anything else to cancel:
```

This final step ensures the user explicitly confirms before broadcasting the irreversible transaction.

## Transfer Options

### Option 1: File-Based Transfer (Fastest)

Both scripts use the same file: `output/transfer.psbt`

**Advantages**:

- Quick demonstration
- No copying required
- Simulates USB drive or SD card transfer

**Usage**: Type `read` when prompted

### Option 2: Copy/Paste Transfer (Most Realistic)

Manually copy base64 PSBT data between scripts

**Advantages**:

- Simulates QR code workflow
- More realistic air-gap experience
- Works across different machines/terminals

**Usage**:

1. Type`paste` when prompted
2. Paste the PSBT data (436 chars unsigned, 1204 chars signed)
3. Press**Ctrl+D** (Linux/Mac) or**Ctrl+Z** (Windows) to finish

**Note**: Using Ctrl+D instead of Enter ensures the entire PSBT is captured, even for longer signed PSBTs (>1000 characters) which may exceed terminal input buffer limits

## Error Handling

### Wrong Execution Order

**Problem**: Running `wallet_coordinator.py` twice without `hw_device.py` in between

**Error Message**:

```
[ERROR] Cannot finalize: Hardware device has not signed yet!

[INFO] Please run hw_device.py first to sign the PSBT.
```

**Solution**: Follow the correct order: coordinator → device → coordinator

### Missing Transfer File

**Problem**: Running `hw_device.py` before `wallet_coordinator.py`

**Error Message**:

```
[ERROR] ERROR: No transfer file found!

[INFO] The wallet coordinator must run wallet_coordinator.py first to create the PSBT.
```

**Solution**: Run `wallet_coordinator.py` first to create the PSBT

### Already Signed PSBT

**Problem**: Running `hw_device.py` twice

**Error Message**:

```
[ERROR] ERROR: Transfer file contains already-signed PSBT!

[INFO] This PSBT was already signed by the hardware device.
   The wallet coordinator should finalize it now.
```

**Solution**: Run `wallet_coordinator.py` to finalize the transaction

## Attack Protection Scenarios

### Malicious Hardware Wallet

**Attack**: Hardware provides incorrect ECDH share to redirect funds to attacker

**How it works**: A compromised hardware device could compute `C = a * B_attacker` instead of `C = a * B_recipient`, where `B_attacker` is the attacker's scan key. This would cause the transaction to send funds to the attacker's silent payment address instead of the intended recipient.

**Protection**:

- **Step 2 validation**: Coordinator verifies DLEQ proof for each input
- DLEQ proof mathematically proves:`C = a * B` where`a` is the input private key and`B` is the recipient scan key
- If hardware used wrong scan key, proof verification fails
- Coordinator immediately rejects transaction with error message
- [OK]**Funds protected** - Transaction never broadcasted

### Compromised Software Coordinator

**Attack**: Software tries to change recipient after ECDH computation

**Protection**:

- DLEQ proof is bound to specific scan key
- Cannot generate valid proof for different recipient
- [OK] Funds protected

### Man-in-the-Middle

**Attack**: Attacker modifies PSBT during transfer

**Protection**:

- DLEQ proofs become invalid after modification
- Validation hash mismatch
- [OK] Tampering detected

### Supply Chain Attack

**Attack**: Hardware wallet shipped with compromised firmware

**Protection**:

- User doesn't need to trust manufacturer
- All computations are cryptographically verified
- [OK] Zero-trust model

## References

- [BIP 375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
- [BIP 352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP 370: PSBT v2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [BIP 374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)

## License

This example code is provided for educational purposes to demonstrate BIP 375 implementation patterns.
