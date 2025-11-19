#!/usr/bin/env python3
"""
Wallet Coordinator - Air-Gapped Hardware Signer Demo

This script represents the ONLINE wallet coordinator that:
1. Creates the initial PSBT structure (CREATOR + CONSTRUCTOR roles)
2. Sends PSBT to hardware device for signing (air-gap transfer)
3. Receives signed PSBT back from hardware device
4. Verifies DLEQ proofs and computes output scripts (SIGNER role)
5. Extracts final transaction (EXTRACTOR role)

Run this script first to create the PSBT, then run hw_device.py on the
"air-gapped" device to sign, then run this script again to finalize.

Usage:
    python3 wallet_coordinator.py          # Create PSBT OR finalize transaction
"""

import sys
import os

# Add current directory to path for shared_utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared_hw_utils import (
    get_transaction_inputs, get_transaction_outputs, get_recipient_address,
    get_hardware_wallet,
    print_transaction_details,
    save_psbt_to_transfer_file, load_psbt_from_transfer_file,
    prompt_for_transfer, wait_for_user_input, print_header, reset_demo, cleanup_transfer_file, TRANSFER_FILE
)

# Add parent directories to path for PSBT imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentPSBT, PSBTFieldType

def create_psbt(mnemonic: str = None, seed: str = None):
    """
    Step 1: Create initial PSBT structure

    Roles: CREATOR + CONSTRUCTOR + UPDATER
    
    Args:
        mnemonic: BIP39 mnemonic phrase for the hardware wallet
        seed: Simple seed string (for testing/demo)
    """
    print_header(1, "Create PSBT Structure", "WALLET COORDINATOR (Online)")

    print("\n CREATOR + CONSTRUCTOR + UPDATER: Setting up transaction...")

    # Get transaction components
    inputs = get_transaction_inputs()
    outputs = get_transaction_outputs()
    recipient_address = get_recipient_address(mnemonic=mnemonic)

    # Display transaction details for user validation
    print_transaction_details(inputs, outputs)

    # Create PSBT
    psbt = SilentPaymentPSBT()
    psbt.create_silent_payment_psbt(inputs, outputs)

    print(f" CREATOR + CONSTRUCTOR: Created PSBT with {len(inputs)} inputs and {len(outputs)} outputs")

    # For this demo, we get the hardware wallet's public keys
    # In a real system, the coordinator would:
    # 1. Get xpub from hardware wallet during initial setup
    # 2. Derive public keys from xpub + path
    # 3. Match public keys to UTXOs being spent
    from psbt_sp.crypto import Wallet
    hw_wallet = get_hardware_wallet(seed=seed, mnemonic=mnemonic)

    # Build derivation info for each input (privacy mode - no derivation path revealed)
    derivation_paths = []
    for i in range(len(inputs)):
        # Get public key for this input
        _, pubkey = hw_wallet.input_key_pair(i)

        # Privacy mode: only include public key, no derivation path
        # Hardware wallet will recognize its own keys internally
        derivation_paths.append({
            "pubkey": pubkey.bytes,
            # No master_fingerprint or path = privacy mode
        })

    psbt.updater_role(inputs, derivation_paths)

    print("   Using privacy mode (no derivation path revealed)")
    print("   Hardware wallet will match public keys internally")

    # Save to transfer file
    metadata = {
        "step": "created",
        "created_by": "wallet_coordinator",
        "hw_must_sign": [0, 1],  # Hardware wallet must sign both inputs
        "recipient_scan_key": recipient_address.scan_key.hex,
        "recipient_spend_key": recipient_address.spend_key.hex,
        "updater_added_bip32": True
    }

    save_psbt_to_transfer_file(psbt, metadata)

    # Display transfer options
    prompt_for_transfer(psbt, "to_device")

    print("\n" + "=" * 70)
    print("PSBT CREATED AND READY FOR HARDWARE DEVICE")
    print("=" * 70)
    print("\n NEXT STEP: Transfer PSBT to hardware device")
    print("   Run hw_device.py to sign, then run this script again to finalize.")

    return True  # Success

def finalize_transaction(auto_read=False, auto_broadcast=False, 
                         mnemonic: str = None, seed: str = None):
    """
    Step 3: Verify and finalize transaction

    Roles: SIGNER (verification) + EXTRACTOR

    Args:
        auto_read: If True, automatically read from transfer file
        auto_broadcast: If True, skip broadcast confirmation
        mnemonic: BIP39 mnemonic phrase for the hardware wallet
        seed: Simple seed string (for testing/demo)
    """
    print_header(3, "Verify and Finalize Transaction", "WALLET COORDINATOR (Online)")

    # Check if we're reading from file or user will paste
    print("\n Receiving signed PSBT from hardware device...")

    if auto_read:
        choice = "read"
    else:
        print("\nHow do you want to receive the signed PSBT?")
        print("  1. Type 'read' to load from transfer file")
        print("  2. Type 'paste' to paste PSBT data")
        print("  3. Type 'reset' to clear working files are restart")
        choice = wait_for_user_input("Your choice (read/paste/reset):")

    if choice == "read":
        # Load from file
        psbt, metadata = load_psbt_from_transfer_file()
        if psbt is None:
            print("\n❌ ERROR: No transfer file found!")
            print(f"   Expected file: {TRANSFER_FILE}")
            print("\n The hardware device must run hw_device.py first to sign the PSBT.")
            return False

        # Check if this is actually a signed PSBT
        if metadata.get("step") != "signed":
            print("\n❌ ERROR: Transfer file contains unsigned PSBT!")
            print(f"   Current step: {metadata.get('step', 'unknown')}")
            print("\n You need to run hw_device.py first to sign the PSBT.")
            print("   The workflow is:")
            print("   1. wallet_coordinator.py → creates PSBT")
            print("   2. hw_device.py → signs PSBT")
            print("   3. wallet_coordinator.py → finalizes transaction")
            return False

        print(f"Loaded signed PSBT from {TRANSFER_FILE}")

    elif choice == "paste":
        # Receive pasted data
        print("\nPaste the PSBT data from hardware device, then press Ctrl+D (or Ctrl+Z on Windows):")
        print("(The PSBT will appear on one or more lines)")

        import sys
        lines = []
        try:
            # Read all lines until EOF (Ctrl+D / Ctrl+Z)
            for line in sys.stdin:
                lines.append(line.strip())
        except KeyboardInterrupt:
            print("\n❌ Paste cancelled")
            return False

        psbt_base64 = "".join(lines).strip()

        if not psbt_base64:
            print("\n❌ ERROR: No PSBT data received!")
            return False

        try:
            # Parse PSBT from base64
            psbt = SilentPaymentPSBT.from_base64(psbt_base64)
            print("Parsed PSBT from pasted data")

            # Load metadata from file if available
            _, metadata = load_psbt_from_transfer_file()
            if metadata is None:
                metadata = {}
        except Exception as e:
            print(f"\n❌ ERROR: Failed to parse PSBT data: {e}")
            return False
    elif choice == "reset":
        reset_demo()
        return True
    else:
        print(f"\n❌ ERROR: Invalid choice '{choice}'. Please choose 'read', 'paste' or 'reset'.")
        return False

    # Comprehensive validation before finalizing
    print("\n VALIDATING SIGNED PSBT")
    print("=" * 70)

    validation_passed = True
    inputs = get_transaction_inputs()

    # 1. ECDH Coverage Check
    print("\n Checking ECDH coverage...")
    is_complete, inputs_with_ecdh = psbt.check_ecdh_coverage()

    if not is_complete:
        print(f"   ❌ FAILED: Incomplete ECDH coverage ({len(inputs_with_ecdh)}/{len(inputs)} inputs)")
        validation_passed = False
    else:
        print(f"   PASSED: Complete ECDH coverage ({len(inputs_with_ecdh)}/{len(inputs)} inputs)")

    # 2. DLEQ Proof Verification (CRITICAL SECURITY CHECK)
    print("\n Verifying DLEQ proofs...")

    # Collect all expected scan keys from transaction outputs
    # We need to validate DLEQ proofs for ALL scan keys in the transaction
    from psbt_sp.crypto import Wallet
    hw_wallet = get_hardware_wallet(seed=seed, mnemonic=mnemonic)
    recipient_address = get_recipient_address(mnemonic=mnemonic)

    # Expected scan keys:
    # 1. Change output (hardware wallet's scan key)
    # 2. Recipient output (recipient's scan key)
    expected_scan_keys = {
        hw_wallet.scan_pub.bytes,
        recipient_address.scan_key.bytes
    }

    # Collect all scan keys found in DLEQ proofs
    found_scan_keys = set()
    for input_fields in psbt.input_maps:
        for field in input_fields:
            if field.field_type == PSBTFieldType.PSBT_IN_SP_DLEQ:
                found_scan_keys.add(field.key_data)

    for field in psbt.global_fields:
        if field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_DLEQ:
            found_scan_keys.add(field.key_data)

    # Check for unexpected scan keys (possible attack)
    unexpected_keys = found_scan_keys - expected_scan_keys
    if unexpected_keys:
        print("   🚨 ATTACK DETECTED: DLEQ proofs for unexpected scan keys!")
        for key in unexpected_keys:
            print(f"      Unexpected: {key.hex()}")
        print("   ⚠️ CRITICAL: Hardware device used attacker's scan key!")
        print("    Hardware device computed ECDH shares with incorrect scan key")
        print("    This could indicate firmware corruption or malicious modification")
        validation_passed = False
    else:
        try:
            if psbt.verify_dleq_proofs(inputs):
                print(f"   PASSED: All DLEQ proofs verified for {len(expected_scan_keys)} scan keys")
                print(f"      Change scan key:    {hw_wallet.scan_pub.hex}")
                print(f"      Recipient scan key: {recipient_address.scan_key.hex}")
            else:
                print("   ❌ FAILED: DLEQ proof verification failed!")
                print("   ⚠️ CRITICAL: Hardware device may be malicious or buggy!")
                validation_passed = False
        except Exception as e:
            print(f"   ❌ FAILED: DLEQ verification error: {e}")
            validation_passed = False

    # 3. Output Script Verification
    print("\n  Verifying output scripts...")
    output_scripts_computed = any(
        any(field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT for field in output_fields)
        for output_fields in psbt.output_maps
    )

    if not output_scripts_computed:
        print("   ❌ FAILED: Output scripts not computed!")
        validation_passed = False
    else:
        print("   PASSED: Output scripts present")

    # 4. Signature Verification
    print("\n  Verifying signatures...")
    signatures_count = 0
    for input_fields in psbt.input_maps:
        has_sig = any(field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG for field in input_fields)
        if has_sig:
            signatures_count += 1

    if signatures_count != len(inputs):
        print(f"   ❌ FAILED: Missing signatures ({signatures_count}/{len(inputs)} inputs)")
        validation_passed = False
    else:
        print(f"   PASSED: All inputs signed ({signatures_count}/{len(inputs)})")

    # 5. TX_MODIFIABLE Flags Check
    print("\n  Checking TX_MODIFIABLE flags...")
    try:
        is_modifiable = psbt.check_tx_modifiable()
        if is_modifiable:
            print("   WARNING: PSBT still modifiable (expected after signing)")
        else:
            print("   PASSED: PSBT finalized (non-modifiable)")
    except Exception:
        print("   INFO: TX_MODIFIABLE check not available")

    # 6. Amount Validation
    print("\n  Validating transaction amounts...")
    outputs = get_transaction_outputs()
    total_input = sum(utxo.amount for utxo in inputs)
    total_output = sum(output["amount"] for output in outputs)
    fee = total_input - total_output

    print(f"   Total input:  {total_input:,} sats")
    print(f"   Total output: {total_output:,} sats")
    print(f"   Fee:          {fee:,} sats")

    if fee < 0:
        print("   ❌ FAILED: Outputs exceed inputs!")
        validation_passed = False
    elif fee > 100000:  # Sanity check: fee > 100k sats
        print(f"   WARNING: High fee ({fee:,} sats)")
    else:
        print("   PASSED: Amounts valid")

    # Validation Summary
    print("\n" + "=" * 70)
    if not validation_passed:
        print("❌ VALIDATION FAILED - TRANSACTION NOT SAFE TO BROADCAST")
        print("=" * 70)
        print("\n⚠️  DO NOT broadcast this transaction!")
        print("   One or more critical validations failed.")
        print("   The hardware device may be compromised or malfunctioning.")
        return False

    print("ALL VALIDATIONS PASSED")
    print("=" * 70)
    print("\n Transaction is safe to broadcast")

    # Extract transaction
    print("\n EXTRACTOR: Creating final transaction...")

    try:
        transaction_bytes = psbt.extract_transaction()
        transaction_hex = transaction_bytes.hex()

        print(f"Transaction extracted ({len(transaction_bytes)} bytes)")

        # Save transaction
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        tx_file = os.path.join(output_dir, "final_transaction.hex")

        with open(tx_file, 'w') as f:
            f.write(transaction_hex)

        print(f"\n Saved transaction to: {tx_file}")

        # Display final transaction
        print("\n" + "═" * 70)
        print(" " * 12 + " FINAL TRANSACTION (Ready for Broadcast)")
        print("═" * 70)
        print(transaction_hex)
        print("═" * 70)
        print(f"Length: {len(transaction_hex)} characters ({len(transaction_bytes)} bytes)")

        print("\n" + "=" * 70)
        print(" TRANSACTION COMPLETE!")
        print("=" * 70)
        print("\n Transaction ready to broadcast to Bitcoin network")

        # Final broadcast confirmation
        if auto_broadcast:
            print("\n Auto-broadcast mode - skipping confirmation")
            print(f"\n Transaction saved to: {tx_file}")
        else:
            print("\n" + "⚠️ " * 35)
            print("BROADCAST CONFIRMATION")
            print("⚠️ " * 35)
            print("\n  This will broadcast the transaction to the Bitcoin network.")
            print("  Once broadcast, the transaction CANNOT be reversed!")
            print("\n Please verify:")
            print("   • Transaction details match what you approved on hardware device")
            print("   • Recipient address is correct")
            print("   • Amounts and fee are acceptable")

            # Get user confirmation
            confirmation = wait_for_user_input("\n  Type 'BROADCAST' to confirm and broadcast, or anything else to cancel:")

            if confirmation == "broadcast":
                print("\nBroadcast confirmed!")
                print("\n In a real implementation, the transaction would be broadcast here:")
                print(f"   $ bitcoin-cli sendrawtransaction {transaction_hex[:64]}...")
                print(f"\n Transaction saved to: {tx_file}")
            else:
                print("\n❌ Broadcast cancelled by user")
                print(f"\n Transaction saved to {tx_file}")
                print("   You can broadcast it later if you choose.")

        return True

    except Exception as e:
        print(f"\n❌ ERROR: Transaction extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """
    Main coordinator workflow

    Detects whether to create a new PSBT or finalize an existing one.
    Supports command-line arguments for automated testing.
    """
    import argparse

    parser = argparse.ArgumentParser(description='Wallet Coordinator - BIP 375 Hardware Signer')
    parser.add_argument('action', nargs='?', choices=['create', 'finalize', 'read', 'new', 'reset'],
                       help='Action: create (new PSBT), finalize (complete), read (auto-read file), new (start fresh), reset (clean up)')
    parser.add_argument('--auto-read', action='store_true',
                       help='Automatically read from transfer file when finalizing')
    parser.add_argument('--auto-broadcast', action='store_true',
                       help='Skip broadcast confirmation prompt')
    parser.add_argument('--mnemonic', type=str,
                       help='BIP39 mnemonic phrase (12 or 24 words)')
    parser.add_argument('--seed', type=str,
                       help='Simple seed string (for testing/demo)')
    args = parser.parse_args()
    
    # Handle mnemonic/seed input
    mnemonic = None
    seed = None
    
    if args.mnemonic:
        # Validate mnemonic
        try:
            from mnemonic import Mnemonic
            mnemo = Mnemonic("english")
            if not mnemo.check(args.mnemonic):
                print("\n❌ ERROR: Invalid BIP39 mnemonic phrase!")
                print("   Please check your mnemonic and try again.")
                sys.exit(1)
            mnemonic = args.mnemonic
        except ImportError:
            print("\n❌ ERROR: 'mnemonic' library not installed!")
            print("   Install with: pip install mnemonic")
            sys.exit(1)
    elif args.seed:
        seed = args.seed

    print("\n" + "═" * 70)
    print(" " * 15 + "WALLET COORDINATOR - Air-Gapped Demo" + " " * 16)
    print(" " * 22 + "BIP 375 Hardware Signer" + " " * 22)
    print("═" * 70)

    # Check if there's already a transfer file
    psbt, metadata = load_psbt_from_transfer_file()

    # Determine action based on command-line args or existing state
    action = args.action

    if action == 'reset':
        print("\n Resetting demo...")
        reset_demo()
        print(" Demo reset complete")
        return

    if psbt is None:
        # No transfer file - create new PSBT
        if action in ['finalize', 'read']:
            print(f"\n❌ ERROR: Cannot {action} - no PSBT found!")
            print("   Run with 'create' first to create a new PSBT")
            sys.exit(1)

        print("\n No existing PSBT found. Starting new transaction...")
        reset_demo()  # Clean up any old files
        success = create_psbt(mnemonic=mnemonic, seed=seed)

    elif metadata.get("step") == "created":
        # PSBT exists but not signed
        if action in ['create', 'new']:
            print("\n🧹 Starting fresh transaction...")
            reset_demo()
            success = create_psbt(mnemonic=mnemonic, seed=seed)
        elif action in ['finalize', 'read']:
            print("\n⚠️  Found unsigned PSBT in transfer file")
            print(f"   Created by: {metadata.get('created_by', 'unknown')}")
            print("\n❌ Cannot finalize: Hardware device has not signed yet!")
            print("\n Run hw_device.py first to sign this PSBT")
            sys.exit(1)
        else:
            # Interactive mode
            print("\n⚠️  Found unsigned PSBT in transfer file")
            print(f"   Created by: {metadata.get('created_by', 'unknown')}")
            print("\n❌ Cannot finalize: Hardware device has not signed yet!")
            print("\n Options:")
            print("   1. Run hw_device.py first to sign this PSBT, then run this script again")
            print("   2. Start a new transaction (will discard the unsigned PSBT)")

            choice = wait_for_user_input("\nWhat would you like to do? (sign/new):")

            if choice == "new":
                print("\n Starting fresh transaction...")
                reset_demo()
                success = create_psbt(mnemonic=mnemonic, seed=seed)
            else:
                print("\n Waiting for hw_device.py to sign the PSBT.")
                print("   Run hw_device.py, then run this script again to finalize.")
                success = False

    elif metadata.get("step") == "signed":
        # PSBT is signed - finalize
        if action in ['create', 'new']:
            print("\n Starting fresh transaction...")
            reset_demo()
            success = create_psbt(mnemonic=mnemonic, seed=seed)
        else:
            print("\n Found signed PSBT from hardware device")
            print("\n Proceeding to finalization...")
            success = finalize_transaction(auto_read=(args.auto_read or action == 'read'),
                                          auto_broadcast=args.auto_broadcast,
                                          mnemonic=mnemonic, seed=seed)

            if success:
                # Clean up transfer file on success
                print("\n Cleaning up transfer file...")
                cleanup_transfer_file()
                print(" Ready for next transaction")
    else:
        print(f"\n⚠️  Unknown PSBT state: {metadata.get('step', 'unknown')}")
        print("   You may want to reset and start fresh.")
        print("\n To reset: python3 wallet_coordinator.py reset")
        success = False

    if not success:
        print("\n" + "=" * 70)
        print("❌ WORKFLOW INCOMPLETE")
        print("=" * 70)
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)