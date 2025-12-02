#!/usr/bin/env python3
"""
Hardware Device - Air-Gapped Hardware Signer Demo

This script represents the OFFLINE air-gapped hardware device that:
1. Receives PSBT from wallet coordinator (air-gap transfer)
2. Displays transaction details for user verification
3. Computes ECDH shares and generates DLEQ proofs (SIGNER role)
4. Signs transaction inputs (SIGNER role)
5. Returns signed PSBT to wallet coordinator (air-gap transfer)

This device is assumed to be AIR-GAPPED (no network connection) and stores
private keys securely. All communication with the coordinator happens via
manual data transfer (copy/paste or file).

Usage:
    python3 hw_device.py
"""

import sys
import os

# Add current directory to path for shared_utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared_hw_utils import (
    get_hardware_wallet, print_transaction_details,
    save_psbt_to_transfer_file, load_psbt_from_transfer_file,
    prompt_for_transfer, wait_for_user_input, print_header, print_separator,
    decode_dnssec_proof,
    TRANSFER_FILE
)

# Add parent directories to path for PSBT imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentPSBT
from psbt_sp.constants import PSBTFieldType
from psbt_sp.crypto import Wallet, PublicKey
from psbt_sp.psbt_utils import extract_inputs_from_psbt, extract_output_details_from_psbt, extract_dnssec_proofs_from_outputs
from secp256k1_374 import GE

def receive_psbt(auto_read=False):
    """
    Receive PSBT from wallet coordinator

    Args:
        auto_read: If True, automatically read from transfer file

    Returns tuple of (psbt, metadata) or (None, None) if failed
    """
    print("\n Receiving PSBT from wallet coordinator...")

    if auto_read:
        choice = "read"
    else:
        print("\nHow do you want to receive the PSBT?")
        print("  1. Type 'read' to load from transfer file")
        print("  2. Type 'paste' to paste PSBT data")
        choice = wait_for_user_input("Your choice (read/paste):")

    if choice == "read":
        # Load from file
        psbt, metadata = load_psbt_from_transfer_file()
        if psbt is None:
            print("\n❌ ERROR: No transfer file found!")
            print(f"   Expected file: {TRANSFER_FILE}")
            print("\n The wallet coordinator must run wallet_coordinator.py first to create the PSBT.")
            return None, None

        # Check if this is an unsigned PSBT
        if metadata.get("step") == "signed":
            print("\n❌ ERROR: Transfer file contains already-signed PSBT!")
            print(f"   Current step: {metadata.get('step', 'unknown')}")
            print("\n This PSBT was already signed by the hardware device.")
            print("   The wallet coordinator should finalize it now.")
            print("   Run wallet_coordinator.py to complete the transaction.")
            return None, None

        print(f"Loaded PSBT from {TRANSFER_FILE}")
        return psbt, metadata

    elif choice == "paste":
        # Receive pasted data
        print("\nPaste the PSBT data from wallet coordinator, then press Ctrl+D (or Ctrl+Z on Windows):")
        print("(The PSBT will appear on one or more lines)")

        lines = []
        try:
            # Read all lines until EOF (Ctrl+D / Ctrl+Z)
            for line in sys.stdin:
                lines.append(line.strip())
        except KeyboardInterrupt:
            print("\n❌ Paste cancelled")
            return None, None

        psbt_base64 = "".join(lines).strip()

        if not psbt_base64:
            print("\n❌ ERROR: No PSBT data received!")
            return None, None

        try:
            # Parse PSBT from base64
            psbt = SilentPaymentPSBT.from_base64(psbt_base64)
            print("Parsed PSBT from pasted data")

            # Try to load metadata from file if available
            _, metadata = load_psbt_from_transfer_file()
            if metadata is None:
                # Create basic metadata if not available
                metadata = {
                    "step": "created",
                    "hw_must_sign": [0, 1]
                }

            return psbt, metadata

        except Exception as e:
            print(f"\n❌ ERROR: Failed to parse PSBT data: {e}")
            return None, None
    else:
        print(f"\n❌ ERROR: Invalid choice '{choice}'. Please choose 'read' or 'paste'.")
        return None, None

def verify_transaction_details(psbt, wallet: Wallet, auto_approve=False, attack=None):
    """
    Display transaction details on hardware device screen for user verification

    Args:
        psbt: SilentPaymentPSBT instance to extract transaction details from
        wallet: Wallet instance for the hardware wallet (for setting private keys)
        auto_approve: If True, automatically approve without user prompt
        attack: If not None, simulate attack mode

    In a real hardware wallet, this would be shown on the device's secure display.
    """
    from psbt_sp.psbt_utils import extract_inputs_from_psbt, extract_output_details_from_psbt
    
    print("\n" + "=" * 70)
    print(" HARDWARE DEVICE DISPLAY (Secure Element)")
    print("=" * 70)

    # Extract transaction details from PSBT (air-gap security model)
    inputs = extract_inputs_from_psbt(psbt)
    outputs = extract_output_details_from_psbt(psbt)
    
    # Extract DNSSEC proofs for inline display
    dnssec_proofs = extract_dnssec_proofs_from_outputs(psbt.output_maps)
    
    # Print transaction details with DNS info inline
    print_transaction_details(inputs, outputs, dnssec_proofs)

    print("\n⚠️  VERIFY TRANSACTION ON DEVICE SCREEN")
    print("─" * 70)
    print("Please carefully verify:")
    print("  • Total amount being spent")
    print("  • Change amount returning to you")
    print("  • Silent payment recipient address")
    if dnssec_proofs:
        print("  • DNS contact name for recipient")
    print("  • Transaction fee")

    # User must confirm
    if auto_approve:
        if attack:
            print("\n Auto-approve with ATTACK mode enabled")
            return attack
        else:
            print("\n Transaction auto-approved")
            return ""
    else:
        print("\n SECURITY PROMPT:")
        confirmation = wait_for_user_input("Type 'YES' to approve, 'ATTACK' to simulate attack, 'ATTACK-STRIP' to simulate attack removing BIP375 fields, or anything else to reject:")

        if "ATTACK" in confirmation.upper():
            print("\n⚠️  ATTACK MODE ENABLED - Simulating malicious hardware!")
            print("   Hardware will compute ECDH shares with wrong scan key")
            print("   Coordinator should detect this via DLEQ proof verification")
            return confirmation.lower()
        elif confirmation.upper() == "YES":
            print("Transaction APPROVED by user")
            return ""
        else:
            print("\n❌ Transaction REJECTED by user")
            return "reject"

def sign_psbt(psbt: SilentPaymentPSBT, metadata: dict, wallet: Wallet,
              attack=None):
    """
    Sign the PSBT with hardware wallet private keys

    Roles: SIGNER
    
    Args:
        psbt: The PSBT to sign
        metadata: Transaction metadata
        wallet: Wallet instance for the hardware wallet
        attack: If not None, simulate attack mode
    """
    from psbt_sp.psbt_utils import extract_inputs_from_psbt, extract_scan_keys_from_outputs
    
    print("\n SIGNER: Processing transaction with hardware keys...")

    # Extract inputs from PSBT (air-gap security model)
    inputs = extract_inputs_from_psbt(psbt)

    scan_key_bytes_list = extract_scan_keys_from_outputs(psbt.output_maps)
    scan_keys = [PublicKey(GE.from_bytes(sk_bytes)) for sk_bytes in scan_key_bytes_list]
    
    print(f"Extracted {len(scan_keys)} scan key(s) from PSBT outputs:")
    for i, sk in enumerate(scan_keys):
        print(f"     Scan key {i}: {sk.bytes.hex()}")

    # For demo verification only - show which is which
    # In real hardware wallet, device wouldn't know which is change vs recipient
    # It just processes all scan keys found in PSBT
    if len(scan_keys) >= 2:
        if scan_keys[0].bytes == wallet.scan_pub.bytes:
            print(f"     (Output 0 is change to hardware wallet)")
        if len(scan_keys) > 1:
            print(f"     (Output 1 is payment to recipient)")

    # Get all scan keys from outputs
    # We need scan keys for ALL silent payment outputs:
    # 1. Change output (hardware wallet's scan key)
    # 2. Recipient output (recipient's scan key)

    if attack:
        # ATTACK SIMULATION: Use attacker's scan key instead of legitimate recipient
        print("\n🚨 ATTACK MODE: Using malicious scan key!")
        print("   Real recipient scan key would be used in honest mode")

        # Create attacker wallet and use their scan key
        from psbt_sp.crypto import Wallet
        attacker_wallet = Wallet(seed="attacker_malicious_scan_key")
        malicious_scan_key = attacker_wallet.scan_pub

        print(f"   Malicious scan key:   {malicious_scan_key.hex}")
        print("   ⚠️  Funds would go to attacker if this succeeds!")

        # SOPHISTICATED ATTACK: Create malicious ECDH shares but prevent method failure
        # We'll monkey-patch the compute_output_scripts method to allow completion
        original_compute_output_scripts = psbt.compute_output_scripts

        def bypass_output_script_computation(scan_privkeys: dict = None):
            """Bypass output script computation to allow attack to complete"""
            print("     🚨 ATTACK: Bypassing output script computation")
            # Manually set some dummy output scripts so the method doesn't fail
            from psbt_sp.serialization import PSBTField
            from psbt_sp.constants import PSBTFieldType

            for output_map in psbt.output_maps:
                # Add a dummy script to make it look like outputs were computed
                dummy_script = b'\x00\x14' + b'\x00' * 20  # Dummy P2WPKH script
                output_map.append(PSBTField(
                    PSBTFieldType.PSBT_OUT_SCRIPT,
                    b'',  # Empty key data
                    dummy_script
                ))
            return True    

        # Temporarily replace the method
        psbt.compute_output_scripts = bypass_output_script_computation

        # Use malicious scan key for ECDH computation
        # Note: In attack mode, we only use malicious key (not realistic but for demo)
        scan_keys[0] = malicious_scan_key

    # Hardware wallet controls both inputs
    hw_controlled_inputs = metadata.get("hw_must_sign", [0, 1])

    print(f"\n   Hardware wallet controls inputs: {hw_controlled_inputs}")

    # Extract BIP32 derivation paths from PSBT
    from psbt_sp.psbt_utils import extract_bip32_derivations_from_psbt
    derivations = extract_bip32_derivations_from_psbt(psbt)

    # Set private keys for hardware-controlled inputs
    for input_idx in hw_controlled_inputs:
        # Check if we have BIP32 derivation info for this input
        if input_idx < len(derivations) and derivations[input_idx] and wallet.bip39_seed:
            # Use the exact path from PSBT
            path = derivations[input_idx]['path']
            print(f"   Deriving key for input {input_idx} using path: {path}")
            private_key, public_key = wallet._derive_bip32_key(path)
            
            # Verify public key matches PSBT
            psbt_pubkey = derivations[input_idx]['public_key']
            if public_key.bytes != psbt_pubkey:
                print(f"⚠️  WARNING: Derived public key mismatch for input {input_idx}!")
                print(f"     Expected: {psbt_pubkey.hex()}")
                print(f"     Derived:  {public_key.bytes.hex()}")
        else:
            # Fallback for demo PSBTs or simple wallet mode
            print(f"   Using default derivation for input {input_idx} (index-based)")
            private_key = wallet.input_key_pair(input_idx)[0]
            
        inputs[input_idx].private_key = private_key

    print(f"   Set private keys for inputs {hw_controlled_inputs}")

    if attack:
        print("\n   🚨 Computing ECDH shares with MALICIOUS scan key...")
        print("   🚨 Generating DLEQ proofs for WRONG scan key...")
        print("    Signing inputs with CORRECT private keys...")
        print("\n   ⚠️  This attack tries to redirect funds while maintaining valid signatures")
        print("   ⚠️  The coordinator should detect this via DLEQ proof verification!")
    else:
        print("\n   Computing ECDH shares (auto-extracted from PSBT)...")
        print("   Generating DLEQ proofs...")
        print("   Signing inputs...")

    # Prepare scan private keys for label computation
    # Hardware wallet knows its own scan private key (for change with label=0)
    scan_privkeys = {
        wallet.scan_pub.bytes: wallet.scan_priv.bytes
    }

    # Perform signing role
    try:
        # Use full signer_role since hardware device controls all inputs
        # This ensures TX_MODIFIABLE is set to 0x00 after computing output scripts (BIP 375 requirement)
        success = psbt.signer_role(inputs, scan_keys, scan_privkeys)

        if not success:
            print("\n❌ ERROR: Hardware signing failed!")
            return None

        if attack:
            print("   🚨 ECDH shares computed with MALICIOUS scan key")
            print("   🚨 DLEQ proofs generated for WRONG scan key")
            print("    Inputs signed with correct private keys")
            print("\n    Attack attempt complete - coordinator should reject this!")
            # Restore original method
            psbt.compute_output_scripts = original_compute_output_scripts
        else:
            print("   ECDH shares computed, DLEQ proofs generated, inputs signed")

        # Verify ECDH coverage
        is_complete, inputs_with_ecdh = psbt.check_ecdh_coverage()

        if attack == "attack-strip":
            strip_bip375_fields(psbt)  # Remove BIP375 fields

        print(f"\n   ECDH coverage: {len(inputs_with_ecdh)}/{len(inputs)} inputs ({'complete' if is_complete else 'incomplete'})")

        if not is_complete:
            print("\n⚠️  Warning: Incomplete ECDH coverage")
            print("   All inputs should have ECDH shares for output computation")

        return psbt

    except Exception as e:
        print(f"\n❌ ERROR: Signing failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def strip_bip375_fields(psbt):
    """Remove BIP375 fields from PSBT"""
    print("     🚨 ATTACK: Stripping BIP375 fields")
    # Remove BIP375 fields from PSBT (only if they exist)
    for output_map in psbt.output_maps:
        # Find and remove fields by checking each field's type
        fields_to_remove = []
        for field in output_map:
            if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                fields_to_remove.append(field)
            elif field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_LABEL:
                fields_to_remove.append(field)
        for field in fields_to_remove:
            output_map.remove(field)
    
    for input_map in psbt.input_maps:
        # Find and remove fields by checking each field's type
        fields_to_remove = []
        for field in input_map:
            if field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE:
                fields_to_remove.append(field)
            elif field.field_type == PSBTFieldType.PSBT_IN_SP_DLEQ:
                fields_to_remove.append(field)
        for field in fields_to_remove:
            input_map.remove(field)
    
    # Remove global fields
    fields_to_remove = []
    for field in psbt.global_fields:
        if field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE:
            fields_to_remove.append(field)
        elif field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_DLEQ:
            fields_to_remove.append(field)
    for field in fields_to_remove:
        psbt.global_fields.remove(field)


def main():
    """
    Main hardware device workflow

    1. Receive PSBT from coordinator
    2. Display transaction details for verification
    3. User approves transaction
    4. Sign PSBT with hardware keys
    5. Return signed PSBT to coordinator

    Supports command-line arguments for automated testing.
    """
    import argparse

    parser = argparse.ArgumentParser(description='Hardware Device - BIP 375 Hardware Signer')
    parser.add_argument('--auto-read', action='store_true',
                       help='Automatically read PSBT from transfer file')
    parser.add_argument('--auto-approve', action='store_true',
                       help='Automatically approve transaction without prompt')
    parser.add_argument('--attack', type=str,
                       help='Simulate malicious hardware [attack|attack-strip]')
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
            print("\n Using provided BIP39 mnemonic")
        except ImportError:
            print("\n❌ ERROR: 'mnemonic' library not installed!")
            print("   Install with: pip install mnemonic")
            sys.exit(1)
    elif args.seed:
        seed = args.seed
        print(f"\n Using provided seed: {seed}")

    print("\n" + "═" * 70)
    print(" " * 17 + "HARDWARE DEVICE - Air-Gapped Demo")
    print(" " * 22 + "BIP 375 Hardware Signer")
    print("═" * 70)

    print_header(2, "Hardware Device Signing", "HARDWARE DEVICE (Air-Gapped)")

    # Step 1: Receive PSBT
    psbt, metadata = receive_psbt(auto_read=args.auto_read)
    if psbt is None:
        print("\n" + "=" * 70)
        print("❌ FAILED TO RECEIVE PSBT")
        print("=" * 70)
        sys.exit(1)
    
    # Create wallet instance once
    hw_wallet = get_hardware_wallet(seed=seed, mnemonic=mnemonic)

    # Step 2: Verify transaction details
    print_separator()
    approval_result = verify_transaction_details(psbt, hw_wallet,
                                                 auto_approve=args.auto_approve, 
                                                  attack=args.attack)

    if approval_result == "reject":
        print("\n" + "=" * 70)
        print("❌ TRANSACTION REJECTED BY USER")
        print("=" * 70)
        sys.exit(1)

    # Determine if we're in attack mode
    attack = approval_result if "attack" in approval_result else None

    # Step 3: Sign PSBT
    print_separator()
    signed_psbt = sign_psbt(psbt, metadata, hw_wallet, attack)

    if signed_psbt is None:
        print("\n" + "=" * 70)
        print("❌ SIGNING FAILED")
        print("=" * 70)
        sys.exit(1)

    if attack:
        print("\n🚨 MALICIOUS HARDWARE SIGNING COMPLETED!")
        print("\n⚠️  WARNING: This PSBT contains malicious ECDH shares!")
        print("   The coordinator should detect and reject this transaction.")
    else:
        print("\nHARDWARE SIGNING COMPLETED")

    # Step 4: Save and return signed PSBT
    updated_metadata = {
        "step": "signed",
        "signed_by": "hardware_device",
        "hw_controlled_inputs": metadata.get("hw_must_sign", [0, 1]),
        "inputs_with_ecdh": signed_psbt.get_inputs_with_ecdh_shares(),
        "ecdh_complete": signed_psbt.can_compute_output_scripts(),
        "recipient_scan_key": metadata.get("recipient_scan_key", ""),
        "recipient_spend_key": metadata.get("recipient_spend_key", "")
    }

    save_psbt_to_transfer_file(signed_psbt, updated_metadata)

    # Display transfer options
    prompt_for_transfer(signed_psbt, "to_coordinator")

    print("\n" + "=" * 70)
    if attack:
        print("🚨 MALICIOUS PSBT READY FOR WALLET COORDINATOR")
        print("=" * 70)
        print("\n NEXT STEP: Transfer MALICIOUS signed PSBT to wallet coordinator")
        print("   The coordinator should REJECT this transaction!")
        print("\n Expected coordinator behavior:")
        print("   • DLEQ proof verification will FAIL")
        print("   • Transaction will be REJECTED")
        print("   • Attack will be DETECTED and PREVENTED")
    else:
        print("SIGNED PSBT READY FOR WALLET COORDINATOR")
        print("=" * 70)
        print("\n NEXT STEP: Transfer signed PSBT back to wallet coordinator")
        print("   Run wallet_coordinator.py to verify and finalize the transaction.")

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