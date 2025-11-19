#!/usr/bin/env python3
"""
Shared utilities for hardware signer air-gapped workflow

Contains common transaction data, validation display utilities,
and file transfer helpers for the wallet_coordinator.py and hw_device.py scripts.
"""

import sys
import os
import hashlib

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentAddress, SilentPaymentPSBT
from psbt_sp.crypto import Wallet, PublicKey, UTXO

# Transfer file for bidirectional communication
TRANSFER_FILE = os.path.join(os.path.dirname(__file__), "output", "transfer.psbt")

def compute_pubkey_hash(public_key: PublicKey) -> bytes:
    """Compute hash160 of public key for P2WPKH addresses"""
    pubkey_bytes = public_key.bytes  # compressed 33 bytes
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

def get_recipient_address(mnemonic: str = None):
    """
    Get the silent payment recipient address

    In a real scenario, this would be provided by the recipient
    or scanned from a QR code / copied from a payment request.
    
    Args:
        mnemonic: Optional BIP39 mnemonic for the recipient wallet
    """
    if mnemonic:
        wallet = Wallet(mnemonic=mnemonic)
    else:
        wallet = Wallet(seed="recipient_hardware_signer_demo")
    return SilentPaymentAddress(
        scan_key=wallet.scan_pub,
        spend_key=wallet.spend_pub
    )

def get_hardware_wallet(seed: str = None, mnemonic: str = None):
    """
    Get the hardware wallet's deterministic wallet for key generation

    In a real scenario, this would be a hardware device with secure storage.
    
    Args:
        seed: Simple seed string (for backward compatibility/testing)
        mnemonic: BIP39 mnemonic phrase (12 or 24 words, for production use)
    
    Returns:
        Wallet instance configured with the provided seed material
    """
    if mnemonic:
        return Wallet(mnemonic=mnemonic)
    elif seed:
        return Wallet(seed=seed)
    else:
        # Default for demo
        return Wallet(seed="hardware_wallet_coldcard_demo")

def get_transaction_inputs():
    """
    Get the transaction inputs for the hardware signing scenario

    2 inputs controlled by the hardware wallet:
    - Input 0: 100,000 sats
    - Input 1: 200,000 sats

    Returns:
        List of UTXO objects with private keys set to None initially.
        Hardware device will set private keys during signing.
    """
    hw_wallet = get_hardware_wallet()

    # Generate public keys for the inputs
    pubkey0 = hw_wallet.input_key_pair(0)[1]
    pubkey1 = hw_wallet.input_key_pair(1)[1]

    inputs = [
        # Input 0
        UTXO(
            txid="a1b2c3d4e5f6789012345678901234567890123456789012345678901234567a",
            vout=0,
            amount=100000,  # 100,000 sats
            script_pubkey="0014" + compute_pubkey_hash(pubkey0).hex(),
            private_key=None,  # Will be set by hardware device
            sequence=0xfffffffe
        ),
        # Input 1
        UTXO(
            txid="b1c2d3e4f5f6789012345678901234567890123456789012345678901234567b",
            vout=1,
            amount=200000,  # 200,000 sats
            script_pubkey="0014" + compute_pubkey_hash(pubkey1).hex(),
            private_key=None,  # Will be set by hardware device
            sequence=0xfffffffe
        )
    ]

    return inputs

def get_transaction_outputs():
    """
    Get the transaction outputs for the hardware signing scenario

    2 outputs:
    - Output 0: Silent payment CHANGE output (50,000 sats with label=0)
    - Output 1: Silent payment output to recipient (245,000 sats)

    Returns:
        List of output dictionaries

    Implementation Notes:

    This demonstrates BIP 375 change detection using silent payment labels.
    Per BIP 352, label=0 is RESERVED FOR CHANGE, allowing:

    1. Privacy: Change stays within silent payment protocol (no address reuse)
    2. Self-custody: Change returns to hardware wallet's own keys
    3. Change detection: Hardware can verify using BIP32 derivation paths
    4. Wallet recovery: Scanners know to check label=0 during backup recovery

    Label Mechanics (BIP 352):
    - Labels modify the spend key: B_m = B_spend + hash(b_scan || m)·G
    - Label 0 is reserved specifically for change outputs
    - Label > 0 can be used for other purposes (payment routing, etc.)

    BIP 375 Change Detection:
    - Updaters add PSBT_OUT_BIP32_DERIVATION for scan/spend keys
    - Signer verifies change using derivation paths
    - PSBT_OUT_SP_V0_LABEL=0 marks the output as change

    See BIP 375 "Change Detection" section and BIP 352 "Labels" section.
    """
    # Hardware wallet keys - change returns to same wallet
    hw_wallet = get_hardware_wallet()

    # Recipient address (external party)
    recipient_address = get_recipient_address()

    outputs = [
        # Silent payment CHANGE output - returns to hardware wallet
        # Using label=0 (reserved for change per BIP 352)
        {
            "amount": 50000,  # 50,000 sats
            "address": SilentPaymentAddress(
                scan_key=hw_wallet.scan_pub,
                spend_key=hw_wallet.spend_pub,
                label=0  # Label 0 = change (BIP 352)
            )
        },
        # Silent payment output to recipient (no label)
        {
            "amount": 245000,  # 245,000 sats (300,000 - 50,000 - 5,000 fee)
            "address": recipient_address
        }
    ]

    return outputs

def print_transaction_details(inputs, outputs):
    """
    Print transaction details for manual validation

    User can verify these details match on both coordinator and hardware device.
    """
    print("\n TRANSACTION DETAILS (Verify these match on both sides)")
    print("─" * 70)

    # Input details
    print("\n INPUTS:")
    total_input = 0
    for i, utxo in enumerate(inputs):
        total_input += utxo.amount
        print(f"  Input {i}:")
        print(f"    Amount:     {utxo.amount:,} sats")
        print(f"    TXID:       {utxo.txid}")
        print(f"    VOUT:       {utxo.vout}")
        print(f"    ScriptPub:  {utxo.script_pubkey}")

    print(f"\n  Total Input:  {total_input:,} sats")

    # Output details
    print("\n OUTPUTS:")
    total_output = 0
    for i, output in enumerate(outputs):
        total_output += output["amount"]
        print(f"  Output {i}:")
        print(f"    Amount:     {output['amount']:,} sats")

        if "address" in output:
            sp_address = output["address"]
            # Check if this is change (label=0) or regular payment
            if hasattr(sp_address, 'label') and sp_address.label == 0:
                print("    Type:       Silent Payment CHANGE (Label 0)")
                print(f"    Scan Key:   {sp_address.scan_key.hex}")
                print(f"    Spend Key:  {sp_address.spend_key.hex}")
                print("    Note:       Returns to your wallet")
            else:
                print("    Type:       Silent Payment")
                print(f"    Scan Key:   {sp_address.scan_key.hex}")
                print(f"    Spend Key:  {sp_address.spend_key.hex}")
                if hasattr(sp_address, 'label') and sp_address.label is not None:
                    print(f"    Label:      {sp_address.label}")
        else:
            print("    Type:       Regular Output (P2WPKH)")
            print(f"    ScriptPub:  {output['script_pubkey']}")

    fee = total_input - total_output
    print(f"\n  Total Output: {total_output:,} sats")
    print(f"  Fee:          {fee:,} sats")
    print()

def save_psbt_to_transfer_file(psbt: SilentPaymentPSBT, metadata: dict):
    """Save PSBT to the shared transfer file"""
    os.makedirs(os.path.dirname(TRANSFER_FILE), exist_ok=True)
    psbt.save_psbt_to_file(TRANSFER_FILE, metadata)
    print(f"\n Saved to transfer file: {TRANSFER_FILE}")

def load_psbt_from_transfer_file():
    """Load PSBT from the shared transfer file"""
    if not os.path.exists(TRANSFER_FILE):
        return None, None
    return SilentPaymentPSBT.load_psbt_from_file(TRANSFER_FILE)

def prompt_for_transfer(psbt: SilentPaymentPSBT, direction: str):
    """
    Prompt user to transfer PSBT data

    Args:
        psbt: The PSBT to transfer
        direction: "to_device" or "to_coordinator"
    """
    psbt_base64 = psbt.encode()

    if direction == "to_device":
        target = "HARDWARE DEVICE"
        color = "\033[93m"  # Yellow
    else:
        target = "WALLET COORDINATOR"
        color = "\033[92m"  # Green

    reset_color = "\033[0m"

    print(f"\n{color}{'═' * 70}")
    print(f"AIR-GAP TRANSFER → {target}")
    print(f"{'═' * 70}{reset_color}")

    print("\nOption 1: COPY PSBT DATA")
    print("─" * 70)

    # Display full PSBT for easy copying
    print("═" * 70)
    print(" " * 20 + " COPY THIS PSBT DATA" + " " * 25)
    print("═" * 70)
    print(psbt_base64)
    print("═" * 70)
    print(f"Length: {len(psbt_base64)} characters")

    print("\nOption 2: READ FROM FILE")
    print("─" * 70)
    print("The other party can type: read")
    print(f"This will load from: {TRANSFER_FILE}")

def wait_for_user_input(prompt_text: str) -> str:
    """
    Wait for user input with a custom prompt

    Returns the user's input (stripped and lowercased)
    """
    print(f"\n{prompt_text}")
    user_input = input("→ ").strip().lower()
    return user_input

def print_header(step_num: int, title: str, role: str):
    """Print a formatted step header"""
    print("\n" + "=" * 70)
    print(f"STEP {step_num}: {title}")
    print(f"Role: {role}")
    print("=" * 70)

def print_separator():
    """Print a visual separator"""
    print("\n" + "─" * 70 + "\n")

def cleanup_transfer_file():
    """Clean up only the transfer file (used after successful completion)"""
    if os.path.exists(TRANSFER_FILE):
        os.remove(TRANSFER_FILE)

def reset_demo():
    """Reset the demo by removing transfer files and final transaction"""
    # Clean transfer file
    if os.path.exists(TRANSFER_FILE):
        os.remove(TRANSFER_FILE)

    # Clean final transaction file
    output_dir = os.path.dirname(TRANSFER_FILE)  # Same directory as transfer file
    final_tx_file = os.path.join(output_dir, "final_transaction.hex")
    if os.path.exists(final_tx_file):
        os.remove(final_tx_file)