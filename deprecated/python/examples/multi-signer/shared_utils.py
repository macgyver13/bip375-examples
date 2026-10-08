#!/usr/bin/env python3
"""
Shared utilities and data for multi-signer silent payment example

Contains common transaction inputs, outputs, keys and utility functions
shared across all three multi-signer scripts (alice_creates.py, bob_signs.py, charlie_finalizes.py).

This implements a realistic 3-of-3 multi-signer workflow where:
- Alice controls input 0
- Bob controls input 1
- Charlie controls input 2
"""

import sys
import os

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentAddress
from psbt_sp.crypto import Wallet, PublicKey, UTXO
import hashlib

# Shared test scenario data for 3-of-3 multi-signer silent payment

def compute_pubkey_hash(public_key: PublicKey) -> bytes:
    """Compute hash160 of public key for P2WPKH addresses"""
    pubkey_bytes = public_key.bytes  # compressed 33 bytes
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

def get_recipient_address():
    """
    Get the silent payment recipient address (same for all signers)

    In a real scenario, this would be provided by the recipient.
    """
    wallet = Wallet()
    return SilentPaymentAddress(
        scan_key=wallet.scan_pub,
        spend_key=wallet.spend_pub
    )

def get_transaction_inputs():
    """
    Get the transaction inputs for the multi-signer scenario

    3 inputs controlled by different parties:
    - Input 0: Alice's UTXO (100,000 sats)
    - Input 1: Bob's UTXO (150,000 sats)
    - Input 2: Charlie's UTXO (200,000 sats)

    Returns:
        List of UTXO objects with private keys set to None initially.
        Each signer will set their own private key when processing.
    """
    # Create deterministic wallets for each party
    alice_wallet = Wallet(seed="alice_multi_signer_silent_payment_test_seed")
    bob_wallet = Wallet(seed="bob_multi_signer_silent_payment_test_seed")
    charlie_wallet = Wallet(seed="charlie_multi_signer_silent_payment_test_seed")

    inputs = [
        # Alice's input (index 0)
        UTXO(
            txid="a1b2c3d4e5f6789012345678901234567890123456789012345678901234567a",
            vout=0,
            amount=100000,  # 100,000 sats
            script_pubkey="0014" + compute_pubkey_hash(alice_wallet.input_key_pair(0)[1]).hex(),
            private_key=None,  # Will be set by Alice
            sequence=0xfffffffe
        ),
        # Bob's input (index 1)
        UTXO(
            txid="b1c2d3e4f5f6789012345678901234567890123456789012345678901234567b",
            vout=1,
            amount=150000,  # 150,000 sats
            script_pubkey="0014" + compute_pubkey_hash(bob_wallet.input_key_pair(0)[1]).hex(),
            private_key=None,  # Will be set by Bob
            sequence=0xfffffffe
        ),
        # Charlie's input (index 2)
        UTXO(
            txid="c1d2e3f4f5f6789012345678901234567890123456789012345678901234567c",
            vout=2,
            amount=200000,  # 200,000 sats
            script_pubkey="0014" + compute_pubkey_hash(charlie_wallet.input_key_pair(0)[1]).hex(),
            private_key=None,  # Will be set by Charlie
            sequence=0xfffffffe
        )
    ]

    return inputs

def get_alice_private_key():
    """Get Alice's private key for her controlled input"""
    alice_wallet = Wallet(seed="alice_multi_signer_silent_payment_test_seed")
    return alice_wallet.input_key_pair(0)[0]

def get_bob_private_key():
    """Get Bob's private key for his controlled input"""
    bob_wallet = Wallet(seed="bob_multi_signer_silent_payment_test_seed")
    return bob_wallet.input_key_pair(0)[0]

def get_charlie_private_key():
    """Get Charlie's private key for his controlled input"""
    charlie_wallet = Wallet(seed="charlie_multi_signer_silent_payment_test_seed")
    return charlie_wallet.input_key_pair(0)[0]

def get_transaction_outputs():
    """
    Get the transaction outputs for the multi-signer scenario

    2 outputs:
    - Output 0: Change output (100,000 sats to a regular P2WPKH address)
    - Output 1: Silent payment output (340,000 sats = 450,000 total input - 100,000 change - 10,000 fee)

    Returns:
        List of output dictionaries
    """
    # Change output to a regular P2WPKH address
    change_wallet = Wallet(seed="change_address_for_multi_signer_test")

    outputs = [
        # Regular change output
        {
            "amount": 100000,  # 100,000 sats
            "script_pubkey": "0014" + compute_pubkey_hash(change_wallet.input_key_pair(0)[1]).hex()
        },
        # Silent payment output (amount will be calculated dynamically)
        {
            "amount": 340000,  # 340,000 sats (450,000 - 100,000 - 10,000 fee)
            "address": get_recipient_address()
        }
    ]

    return outputs

def calculate_silent_payment_amount():
    """
    Calculate the silent payment amount based on inputs and change

    Total inputs: 100,000 + 150,000 + 200,000 = 450,000 sats
    Change output: 100,000 sats
    Transaction fee: 10,000 sats
    Silent payment: 450,000 - 100,000 - 10,000 = 340,000 sats
    """
    inputs = get_transaction_inputs()
    total_input = sum(utxo.amount for utxo in inputs)
    change_amount = 100000
    fee = 10000

    silent_payment_amount = total_input - change_amount - fee
    return silent_payment_amount

def print_step_header(step_number, step_name, party_name):
    """Print a formatted step header for consistency"""
    print(f"\n{'='*60}")
    print(f"Step {step_number}: {step_name}")
    print(f"Party: {party_name}")
    print(f"{'='*60}")

def print_scenario_overview():
    """Print an overview of the multi-signer scenario"""
    print("Multi-Signer Silent Payment Scenario")
    print("=" * 50)
    print(" Transaction Overview:")
    print("   • 3 inputs controlled by different parties")
    print("   • 2 outputs: change + silent payment")
    print("   • Per-input ECDH approach (not global)")
    print("   • File-based handoffs between parties")
    print()

    inputs = get_transaction_inputs()
    outputs = get_transaction_outputs()

    print(" Inputs:")
    for i, utxo in enumerate(inputs):
        party = ["Alice", "Bob", "Charlie"][i]
        print(f"   Input {i} ({party}): {utxo.amount:,} sats")
        print(f"      TXID: {utxo.txid[:16]}...{utxo.txid[-8:]}")
        print(f"      VOUT: {utxo.vout}")

    total_input = sum(utxo.amount for utxo in inputs)
    print(f"   Total Input: {total_input:,} sats")
    print()

    print(" Outputs:")
    for i, output in enumerate(outputs):
        if "address" in output:
            print(f"   Output {i} (Silent Payment): {output['amount']:,} sats")
            addr = output["address"]
            print(f"      Scan Key:  {addr.scan_key.hex}")
            print(f"      Spend Key: {addr.spend_key.hex}")
        else:
            print(f"   Output {i} (Change): {output['amount']:,} sats")
            print(f"      Script: {output['script_pubkey']}")

    fee = total_input - sum(output["amount"] for output in outputs)
    print(f"   Transaction Fee: {fee:,} sats")
    print()

def print_file_status(filename, exists=None):
    """Print status of file existence"""
    if exists is None:
        exists = os.path.exists(filename)

    status = "✅ EXISTS" if exists else "❌ MISSING"
    print(f"   File: {filename} - {status}")

def verify_file_exists(filename, description):
    """Verify a file exists, raise error if not"""
    if not os.path.exists(filename):
        raise FileNotFoundError(f"{description} file not found: {filename}")
    print(f" Loading {description} from {filename}")

def print_ecdh_coverage_status(psbt):
    """Print current ECDH coverage status"""
    is_complete, inputs_with_ecdh = psbt.check_ecdh_coverage()
    total_inputs = len(psbt.input_maps) if psbt.input_maps else 0

    print(f"   ECDH Coverage: {len(inputs_with_ecdh)}/{total_inputs} inputs")
    print(f"   Covered inputs: {inputs_with_ecdh}")
    print(f"   Complete: {'✅ YES' if is_complete else '❌ NO'}")

def print_workflow_progress():
    """Print workflow progress based on existing files"""
    print("\n Workflow Progress:")

    files_to_check = [
        ("output/transfer.psbt", "Current Working PSBT"),
        ("output/final_transaction.hex", "Final Transaction")
    ]

    for filename, description in files_to_check:
        full_path = os.path.join(os.path.dirname(__file__), filename)
        exists = os.path.exists(full_path)
        status = "✅ COMPLETED" if exists else "⏳ PENDING"
        print(f"   {description}: {status}")

def reset_workflow():
    """
    Reset the workflow by removing all generated files

    This function is called automatically by Alice's script, but can also
    be called manually for cleanup between demonstrations.
    """
    import glob

    output_dir = os.path.join(os.path.dirname(__file__), "output")
    if not os.path.exists(output_dir):
        print("No output directory found - nothing to clean")
        return

    # Find all workflow files
    files_to_remove = (
        glob.glob(os.path.join(output_dir, "transfer.psbt")) +
        glob.glob(os.path.join(output_dir, "final_transaction.hex"))
    )

    if not files_to_remove:
        print("No workflow files found - already clean")
        return

    print(" Resetting workflow...")
    for file_path in files_to_remove:
        try:
            os.remove(file_path)
            print(f"   Removed {os.path.basename(file_path)}")
        except OSError as e:
            print(f"   Failed to remove {os.path.basename(file_path)}: {e}")

    print(" Workflow reset complete")

if __name__ == "__main__":
    # Demo the shared utilities
    print_scenario_overview()
    print_workflow_progress()