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
        mnemonic: BIP39 mnemonic phrase (12 or 24 words)
    
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

def get_transaction_inputs(wallet: Wallet):
    """
    Get the transaction inputs for the hardware signing scenario

    2 inputs controlled by the hardware wallet:
    - Input 0: 100,000 sats
    - Input 1: 200,000 sats
    
    Args:
        hw_wallet: Wallet instance for the hardware wallet

    Returns:
        List of UTXO objects with private keys set to None initially.
        Hardware device will set private keys during signing.
    """

    # Generate public keys for the inputs
    pubkey0 = wallet.input_key_pair(0)[1]
    pubkey1 = wallet.input_key_pair(1)[1]

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

def get_transaction_outputs(wallet: Wallet, recipient_address):
    """
    Get the transaction outputs for the hardware signing scenario

    2 outputs:
    - Output 0: Silent payment CHANGE output (50,000 sats with label=0)
    - Output 1: Silent payment output to recipient (245,000 sats)
    
    Args:
        wallet: Wallet instance for the hardware wallet
        recipient_address: SilentPaymentAddress for recipient

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

    outputs = [
        # Silent payment CHANGE output - returns to hardware wallet
        # Using label=0 (reserved for change per BIP 352)
        {
            "amount": 50000,  # 50,000 sats
            "address": SilentPaymentAddress(
                scan_key=wallet.scan_pub,
                spend_key=wallet.spend_pub,
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

def print_transaction_details(inputs, outputs, dnssec_proofs=None):
    """
    Print transaction details for manual validation

    User can verify these details match on both coordinator and hardware device.
    
    Args:
        inputs: List of UTXO objects
        outputs: List of output dictionaries
        dnssec_proofs: Optional dict mapping output_index -> proof_bytes (for DNS name display)
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
                
                # Display DNS contact info inline if available
                if dnssec_proofs and i in dnssec_proofs:
                    try:
                        dns_name, proof_data = decode_dnssec_proof(dnssec_proofs[i])
                        print(f"    Contact:    {dns_name}")
                        # Display proof bytes for verification
                        proof_hex = dnssec_proofs[i].hex()
                        print(f"    DNS Proof:  {proof_hex}")
                    except Exception:
                        print("    WARNING: DNSSEC proof decoding failed")
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

# =============================================================================
# DNSSEC Proof Utilities (BIP 353)
# =============================================================================

def create_dnssec_proof(dns_name: str) -> bytes:
    """
    Create a BIP 353 DNSSEC proof for a DNS name
    
    Format: <1-byte-length-prefixed BIP 353 human-readable name without the ₿ prefix>
            <RFC 9102-formatted DNSSEC Proof>
    
    Args:
        dns_name: DNS name (e.g., "donate@example.com")
    
    Returns:
        Encoded bytes ready for PSBT_OUT_DNSSEC_PROOF field
        
    Note:
        For demo purposes, this creates a mock DNSSEC proof.
        In production, this would contain real RFC 9102 DNSSEC proof data.
    """
    # Encode DNS name with 1-byte length prefix (BIP 353)
    dns_name_bytes = dns_name.encode('utf-8')
    if len(dns_name_bytes) > 255:
        raise ValueError(f"DNS name too long: {len(dns_name_bytes)} bytes (max 255)")
    
    # Create mock DNSSEC proof (RFC 9102 format would be used in production)
    # For demo, we'll create a simple mock proof with recognizable structure
    mock_proof = b'DNSSEC_PROOF_MOCK_DATA_' + hashlib.sha256(dns_name_bytes).digest()
    
    # Combine: <1-byte-length><dns_name><proof_data>
    proof_bytes = bytes([len(dns_name_bytes)]) + dns_name_bytes + mock_proof
    
    return proof_bytes

def decode_dnssec_proof(proof_bytes: bytes) -> tuple:
    """
    Decode a BIP 353 DNSSEC proof
    
    Args:
        proof_bytes: Encoded DNSSEC proof from PSBT_OUT_DNSSEC_PROOF field
    
    Returns:
        Tuple of (dns_name: str, proof_data: bytes)
        
    Raises:
        ValueError: If proof_bytes is malformed
    """
    if len(proof_bytes) < 1:
        raise ValueError("DNSSEC proof too short (missing length byte)")
    
    # Extract DNS name length (first byte)
    dns_name_length = proof_bytes[0]
    
    if len(proof_bytes) < 1 + dns_name_length:
        raise ValueError(f"DNSSEC proof too short (expected {1 + dns_name_length} bytes minimum)")
    
    # Extract DNS name
    dns_name_bytes = proof_bytes[1:1 + dns_name_length]
    dns_name = dns_name_bytes.decode('utf-8')
    
    # Extract proof data (remainder)
    proof_data = proof_bytes[1 + dns_name_length:]
    
    return dns_name, proof_data

def print_dnssec_info(dns_name: str, proof_data: bytes):
    """
    Pretty-print DNSSEC information for user display
    
    Args:
        dns_name: Decoded DNS name
        proof_data: DNSSEC proof data
    """
    print(f"    DNS Name:   {dns_name}")
    print(f"    Proof Size: {len(proof_data)} bytes")
    if len(proof_data) > 0:
        # Show first few bytes of proof for verification
        proof_preview = proof_data[:32].hex() if len(proof_data) >= 32 else proof_data.hex()
        print(f"    Proof:      {proof_preview}{'...' if len(proof_data) > 32 else ''}")