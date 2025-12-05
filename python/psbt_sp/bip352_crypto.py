#!/usr/bin/env python3
"""
BIP 352 Silent Payments Cryptographic Utilities

Pure cryptographic functions for BIP 352 silent payments protocol.
These functions are independent of PSBT and can be used by wallets,
receivers, and other silent payment implementations.
"""

import hashlib
import struct
from typing import List, Tuple
from secp256k1_374 import GE, G


def compute_label_tweak(scan_privkey_bytes: bytes, label: int) -> int:
    """
    Compute BIP 352 label tweak for modifying spend key

    Formula: hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))

    Args:
        scan_privkey_bytes: Scan private key (32 bytes)
        label: Label integer (0 for change, > 0 for other purposes)

    Returns:
        Scalar for point multiplication to modify spend key
    """
    # BIP 352: ser_256(b_scan) || ser_32(m)
    label_bytes = struct.pack('<I', label)  # 4 bytes little-endian

    # Tagged hash: BIP0352/Label
    tag = b"BIP0352/Label"
    tag_hash = hashlib.sha256(tag).digest()

    # hash_BIP0352/Label(b_scan || m)
    tagged_input = tag_hash + tag_hash + scan_privkey_bytes + label_bytes
    tweak_hash = hashlib.sha256(tagged_input).digest()
    tweak_scalar = int.from_bytes(tweak_hash, 'big') % GE.ORDER

    return tweak_scalar


def compute_shared_secret_tweak(ecdh_shared_secret_bytes: bytes, k: int = 0) -> int:
    """
    Compute BIP 352 shared secret tweak for output derivation

    Formula: t_k = hash_BIP0352/SharedSecret(ecdh_shared_secret || ser_32(k))

    Args:
        ecdh_shared_secret_bytes: ECDH shared secret point (33 bytes compressed)
        k: Output index for this scan key (default 0)

    Returns:
        Scalar tweak for deriving output public key
    """
    k_bytes = k.to_bytes(4, 'big')  # 4 bytes big-endian

    # Tagged hash: BIP0352/SharedSecret
    tag_data = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag_data).digest()

    tagged_input = tag_hash + tag_hash + ecdh_shared_secret_bytes + k_bytes
    tweak_hash = hashlib.sha256(tagged_input).digest()
    tweak_int = int.from_bytes(tweak_hash, 'big') % GE.ORDER

    return tweak_int


def apply_label_to_spend_key(spend_key_point: GE, scan_privkey_bytes: bytes, label: int) -> GE:
    """
    Apply BIP 352 label to spend public key

    Formula: B_m = B_spend + hash_BIP0352/Label(b_scan || m) * G

    Args:
        spend_key_point: Base spend public key
        scan_privkey_bytes: Scan private key (32 bytes)
        label: Label integer

    Returns:
        Modified spend public key B_m
    """
    label_tweak = compute_label_tweak(scan_privkey_bytes, label)
    label_tweak_point = label_tweak * G
    return spend_key_point + label_tweak_point


def derive_silent_payment_output_pubkey(
    spend_key_point: GE,
    ecdh_shared_secret_bytes: bytes,
    k: int = 0
) -> GE:
    """
    Derive final output public key for silent payment

    Formula: P_k = B_m + t_k * G
    where t_k = hash_BIP0352/SharedSecret(ecdh_shared_secret || ser_32(k))

    Args:
        spend_key_point: Spend public key (possibly label-modified B_m)
        ecdh_shared_secret_bytes: ECDH shared secret (33 bytes compressed)
        k: Output index for this scan key

    Returns:
        Final output public key P_k
    """
    tweak_int = compute_shared_secret_tweak(ecdh_shared_secret_bytes, k)
    tweak_point = tweak_int * G
    return spend_key_point + tweak_point


def pubkey_to_p2wpkh_script(pubkey_point: GE) -> bytes:
    """
    Convert public key to P2WPKH script

    Args:
        pubkey_point: Public key point

    Returns:
        P2WPKH script: OP_0 <20-byte-pubkey-hash>
    """
    pubkey_bytes = pubkey_point.to_bytes_compressed()
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
    return b'\x00\x14' + pubkey_hash  # OP_0 + 20 bytes


def pubkey_to_p2tr_script(pubkey_point: GE) -> bytes:
    """
    Convert public key to P2TR (Taproot) script

    BIP 352 requires silent payment outputs to use P2TR (Taproot).
    
    Formula: OP_1 <32-byte-x-only-pubkey>
    
    Args:
        pubkey_point: Public key point

    Returns:
        P2TR script: OP_1 (0x51) + 32 bytes (x-only public key)
    """
    # Get x-only public key (32 bytes) - BIP 340/341
    pubkey_bytes = pubkey_point.to_bytes_compressed()
    x_only = pubkey_bytes[1:]  # Remove first byte (02/03 parity), keep 32-byte x coordinate
    return b'\x51\x20' + x_only  # OP_1 (0x51) + PUSH_32 (0x20) + 32 bytes

def compute_bip352_output_script(
    outpoints: List[Tuple[bytes, int]],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int = 0,
) -> bytes:
    """Compute BIP-352 silent payment output script"""
    # Find smallest outpoint lexicographically
    serialized_outpoints = [txid + struct.pack("<I", idx) for txid, idx in outpoints]
    smallest_outpoint = min(serialized_outpoints)

    # Compute input_hash = hash_BIP0352/Inputs(smallest_outpoint || A)
    tag_data = b"BIP0352/Inputs"
    tag_hash = hashlib.sha256(tag_data).digest()
    input_hash_preimage = tag_hash + tag_hash + smallest_outpoint + summed_pubkey_bytes
    input_hash_bytes = hashlib.sha256(input_hash_preimage).digest()
    input_hash = int.from_bytes(input_hash_bytes, "big")

    # Compute shared_secret = input_hash * ecdh_share
    ecdh_point = GE.from_bytes(ecdh_share_bytes)
    shared_secret_point = input_hash * ecdh_point
    shared_secret_bytes = shared_secret_point.to_bytes_compressed()

    # Compute t_k = hash_BIP0352/SharedSecret(shared_secret || k)
    tag_data = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag_data).digest()
    t_preimage = tag_hash + tag_hash + shared_secret_bytes + k.to_bytes(4, "big")
    t_k_bytes = hashlib.sha256(t_preimage).digest()
    t_k = int.from_bytes(t_k_bytes, "big")

    # Compute P_k = B_spend + t_k * G
    B_spend = GE.from_bytes(spend_pubkey_bytes)
    P_k = B_spend + (t_k * G)

    # Create P2TR script (x-only pubkey)
    x_only = P_k.to_bytes_compressed()[1:]  # Remove parity byte
    return bytes([0x51, 0x20]) + x_only