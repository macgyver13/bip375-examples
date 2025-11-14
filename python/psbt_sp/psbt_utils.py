#!/usr/bin/env python3
"""
PSBT Utility Functions

Helper functions for extracting and processing PSBT data.
"""

from typing import List, Optional
from .constants import PSBTFieldType
from secp256k1_374 import GE, G, FE
from .serialization import PSBTField
from .crypto import UTXO

# TODO: Add explicit is_p2wpkh(), is_p2pkh(), is_p2sh_p2wpkh() helpers
# TODO: Add extract other input types

def is_taproot_output(script_pubkey: bytes) -> bool:
    """
    Check if script_pubkey is a Taproot (Segwit v1) output
    
    Taproot format: 0x5120 || 32-byte x-only pubkey
    
    Args:
        script_pubkey: The scriptPubKey bytes to check
        
    Returns:
        True if this is a Taproot output, False otherwise
    """
    return len(script_pubkey) == 34 and script_pubkey[0] == 0x51 and script_pubkey[1] == 0x20


def extract_taproot_pubkey(input_fields: List[PSBTField]) -> Optional[GE]:
    """
    Extract Taproot internal public key from PSBT input fields.
    
    Looks for PSBT_IN_TAP_INTERNAL_KEY field and lifts the x-only key to a full point.
    
    Args:
        input_fields: List of PSBT fields for the input
        
    Returns:
        Lifted public key point, or None if field not found
    """
    for field in input_fields:
        if field.field_type == PSBTFieldType.PSBT_IN_TAP_INTERNAL_KEY:
            if len(field.value_data) == 32:
                # Lift x-only key to full point (assumes even y-coordinate per BIP340)
                x_coord = int.from_bytes(field.value_data, 'big')
                # Validate x-coordinate is in valid range (must be < field prime)
                if x_coord >= FE.SIZE:
                    return None
                try:
                    return GE.lift_x(x_coord)
                except Exception:
                    return None
    return None


def extract_input_pubkey(input_fields: List[PSBTField], inputs: List[UTXO] = None, input_index: int = None) -> Optional[GE]:
    """
    Extract public key for a specific input from PSBT fields

    Priority order (per BIP174 best practices):
    1. PSBT_IN_BIP32_DERIVATION (preferred - standard way, hardware wallet compatible)
    2. PSBT_IN_TAP_INTERNAL_KEY (for Taproot inputs)
    3. PSBT_IN_PARTIAL_SIG (public key is the key field)
    4. Derive from private key (fallback for reference implementation)

    Args:
        input_fields: List of PSBT fields for the input
        inputs: Optional list of UTXO objects (for fallback extraction from private key)
        input_index: Optional input index (required if using inputs for fallback)

    Returns:
        Public key point, or None if not found
    """
    # Method 1: Extract from BIP32 derivation field (HIGHEST PRIORITY)
    # This is the standard BIP174 way and supports hardware wallets
    for field in input_fields:
        if field.field_type == PSBTFieldType.PSBT_IN_BIP32_DERIVATION:
            try:
                # BIP32 derivation format: key is 33-byte compressed pubkey
                # value is <4-byte fingerprint><32-bit path elements> or empty for privacy
                if len(field.key_data) == 33:
                    return GE.from_bytes(field.key_data)
            except Exception:
                continue

    # Method 2: Extract from Taproot internal key (for Taproot inputs)
    # This handles key path spending for Taproot (Segwit v1)
    taproot_pubkey = extract_taproot_pubkey(input_fields)
    if taproot_pubkey is not None:
        return taproot_pubkey

    # Method 3: Extract from partial signature field
    # Public key is in the key field of PSBT_IN_PARTIAL_SIG
    for field in input_fields:
        if field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG:
            try:
                if len(field.key_data) == 33:
                    return GE.from_bytes(field.key_data)
            except Exception:
                continue

    # Method 3: Derive from private key (FALLBACK - reference implementation only)
    # This should NOT be used in production hardware wallet flows
    if inputs and input_index is not None and input_index < len(inputs):
        utxo = inputs[input_index]
        if hasattr(utxo, 'private_key') and utxo.private_key is not None:
            try:
                input_private_key_int = int(utxo.private_key)
                input_public_key_point = input_private_key_int * G
                return input_public_key_point
            except Exception:
                pass

    return None


def extract_combined_input_pubkeys(input_maps: List[List[PSBTField]], inputs: List[UTXO] = None) -> Optional[GE]:
    """
    Extract and combine all input public keys for global DLEQ verification

    Args:
        input_maps: List of input field lists
        inputs: Optional list of UTXO objects (for fallback extraction)

    Returns:
        Combined public key point (sum of all input pubkeys), or None if extraction fails
    """
    A_combined = None

    for input_index, input_fields in enumerate(input_maps):
        pubkey = extract_input_pubkey(input_fields, inputs, input_index)

        if pubkey is None:
            return None

        if A_combined is None:
            A_combined = pubkey
        else:
            A_combined = A_combined + pubkey

    return A_combined


def check_ecdh_coverage(global_fields: List[PSBTField], input_maps: List[List[PSBTField]]) -> tuple[bool, List[int]]:
    """
    Check which inputs have ECDH shares and if coverage is complete

    Args:
        global_fields: List of global PSBT fields
        input_maps: List of input field lists

    Returns:
        Tuple of (is_complete, list_of_input_indices_with_ecdh)
    """
    inputs_with_ecdh = []

    # Check for global ECDH shares (covers all inputs if present)
    has_global_ecdh = any(
        field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE
        for field in global_fields
    )

    if has_global_ecdh:
        # Global ECDH covers all inputs
        inputs_with_ecdh = list(range(len(input_maps)))
        is_complete = True
    else:
        # Check per-input ECDH shares
        for i, input_fields in enumerate(input_maps):
            has_input_ecdh = any(
                field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE
                for field in input_fields
            )
            if has_input_ecdh:
                inputs_with_ecdh.append(i)

        # Complete if all inputs have ECDH shares
        is_complete = len(inputs_with_ecdh) == len(input_maps)

    return is_complete, inputs_with_ecdh


def extract_scan_keys_from_outputs(output_maps: List[List[PSBTField]]) -> List[bytes]:
    """
    Extract unique scan keys from silent payment outputs

    Args:
        output_maps: List of output field lists

    Returns:
        List of unique scan key bytes (33 bytes each)
    """
    scan_keys = []

    for output_fields in output_maps:
        for field in output_fields:
            if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                if len(field.value_data) == 66:  # 33 + 33 bytes
                    scan_key_bytes = field.value_data[:33]
                    if scan_key_bytes not in scan_keys:
                        scan_keys.append(scan_key_bytes)

    return scan_keys
