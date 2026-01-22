#!/usr/bin/env python3
"""
PSBT Utility Functions

Helper functions for extracting and processing PSBT data.
"""

from typing import List, Optional, Dict
from .constants import PSBTKeyType
from secp256k1_374 import GE, G, FE
from .serialization import PSBTField
from .crypto import UTXO

# TODO: Add explicit is_p2wpkh(), is_p2pkh(), is_p2sh_p2wpkh() helpers
# TODO: Add extract other input types

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
        if field.key_type == PSBTKeyType.PSBT_IN_TAP_INTERNAL_KEY:
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
        if field.key_type == PSBTKeyType.PSBT_IN_BIP32_DERIVATION:
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
        if field.key_type == PSBTKeyType.PSBT_IN_PARTIAL_SIG:
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


def _input_fields_to_dict(input_fields: List[PSBTField]) -> Dict[PSBTKeyType, bytes]:
    """
    Convert list of PSBTField objects to a dictionary keyed by key type.

    Args:
        input_fields: List of PSBTField objects for an input

    Returns:
        Dictionary mapping key type to value data
    """
    result = {}
    for field in input_fields:
        # For fields with key_data, use value_data
        # For fields without key_data, concatenate key_data + value_data
        if field.key_data:
            result[field.key_type] = field.value_data
        else:
            result[field.key_type] = field.value_data
    return result


def check_ecdh_coverage(global_fields: List[PSBTField], input_maps: List[List[PSBTField]], output_maps: List[List[PSBTField]]) -> tuple[bool, List[int]]:
    """
    Check which inputs have ECDH shares and if coverage is complete

    Per BIP 375: Global ECDH shares are keyed by scan public key.
    Per BIP 352: Only eligible inputs (single-key inputs) need ECDH shares.

    Complete coverage requires either:
    - Global ECDH shares for ALL unique scan keys in outputs, OR
    - Per-input ECDH shares for ALL ELIGIBLE inputs

    Eligible inputs are those with a single extractable public key:
    - P2WPKH (Segwit v0)
    - P2TR (Taproot, Segwit v1)
    - P2PKH (legacy)
    - P2SH-P2WPKH (wrapped segwit)

    Ineligible inputs (skipped in coverage check):
    - P2SH multisig
    - Bare multisig
    - Any input with multiple public keys

    Args:
        global_fields: List of global PSBT fields
        input_maps: List of input field lists
        output_maps: List of output field lists

    Returns:
        Tuple of (is_complete, list_of_input_indices_with_ecdh)
    """
    from .inputs import validate_input_eligibility

    inputs_with_ecdh = []

    # Extract unique scan keys from outputs
    scan_keys = extract_scan_keys_from_outputs(output_maps)

    # Check for global ECDH shares per scan key
    global_ecdh_scan_keys = set()
    for field in global_fields:
        if field.key_type == PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE:
            # Key field contains the scan public key (33 bytes)
            if len(field.key_data) == 33:
                global_ecdh_scan_keys.add(field.key_data)

    # Check if all scan keys have global ECDH shares
    has_complete_global_ecdh = all(
        scan_key in global_ecdh_scan_keys
        for scan_key in scan_keys
    )

    # FIXME: ECDH coverage should consider sp outputs too
    if has_complete_global_ecdh and len(scan_keys) > 0:
        # Global ECDH covers all inputs (for all scan keys)
        inputs_with_ecdh = list(range(len(input_maps)))
        is_complete = True
    else:
        # Check per-input ECDH shares
        # Count only eligible inputs for coverage check
        eligible_input_count = 0

        for i, input_fields in enumerate(input_maps):
            # Convert input fields to dict format for validation
            input_fields_dict = _input_fields_to_dict(input_fields)

            # Check if this input is eligible for silent payment derivation
            is_eligible, _ = validate_input_eligibility(input_fields_dict, i)

            if is_eligible:
                eligible_input_count += 1

                # Check if this eligible input has ECDH share
                has_input_ecdh = any(
                    field.key_type == PSBTKeyType.PSBT_IN_SP_ECDH_SHARE
                    for field in input_fields
                )
                if has_input_ecdh:
                    inputs_with_ecdh.append(i)

        # Complete if all ELIGIBLE inputs have ECDH shares
        is_complete = len(inputs_with_ecdh) == eligible_input_count

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
            if field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                if len(field.value_data) == 66:  # 33 + 33 bytes
                    scan_key_bytes = field.value_data[:33]
                    if scan_key_bytes not in scan_keys:
                        scan_keys.append(scan_key_bytes)

    return scan_keys


def extract_inputs_from_psbt(psbt) -> List[UTXO]:
    """
    Extract input details from PSBT fields and return as UTXO objects
    
    This function is designed for hardware wallets to independently verify
    transaction details from the PSBT without relying on coordinator logic.
    
    Parses PSBT fields to extract:
    - txid: from PSBT_IN_PREVIOUS_TXID
    - vout: from PSBT_IN_OUTPUT_INDEX
    - amount: from PSBT_IN_WITNESS_UTXO
    - script_pubkey: from PSBT_IN_WITNESS_UTXO
    - sequence: from PSBT_IN_SEQUENCE
    
    Args:
        psbt: SilentPaymentPSBT instance
    
    Returns:
        List of UTXO objects (without private_key set - hardware device will set these)
    
    Raises:
        ValueError: If required PSBT fields are missing or malformed
    """
    import struct
    
    inputs = []
    
    for input_index, input_fields in enumerate(psbt.input_maps):
        # Extract required fields
        txid = None
        vout = None
        amount = None
        script_pubkey = None
        sequence = 0xfffffffe  # Default sequence
        
        for field in input_fields:
            if field.key_type == PSBTKeyType.PSBT_IN_PREVIOUS_TXID:
                if len(field.value_data) == 32:
                    # Reverse for display (Bitcoin uses little-endian internally)
                    txid = field.value_data[::-1].hex()
            
            elif field.key_type == PSBTKeyType.PSBT_IN_OUTPUT_INDEX:
                if len(field.value_data) == 4:
                    vout = struct.unpack('<I', field.value_data)[0]
            
            elif field.key_type == PSBTKeyType.PSBT_IN_WITNESS_UTXO:
                # Format: 8-byte amount + compact_size script_len + script
                if len(field.value_data) >= 9:
                    amount = struct.unpack('<Q', field.value_data[:8])[0]
                    script_len = field.value_data[8]
                    if len(field.value_data) >= 9 + script_len:
                        script_pubkey = field.value_data[9:9+script_len].hex()
            
            elif field.key_type == PSBTKeyType.PSBT_IN_SEQUENCE:
                if len(field.value_data) == 4:
                    sequence = struct.unpack('<I', field.value_data)[0]
        
        # Validate required fields
        if txid is None:
            raise ValueError(f"Input {input_index}: Missing PSBT_IN_PREVIOUS_TXID")
        if vout is None:
            raise ValueError(f"Input {input_index}: Missing PSBT_IN_OUTPUT_INDEX")
        if amount is None:
            raise ValueError(f"Input {input_index}: Missing PSBT_IN_WITNESS_UTXO")
        if script_pubkey is None:
            raise ValueError(f"Input {input_index}: Missing scriptPubKey in PSBT_IN_WITNESS_UTXO")
        
        # Create UTXO object (without private key - hardware device will set it)
        utxo = UTXO(
            txid=txid,
            vout=vout,
            amount=amount,
            script_pubkey=script_pubkey,
            private_key=None,  # Hardware device will set this
            sequence=sequence
        )
        
        inputs.append(utxo)
    
    return inputs


def extract_output_details_from_psbt(psbt) -> List[dict]:
    """
    Extract output details from PSBT fields
    
    This function is designed for hardware wallets to independently verify
    transaction details from the PSBT without relying on coordinator logic.
    
    Returns list of dicts with:
    - amount: output amount (from PSBT_OUT_AMOUNT)
    - address: SilentPaymentAddress (from PSBT_OUT_SP_V0_INFO) if present
    - label: optional label (from PSBT_OUT_SP_V0_LABEL) if present
    - script_pubkey: scriptPubKey hex (from PSBT_OUT_SCRIPT) for regular outputs
    
    Args:
        psbt: SilentPaymentPSBT instance
    
    Returns:
        List of output dicts matching the format expected by print_transaction_details()
    
    Raises:
        ValueError: If required PSBT fields are missing or malformed
    """
    import struct
    from .psbt import SilentPaymentAddress
    from .crypto import PublicKey
    from secp256k1_374 import GE
    
    outputs = []
    
    for output_index, output_fields in enumerate(psbt.output_maps):
        # Extract fields
        amount = None
        sp_info = None
        label = None
        script_pubkey = None
        
        for field in output_fields:
            if field.key_type == PSBTKeyType.PSBT_OUT_AMOUNT:
                if len(field.value_data) == 8:
                    amount = struct.unpack('<Q', field.value_data)[0]
            
            elif field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                # Format: 33-byte scan key + 33-byte spend key
                if len(field.value_data) == 66:
                    scan_key_bytes = field.value_data[:33]
                    spend_key_bytes = field.value_data[33:]
                    
                    scan_key = PublicKey(GE.from_bytes(scan_key_bytes))
                    spend_key = PublicKey(GE.from_bytes(spend_key_bytes))
                    
                    sp_info = (scan_key, spend_key)
            
            elif field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_LABEL:
                if len(field.value_data) == 4:
                    label = struct.unpack('<I', field.value_data)[0]
            
            elif field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT:
                script_pubkey = field.value_data.hex()
        
        # Validate required fields
        if amount is None:
            raise ValueError(f"Output {output_index}: Missing PSBT_OUT_AMOUNT")
        
        # Build output dict
        output_dict = {"amount": amount}
        
        if sp_info:
            # Silent payment output
            scan_key, spend_key = sp_info
            output_dict["address"] = SilentPaymentAddress(
                scan_key=scan_key,
                spend_key=spend_key,
                label=label
            )
        elif script_pubkey:
            # Regular output
            output_dict["script_pubkey"] = script_pubkey
        else:
            # Output has neither SP info nor script - might be pending computation
            # This is valid during PSBT construction, just note it
            pass
        
        outputs.append(output_dict)
    
    return outputs


def extract_bip32_derivations_from_psbt(psbt) -> List[Optional[dict]]:
    """
    Extract BIP32 derivation paths from PSBT inputs
    
    Parses PSBT_IN_BIP32_DERIVATION fields to get the exact derivation path
    for each input. This allows the hardware device to derive the correct
    private key regardless of whether the input uses external addresses,
    change addresses, or any other BIP32 path.
    
    Args:
        psbt: SilentPaymentPSBT object
        
    Returns:
        List of dicts (one per input), each containing:
        - 'public_key': bytes (33 bytes compressed public key)
        - 'fingerprint': bytes (4 bytes master key fingerprint)
        - 'path': str (e.g., "m/84'/0'/0'/1/1")
        
        Returns None for inputs without BIP32 derivation info
    """
    import struct
    
    derivations = []
    
    for input_idx, input_fields in enumerate(psbt.input_maps):
        derivation_info = None
        
        # Look for PSBT_IN_BIP32_DERIVATION field
        for field in input_fields:
            if field.key_type == PSBTKeyType.PSBT_IN_BIP32_DERIVATION:
                # Key data is the public key (33 bytes compressed)
                public_key = field.key_data
                
                # Value data format: <master_fingerprint (4 bytes)> <path_indices (4 bytes each)>
                if len(field.value_data) >= 4:
                    fingerprint = field.value_data[:4]
                    
                    # Parse derivation path indices
                    path_data = field.value_data[4:]
                    path_indices = []
                    
                    for i in range(0, len(path_data), 4):
                        if i + 4 <= len(path_data):
                            # Each index is 4 bytes, little-endian
                            index = struct.unpack('<I', path_data[i:i+4])[0]
                            
                            # Check if hardened (bit 31 set)
                            if index >= 0x80000000:
                                # Hardened derivation
                                path_indices.append(f"{index - 0x80000000}'")
                            else:
                                # Normal derivation
                                path_indices.append(str(index))
                    
                    # Construct path string
                    if path_indices:
                        path = "m/" + "/".join(path_indices)
                    else:
                        path = "m"
                    
                    derivation_info = {
                        'public_key': public_key,
                        'fingerprint': fingerprint,
                        'path': path
                    }
                    
                    # Only use the first BIP32 derivation found for this input
                    break
        
        derivations.append(derivation_info)
    
    return derivations


def extract_dnssec_proofs_from_outputs(output_maps: List[List[PSBTField]]) -> dict:
    """
    Extract DNSSEC proofs from PSBT outputs
    
    Parses PSBT_OUT_DNSSEC_PROOF fields to get DNS name verification data
    for outputs that have associated DNS names (BIP 353).
    
    Args:
        output_maps: List of output field lists from PSBT
        
    Returns:
        Dict mapping output_index -> proof_bytes
        
    Example:
        proofs = extract_dnssec_proofs_from_outputs(psbt.output_maps)
        if 1 in proofs:
            dns_name, proof_data = decode_dnssec_proof(proofs[1])
            print(f"Output 1 pays to: {dns_name}")
    """
    dnssec_proofs = {}
    
    for output_index, output_fields in enumerate(output_maps):
        for field in output_fields:
            if field.key_type == PSBTKeyType.PSBT_OUT_DNSSEC_PROOF:
                # Store the proof bytes for this output
                dnssec_proofs[output_index] = field.value_data
                # Only take the first DNSSEC proof per output
                break
    
    return dnssec_proofs

