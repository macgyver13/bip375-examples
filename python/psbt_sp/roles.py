#!/usr/bin/env python3
"""
BIP 174/370/375 PSBT Role-Based Classes

Implements the distinct roles defined in Bitcoin PSBT specifications:
- Creator: Creates the initial PSBT structure
- Constructor: Adds inputs and outputs
- Updater: Adds BIP32 derivation info for hardware wallet compatibility
- Signer: Computes ECDH shares, generates DLEQ proofs, and signs inputs
- Input Finalizer: Computes final output scripts for silent payments
- Extractor: Extracts final Bitcoin transaction from completed PSBT
"""

import struct
import hashlib
from typing import List, Dict, Optional, Tuple
from .constants import PSBTFieldType
from secp256k1_374 import GE, G
from .serialization import PSBTField
from .crypto import Wallet, PublicKey, UTXO, sign_p2wpkh_input
from .bip352_crypto import (
    apply_label_to_spend_key,
    derive_silent_payment_output_pubkey,
    pubkey_to_p2tr_script
)
from dleq_374 import dleq_generate_proof


class PSBTCreator:
    """
    Creator Role: Initializes PSBT with base fields

    Responsibilities:
    - Create PSBT v2 global fields (version, input/output counts, modifiable flags)
    """

    @staticmethod
    def create_base_psbt(num_inputs: int, num_outputs: int) -> Tuple[List[PSBTField], List[List[PSBTField]], List[List[PSBTField]]]:
        """
        Create PSBT v2 base structure with required global fields

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Total number of outputs (regular + silent payment)

        Returns:
            Tuple of (global_fields, empty input_maps, empty output_maps)
        """
        global_fields = []

        # PSBT v2 requires these global fields
        global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_VERSION, b'', struct.pack('<I', 2)))  # PSBT format version
        global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_TX_VERSION, b'', struct.pack('<I', 2)))
        global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b'', struct.pack('<B', num_inputs)))
        global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'', struct.pack('<B', num_outputs)))
        global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE, b'', struct.pack('<B', 0x03)))  # Inputs and outputs modifiable
        # Omit optional PSBT_GLOBAL_FALLBACK_LOCKTIME

        # Initialize empty input and output maps
        input_maps = [[] for _ in range(num_inputs)]
        output_maps = [[] for _ in range(num_outputs)]

        return global_fields, input_maps, output_maps


class PSBTConstructor:
    """
    Constructor Role: Adds transaction inputs and outputs to PSBT

    Responsibilities:
    - Add input information (previous txid, vout, witness UTXO, sequence)
    - Add output information (amount, script or silent payment address)
    - Validate Segwit version restrictions per BIP 375
    """

    @staticmethod
    def _get_segwit_version(script_pubkey: bytes) -> Optional[int]:
        """
        Extract segwit version from script_pubkey

        Args:
            script_pubkey: Script public key bytes

        Returns:
            Segwit version (0, 1, 2, ..., 16) or None if not segwit
        """
        if len(script_pubkey) < 2:
            return None
        
        # Segwit scriptPubkey format: <version> <program>
        # Version byte: OP_0 (0x00) or OP_1..OP_16 (0x51..0x60)
        version_byte = script_pubkey[0]
        
        if version_byte == 0x00:
            # Segwit v0 (P2WPKH or P2WSH)
            return 0
        elif 0x51 <= version_byte <= 0x60:
            # Segwit v1-v16 (Taproot = v1)
            return version_byte - 0x50
        else:
            # Not segwit (P2PKH, P2SH, etc.)
            return None

    @staticmethod
    def _check_segwit_version_restrictions(
        input_maps: List[List[PSBTField]], 
        output_maps: List[List[PSBTField]]
    ) -> None:
        """
        Validate BIP 375 Segwit version restrictions
        
        BIP 375: Cannot mix inputs spending Segwit v>1 with silent payment outputs
        
        Args:
            input_maps: List of input field lists
            output_maps: List of output field lists
            
        Raises:
            ValueError: If Segwit version restrictions are violated
        """
        # Check if any output is a silent payment
        has_silent_payment_output = False
        for output_idx, output_fields in enumerate(output_maps):
            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                    has_silent_payment_output = True
                    break
            if has_silent_payment_output:
                break
        
        if not has_silent_payment_output:
            # No silent payment outputs, no restriction applies
            return
        
        # Check each input for Segwit version > 1
        for input_idx, input_fields in enumerate(input_maps):
            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_WITNESS_UTXO:
                    # Parse witness UTXO to extract script_pubkey
                    if len(field.value_data) < 9:
                        continue
                    
                    # Format: <8-byte amount> <1-byte script length> <script>
                    script_len = field.value_data[8]
                    if len(field.value_data) < 9 + script_len:
                        continue
                    
                    script_pubkey = field.value_data[9:9 + script_len]
                    segwit_version = PSBTConstructor._get_segwit_version(script_pubkey)
                    
                    if segwit_version is not None and segwit_version > 1:
                        raise ValueError(
                            f"BIP 375 validation error: Input {input_idx} spends Segwit v{segwit_version} "
                            f"output, which cannot be mixed with silent payment outputs. "
                            f"Silent payments only support Segwit v0 (P2WPKH/P2WSH) and v1 (Taproot) inputs."
                        )

    @staticmethod
    def add_inputs(input_maps: List[List[PSBTField]], inputs: List) -> None:
        """
        Add input information to PSBT

        Args:
            input_maps: List of input field lists (modified in-place)
            inputs: List of input objects (UTXO dataclass) or dictionaries with txid, vout, amount, script_pubkey, sequence
        """
        for i, inp in enumerate(inputs):
            if i >= len(input_maps):
                input_maps.append([])

            input_fields = input_maps[i]

            # Handle both UTXO objects and dict inputs
            if hasattr(inp, 'txid'):
                # UTXO object
                txid = bytes.fromhex(inp.txid) if isinstance(inp.txid, str) else inp.txid
                vout = inp.vout
                amount = inp.amount
                script_pubkey = bytes.fromhex(inp.script_pubkey) if isinstance(inp.script_pubkey, str) else inp.script_pubkey
                sequence = getattr(inp, 'sequence', 0xfffffffe)
            else:
                # Dictionary input
                txid = bytes.fromhex(inp['txid']) if isinstance(inp['txid'], str) else inp['txid']
                vout = inp['vout']
                amount = inp['amount']
                script_pubkey = bytes.fromhex(inp['script_pubkey']) if isinstance(inp['script_pubkey'], str) else inp['script_pubkey']
                sequence = inp.get('sequence', 0xfffffffe)

            # Add PSBT_IN_PREVIOUS_TXID
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_PREVIOUS_TXID, b'', txid))

            # Add PSBT_IN_OUTPUT_INDEX
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_OUTPUT_INDEX, b'', struct.pack('<I', vout)))

            # Add PSBT_IN_WITNESS_UTXO (P2WSH, P2TR, P2WPKH)
            witness_utxo = struct.pack('<Q', amount)  # 8-byte amount
            witness_utxo += struct.pack('<B', len(script_pubkey)) + script_pubkey
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_WITNESS_UTXO, b'', witness_utxo))

            # TODO: Add PSBT_IN_BIP32_DERIVATION
            # input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_BIP32_DERIVATION, <bytes pubkey>, <4 byte fingerprint> <32-bit little endian uint path element>))

            # TODO: Handle PSBT_IN_NON_WITNESS_UTXO (P2PKH, P2SH)

            # Add PSBT_IN_SEQUENCE
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_SEQUENCE, b'', struct.pack('<I', sequence)))

            # Add PSBT_IN_SIGHASH_TYPE (SIGHASH_ALL for silent payments)
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 1)))

            # Omit optional PSBT_IN_REQUIRED_TIME_LOCKTIME || PSBT_IN_REQUIRED_HEIGHT_LOCKTIME

    @staticmethod
    def add_outputs(output_maps: List[List[PSBTField]], outputs: List[dict]) -> None:
        """
        Add output information to PSBT

        Args:
            output_maps: List of output field lists (modified in-place)
            outputs: List of output dicts (can contain regular outputs or silent payment addresses)
        """
        for i, output in enumerate(outputs):
            if i >= len(output_maps):
                output_maps.append([])

            output_fields = output_maps[i]

            # Add PSBT_OUT_AMOUNT (always present)
            output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', output["amount"])))

            # Check if this is a silent payment output
            if "address" in output:
                # Silent payment output
                sp_address = output["address"]

                # Add PSBT_OUT_SP_V0_INFO (scan_key + spend_key)
                # TODO: This statement from SPEC needs to be resolved: 
                ## The PSBT_OUT_SP_V0_INFO should be serialized as a zero byte for the version, followed by the 33 bytes of the scan key and then 33 bytes for the spend key.
                sp_info = sp_address.scan_key.bytes + sp_address.spend_key.bytes
                output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info))

                # Add PSBT_OUT_SP_V0_LABEL if present
                # TODO: should change label always be added?
                if sp_address.label is not None:
                    output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SP_V0_LABEL, b'', struct.pack('<I', sp_address.label)))
            else:
                # Regular output - has script_pubkey
                script_pubkey = bytes.fromhex(output["script_pubkey"]) if isinstance(output["script_pubkey"], str) else output["script_pubkey"]
                output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SCRIPT, b'', script_pubkey))


class PSBTSigner:
    """
    Signer Role: Computes ECDH shares, generates DLEQ proofs, and signs inputs

    Responsibilities:
    - Compute ECDH shares for silent payment outputs
    - Generate DLEQ proofs proving correctness of ECDH computation
    - Verify DLEQ proofs from other signers
    - Sign transaction inputs with private keys
    """

    @staticmethod
    def add_ecdh_shares(
        global_fields: List[PSBTField],
        input_maps: List[List[PSBTField]],
        inputs: List[UTXO],
        scan_keys: List[PublicKey],
        use_global: bool = True
    ) -> None:
        """
        Add ECDH shares and DLEQ proofs for given UTXOs and scan keys

        Args:
            global_fields: List of global PSBT fields (modified in-place if use_global=True)
            input_maps: List of input field lists (modified in-place if use_global=False)
            inputs: List of UTXO objects, some may have private_key = None
            scan_keys: List of scan keys (PublicKey objects)
            use_global: If True, use global ECDH approach; if False, use per-input approach
        """
        from .psbt_utils import is_taproot_output
        
        # Only process inputs that have private keys
        spendable_inputs = [(i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None]

        if not spendable_inputs:
            return  # No inputs we can spend

        # Adjust private keys for Taproot inputs (need negation if odd y-coordinate)
        adjusted_privkeys = {}
        for index, utxo in spendable_inputs:
            privkey = int(utxo.private_key)
            # Check if this is a Taproot input
            if is_taproot_output(utxo.script_pubkey_bytes):
                # Compute original public key and adjust if needed
                pubkey = privkey * G
                # Check if y-coordinate is odd
                if int(pubkey.y) % 2 == 1:
                    # Negate the private key to match the even-y version
                    privkey = GE.ORDER - privkey
            adjusted_privkeys[index] = privkey

        if use_global:
            # Global ECDH approach - single entity controls all inputs
            combined_private_key = 0
            for index, utxo in spendable_inputs:
                combined_private_key += adjusted_privkeys[index]

            for scan_key in scan_keys:
                # Compute ECDH: combined_private_key * scan_key
                ecdh_result_point = combined_private_key * scan_key
                ecdh_result_bytes = ecdh_result_point.to_bytes_compressed()

                # Generate DLEQ proof
                dleq_proof = dleq_generate_proof(
                    a=combined_private_key,
                    B=scan_key,
                    r=Wallet.random_bytes()
                )

                if dleq_proof is None:
                    raise ValueError("Failed to generate DLEQ proof")

                # Add global ECDH share field
                global_fields.append(PSBTField(
                    PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE,
                    scan_key.bytes,
                    ecdh_result_bytes
                ))

                # Add global DLEQ proof field
                global_fields.append(PSBTField(
                    PSBTFieldType.PSBT_GLOBAL_SP_DLEQ,
                    scan_key.bytes,
                    dleq_proof
                ))
        else:
            # Per-input ECDH approach - each input contributes separate shares
            for input_index, utxo in spendable_inputs:
                privkey = adjusted_privkeys[input_index]
                for scan_key in scan_keys:
                    # Compute ECDH: private_key * scan_key
                    ecdh_result_point = privkey * scan_key
                    ecdh_result_bytes = ecdh_result_point.to_bytes_compressed()

                    # Generate DLEQ proof
                    dleq_proof = dleq_generate_proof(
                        a=privkey,
                        B=scan_key,
                        r=Wallet.random_bytes()
                    )

                    if dleq_proof is None:
                        raise ValueError(f"Failed to generate DLEQ proof for input {input_index}")

                    # Add per-input ECDH share field
                    input_maps[input_index].append(PSBTField(
                        PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                        scan_key.bytes,
                        ecdh_result_bytes
                    ))

                    # Add per-input DLEQ proof field
                    input_maps[input_index].append(PSBTField(
                        PSBTFieldType.PSBT_IN_SP_DLEQ,
                        scan_key.bytes,
                        dleq_proof
                    ))

    @staticmethod
    def sign_inputs(
        input_maps: List[List[PSBTField]],
        output_maps: List[List[PSBTField]],
        inputs: List[UTXO]
    ) -> int:
        """
        Sign transaction inputs using private keys from UTXOs

        Args:
            input_maps: List of input field lists (modified in-place)
            output_maps: List of output field lists (for signature generation)
            inputs: List of UTXO objects with private keys

        Returns:
            Number of inputs signed

        Raises:
            ValueError: If no inputs can be signed
        """
        # Only sign inputs that have private keys
        spendable_inputs = [(i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None]

        if not spendable_inputs:
            raise ValueError("No spendable inputs found (no private keys provided)")

        # Prepare transaction data for signing
        transaction_data = {
            'inputs': inputs,
            'outputs': []
        }

        # Extract outputs from PSBT output maps
        for output_fields in output_maps:
            output_dict = {}
            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_AMOUNT:
                    output_dict['amount'] = struct.unpack('<Q', field.value_data)[0]
                elif field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT:
                    output_dict['script_pubkey'] = field.value_data.hex()
            transaction_data['outputs'].append(output_dict)

        # Sign each spendable input
        signatures_added = 0
        for input_index, utxo in spendable_inputs:
            try:
                # Extract public key hash from P2WPKH script_pubkey
                script_bytes = utxo.script_pubkey_bytes
                if len(script_bytes) != 22 or script_bytes[:2] != b'\x00\x14':
                    print(f"⚠️  Skipping input {input_index}: Not P2WPKH")
                    continue

                pubkey_hash = script_bytes[2:]

                # Generate signature
                signature = sign_p2wpkh_input(
                    private_key=int(utxo.private_key),
                    transaction_data=transaction_data,
                    input_index=input_index,
                    pubkey_hash=pubkey_hash,
                    amount=utxo.amount
                )

                # Add partial signature to PSBT input
                public_key_point = int(utxo.private_key) * G
                public_key_compressed = public_key_point.to_bytes_compressed()

                input_maps[input_index].append(PSBTField(
                    PSBTFieldType.PSBT_IN_PARTIAL_SIG,
                    public_key_compressed,
                    signature
                ))

                signatures_added += 1
                print(f" Signed input {input_index}")

            except Exception as e:
                print(f"❌ Failed to sign input {input_index}: {e}")
                raise

        return signatures_added

    @staticmethod
    def add_ecdh_shares_for_inputs(
        input_maps: List[List[PSBTField]],
        inputs: List[UTXO],
        input_indices: List[int],
        scan_keys: List[PublicKey]
    ) -> None:
        """
        Add ECDH shares and DLEQ proofs for specific input indices only (per-input approach)

        Args:
            input_maps: List of input field lists (modified in-place)
            inputs: List of UTXO objects
            input_indices: List of input indices to process
            scan_keys: List of scan keys (PublicKey objects)

        Raises:
            ValueError: If input index is out of range or missing private key
        """
        for input_index in input_indices:
            if input_index >= len(inputs):
                raise ValueError(f"Input index {input_index} out of range")

            utxo = inputs[input_index]
            if utxo.private_key is None:
                raise ValueError(f"No private key for input {input_index}")

            # Ensure we have enough input maps
            while len(input_maps) <= input_index:
                input_maps.append([])

            for scan_key in scan_keys:
                # Compute ECDH: private_key * scan_key
                ecdh_result_point = utxo.private_key * scan_key
                ecdh_result_bytes = ecdh_result_point.to_bytes_compressed()

                # Generate DLEQ proof
                dleq_proof = dleq_generate_proof(
                    a=utxo.private_key,
                    B=scan_key,
                    r=Wallet.random_bytes()
                )

                if dleq_proof is None:
                    raise ValueError(f"Failed to generate DLEQ proof for input {input_index}")

                # Add per-input ECDH share field
                input_maps[input_index].append(PSBTField(
                    PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                    scan_key.bytes,
                    ecdh_result_bytes
                ))

                # Add per-input DLEQ proof field
                input_maps[input_index].append(PSBTField(
                    PSBTFieldType.PSBT_IN_SP_DLEQ,
                    scan_key.bytes,
                    dleq_proof
                ))

    @staticmethod
    def sign_specific_inputs(
        input_maps: List[List[PSBTField]],
        output_maps: List[List[PSBTField]],
        inputs: List[UTXO],
        input_indices: List[int]
    ) -> int:
        """
        Sign only the specified input indices

        Args:
            input_maps: List of input field lists (modified in-place)
            output_maps: List of output field lists (for signature generation)
            inputs: List of UTXO objects with private keys
            input_indices: List of input indices to sign

        Returns:
            Number of inputs signed

        Raises:
            ValueError: If input index is out of range or missing private key
        """
        if not input_indices:
            return 0

        # Build transaction data for signing
        transaction_data = {
            'inputs': inputs,
            'outputs': []
        }

        # Extract outputs from PSBT output maps
        for output_fields in output_maps:
            output_dict = {}
            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_AMOUNT:
                    output_dict['amount'] = struct.unpack('<Q', field.value_data)[0]
                elif field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT:
                    output_dict['script_pubkey'] = field.value_data.hex()
            transaction_data['outputs'].append(output_dict)

        # Sign each specified input
        signatures_added = 0
        for input_index in input_indices:
            if input_index >= len(inputs):
                print(f"⚠️  Skipping input {input_index}: Index out of range")
                continue

            utxo = inputs[input_index]
            if utxo.private_key is None:
                print(f"⚠️  Skipping input {input_index}: No private key")
                continue

            try:
                # Extract public key hash from P2WPKH script_pubkey
                script_bytes = utxo.script_pubkey_bytes
                if len(script_bytes) != 22 or script_bytes[:2] != b'\x00\x14':
                    print(f"⚠️  Skipping input {input_index}: Not P2WPKH")
                    continue

                pubkey_hash = script_bytes[2:]

                # Generate signature
                signature = sign_p2wpkh_input(
                    private_key=int(utxo.private_key),
                    transaction_data=transaction_data,
                    input_index=input_index,
                    pubkey_hash=pubkey_hash,
                    amount=utxo.amount
                )

                # Add partial signature to PSBT input
                public_key_point = int(utxo.private_key) * G
                public_key_compressed = public_key_point.to_bytes_compressed()

                input_maps[input_index].append(PSBTField(
                    PSBTFieldType.PSBT_IN_PARTIAL_SIG,
                    public_key_compressed,
                    signature
                ))

                signatures_added += 1
                print(f" Signed input {input_index}")

            except Exception as e:
                print(f"❌ Failed to sign input {input_index}: {e}")
                raise

        return signatures_added


class PSBTInputFinalizer:
    """
    Input Finalizer Role: Computes output scripts for silent payments

    Responsibilities:
    - Collect and combine ECDH shares from all signers
    - Compute final output public keys using BIP 352 protocol
    - Generate P2TR scripts for silent payment outputs
    - Set TX_MODIFIABLE flags to False after computing scripts
    """

    @staticmethod
    def compute_output_scripts(
        global_fields: List[PSBTField],
        input_maps: List[List[PSBTField]],
        output_maps: List[List[PSBTField]],
        scan_privkeys: Optional[Dict[bytes, bytes]] = None
    ) -> int:
        """
        Compute output scripts for all silent payment addresses

        Args:
            global_fields: List of global PSBT fields (modified in-place to set non-modifiable flag)
            input_maps: List of input field lists (for collecting ECDH shares)
            output_maps: List of output field lists (modified in-place with scripts)
            scan_privkeys: Optional dict mapping scan_key_bytes -> scan_privkey_bytes
                          (required for computing label tweaks for change outputs)

        Returns:
            Number of output scripts computed

        Raises:
            ValueError: If ECDH shares are missing or invalid
        """
        # Collect ECDH shares - first try global, then per-input
        ecdh_shares = {}  # scan_key -> combined_ecdh_share

        # Check for global ECDH shares
        for field in global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE:
                scan_key = field.key_data
                ecdh_share = field.value_data
                if scan_key not in ecdh_shares:
                    ecdh_shares[scan_key] = PublicKey(GE.from_bytes(ecdh_share))
                else:
                    existing = ecdh_shares[scan_key]
                    new_share = PublicKey(GE.from_bytes(ecdh_share))
                    ecdh_shares[scan_key] = existing + new_share

        # Check for per-input ECDH shares and combine them
        for input_fields in input_maps:
            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE:
                    scan_key = field.key_data
                    ecdh_share = field.value_data
                    if scan_key not in ecdh_shares:
                        ecdh_shares[scan_key] = PublicKey(GE.from_bytes(ecdh_share))
                    else:
                        existing = ecdh_shares[scan_key]
                        new_share = PublicKey(GE.from_bytes(ecdh_share))
                        ecdh_shares[scan_key] = existing + new_share

        if not ecdh_shares:
            raise ValueError("No ECDH shares found in PSBT")

        print(f" Found ECDH shares for {len(ecdh_shares)} scan key(s)")

        # Process each silent payment output
        scripts_computed = 0
        for output_index, output_fields in enumerate(output_maps):
            sp_info_field = None
            sp_label_field = None

            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                    sp_info_field = field
                elif field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_LABEL:
                    sp_label_field = field

            if sp_info_field is None:
                continue  # Not a silent payment output

            # Extract scan and spend keys
            if len(sp_info_field.value_data) != 66:
                raise ValueError(f"Output {output_index} SP_V0_INFO has invalid length")

            scan_key_bytes = sp_info_field.value_data[:33]
            spend_key_bytes = sp_info_field.value_data[33:]

            # Find matching ECDH share
            if scan_key_bytes not in ecdh_shares:
                raise ValueError(f"Output {output_index} scan key not found in ECDH shares")

            ecdh_shared_secret_point = ecdh_shares[scan_key_bytes]
            spend_key_point = GE.from_bytes(spend_key_bytes)

            # Apply label if present
            if sp_label_field is not None:
                if len(sp_label_field.value_data) != 4:
                    raise ValueError(f"Output {output_index} label has invalid length")

                label = struct.unpack('<I', sp_label_field.value_data)[0]
                print(f" Output {output_index} has label={label}")

                if scan_privkeys and scan_key_bytes in scan_privkeys:
                    scan_privkey_bytes = scan_privkeys[scan_key_bytes]
                    spend_key_point = apply_label_to_spend_key(spend_key_point, scan_privkey_bytes, label)
                    print(f" Applied label tweak for label={label}")

            # Derive final output public key using BIP 352
            k = 0  # Output index (simplified - would need proper tracking in full implementation)
            final_pubkey_point = derive_silent_payment_output_pubkey(
                spend_key_point,
                ecdh_shared_secret_point.bytes,
                k
            )

            # Create P2TR (Taproot) script - BIP 352 requires P2TR for silent payments
            script_pubkey = pubkey_to_p2tr_script(final_pubkey_point)

            # Add PSBT_OUT_SCRIPT field
            output_fields.append(PSBTField(
                PSBTFieldType.PSBT_OUT_SCRIPT,
                b'',
                script_pubkey
            ))

            scripts_computed += 1
            print(f" Computed output script for output {output_index}")

        if scripts_computed == 0:
            raise ValueError("No silent payment outputs found to compute")

        # Set TX_MODIFIABLE flags to False
        PSBTInputFinalizer._set_non_modifiable(global_fields)

        return scripts_computed

    @staticmethod
    def _set_non_modifiable(global_fields: List[PSBTField]) -> None:
        """Set TX_MODIFIABLE flags to 0x00 (neither inputs nor outputs modifiable)"""
        for field in global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE:
                field.value_data = struct.pack('<B', 0x00)
                print("Set TX_MODIFIABLE flags to 0x00")
                return

        # Add if doesn't exist
        global_fields.append(PSBTField(
            PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE,
            b'',
            struct.pack('<B', 0x00)
        ))


class PSBTUpdater:
    """
    Updater Role: Adds metadata and derivation information to existing PSBT

    Responsibilities:
    - Add PSBT_IN_BIP32_DERIVATION for inputs (enables hardware wallets to extract public keys)
    - Add PSBT_OUT_BIP32_DERIVATION for change detection
    - Validate and enhance PSBT fields

    This role is essential for hardware wallet compatibility as it allows the hardware
    device to know which keys to use without exposing private keys in the PSBT.
    """

    @staticmethod
    def add_input_bip32_derivation(
        input_maps: List[List[PSBTField]],
        inputs: List[UTXO],
        derivation_paths: Optional[List[Dict]] = None
    ) -> int:
        """
        Add PSBT_IN_BIP32_DERIVATION fields for inputs

        This field allows hardware wallets and external signers to:
        1. Extract public keys without needing private keys in the PSBT
        2. Match public keys to their internal key derivation
        3. Derive the correct private key from their master seed

        Args:
            input_maps: List of input field lists (modified in-place)
            inputs: List of UTXO objects with public keys
            derivation_paths: Optional list of derivation info per input:
                [
                    {
                        "pubkey": bytes (33 bytes compressed),
                        "master_fingerprint": bytes (4 bytes) - optional,
                        "path": [0x80000054, 0x80000000, ...]  # BIP32 path - optional
                    },
                    ...
                ]
                If None, derives pubkey from UTXO private key and uses privacy mode.
                If dict has only "pubkey", uses privacy mode (empty derivation).
                If dict has all fields, includes full derivation path.

        Returns:
            Number of inputs with BIP32 derivation added

        Privacy modes:
        - Empty derivation (recommended): Only public key revealed, no path
        - Full derivation: Public key + master fingerprint + derivation path
        """
        fields_added = 0

        for i, inp in enumerate(inputs):
            if i >= len(input_maps):
                continue

            input_fields = input_maps[i]

            # Check if field already exists
            has_bip32_derivation = any(
                field.field_type == PSBTFieldType.PSBT_IN_BIP32_DERIVATION
                for field in input_fields
            )
            if has_bip32_derivation:
                continue  # Skip if already present

            # Determine public key and derivation info
            if derivation_paths and i < len(derivation_paths) and derivation_paths[i]:
                deriv_info = derivation_paths[i]

                # Get public key from derivation info
                if "pubkey" in deriv_info:
                    pubkey_bytes = deriv_info["pubkey"]
                else:
                    # Fall back to deriving from private key
                    if hasattr(inp, 'private_key') and inp.private_key is not None:
                        pubkey_point = int(inp.private_key) * G
                        pubkey_bytes = pubkey_point.to_bytes_compressed()
                    else:
                        continue  # Skip if no pubkey available

                # Build derivation value data
                if "master_fingerprint" in deriv_info and "path" in deriv_info:
                    # Full derivation mode: <4-byte fingerprint> <32-bit uint path elements>
                    value_data = deriv_info["master_fingerprint"]
                    for path_element in deriv_info["path"]:
                        value_data += struct.pack('<I', path_element)
                else:
                    # Privacy mode: empty derivation (only public key in key field)
                    value_data = b''

            else:
                # No derivation info provided - derive pubkey from private key and use privacy mode
                if hasattr(inp, 'private_key') and inp.private_key is not None:
                    pubkey_point = int(inp.private_key) * G
                    pubkey_bytes = pubkey_point.to_bytes_compressed()
                    value_data = b''  # Privacy mode
                else:
                    continue  # Skip if no way to get pubkey

            # Add PSBT_IN_BIP32_DERIVATION field
            input_fields.append(PSBTField(
                PSBTFieldType.PSBT_IN_BIP32_DERIVATION,
                pubkey_bytes,      # Key: 33-byte compressed public key
                value_data         # Value: fingerprint + path (or empty for privacy)
            ))
            fields_added += 1

        return fields_added

    @staticmethod
    def add_output_bip32_derivation(
        output_maps: List[List[PSBTField]],
        change_indices: List[int],
        derivation_info: Dict[int, Dict]
    ) -> int:
        """
        Add PSBT_OUT_BIP32_DERIVATION for change outputs

        Allows hardware wallets to verify that change outputs return to the user's wallet.

        Args:
            output_maps: List of output field lists (modified in-place)
            change_indices: List of output indices that are change
            derivation_info: Dict mapping output_index -> derivation_info
                {
                    output_index: {
                        "pubkey": bytes (33 bytes),  # For scan or spend key
                        "master_fingerprint": bytes (4 bytes) - optional,
                        "path": [0x80000054, ...]  # BIP32 path - optional
                    },
                    ...
                }

        Returns:
            Number of outputs with BIP32 derivation added

        Note: For silent payment outputs, you may need to add derivation for both
        scan and spend keys if both are derived from the same wallet.
        """
        fields_added = 0

        for output_index in change_indices:
            if output_index >= len(output_maps):
                continue

            if output_index not in derivation_info:
                continue

            output_fields = output_maps[output_index]
            deriv_info = derivation_info[output_index]

            # Get public key
            if "pubkey" not in deriv_info:
                continue

            pubkey_bytes = deriv_info["pubkey"]

            # Build derivation value
            if "master_fingerprint" in deriv_info and "path" in deriv_info:
                # Full derivation
                value_data = deriv_info["master_fingerprint"]
                for path_element in deriv_info["path"]:
                    value_data += struct.pack('<I', path_element)
            else:
                # Privacy mode
                value_data = b''

            # Add PSBT_OUT_BIP32_DERIVATION field
            output_fields.append(PSBTField(
                PSBTFieldType.PSBT_OUT_BIP32_DERIVATION,
                pubkey_bytes,
                value_data
            ))
            fields_added += 1

        return fields_added


class PSBTExtractor:
    """
    Transaction Extractor Role: Extracts finalized Bitcoin transaction from completed PSBT

    Responsibilities:
    - Verify PSBT completeness (all inputs signed, all outputs have scripts)
    - Extract and serialize the final Bitcoin transaction
    - Compute transaction ID
    - Optionally save transaction to file
    """

    @staticmethod
    def extract_transaction(
        global_fields: List[PSBTField],
        input_maps: List[List[PSBTField]],
        output_maps: List[List[PSBTField]]
    ) -> bytes:
        """
        Extract the final Bitcoin transaction from completed PSBT fields

        Args:
            global_fields: List of global PSBT fields
            input_maps: List of input field lists
            output_maps: List of output field lists

        Returns:
            Serialized transaction bytes

        Raises:
            ValueError: If PSBT is incomplete or invalid
        """
        # Verify all outputs have scripts
        for i, output_fields in enumerate(output_maps):
            has_script = any(field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT for field in output_fields)
            if not has_script:
                raise ValueError(f"Output {i} missing script - run compute_output_scripts() first")

        # Verify all inputs have signatures
        for i, input_fields in enumerate(input_maps):
            has_signature = any(field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG for field in input_fields)
            if not has_signature:
                raise ValueError(f"Input {i} missing signature - run sign_inputs() first")

        print(f"Extracting transaction with {len(input_maps)} inputs and {len(output_maps)} outputs")

        # Build transaction
        tx_data = b''

        # Extract version from PSBT_GLOBAL_TX_VERSION (default to 2 per BIP 370)
        version = 2
        for field in global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_TX_VERSION:
                version = struct.unpack('<I', field.value_data)[0]
                break

        tx_data += struct.pack('<I', version)

        # Segwit flag (0x00 0x01)
        tx_data += b'\x00\x01'

        # Input count (varint)
        tx_data += bytes([len(input_maps)])

        # Inputs
        for i, input_fields in enumerate(input_maps):
            input_dict = {field.field_type: field for field in input_fields}

            # Previous output (36 bytes)
            if PSBTFieldType.PSBT_IN_PREVIOUS_TXID in input_dict:
                txid = input_dict[PSBTFieldType.PSBT_IN_PREVIOUS_TXID].value_data
                tx_data += txid
            else:
                raise ValueError(f"Input {i} missing previous txid")

            if PSBTFieldType.PSBT_IN_OUTPUT_INDEX in input_dict:
                vout = input_dict[PSBTFieldType.PSBT_IN_OUTPUT_INDEX].value_data
                tx_data += vout
            else:
                raise ValueError(f"Input {i} missing output index")

            # ScriptSig (empty for witness inputs)
            tx_data += b'\x00'  # Empty scriptSig

            # Sequence (4 bytes)
            if PSBTFieldType.PSBT_IN_SEQUENCE in input_dict:
                sequence = input_dict[PSBTFieldType.PSBT_IN_SEQUENCE].value_data
                tx_data += sequence
            else:
                tx_data += b'\xfe\xff\xff\xff'  # Default sequence

        # Output count (varint)
        tx_data += bytes([len(output_maps)])

        # Outputs
        for i, output_fields in enumerate(output_maps):
            output_dict = {field.field_type: field for field in output_fields}

            # Amount (8 bytes, little-endian)
            if PSBTFieldType.PSBT_OUT_AMOUNT in output_dict:
                amount = output_dict[PSBTFieldType.PSBT_OUT_AMOUNT].value_data
                tx_data += amount
            else:
                raise ValueError(f"Output {i} missing amount")

            # Script
            if PSBTFieldType.PSBT_OUT_SCRIPT in output_dict:
                script = output_dict[PSBTFieldType.PSBT_OUT_SCRIPT].value_data
                tx_data += bytes([len(script)]) + script
            else:
                raise ValueError(f"Output {i} missing script")

        # Witness data
        for i, input_fields in enumerate(input_maps):
            input_dict = {field.field_type: field for field in input_fields}

            # For P2WPKH: witness = [signature, pubkey]
            witness_items = []

            # Find signature and pubkey
            signature = None
            pubkey = None

            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG:
                    signature = field.value_data
                    pubkey = field.key_data  # Public key is the key for partial sig
                    break

            if signature is None:
                raise ValueError(f"Input {i} missing witness signature")
            if pubkey is None:
                raise ValueError(f"Input {i} missing witness pubkey")

            witness_items = [signature, pubkey]

            # Write witness stack
            tx_data += bytes([len(witness_items)])  # Number of witness items
            for item in witness_items:
                tx_data += bytes([len(item)]) + item

        # Determine locktime per BIP 370 specification
        locktime = 0
        required_locktimes = []

        # Check inputs for required locktimes (PSBT_IN_REQUIRED_TIME_LOCKTIME or PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
        for input_fields in input_maps:
            for field in input_fields:
                if field.field_type in (PSBTFieldType.PSBT_IN_REQUIRED_TIME_LOCKTIME,
                                        PSBTFieldType.PSBT_IN_REQUIRED_HEIGHT_LOCKTIME):
                    required_locktimes.append(struct.unpack('<I', field.value_data)[0])

        if required_locktimes:
            # Use maximum of required locktimes if any inputs specify them
            locktime = max(required_locktimes)
        else:
            # Use fallback locktime from global fields (defaults to 0 if not present)
            for field in global_fields:
                if field.field_type == PSBTFieldType.PSBT_GLOBAL_FALLBACK_LOCKTIME:
                    locktime = struct.unpack('<I', field.value_data)[0]
                    break

        tx_data += struct.pack('<I', locktime)

        print(f" Transaction extracted ({len(tx_data)} bytes)")
        print(f" Transaction ID: {hashlib.sha256(hashlib.sha256(tx_data[:4] + tx_data[6:]).digest()).digest()[::-1].hex()}")

        return tx_data

    @staticmethod
    def save_transaction(tx_bytes: bytes, filename: str) -> None:
        """
        Save final transaction to hex file

        Args:
            tx_bytes: Raw transaction bytes
            filename: File path to save to
        """
        with open(filename, 'w') as f:
            f.write(tx_bytes.hex())

        print(f"Saved transaction to {filename}")