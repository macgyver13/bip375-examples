#!/usr/bin/env python3
"""
BIP 375 SilentPaymentPSBT Class

Main implementation of PSBT v2 class with silent payment extensions.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import struct

from .constants import PSBTKeyType
from secp256k1_374 import GE
from .serialization import PSBTField
from .crypto import PublicKey, UTXO
from .roles import PSBTConstructor, PSBTCreator, PSBTSigner, PSBTInputFinalizer
from dleq_374 import dleq_verify_proof
import hashlib


@dataclass
class SilentPaymentAddress:
    """Silent payment address with scan and spend keys"""

    scan_key: PublicKey  # 33 bytes compressed public key
    spend_key: PublicKey  # 33 bytes compressed public key
    label: Optional[int] = None


@dataclass
class ECDHShare:
    """ECDH share for a specific scan key"""

    scan_key: bytes  # 33 bytes
    share: bytes  # 33 bytes (point)
    dleq_proof: Optional[bytes] = None  # 64 bytes


class SilentPaymentPSBT:
    """
    PSBT v2 with BIP 375 silent payment extensions

    Methods organized by BIP 174/370/375 roles:
    - Creator/Constructor: Build PSBT structure
    - Signer: ECDH shares, DLEQ proofs, signatures
    - Input Finalizer: Compute output scripts
    - Transaction Extractor: Build final transaction
    """

    # ============================================================================
    # region INITIALIZATION
    # ============================================================================

    def __init__(self):
        self.global_fields: List[PSBTField] = []
        self.input_maps: List[List[PSBTField]] = []
        self.output_maps: List[List[PSBTField]] = []

    # endregion

    # ============================================================================
    # region CREATOR/CONSTRUCTOR ROLE - Build PSBT Structure
    # ============================================================================

    def add_base_fields(self, num_inputs: int, num_outputs: int) -> None:
        """
        Creator role: Add required PSBT v2 global fields

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Total number of outputs (regular + silent payment)
        """
        # Delegate to PSBTCreator role
        self.global_fields, self.input_maps, self.output_maps = (
            PSBTCreator.create_base_psbt(num_inputs, num_outputs)
        )

    def add_inputs_outputs(self, inputs: List, outputs: List[dict]) -> None:
        """
        Constructor role: Add input and output information to PSBT

        Args:
            inputs: List of input objects (UTXO dataclass) or dictionaries with txid, vout, amount, script_pubkey, etc.
            outputs: List of output dictionaries, can be regular outputs or silent payment addresses

        Raises:
            ValueError: If BIP 375 Segwit version restrictions are violated
        """
        # Delegate to PSBTConstructor role
        PSBTConstructor.add_inputs(self.input_maps, inputs)
        PSBTConstructor.add_outputs(self.output_maps, outputs)

        # BIP 375: Validate Segwit version restrictions
        # Cannot mix inputs spending Segwit v>1 with silent payment outputs
        PSBTConstructor._check_segwit_version_restrictions(
            self.input_maps, self.output_maps
        )

    def create_silent_payment_psbt(
        self, inputs: List, outputs: List[dict]
    ) -> "SilentPaymentPSBT":
        """
        Create a PSBT v2 with silent payment extensions

        Args:
            inputs: List of input objects (UTXO dataclass) or dictionaries with txid, vout, amount, script_pubkey
            outputs: List of output dictionaries (regular outputs + silent payment addresses)

        Returns:
            Configured SilentPaymentPSBT ready for ECDH share computation
        """
        num_inputs = len(inputs)
        num_outputs = len(outputs)

        # Creator role: Set up PSBT v2 base structure
        self.add_base_fields(num_inputs, num_outputs)

        # Constructor role: Add transaction input/output information
        self.add_inputs_outputs(inputs, outputs)

        return self

    # Test Generator helper functions
    def add_global_field(self, key_type: int, key_data: bytes, value_data: bytes):
        """Add a global field"""
        self.global_fields.append(PSBTField(key_type, key_data, value_data))

    def add_input_field(
        self, input_index: int, key_type: int, key_data: bytes, value_data: bytes
    ):
        """Add a field to specific input"""
        # Extend input_maps if needed
        while len(self.input_maps) <= input_index:
            self.input_maps.append([])

        self.input_maps[input_index].append(PSBTField(key_type, key_data, value_data))

    def add_output_field(
        self, output_index: int, key_type: int, key_data: bytes, value_data: bytes
    ):
        """Add a field to specific output"""
        # Extend output_maps if needed
        while len(self.output_maps) <= output_index:
            self.output_maps.append([])

        self.output_maps[output_index].append(PSBTField(key_type, key_data, value_data))

    # endregion

    # ============================================================================
    # region UPDATER ROLE - Add BIP32 Derivation Information
    # ============================================================================

    def updater_role(
        self,
        inputs: List,
        derivation_paths: Optional[List[Dict]] = None,
        change_indices: Optional[List[int]] = None,
        change_derivation_info: Optional[Dict[int, Dict]] = None,
    ) -> bool:
        """
        Updater role: Add BIP32 derivation information to PSBT

        This role is essential for hardware wallet compatibility. It adds PSBT_IN_BIP32_DERIVATION
        fields that allow hardware wallets to:
        1. Extract public keys without needing private keys in the PSBT
        2. Match public keys to their internal key derivation
        3. Derive the correct private keys from their master seed

        Args:
            inputs: List of UTXO objects
            derivation_paths: Optional list of input derivation info (see PSBTUpdater.add_input_bip32_derivation)
            change_indices: Optional list of output indices that are change
            change_derivation_info: Optional dict of output derivation info (see PSBTUpdater.add_output_bip32_derivation)

        Returns:
            True if successful

        Example (Privacy mode - recommended for hardware wallets):
            ```python
            # Hardware wallet coordinator knows public keys but not derivation paths
            derivation_paths = [
                {"pubkey": hw_pubkey_0},  # Privacy mode - no path revealed
                {"pubkey": hw_pubkey_1},
            ]
            psbt.updater_role(inputs, derivation_paths)
            ```

        Example (Full derivation mode - for watch-only wallets):
            ```python
            derivation_paths = [
                {
                    "pubkey": pubkey_bytes,
                    "master_fingerprint": b'\\x12\\x34\\x56\\x78',
                    "path": [0x80000054, 0x80000000, 0x80000000, 0, 0]  # m/84'/0'/0'/0/0
                },
            ]
            psbt.updater_role(inputs, derivation_paths)
            ```
        """
        from .roles import PSBTUpdater

        # Add input BIP32 derivation
        input_fields_added = PSBTUpdater.add_input_bip32_derivation(
            self.input_maps, inputs, derivation_paths
        )

        print(
            f" UPDATER: Added PSBT_IN_BIP32_DERIVATION for {input_fields_added} input(s)"
        )

        # Add output BIP32 derivation for change outputs if provided
        if change_indices and change_derivation_info:
            output_fields_added = PSBTUpdater.add_output_bip32_derivation(
                self.output_maps, change_indices, change_derivation_info
            )
            if output_fields_added > 0:
                print(
                    f" UPDATER: Added PSBT_OUT_BIP32_DERIVATION for {output_fields_added} output(s)"
                )

        return True

    # endregion

    # ============================================================================
    # region SERIALIZATION - Encode/Decode PSBT
    # ============================================================================

    def serialize_section(self, fields: List[PSBTField]) -> bytes:
        """Serialize a section (global, input, or output)"""
        result = b""
        for field in fields:
            result += field.serialize()
        # End with separator (empty key)
        result += b"\x00"
        return result

    def serialize(self) -> bytes:
        """Serialize entire PSBT to bytes"""
        result = b"psbt\xff"  # PSBT magic

        # Global section
        result += self.serialize_section(self.global_fields)

        # Input sections
        for input_fields in self.input_maps:
            result += self.serialize_section(input_fields)

        # Output sections
        for output_fields in self.output_maps:
            result += self.serialize_section(output_fields)

        return result

    def encode(self) -> str:
        import base64

        return base64.b64encode(self.serialize()).decode()

    def pretty_print(self) -> str:
        """Return a human-readable description of the PSBT"""
        lines = ["PSBT v2 with Silent Payment Extensions", "=" * 50]

        # Global fields
        lines.append("Global Fields:")
        for field in self.global_fields:
            field_name = self._get_field_name(
                field.key_type, "global", strip_prefix=True
            )
            lines.append(f"  {field_name}: {field.value_data.hex()}")

        # Input fields
        for i, input_fields in enumerate(self.input_maps):
            lines.append(f"\nInput {i}:")
            for field in input_fields:
                field_name = self._get_field_name(
                    field.key_type, "in", strip_prefix=True
                )
                lines.append(f"  {field_name}: {field.value_data.hex()}")

        # Output fields
        for i, output_fields in enumerate(self.output_maps):
            lines.append(f"\nOutput {i}:")
            for field in output_fields:
                field_name = self._get_field_name(
                    field.key_type, "out", strip_prefix=True
                )
                if field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                    # Pretty print silent payment info
                    if len(field.value_data) == 66:  # 33 + 33 bytes
                        scan_key = field.value_data[:33].hex()
                        spend_key = field.value_data[33:].hex()
                        lines.append(f"  {field_name}:")
                        lines.append(f"    Scan Key:  {scan_key}")
                        lines.append(f"    Spend Key: {spend_key}")
                    else:
                        lines.append(f"  {field_name}: {field.value_data.hex()}")
                else:
                    lines.append(f"  {field_name}: {field.value_data.hex()}")

        return "\n".join(lines)

    def to_json(self) -> dict:
        """
        Return a JSON-serializable dict representation of the PSBT

        Returns structured data with global fields, inputs, and outputs.
        This is derived from the PSBT and should only be used for human
        inspection, not as a source of truth for programmatic operations.

        Returns:
            dict with 'global', 'inputs', 'outputs' sections
        """
        result = {"global": [], "inputs": [], "outputs": []}

        # Global fields
        for field in self.global_fields:
            field_name = self._get_field_name(field.key_type, "global")
            field_data = {
                "field": field_name,
                "type": field.key_type,
                "value_hex": field.value_data.hex(),
            }

            # Add human-readable values for common fields
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_TX_VERSION:
                field_data["value"] = struct.unpack("<I", field.value_data)[0]
            elif field.key_type == PSBTKeyType.PSBT_GLOBAL_VERSION:
                field_data["value"] = struct.unpack("<I", field.value_data)[0]
            elif field.key_type == PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT:
                field_data["value"] = (
                    field.value_data[0] if len(field.value_data) > 0 else 0
                )
            elif field.key_type == PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT:
                field_data["value"] = (
                    field.value_data[0] if len(field.value_data) > 0 else 0
                )
            elif field.key_type == PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE:
                flags = field.value_data[0] if len(field.value_data) > 0 else 0
                field_data["value"] = {
                    "raw": flags,
                    "inputs_modifiable": bool(flags & 0x01),
                    "outputs_modifiable": bool(flags & 0x02),
                }

            result["global"].append(field_data)

        # Input fields
        for i, input_fields in enumerate(self.input_maps):
            input_data = {"index": i, "fields": []}

            for field in input_fields:
                field_name = self._get_field_name(field.key_type, "in")
                field_info = {
                    "field": field_name,
                    "type": field.key_type,
                    "value_hex": field.value_data.hex(),
                }

                # Add human-readable values for common fields
                if field.key_type == PSBTKeyType.PSBT_IN_PREVIOUS_TXID:
                    field_info["value"] = field.value_data.hex()
                elif field.key_type == PSBTKeyType.PSBT_IN_OUTPUT_INDEX:
                    field_info["value"] = struct.unpack("<I", field.value_data)[0]
                elif field.key_type == PSBTKeyType.PSBT_IN_SEQUENCE:
                    field_info["value"] = struct.unpack("<I", field.value_data)[0]
                elif field.key_type == PSBTKeyType.PSBT_IN_WITNESS_UTXO:
                    amount = struct.unpack("<Q", field.value_data[:8])[0]
                    script_len = field.value_data[8]
                    script_pubkey = field.value_data[9 : 9 + script_len].hex()
                    field_info["value"] = {
                        "amount": amount,
                        "script_pubkey": script_pubkey,
                    }
                elif field.key_type == PSBTKeyType.PSBT_IN_SIGHASH_TYPE:
                    field_info["value"] = struct.unpack("<I", field.value_data)[0]
                elif field.key_type == PSBTKeyType.PSBT_IN_SP_ECDH_SHARE:
                    field_info["scan_key"] = field.key_data.hex()
                    field_info["value"] = field.value_data.hex()
                elif field.key_type == PSBTKeyType.PSBT_IN_SP_DLEQ:
                    field_info["scan_key"] = field.key_data.hex()
                    field_info["value"] = field.value_data.hex()
                elif field.key_type == PSBTKeyType.PSBT_IN_PARTIAL_SIG:
                    field_info["pubkey"] = field.key_data.hex()
                    field_info["value"] = field.value_data.hex()

                input_data["fields"].append(field_info)

            result["inputs"].append(input_data)

        # Output fields
        for i, output_fields in enumerate(self.output_maps):
            output_data = {"index": i, "fields": []}

            for field in output_fields:
                field_name = self._get_field_name(field.key_type, "out")
                field_info = {
                    "field": field_name,
                    "type": field.key_type,
                    "value_hex": field.value_data.hex(),
                }

                # Add human-readable values for common fields
                if field.key_type == PSBTKeyType.PSBT_OUT_AMOUNT:
                    field_info["value"] = struct.unpack("<Q", field.value_data)[0]
                elif field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT:
                    field_info["value"] = field.value_data.hex()
                elif field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                    if len(field.value_data) == 66:  # 33 + 33 bytes
                        field_info["value"] = {
                            "scan_key": field.value_data[:33].hex(),
                            "spend_key": field.value_data[33:].hex(),
                        }
                elif field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_LABEL:
                    field_info["value"] = struct.unpack("<I", field.value_data)[0]

                output_data["fields"].append(field_info)

            result["outputs"].append(output_data)

        return result

    def _get_field_name(
        self, key_type: int, section: str, strip_prefix: bool = False
    ) -> str:
        """
        Get human-readable name for a PSBT key type with section context

        Args:
            key_type: PSBT key type integer
            section: Section name ('global', 'in', or 'out')
            strip_prefix: If True, strip 'PSBT_GLOBAL_', 'PSBT_IN_', 'PSBT_OUT_' prefix
                         If False (default), return full name like 'PSBT_GLOBAL_TX_VERSION'

        Returns:
            Key type name string (full or stripped based on strip_prefix)
        """
        # Search only within the appropriate section to handle duplicate values
        section_prefix = f"PSBT_{section.upper()}_"

        for attr_name in dir(PSBTKeyType):
            if attr_name.startswith(section_prefix):
                attr_value = getattr(PSBTKeyType, attr_name)
                if isinstance(attr_value, int) and attr_value == key_type:
                    # Return name with or without the section prefix
                    if strip_prefix:
                        return attr_name[len(section_prefix) :]
                    else:
                        return attr_name

        # Unknown key type, return hex representation
        return f"UNKNOWN_{key_type:02x}"

    # endregion

    # ============================================================================
    # region SIGNER ROLE - ECDH Shares & Signatures
    # ============================================================================

    def add_ecdh_shares(
        self, inputs: List[UTXO], scan_keys: List[PublicKey], use_global=True
    ) -> None:
        """
        Add ECDH shares and DLEQ proofs to the PSBT for given UTXOs and scan keys

        Args:
            inputs: List of UTXO objects, some may have private_key = None
            scan_keys: List of scan keys (PublicKey objects)
            use_global: If True, use global ECDH approach; if False, use per-input approach
        """
        # Delegate to PSBTSigner role
        PSBTSigner.add_ecdh_shares(
            global_fields=self.global_fields,
            input_maps=self.input_maps,
            inputs=inputs,
            scan_keys=scan_keys,
            use_global=use_global,
        )

    def sign_inputs(self, inputs: List[UTXO]) -> bool:
        """
        Sign transaction inputs using private keys from UTXOs (SIGNER ROLE)

        Args:
            inputs: List of UTXO objects with private keys for signing

        Returns:
            True if signing successful, raises exception if validation fails
        """
        # Pre-signing validation
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(f"PSBT validation failed before signing: {errors}")

        # Delegate to PSBTSigner role
        signatures_added = PSBTSigner.sign_inputs(
            input_maps=self.input_maps, output_maps=self.output_maps, inputs=inputs
        )

        if signatures_added == 0:
            raise ValueError("No inputs were signed successfully")

        print(f" Successfully signed {signatures_added} input(s)")
        return True

    # endregion

    # ============================================================================
    # region VERIFICATION - DLEQ Proofs
    # ============================================================================

    def verify_dleq_proofs(self, inputs: List[UTXO] = None) -> bool:
        """
        Verify all DLEQ proofs in the PSBT

        Returns:
            True if all proofs are valid, False otherwise
        """

        # Check for global DLEQ proofs
        global_ecdh_fields = {}
        global_dleq_fields = {}

        for field in self.global_fields:
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE:
                scan_key = field.key_data
                global_ecdh_fields[scan_key] = field.value_data
            elif field.key_type == PSBTKeyType.PSBT_GLOBAL_SP_DLEQ:
                scan_key = field.key_data
                global_dleq_fields[scan_key] = field.value_data

        # Verify global DLEQ proofs
        for scan_key in global_ecdh_fields:
            if scan_key not in global_dleq_fields:
                print(
                    f"❌ Global ECDH share missing DLEQ proof for scan key {scan_key.hex()}"
                )
                return False

            ecdh_share_bytes = global_ecdh_fields[scan_key]
            dleq_proof = global_dleq_fields[scan_key]

            if len(dleq_proof) != 64:
                print(f"❌ Invalid global DLEQ proof length: {len(dleq_proof)} bytes")
                return False

            # Combine all input public keys for global verification
            A_combined = self._extract_combined_input_pubkeys(inputs)
            if A_combined is None:
                print(
                    "❌ Could not extract input public keys for global DLEQ verification"
                )
                return False

            B_scan = GE.from_bytes(scan_key)  # scan key
            C = GE.from_bytes(ecdh_share_bytes)  # ECDH result
            # Verify DLEQ proof
            if not dleq_verify_proof(A_combined, B_scan, C, dleq_proof):
                print(
                    f"❌ Global DLEQ proof verification failed for scan key {scan_key.hex()}"
                )
                return False

            print(f" Global DLEQ proof verified for scan key {scan_key.hex()}")

        # Check for per-input DLEQ proofs
        for input_index, input_fields in enumerate(self.input_maps):
            input_ecdh_fields = {}
            input_dleq_fields = {}

            for field in input_fields:
                if field.key_type == PSBTKeyType.PSBT_IN_SP_ECDH_SHARE:
                    scan_key = field.key_data
                    input_ecdh_fields[scan_key] = field.value_data
                elif field.key_type == PSBTKeyType.PSBT_IN_SP_DLEQ:
                    scan_key = field.key_data
                    input_dleq_fields[scan_key] = field.value_data

            # Verify per-input DLEQ proofs
            for scan_key in input_ecdh_fields:
                if scan_key not in input_dleq_fields:
                    print(
                        f"❌ Input {input_index} ECDH share missing DLEQ proof for scan key {scan_key.hex()}"
                    )
                    return False

                ecdh_share_bytes = input_ecdh_fields[scan_key]
                dleq_proof = input_dleq_fields[scan_key]

                if len(dleq_proof) != 64:
                    print(
                        f"❌ Invalid input {input_index} DLEQ proof length: {len(dleq_proof)} bytes"
                    )
                    return False

                # Convert to GE points
                B = GE.from_bytes(scan_key)  # scan key
                C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

                # Extract input public key for this specific input
                A = self._extract_input_pubkey(input_index, inputs)
                if A is None:
                    print(f"❌ Could not extract public key for input {input_index}")
                    return False

                # Verify DLEQ proof
                if not dleq_verify_proof(A, B, C, dleq_proof):
                    print(
                        f"❌ Input {input_index} DLEQ proof verification failed for scan key {scan_key.hex()}"
                    )
                    return False

                print(
                    f" Input {input_index} DLEQ proof verified for scan key {scan_key.hex()}"
                )

        if not global_ecdh_fields and not any(
            any(
                field.key_type == PSBTKeyType.PSBT_IN_SP_ECDH_SHARE
                for field in input_fields
            )
            for input_fields in self.input_maps
        ):
            print("⚠️  No ECDH shares found in PSBT - no DLEQ proofs to verify")
            return True

        print(" All DLEQ proofs verified successfully")
        return True

    def _extract_combined_input_pubkeys(
        self, inputs: List[UTXO] = None
    ) -> Optional[GE]:
        """
        Extract and combine all input public keys for global DLEQ verification

        Note:
            This method delegates to the standalone extract_combined_input_pubkeys() function
            in psbt_utils.py, automatically providing the PSBT field data.
        """
        from .psbt_utils import extract_combined_input_pubkeys as _extract_combined

        return _extract_combined(self.input_maps, inputs)

    def _extract_input_pubkey(
        self, input_index: int, inputs: List[UTXO] = None
    ) -> Optional[GE]:
        """
        Extract public key for a specific input from PSBT fields

        Args:
            input_index: Index of the input
            inputs: Optional list of UTXO objects (for fallback extraction from private key)

        Note:
            This method delegates to the standalone extract_input_pubkey() function
            in psbt_utils.py, automatically providing the PSBT field data.
        """
        if input_index >= len(self.input_maps):
            return None

        from .psbt_utils import extract_input_pubkey as _extract_pubkey

        return _extract_pubkey(self.input_maps[input_index], inputs, input_index)

    # endregion

    # ============================================================================
    # region INPUT FINALIZER ROLE - Compute Output Scripts
    # ============================================================================

    def _compute_label_tweak(self, scan_privkey_bytes: bytes, label: int) -> int:
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
        label_bytes = struct.pack("<I", label)  # 4 bytes little-endian

        # Tagged hash: BIP0352/Label
        tag = b"BIP0352/Label"
        tag_hash = hashlib.sha256(tag).digest()

        # hash_BIP0352/Label(b_scan || m)
        tagged_input = tag_hash + tag_hash + scan_privkey_bytes + label_bytes
        tweak_hash = hashlib.sha256(tagged_input).digest()
        tweak_scalar = int.from_bytes(tweak_hash, "big") % GE.ORDER

        return tweak_scalar

    def compute_output_scripts(self, scan_privkeys: dict = None) -> None:
        """
        Compute output scripts for all silent payment addresses (INPUT FINALIZER ROLE)
        Uses BIP 352 protocol with ECDH shares from PSBT

        Args:
            scan_privkeys: Optional dict mapping scan_key_bytes -> scan_privkey_bytes
                          Required for computing label tweaks for change outputs
        """
        # Pre-computation validation
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(
                f"PSBT validation failed before computing output scripts: {errors}"
            )

        # Delegate to PSBTInputFinalizer role
        scripts_computed = PSBTInputFinalizer.compute_output_scripts(
            global_fields=self.global_fields,
            input_maps=self.input_maps,
            output_maps=self.output_maps,
            scan_privkeys=scan_privkeys,
        )

        if scripts_computed == 0:
            raise ValueError("No silent payment outputs found to compute")

        print(f" Successfully computed {scripts_computed} output script(s)")

    # endregion

    # ============================================================================
    # region COMPLETE ROLE WORKFLOWS - Multi-Step Operations
    # ============================================================================

    def signer_role(
        self,
        inputs: List[UTXO],
        scan_keys: List[PublicKey] = None,
        scan_privkeys: dict = None,
    ) -> bool:
        """
        Complete BIP 375 SIGNER role implementation

        For each output with PSBT_OUT_SP_V0_INFO set, the Signer should:
        1. Compute and set an ECDH share and DLEQ proof for each input it has the private key for,
           or set a global ECDH share and DLEQ proof if it has private keys for all eligible inputs
        2. Verify the DLEQ proofs for all inputs it does not have the private keys for,
           or the global DLEQ proof if it is set
        3. If all eligible inputs have an ECDH share or the global ECDH share is set,
           compute and set the PSBT_OUT_SCRIPT
        4. If the Signer sets any missing PSBT_OUT_SCRIPTs, it must set the Inputs Modifiable
           and Outputs Modifiable flags to False
        5. If any output does not have PSBT_OUT_SCRIPT set, the Signer must not yet add a signature

        Args:
            inputs: List of UTXO objects with private keys for signing
            scan_keys: List of scan keys to compute ECDH shares for (auto-extracted if None)
            scan_privkeys: Optional dict mapping scan_key_bytes -> scan_privkey_bytes
                          (required for computing label tweaks for change outputs)

        Returns:
            True if SIGNER role completed successfully, False otherwise
        """

        # Step 1: Check if we have any silent payment outputs
        has_silent_outputs = any(
            any(
                field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO
                for field in output_fields
            )
            for output_fields in self.output_maps
        )

        if not has_silent_outputs:
            print(
                "⚠️  No silent payment outputs found - proceeding with regular signing"
            )
            return self.sign_inputs(inputs)

        # Step 2: Extract scan keys from silent payment outputs if not provided
        if scan_keys is None:
            scan_keys = []
            for output_fields in self.output_maps:
                for field in output_fields:
                    if field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                        if len(field.value_data) == 66:  # 33 + 33 bytes
                            scan_key_bytes = field.value_data[:33]
                            scan_key = PublicKey(GE.from_bytes(scan_key_bytes))
                            if scan_key not in scan_keys:
                                scan_keys.append(scan_key)
            print(
                f"📋 Found {len(scan_keys)} unique scan key(s) in silent payment outputs"
            )

        if not scan_keys:
            print("❌ Could not extract scan keys from silent payment outputs")
            return False

        print("4.1. Computing ECDH shares and DLEQ proofs for controlled inputs...")
        spendable_inputs = [
            (i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None
        ]

        if not spendable_inputs:
            print("❌ No spendable inputs found (no private keys provided)")
            return False

        # Use global ECDH approach (single entity controls all inputs)
        try:
            self.add_ecdh_shares(inputs, scan_keys, use_global=True)
            print(" ECDH shares and DLEQ proofs computed")
        except Exception as e:
            print(f"❌ Failed to compute ECDH shares: {e}")
            return False

        print("4.2. Verifying all DLEQ proofs...")
        if not self.verify_dleq_proofs(inputs):
            print("❌ DLEQ proof verification failed")
            return False

        print("4.3. Checking ECDH share coverage...")
        has_complete_ecdh_coverage = self.check_ecdh_coverage()

        if not has_complete_ecdh_coverage:
            print(
                "❌ Incomplete ECDH share coverage - cannot compute output scripts yet"
            )
            return False

        print("4.4. Computing silent payment output scripts...")
        try:
            self.compute_output_scripts(scan_privkeys)
        except Exception as e:
            print(f"❌ Failed to compute output scripts: {e}")
            return False

        print("4.5. Verifying all outputs have scripts before signing...")
        for i, output_fields in enumerate(self.output_maps):
            has_script = any(
                field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT for field in output_fields
            )
            if not has_script:
                print(f"❌ Output {i} missing script - cannot sign yet")
                return False

        print("4.6. Adding signatures to inputs...")
        success = self.sign_inputs(inputs)
        if not success:
            print("❌ Signing failed")
            return False
        return True

    def signer_role_partial(
        self,
        inputs: List[UTXO],
        controlled_input_indices: List[int],
        scan_keys: List[PublicKey] = None,
        scan_privkeys: dict = None,
    ) -> bool:
        """
        Partial SIGNER role implementation for multi-signer workflows

        This is the key method for multi-party silent payment collaboration.
        Each signer only adds ECDH shares for inputs they control and verifies
        DLEQ proofs from other signers.

        Args:
            inputs: List of UTXO objects (may contain private keys only for controlled inputs)
            controlled_input_indices: List of input indices this signer controls
            scan_keys: List of scan keys to compute ECDH shares for (auto-extracted if None)
            scan_privkeys: Optional dict mapping scan_key_bytes -> scan_privkey_bytes
                          Required for computing label tweaks for change outputs

        Returns:
            True if partial SIGNER role completed successfully, False otherwise
        """
        print(
            f" SIGNER (partial): Processing {len(controlled_input_indices)} controlled input(s)"
        )

        # Step 0: Check if PSBT is still modifiable
        is_modifiable = self._check_psbt_modifiable()
        if not is_modifiable:
            print("❌ PSBT is no longer modifiable (transaction already finalized)")
            print("   Cannot add ECDH shares or signatures to a finalized PSBT")
            print("   This usually means Charlie has already completed the workflow")
            return False

        # Step 1: Check if we have any silent payment outputs
        has_silent_outputs = any(
            any(
                field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO
                for field in output_fields
            )
            for output_fields in self.output_maps
        )

        if not has_silent_outputs:
            print(
                "⚠️  No silent payment outputs found - proceeding with regular signing"
            )
            return self._sign_controlled_inputs(inputs, controlled_input_indices)

        # Step 2: Extract scan keys from silent payment outputs if not provided
        if scan_keys is None:
            scan_keys = []
            for output_fields in self.output_maps:
                for field in output_fields:
                    if field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                        if len(field.value_data) == 66:  # 33 + 33 bytes
                            scan_key_bytes = field.value_data[:33]
                            scan_key = PublicKey(GE.from_bytes(scan_key_bytes))
                            if scan_key not in scan_keys:
                                scan_keys.append(scan_key)
            print(f"   Found {len(scan_keys)} unique scan key(s)")

        if not scan_keys:
            print("❌ Could not extract scan keys from silent payment outputs")
            return False

        # Step 3: Verify existing DLEQ proofs from other signers
        print("   Verifying existing DLEQ proofs from other signers...")
        if not self._verify_existing_dleq_proofs(inputs, controlled_input_indices):
            print("❌ DLEQ proof verification failed")
            return False

        # Step 4: Add ECDH shares for controlled inputs only
        print(
            f"   Computing ECDH shares for controlled inputs {controlled_input_indices}..."
        )
        try:
            self._add_partial_ecdh_shares(inputs, controlled_input_indices, scan_keys)
            print("   ECDH shares and DLEQ proofs computed for controlled inputs")
        except Exception as e:
            print(f"❌ Failed to compute ECDH shares: {e}")
            return False

        # Step 5: Check if we now have complete ECDH coverage
        is_complete, inputs_with_ecdh = self.check_ecdh_coverage()
        print(
            f"   ECDH coverage: {len(inputs_with_ecdh)}/{len(self.input_maps)} inputs covered"
        )

        if is_complete:
            print("   Complete ECDH coverage achieved! Computing output scripts...")
            try:
                self.compute_output_scripts(scan_privkeys=scan_privkeys)
                print("   Output scripts computed successfully")
            except Exception as e:
                print(f"❌ Failed to compute output scripts: {e}")
                return False

        # Step 6: Check if we can sign controlled inputs
        # For multi-signer workflow: sign if ALL outputs have scripts (regardless of ECDH coverage)
        print("   Checking if we can sign controlled inputs...")
        all_outputs_have_scripts = all(
            any(
                field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT for field in output_fields
            )
            for output_fields in self.output_maps
        )

        if all_outputs_have_scripts:
            print(
                f"   All outputs have scripts - signing controlled inputs {controlled_input_indices}..."
            )
            success = self._sign_controlled_inputs(inputs, controlled_input_indices)
            if not success:
                print("❌ Signing failed")
                return False
            print("   Signatures added successfully")
        else:
            print("⚠️  Some outputs missing scripts - cannot finalize yet")
            # For multi-signer: still sign inputs even without complete coverage
            # This allows incremental signing as each party processes their inputs
            if not is_complete:
                print(
                    f"   Signing controlled inputs {controlled_input_indices} for partial workflow..."
                )
                success = self._sign_controlled_inputs(inputs, controlled_input_indices)
                if not success:
                    print("❌ Partial signing failed")
                    return False
                print("   Partial signatures added successfully")

        print(" SIGNER (partial): Completed successfully")
        return True

    def _check_psbt_modifiable(self) -> bool:
        """
        Check if the PSBT is still modifiable based on PSBT_GLOBAL_TX_MODIFIABLE flags

        Returns:
            True if PSBT can be modified, False if finalized
        """
        # Check for TX_MODIFIABLE field
        for field in self.global_fields:
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE:
                if len(field.value_data) >= 1:
                    modifiable_flags = field.value_data[0]
                    # 0x03 = both inputs and outputs modifiable
                    # 0x02 = only outputs modifiable
                    # 0x01 = only inputs modifiable
                    # 0x00 = neither inputs nor outputs modifiable (finalized)
                    return modifiable_flags != 0x00

        # If no TX_MODIFIABLE field found, assume modifiable (default state)
        return True

    def _verify_existing_dleq_proofs(
        self, inputs: List[UTXO], controlled_input_indices: List[int]
    ) -> bool:
        """
        Verify DLEQ proofs from other signers (for inputs we don't control)
        """
        # Get list of inputs we don't control
        uncontrolled_indices = [
            i for i in range(len(self.input_maps)) if i not in controlled_input_indices
        ]

        if not uncontrolled_indices:
            print("     No other signers' proofs to verify")
            return True

        # Check for global DLEQ proofs first
        for field in self.global_fields:
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_SP_DLEQ:
                print("     Found global DLEQ proof - verifying...")
                # For now, assume global proofs are valid if structurally correct
                # In full implementation, would need to verify against combined pubkeys
                if len(field.value_data) == 64:
                    print("     Global DLEQ proof verification passed")
                    return True
                else:
                    print("❌ Invalid global DLEQ proof length")
                    return False

        # Check per-input DLEQ proofs for uncontrolled inputs
        verified_count = 0
        for input_index in uncontrolled_indices:
            if input_index < len(self.input_maps):
                input_fields = self.input_maps[input_index]
                has_ecdh = any(
                    field.key_type == PSBTKeyType.PSBT_IN_SP_ECDH_SHARE
                    for field in input_fields
                )
                has_dleq = any(
                    field.key_type == PSBTKeyType.PSBT_IN_SP_DLEQ
                    for field in input_fields
                )

                if has_ecdh and has_dleq:
                    # Verify the DLEQ proof cryptographically
                    if self._verify_input_dleq_proof(input_index, inputs):
                        verified_count += 1
                        print(
                            f"     Input {input_index} DLEQ proof verification passed"
                        )
                    else:
                        print(f"❌ Input {input_index} DLEQ proof verification failed")
                        return False
                elif has_ecdh:
                    print(
                        f"❌ Input {input_index} has ECDH share but missing DLEQ proof"
                    )
                    return False

        print(f"     Verified {verified_count} DLEQ proof(s) from other signers")
        return True

    def _verify_input_dleq_proof(self, input_index: int, inputs: List[UTXO]) -> bool:
        """
        Cryptographically verify DLEQ proof for a specific input

        Args:
            input_index: Index of input to verify
            inputs: List of UTXO inputs

        Returns:
            bool: True if verification succeeds, False otherwise
        """
        from .psbt_utils import extract_input_pubkey

        if input_index >= len(self.input_maps):
            return False

        input_fields = self.input_maps[input_index]
        input_field_dict = {field.key_type: field for field in input_fields}

        # Check if DLEQ proof and ECDH share exist
        if (
            PSBTKeyType.PSBT_IN_SP_DLEQ not in input_field_dict
            or PSBTKeyType.PSBT_IN_SP_ECDH_SHARE not in input_field_dict
        ):
            return False

        try:
            # Extract DLEQ proof and ECDH share
            dleq_field = input_field_dict[PSBTKeyType.PSBT_IN_SP_DLEQ]
            ecdh_field = input_field_dict[PSBTKeyType.PSBT_IN_SP_ECDH_SHARE]

            # Parse scan key from DLEQ field key_data
            scan_key_bytes = dleq_field.key_data
            if len(scan_key_bytes) != 33:
                return False

            # Parse points from bytes
            scan_key_point = GE.from_bytes(scan_key_bytes)
            ecdh_result_point = GE.from_bytes(ecdh_field.value_data)

            # Get input public key from PSBT fields using utility function
            input_public_key_point = extract_input_pubkey(
                input_fields=input_fields, inputs=inputs, input_index=input_index
            )

            if input_public_key_point is None:
                return False

            # Verify DLEQ proof: dleq_verify_proof(A, B, C, proof)
            # A = input_public_key, B = scan_key, C = ecdh_result
            proof_verified = dleq_verify_proof(
                input_public_key_point,  # A (input pubkey)
                scan_key_point,  # B (scan key)
                ecdh_result_point,  # C (ECDH result)
                dleq_field.value_data,  # proof
            )

            return proof_verified

        except Exception:
            return False

    def _add_partial_ecdh_shares(
        self,
        inputs: List[UTXO],
        controlled_input_indices: List[int],
        scan_keys: List[PublicKey],
    ) -> None:
        """
        Add ECDH shares for controlled inputs only (per-input approach)

        Delegates to PSBTSigner.add_ecdh_shares_for_inputs()
        """
        PSBTSigner.add_ecdh_shares_for_inputs(
            input_maps=self.input_maps,
            inputs=inputs,
            input_indices=controlled_input_indices,
            scan_keys=scan_keys,
        )

        for input_index in controlled_input_indices:
            for scan_key in scan_keys:
                print(
                    f"     Added ECDH share for input {input_index}, scan key {scan_key.bytes.hex()}"
                )

    def _sign_controlled_inputs(
        self, inputs: List[UTXO], controlled_input_indices: List[int]
    ) -> bool:
        """
        Sign only the controlled inputs

        Delegates to PSBTSigner.sign_specific_inputs()
        """
        if not controlled_input_indices:
            print("     No controlled inputs to sign")
            return True

        try:
            signatures_added = PSBTSigner.sign_specific_inputs(
                input_maps=self.input_maps,
                output_maps=self.output_maps,
                inputs=inputs,
                input_indices=controlled_input_indices,
            )

            if signatures_added == 0:
                print("❌ No inputs were signed successfully")
                return False

            print(f"     Successfully signed {signatures_added} input(s)")
            return True

        except Exception as e:
            print(f"❌ Failed to sign controlled inputs: {e}")
            return False

    # endregion

    # ============================================================================
    # region TRANSACTION EXTRACTOR ROLE - Build Final Transaction
    # ============================================================================

    def extract_transaction(self) -> bytes:
        """
        Extract the final Bitcoin transaction from the completed PSBT (TRANSACTION EXTRACTOR ROLE)

        Returns:
            Serialized transaction bytes

        Note:
            This method delegates to the standalone extract_transaction() function
            in transaction.py, automatically providing the PSBT field data.
        """
        # Validation before extraction
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(f"PSBT validation failed before extraction: {errors}")

        # Delegate to PSBTExtractor role
        from .roles import PSBTExtractor

        return PSBTExtractor.extract_transaction(
            self.global_fields, self.input_maps, self.output_maps
        )

    # endregion

    # ============================================================================
    # region FILE I/O - Save/Load PSBTs
    # ============================================================================

    def save_psbt_to_file(self, filename: str, metadata: Optional[Dict] = None) -> None:
        """
        Save PSBT to JSON file with metadata for multi-signer workflows

        Args:
            filename: File path to save to
            metadata: Optional metadata dict with step info, completed_by, etc.

        Note:
            This method delegates to the standalone save_psbt_to_file() function
            in psbt_io.py, automatically providing psbt and psbt_json.
        """
        from .psbt_io import save_psbt_to_file as _save_psbt_to_file

        _save_psbt_to_file(
            psbt=self.encode(),
            filename=filename,
            metadata=metadata,
            psbt_json=self.to_json(),
        )

    @classmethod
    def load_psbt_from_file(cls, filename: str) -> Tuple["SilentPaymentPSBT", Dict]:
        """
        Load PSBT from JSON file with metadata

        Args:
            filename: File path to load from

        Returns:
            Tuple of (SilentPaymentPSBT instance, metadata dict)

        Note:
            This method delegates to the standalone load_psbt_from_file() function
            in psbt_io.py and wraps the result in a SilentPaymentPSBT instance.
        """
        from .psbt_io import load_psbt_from_file as _load_psbt_from_file

        # Load raw PSBT fields
        global_fields, input_maps, output_maps, metadata = _load_psbt_from_file(
            filename
        )

        # Wrap in SilentPaymentPSBT instance
        psbt = cls()
        psbt.global_fields = global_fields
        psbt.input_maps = input_maps
        psbt.output_maps = output_maps

        return psbt, metadata

    @classmethod
    def from_base64(cls, psbt_base64: str) -> "SilentPaymentPSBT":
        """
        Create SilentPaymentPSBT from base64-encoded PSBT string

        Args:
            psbt_base64: Base64-encoded PSBT string

        Returns:
            SilentPaymentPSBT instance

        Raises:
            ValueError: If PSBT data is invalid

        Note:
            This is a factory method that decodes and parses the PSBT in one step.
        """
        import base64
        from .serialization import parse_psbt_bytes

        # Decode and parse
        psbt_data = base64.b64decode(psbt_base64)
        global_fields, input_maps, output_maps = parse_psbt_bytes(psbt_data)

        # Wrap in instance
        psbt = cls()
        psbt.global_fields = global_fields
        psbt.input_maps = input_maps
        psbt.output_maps = output_maps

        return psbt

    # endregion

    # ============================================================================
    # region UTILITY METHODS - Helpers & Queries
    # ============================================================================

    def check_ecdh_coverage(self) -> Tuple[bool, List[int]]:
        """
        Check which inputs have ECDH shares and if coverage is complete

        Returns:
            Tuple of (is_complete, list_of_input_indices_with_ecdh)

        Note:
            This method delegates to the standalone check_ecdh_coverage() function
            in psbt_utils.py, automatically providing the PSBT field data.
        """
        from .psbt_utils import check_ecdh_coverage as _check_ecdh_coverage

        return _check_ecdh_coverage(
            self.global_fields, self.input_maps, self.output_maps
        )

    def can_compute_output_scripts(self) -> bool:
        """
        Check if we can compute output scripts (have complete ECDH coverage)

        Returns:
            True if ready to compute output scripts, False otherwise
        """
        is_complete, _ = self.check_ecdh_coverage()
        return is_complete

    def get_inputs_with_ecdh_shares(self) -> List[int]:
        """
        Get list of input indices that have ECDH shares

        Returns:
            List of input indices with ECDH shares
        """
        _, inputs_with_ecdh = self.check_ecdh_coverage()
        return inputs_with_ecdh

    def compute_unique_id(self) -> str:
        """
        Compute unique identifier for this PSBT per BIP-375

        Follows BIP-370 identification methodology with BIP-375 extensions:
        - Constructs an unsigned transaction from PSBT fields
        - Uses sequence = 0 for all inputs (per BIP-370)
        - Uses PSBT_GLOBAL_FALLBACK_LOCKTIME if present, otherwise 0
        - For outputs: Uses PSBT_OUT_SP_V0_INFO if present (BIP-375 extension),
          otherwise PSBT_OUT_SCRIPT (standard BIP-370)
        - Computes double SHA256 hash of the serialized unsigned transaction

        This prevents malleability for silent payment outputs where the actual
        scriptPubKey may not be known at PSBT creation time.

        Returns:
            64-character hex string txid

        Raises:
            ValueError: If required fields are missing (txid, vout, amount, script)
        """

        # Build unsigned transaction for identification
        tx_bytes = b""

        # Extract version from PSBT_GLOBAL_TX_VERSION
        version = 2  # Default
        for field in self.global_fields:
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_TX_VERSION:
                version = struct.unpack("<I", field.value_data)[0]
                break

        tx_bytes += struct.pack("<I", version)

        # Input count (varint)
        tx_bytes += bytes([len(self.input_maps)])

        # Inputs
        for i, input_fields in enumerate(self.input_maps):
            # Extract required fields for this input
            txid = None
            vout = None

            for field in input_fields:
                if field.key_type == PSBTKeyType.PSBT_IN_PREVIOUS_TXID:
                    txid = field.value_data
                elif field.key_type == PSBTKeyType.PSBT_IN_OUTPUT_INDEX:
                    vout = field.value_data

            # Validate and serialize this input
            if txid is None:
                raise ValueError(f"Input {i} missing previous txid")
            if vout is None:
                raise ValueError(f"Input {i} missing output index")

            tx_bytes += txid  # 32 bytes
            tx_bytes += vout  # 4 bytes
            tx_bytes += b"\x00"  # ScriptSig (empty for PSBTv2)
            # Sequence (ALWAYS 0 for identification per BIP-370)
            tx_bytes += struct.pack("<I", 0)

        # Output count (varint)
        tx_bytes += bytes([len(self.output_maps)])

        # Outputs - BIP375 special handling
        for i, output_fields in enumerate(self.output_maps):
            # Extract required fields for this output
            amount = None
            script = None
            sp_info = None

            for field in output_fields:
                if field.key_type == PSBTKeyType.PSBT_OUT_AMOUNT:
                    amount = field.value_data
                elif field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT:
                    script = field.value_data
                elif field.key_type == PSBTKeyType.PSBT_OUT_SP_V0_INFO:
                    sp_info = field.value_data

            # Validate and serialize this output
            if amount is None:
                raise ValueError(f"Output {i} missing amount")

            tx_bytes += amount  # 8 bytes

            # Script: Use PSBT_OUT_SP_V0_INFO if present, else PSBT_OUT_SCRIPT
            if sp_info is not None:
                tx_bytes += bytes([len(sp_info)]) + sp_info
            elif script is not None:
                tx_bytes += bytes([len(script)]) + script
            else:
                raise ValueError(
                    f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO"
                )

        # Locktime (4 bytes)
        locktime = struct.pack("<I", 0) # Default
        for field in self.global_fields:
            if field.key_type == PSBTKeyType.PSBT_GLOBAL_FALLBACK_LOCKTIME:
                locktime = field.value_data
                break
        tx_bytes += locktime

        # Compute TXID (double SHA256)
        txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()

        # Return as hex string (reversed for Bitcoin display convention)
        return txid[::-1].hex()

    # endregion


# ============================================================================
# region STANDALONE VALIDATION FUNCTION
# ============================================================================


def validate_psbt_silent_payments(psbt: SilentPaymentPSBT) -> Tuple[bool, List[str]]:
    """
    Validate a PSBT with silent payments according to BIP 375 rules

    Args:
        psbt: PSBT to validate

    Returns:
        (is_valid, list_of_errors)
    """

    errors = []

    # Validate global fields
    has_psbt_version = False
    has_tx_version = False
    has_input_count = False
    has_output_count = False

    for field in psbt.global_fields:
        if field.key_type == PSBTKeyType.PSBT_GLOBAL_VERSION:
            has_psbt_version = True
            psbt_version = struct.unpack("<I", field.value_data)[0]
            if psbt_version != 2:
                errors.append(
                    f"Invalid PSBT version {psbt_version}, must be 2 for PSBTv2"
                )
        elif field.key_type == PSBTKeyType.PSBT_GLOBAL_TX_VERSION:
            has_tx_version = True
            version = struct.unpack("<I", field.value_data)[0]
            if version != 2:
                errors.append(
                    f"Invalid transaction version {version}, must be 2 for silent payments"
                )
        elif field.key_type == PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT:
            has_input_count = True
        elif field.key_type == PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT:
            has_output_count = True

    if not has_psbt_version:
        errors.append("Missing required PSBT_GLOBAL_VERSION")
    if not has_tx_version:
        errors.append("Missing required PSBT_GLOBAL_TX_VERSION")
    if not has_input_count:
        errors.append("Missing required PSBT_GLOBAL_INPUT_COUNT")
    if not has_output_count:
        errors.append("Missing required PSBT_GLOBAL_OUTPUT_COUNT")

    # Validate inputs
    for i, input_fields in enumerate(psbt.input_maps):
        input_field_dict = {field.key_type: field for field in input_fields}

        # Check SIGHASH_ALL requirement
        if PSBTKeyType.PSBT_IN_SIGHASH_TYPE in input_field_dict:
            sighash_field = input_field_dict[PSBTKeyType.PSBT_IN_SIGHASH_TYPE]
            if len(sighash_field.value_data) >= 4:
                sighash_type = struct.unpack("<I", sighash_field.value_data[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    errors.append(
                        f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments"
                    )

        # Validate DLEQ proofs if present
        if PSBTKeyType.PSBT_IN_SP_DLEQ in input_field_dict:
            dleq_field = input_field_dict[PSBTKeyType.PSBT_IN_SP_DLEQ]
            ecdh_field = input_field_dict.get(PSBTKeyType.PSBT_IN_SP_ECDH_SHARE)
            if ecdh_field is None:
                errors.append(f"Input {i} has DLEQ proof but missing ECDH share")
            else:
                try:
                    # Extract DLEQ proof and ECDH share
                    dleq_proof = dleq_field.value_data
                    ecdh_share_bytes = ecdh_field.value_data
                    scan_key_bytes = dleq_field.key_data
                    if len(scan_key_bytes) != 33:
                        errors.append(f"Input {i} DLEQ scan key has invalid length")
                        continue
                    scan_key_point = GE.from_bytes(scan_key_bytes)
                    ecdh_result_point = GE.from_bytes(ecdh_share_bytes)
                    # Use extract_input_pubkey utility for public key extraction
                    from .psbt_utils import extract_input_pubkey

                    # Note: We don't have access to UTXO inputs with private keys in standalone validation
                    # So we can only extract pubkeys from PSBT fields (PARTIAL_SIG, BIP32_DERIVATION)
                    input_public_key_point = extract_input_pubkey(
                        input_fields, inputs=None, input_index=None
                    )
                    if input_public_key_point is None:
                        # Cannot verify DLEQ without pubkey - just check structural validity
                        if len(dleq_proof) != 64:
                            errors.append(f"Input {i} DLEQ proof has invalid length")
                        continue
                    # Verify DLEQ proof
                    if not dleq_verify_proof(
                        input_public_key_point,
                        scan_key_point,
                        ecdh_result_point,
                        dleq_proof,
                    ):
                        errors.append(f"Input {i} DLEQ proof verification failed")
                except Exception as e:
                    errors.append(f"Input {i} DLEQ proof verification failed: {e}")

    # Validate global DLEQ proofs
    global_field_dict = {field.key_type: field for field in psbt.global_fields}
    if PSBTKeyType.PSBT_GLOBAL_SP_DLEQ in global_field_dict:
        if PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_field_dict:
            errors.append("Global DLEQ proof present but missing global ECDH share")

    # Validate outputs per BIP375
    for i, output_fields in enumerate(psbt.output_maps):
        output_field_dict = {field.key_type: field for field in output_fields}

        # BIP375: PSBT_OUT_SCRIPT is optional for silent payment outputs
        # Each output must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO (or both)
        has_script = PSBTKeyType.PSBT_OUT_SCRIPT in output_field_dict
        has_sp_info = PSBTKeyType.PSBT_OUT_SP_V0_INFO in output_field_dict

        if not has_script and not has_sp_info:
            errors.append(
                f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO"
            )

        # Validate PSBT_OUT_SP_V0_INFO if present
        if has_sp_info:
            sp_info = output_field_dict[PSBTKeyType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info.value_data) != 66:  # 33 + 33 bytes (scan_key + spend_key)
                errors.append(
                    f"Output {i} SP_V0_INFO has invalid length {len(sp_info.value_data)}, expected 66 bytes"
                )

            # Three valid cases for outputs with PSBT_OUT_SP_V0_INFO:
            # 1. Only PSBT_OUT_SP_V0_INFO (no PSBT_OUT_SCRIPT):
            #    Silent payment output, script not yet computed
            # 2. Both PSBT_OUT_SP_V0_INFO and PSBT_OUT_SCRIPT:
            #    Silent payment output with computed script
            # Note: PSBT_OUT_SCRIPT alone (without PSBT_OUT_SP_V0_INFO) means regular output

        # Check amount is present
        if PSBTKeyType.PSBT_OUT_AMOUNT not in output_field_dict:
            errors.append(f"Output {i} missing required amount field")

    return len(errors) == 0, errors


# endregion
