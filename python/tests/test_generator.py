#!/usr/bin/env python3
"""
Refactored BIP-375 Test Vector Generator

Configuration-driven system for generating test vectors with support for large PSBTs.
Organized by validation type → input/output type → complexity.
"""

import json
import hashlib
import struct
import base64
import sys
import os
import yaml
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dleq_374 import dleq_generate_proof
from psbt_sp.bip352_crypto import compute_bip352_output_script
from psbt_sp.crypto import Wallet
from psbt_sp.serialization import create_witness_utxo
from psbt_sp.psbt import SilentPaymentPSBT
from psbt_sp.constants import PSBTKeyType


# ============================================================================
# Core Data Structures
# ============================================================================


class InputType(Enum):
    P2WPKH = "p2wpkh"
    P2SH_MULTISIG = "p2sh_multisig"
    P2WSH_MULTISIG = "p2wsh_multisig"
    P2TR = "p2tr"  # TODO: Implement when needed


class OutputType(Enum):
    SILENT_PAYMENT = "silent_payment"
    REGULAR_P2TR = "regular_p2tr"
    REGULAR_P2WPKH = "regular_p2wpkh"


class ValidationResult(Enum):
    VALID = "valid"
    INVALID = "invalid"


@dataclass
class InputSpec:
    """Specification for creating a PSBT input"""

    input_type: InputType
    amount: int
    sequence: int = 0xFFFFFFFE
    # Type-specific parameters
    multisig_threshold: Optional[int] = None
    multisig_pubkey_count: Optional[int] = None
    key_derivation_suffix: str = ""  # For deterministic key generation

    def __setattr__(self, name, value):
        """Allow dynamic attributes for error injection"""
        super().__setattr__(name, value)


@dataclass
class OutputSpec:
    """Specification for creating a PSBT output"""

    output_type: OutputType
    amount: int
    # Silent payment specific
    scan_key_id: Optional[str] = None  # References scan key from scenario
    spend_key_id: Optional[str] = None
    label: Optional[int] = None
    force_wrong_script: bool = False  # For testing wrong addresses


@dataclass
class ScanKeySpec:
    """Specification for a scan/spend key pair"""

    key_id: str
    derivation_suffix: str = ""  # For deterministic generation


@dataclass
class TestScenario:
    """Complete specification for a test case"""

    description: str
    validation_result: ValidationResult
    inputs: List[InputSpec]
    outputs: List[OutputSpec]
    scan_keys: List[ScanKeySpec]

    # Error injection for invalid tests
    missing_dleq_for_input: Optional[int] = None
    invalid_dleq_for_input: Optional[int] = None
    wrong_sighash_for_input: Optional[int] = None
    missing_ecdh_for_input: Optional[int] = None
    wrong_sp_info_size: bool = False
    missing_global_dleq: bool = False
    use_global_ecdh: bool = False  # vs per-input

    # New error injection types
    use_segwit_v2_input: bool = False
    set_tx_modifiable: bool = False
    missing_sp_info_field: bool = False
    wrong_ecdh_share_size: bool = False
    wrong_dleq_proof_size: bool = False
    missing_ecdh_for_scan_key: Optional[str] = None
    missing_dleq_for_scan_key: Optional[str] = None
    invalid_dleq_for_scan_key: Optional[str] = None
    # Flag to explicitly inject ECDH shares into ineligible inputs (for invalid test cases)
    inject_ineligible_ecdh: bool = False
    force_output_script: bool = False


# ============================================================================
# Specialized Input Factories
# ============================================================================


class InputFactory:
    """Creates PSBT inputs based on specifications"""

    def __init__(self, wallet: Wallet, base_seed: str = "deterministic_test"):
        self.wallet = wallet
        self.base_seed = base_seed

    def create_input(
        self,
        spec: InputSpec,
        input_index: int,
        scenario: Optional["TestScenario"] = None,
    ) -> Dict[str, Any]:
        """Create input based on specification"""
        if scenario and scenario.use_segwit_v2_input:
            spec.use_segwit_v2 = True

        if spec.input_type == InputType.P2WPKH:
            return self._create_p2wpkh_input(spec, input_index)
        elif spec.input_type == InputType.P2SH_MULTISIG:
            return self._create_p2sh_multisig_input(spec, input_index)
        elif spec.input_type == InputType.P2WSH_MULTISIG:
            return self._create_p2wsh_multisig_input(spec, input_index)
        elif spec.input_type == InputType.P2TR:
            return self._create_p2tr_input(spec, input_index)  # TODO
        else:
            raise ValueError(f"Unknown input type: {spec.input_type}")

    def _create_p2wpkh_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2WPKH input"""
        # Deterministic key generation
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", hash(key_suffix) % 1000
        )

        # Create prevout
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_prevout_{input_index}".encode()
        ).digest()

        # Create P2WPKH script: OP_0 OP_PUSHBYTES_20 <20-byte-hash160(pubkey)>
        # Error injection: Use segwit v2 instead of v0
        segwit_version = (
            0x02
            if hasattr(spec, "use_segwit_v2") and getattr(spec, "use_segwit_v2", False)
            else 0x00
        )
        witness_script = (
            bytes([segwit_version, 0x14])
            + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(spec.amount, witness_script)

        return {
            "input_index": input_index,
            "input_type": InputType.P2WPKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": segwit_version
            == 0x00,  # Only v0 segwit is eligible for silent payments
        }

    def _create_p2sh_multisig_input(
        self, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Create P2SH multisig input"""
        threshold = spec.multisig_threshold or 2
        pubkey_count = spec.multisig_pubkey_count or 2

        # Generate multiple keys for multisig
        keys = []
        for i in range(pubkey_count):
            key_suffix = f"{spec.key_derivation_suffix}_{input_index}_{i}"
            priv_key, pub_key = self.wallet.create_key_pair(
                "multisig", hash(key_suffix) % 1000
            )
            keys.append((priv_key, pub_key))

        # Create redeem script: OP_M <pubkey1> <pubkey2> ... OP_N OP_CHECKMULTISIG
        redeem_script = bytes([0x50 + threshold])  # OP_M
        for _, pub_key in keys:
            redeem_script += bytes([0x21]) + pub_key.to_bytes_compressed()
        redeem_script += bytes([0x50 + pubkey_count, 0xAE])  # OP_N OP_CHECKMULTISIG

        # P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        redeem_script_hash = hashlib.new(
            "ripemd160", hashlib.sha256(redeem_script).digest()
        ).digest()
        script_pubkey = bytes([0xA9, 0x14]) + redeem_script_hash + bytes([0x87])

        # Create non-witness UTXO for P2SH
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_p2sh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prevout_txid, spec.amount, script_pubkey)

        return {
            "input_index": input_index,
            "input_type": InputType.P2SH_MULTISIG,
            "private_keys": [priv for priv, _ in keys],
            "public_keys": [pub for _, pub in keys],
            "public_key": keys[0][1]
            if keys
            else None,  # First public key for compatibility
            "prevout_txid": hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest(),
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "redeem_script": redeem_script,
            "prev_tx": prev_tx,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": False,  # P2SH multisig not eligible for silent payments
        }

    def _create_p2wsh_multisig_input(
        self, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Create P2WSH multisig input"""
        threshold = spec.multisig_threshold or 2
        pubkey_count = spec.multisig_pubkey_count or 2

        # Generate multiple keys for multisig
        keys = []
        for i in range(pubkey_count):
            key_suffix = f"{spec.key_derivation_suffix}_{input_index}_{i}"
            priv_key, pub_key = self.wallet.create_key_pair(
                "wsh_multisig", hash(key_suffix) % 1000
            )
            keys.append((priv_key, pub_key))

        # Create witness script (same as P2SH redeem script)
        witness_script = bytes([0x50 + threshold])  # OP_M
        for _, pub_key in keys:
            witness_script += bytes([0x21]) + pub_key.to_bytes_compressed()
        witness_script += bytes([0x50 + pubkey_count, 0xAE])  # OP_N OP_CHECKMULTISIG

        # P2WSH scriptPubKey: OP_0 <32-byte SHA256 hash>
        witness_script_hash = hashlib.sha256(witness_script).digest()
        script_pubkey = bytes([0x00, 0x20]) + witness_script_hash

        # Create witness UTXO
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_p2wsh_prevout_{input_index}".encode()
        ).digest()
        witness_utxo = create_witness_utxo(spec.amount, script_pubkey)

        return {
            "input_index": input_index,
            "input_type": InputType.P2WSH_MULTISIG,
            "private_keys": [priv for priv, _ in keys],
            "public_keys": [pub for _, pub in keys],
            "public_key": keys[0][1]
            if keys
            else None,  # First public key for compatibility
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": False,  # P2WSH multisig not eligible for silent payments
        }

    def _create_p2tr_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2TR input - TODO: Implement when needed"""
        # TODO: Implement P2TR input creation
        # Will need taproot key generation and script construction
        raise NotImplementedError("P2TR inputs not yet implemented")

    def _create_prev_tx(
        self, prev_input_txid: bytes, amount: int, script_pubkey: bytes
    ) -> bytes:
        """Create a previous transaction for non-witness UTXOs"""
        prev_tx = bytes([0x02, 0x00, 0x00, 0x00])  # version
        prev_tx += bytes([0x01])  # 1 input
        prev_tx += prev_input_txid  # prev txid
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # prev vout
        prev_tx += bytes([0x00])  # empty scriptSig
        prev_tx += bytes([0xFF, 0xFF, 0xFF, 0xFF])  # sequence
        prev_tx += bytes([0x01])  # 1 output
        prev_tx += struct.pack("<Q", amount)  # amount
        prev_tx += bytes([len(script_pubkey)]) + script_pubkey
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # locktime
        return prev_tx


# ============================================================================
# Output Factory
# ============================================================================


class OutputFactory:
    """Creates PSBT outputs based on specifications"""

    def __init__(self, wallet: Wallet):
        self.wallet = wallet

    def create_output(
        self, spec: OutputSpec, output_index: int, scan_keys: Dict[str, tuple]
    ) -> Dict[str, Any]:
        """Create output based on specification"""
        if spec.output_type == OutputType.SILENT_PAYMENT:
            return self._create_silent_payment_output(spec, output_index, scan_keys)
        elif spec.output_type == OutputType.REGULAR_P2TR:
            return self._create_regular_p2tr_output(spec, output_index)
        elif spec.output_type == OutputType.REGULAR_P2WPKH:
            return self._create_regular_p2wpkh_output(spec, output_index)
        else:
            raise ValueError(f"Unknown output type: {spec.output_type}")

    def _create_silent_payment_output(
        self, spec: OutputSpec, output_index: int, scan_keys: Dict[str, tuple]
    ) -> Dict[str, Any]:
        """Create silent payment output"""
        if not spec.scan_key_id or spec.scan_key_id not in scan_keys:
            raise ValueError(f"Silent payment output requires valid scan_key_id")

        scan_pub, spend_pub = scan_keys[spec.scan_key_id]

        return {
            "output_index": output_index,
            "output_type": OutputType.SILENT_PAYMENT,
            "amount": spec.amount,
            "scan_pubkey": scan_pub,
            "spend_pubkey": spend_pub,
            "label": spec.label,
            "force_wrong_script": spec.force_wrong_script,
        }

    def _create_regular_p2tr_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2TR output"""
        # Simple P2TR output for testing
        output_script = (
            bytes([0x51, 0x20])
            + hashlib.sha256(f"regular_p2tr_{output_index}".encode()).digest()
        )

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2TR,
            "amount": spec.amount,
            "script": output_script,
        }

    def _create_regular_p2wpkh_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2WPKH output"""
        # Simple P2WPKH output for testing
        pubkey_hash = hashlib.sha256(
            f"regular_p2wpkh_{output_index}".encode()
        ).digest()[:20]
        output_script = bytes([0x00, 0x14]) + pubkey_hash

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2WPKH,
            "amount": spec.amount,
            "script": output_script,
        }


# ============================================================================
# PSBT Builder
# ============================================================================


class PSBTBuilder:
    """Builds PSBTs from test scenarios"""

    def __init__(self, wallet: Wallet, base_seed: str = "deterministic_test"):
        self.wallet = wallet
        self.base_seed = base_seed
        self.input_factory = InputFactory(wallet, base_seed)
        self.output_factory = OutputFactory(wallet)

    def build_psbt(self, scenario: TestScenario) -> Dict[str, Any]:
        """Build a complete PSBT from a test scenario"""
        # Create base PSBT structure
        psbt = self._create_psbt_base(
            len(scenario.inputs), len(scenario.outputs), scenario
        )

        # Generate scan keys deterministically
        scan_keys = self._generate_scan_keys(scenario.scan_keys)

        # Create inputs
        input_data = []
        for i, input_spec in enumerate(scenario.inputs):
            input_info = self.input_factory.create_input(input_spec, i, scenario)
            input_data.append(input_info)
            self._add_input_to_psbt(psbt, input_info)

        # Create outputs
        output_data = []
        for i, output_spec in enumerate(scenario.outputs):
            output_info = self.output_factory.create_output(output_spec, i, scan_keys)
            output_data.append(output_info)

        # Compute ECDH shares for silent payment outputs
        ecdh_data = self._compute_ecdh_shares(input_data, scan_keys, scenario)

        # Add ECDH shares to PSBT (with error injection)
        self._add_ecdh_shares_to_psbt(psbt, ecdh_data, scenario)

        # Compute and add outputs to PSBT
        self._add_outputs_to_psbt(psbt, output_data, input_data, ecdh_data, scenario)

        # Build result structure
        return {
            "psbt": psbt,
            "input_data": input_data,
            "output_data": output_data,
            "scan_keys": scan_keys,
            "ecdh_data": ecdh_data,
            "scenario": scenario,
        }

    def _create_psbt_base(
        self, num_inputs: int, num_outputs: int, scenario: TestScenario
    ) -> SilentPaymentPSBT:
        """Create PSBT v2 base structure"""
        psbt = SilentPaymentPSBT()

        # Add required global fields for PSBT v2
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_VERSION, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_TX_VERSION, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT, b"", struct.pack("<I", num_inputs)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT, b"", struct.pack("<I", num_outputs)
        )

        # Error injection: Set TX_MODIFIABLE to invalid value
        if scenario.set_tx_modifiable:
            psbt.add_global_field(
                PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE, b"", b"\x01"
            )  # Modifiable
        else:
            psbt.add_global_field(
                PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE, b"", b"\x00"
            )  # Not modifiable

        return psbt

    def _generate_scan_keys(
        self, scan_key_specs: List[ScanKeySpec]
    ) -> Dict[str, tuple]:
        """Generate scan/spend key pairs deterministically"""
        scan_keys = {}

        for spec in scan_key_specs:
            if spec.key_id == "default":
                # Use wallet's default keys
                scan_keys[spec.key_id] = (self.wallet.scan_pub, self.wallet.spend_pub)
            else:
                # Generate deterministic keys
                seed_suffix = hash(f"{spec.key_id}_{spec.derivation_suffix}") % 1000
                scan_priv, scan_pub = self.wallet.create_key_pair("scan", seed_suffix)
                spend_priv, spend_pub = self.wallet.create_key_pair(
                    "spend", seed_suffix
                )
                scan_keys[spec.key_id] = (scan_pub, spend_pub)

        return scan_keys

    def _add_input_to_psbt(self, psbt: SilentPaymentPSBT, input_info: Dict[str, Any]):
        """Add input fields to PSBT based on input type"""
        idx = input_info["input_index"]
        input_type = input_info["input_type"]

        # Add common fields
        psbt.add_input_field(
            idx, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", input_info["prevout_txid"]
        )
        psbt.add_input_field(
            idx,
            PSBTKeyType.PSBT_IN_OUTPUT_INDEX,
            b"",
            struct.pack("<I", input_info["prevout_index"]),
        )
        psbt.add_input_field(
            idx,
            PSBTKeyType.PSBT_IN_SEQUENCE,
            b"",
            struct.pack("<I", input_info["sequence"]),
        )

        if input_type == InputType.P2WPKH:
            # Add witness UTXO and BIP32 derivation
            psbt.add_input_field(
                idx, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", input_info["witness_utxo"]
            )
            # Add BIP32 derivation for pubkey exposure
            fake_derivation = struct.pack("<I", 0x80000000) + struct.pack(
                "<I", idx
            )  # m/0'/idx'
            psbt.add_input_field(
                idx,
                PSBTKeyType.PSBT_IN_BIP32_DERIVATION,
                input_info["public_key"].bytes,
                fake_derivation,
            )

        elif input_type == InputType.P2SH_MULTISIG:
            # Add non-witness UTXO and redeem script
            psbt.add_input_field(
                idx, PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO, b"", input_info["prev_tx"]
            )
            psbt.add_input_field(
                idx, PSBTKeyType.PSBT_IN_REDEEM_SCRIPT, b"", input_info["redeem_script"]
            )

        elif input_type == InputType.P2WSH_MULTISIG:
            # Add witness UTXO and witness script
            psbt.add_input_field(
                idx, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", input_info["witness_utxo"]
            )
            psbt.add_input_field(
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_SCRIPT,
                b"",
                input_info["witness_script"],
            )

    def _compute_ecdh_shares(
        self,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
        scenario: TestScenario,
    ) -> Dict:
        """Compute ECDH shares for eligible inputs"""
        ecdh_shares = {}  # (input_idx, scan_key_id) -> (ecdh_result, dleq_proof)

        eligible_inputs = [inp for inp in input_data if inp["is_eligible"]]

        for input_info in eligible_inputs:
            input_idx = input_info["input_index"]

            # Skip if error injection says to skip this input
            if scenario.missing_ecdh_for_input == input_idx:
                continue

            private_key = input_info["private_key"]

            for scan_key_id, (scan_pub, _) in scan_keys.items():
                # Skip ECDH for specific scan key (affects all inputs)
                if scenario.missing_ecdh_for_scan_key == scan_key_id:
                    continue

                # Compute ECDH share
                ecdh_result = private_key * scan_pub

                # Generate DLEQ proof (with potential error injection)
                if (
                    scenario.invalid_dleq_for_input == input_idx
                    or scenario.invalid_dleq_for_scan_key == scan_key_id
                ):
                    # Use wrong private key for invalid proof
                    wrong_priv, _ = self.wallet.create_key_pair("wrong", 999)
                    dleq_proof = dleq_generate_proof(
                        wrong_priv, scan_pub, self.wallet.random_bytes(32)
                    )
                elif (
                    scenario.missing_dleq_for_input == input_idx
                    or scenario.missing_dleq_for_scan_key == scan_key_id
                ):
                    dleq_proof = None
                else:
                    # Normal valid proof
                    random_bytes = hashlib.sha256(
                        f"{self.base_seed}_dleq_{input_idx}_{scan_key_id}".encode()
                    ).digest()
                    dleq_proof = dleq_generate_proof(
                        private_key, scan_pub, random_bytes
                    )

                    # Error injection: Wrong DLEQ proof size
                    if scenario.wrong_dleq_proof_size:
                        dleq_proof = dleq_proof[:63]  # Truncate to wrong size

                ecdh_shares[(input_idx, scan_key_id)] = (ecdh_result, dleq_proof)

        return ecdh_shares

    def _add_ecdh_shares_to_psbt(
        self, psbt: SilentPaymentPSBT, ecdh_data: Dict, scenario: TestScenario
    ):
        """Add ECDH shares and DLEQ proofs to PSBT"""
        if scenario.use_global_ecdh:
            self._add_global_ecdh_shares(psbt, ecdh_data, scenario)
        else:
            self._add_per_input_ecdh_shares(psbt, ecdh_data, scenario)

        # Error injection: Add ECDH share for ineligible input (only when explicitly requested)
        if scenario.inject_ineligible_ecdh:
            self._inject_ineligible_input_ecdh_shares(psbt, scenario)

    def _add_per_input_ecdh_shares(
        self, psbt: SilentPaymentPSBT, ecdh_data: Dict, scenario: TestScenario
    ):
        """Add per-input ECDH shares"""
        scan_keys = self._generate_scan_keys(scenario.scan_keys)

        # Track which inputs have been processed to add sighash type
        processed_inputs = set()

        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in ecdh_data.items():
            if scan_key_id not in scan_keys:
                continue

            scan_pub = scan_keys[scan_key_id][0]

            # Add ECDH share with potential error injection
            ecdh_bytes = ecdh_result.to_bytes_compressed()
            if scenario.wrong_ecdh_share_size:
                ecdh_bytes = ecdh_bytes[:32]  # Wrong size: 32 instead of 33 bytes

            psbt.add_input_field(
                input_idx, PSBTKeyType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_bytes
            )

            # Add DLEQ proof (if not missing due to error injection)
            if dleq_proof is not None:
                psbt.add_input_field(
                    input_idx, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof
                )

            # Add sighash type only once per input
            if input_idx not in processed_inputs:
                sighash_type = (
                    0x02 if scenario.wrong_sighash_for_input == input_idx else 0x01
                )
                psbt.add_input_field(
                    input_idx,
                    PSBTKeyType.PSBT_IN_SIGHASH_TYPE,
                    b"",
                    struct.pack("<I", sighash_type),
                )
                processed_inputs.add(input_idx)

    def _add_global_ecdh_shares(
        self, psbt: SilentPaymentPSBT, ecdh_data: Dict, scenario: TestScenario
    ):
        """Add global ECDH shares"""
        # Group by scan key and sum ECDH shares
        global_shares = {}  # scan_key_id -> summed_ecdh

        for (input_idx, scan_key_id), (ecdh_result, _) in ecdh_data.items():
            if scan_key_id not in global_shares:
                global_shares[scan_key_id] = ecdh_result
            else:
                global_shares[scan_key_id] += ecdh_result

        scan_keys = self._generate_scan_keys(scenario.scan_keys)

        for scan_key_id, summed_ecdh in global_shares.items():
            scan_pub = scan_keys[scan_key_id][0]

            # Add global ECDH share
            psbt.add_global_field(
                PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE,
                scan_pub.bytes,
                summed_ecdh.to_bytes_compressed(),
            )

            # Add global DLEQ proof (if not missing due to error injection)
            if not scenario.missing_global_dleq:
                # For global DLEQ, we need to prove sum of private keys
                # Sum all private keys from eligible inputs for this scan key
                summed_private_key = None
                eligible_inputs = self._get_eligible_inputs_from_scenario(scenario)

                for (input_idx, sk_id), (ecdh_result, _) in ecdh_data.items():
                    if sk_id == scan_key_id:
                        # Find the corresponding input data to get private key
                        input_data = [
                            inp
                            for inp in eligible_inputs
                            if inp["input_index"] == input_idx
                        ]
                        if input_data:
                            inp_priv_key = input_data[0]["private_key"]
                            if summed_private_key is None:
                                summed_private_key = inp_priv_key
                            else:
                                summed_private_key = summed_private_key + inp_priv_key

                if summed_private_key is not None:
                    # Generate valid DLEQ proof with summed private key
                    random_bytes = hashlib.sha256(
                        f"{self.base_seed}_global_dleq_{scan_key_id}".encode()
                    ).digest()
                    global_dleq_proof = dleq_generate_proof(
                        summed_private_key, scan_pub, random_bytes
                    )
                    psbt.add_global_field(
                        PSBTKeyType.PSBT_GLOBAL_SP_DLEQ,
                        scan_pub.bytes,
                        global_dleq_proof,
                    )

    def _get_eligible_inputs_from_scenario(
        self, scenario: TestScenario
    ) -> List[Dict[str, Any]]:
        """Get eligible inputs from the current scenario"""
        eligible_inputs = []
        for i, input_spec in enumerate(scenario.inputs):
            input_info = self.input_factory.create_input(input_spec, i, scenario)
            if input_info.get("is_eligible", False):
                eligible_inputs.append(input_info)
        return eligible_inputs

    def _inject_ineligible_input_ecdh_shares(
        self, psbt: SilentPaymentPSBT, scenario: TestScenario
    ):
        """Error injection: Add ECDH shares for ineligible inputs"""
        # Check if we have ineligible inputs that should incorrectly have ECDH shares
        for i, input_spec in enumerate(scenario.inputs):
            input_info = self.input_factory.create_input(input_spec, i, scenario)
            if not input_info.get("is_eligible", False):
                # This is an ineligible input - inject ECDH share to make PSBT invalid
                scan_keys = self._generate_scan_keys(scenario.scan_keys)
                if scan_keys:
                    scan_key_id, (scan_pub, _) = next(iter(scan_keys.items()))
                    # Create fake ECDH share
                    fake_ecdh_bytes = hashlib.sha256(
                        f"fake_ecdh_{i}".encode()
                    ).digest()[:33]
                    fake_dleq = b"\x00" * 64

                    psbt.add_input_field(
                        i,
                        PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
                        scan_pub.bytes,
                        fake_ecdh_bytes,
                    )
                    psbt.add_input_field(
                        i, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, fake_dleq
                    )
                break

    def _add_outputs_to_psbt(
        self,
        psbt: SilentPaymentPSBT,
        output_data: List[Dict],
        input_data: List[Dict],
        ecdh_data: Dict,
        scenario: TestScenario,
    ):
        """Add outputs to PSBT"""
        for output_info in output_data:
            idx = output_info["output_index"]
            output_type = output_info["output_type"]

            # Add amount
            psbt.add_output_field(
                idx,
                PSBTKeyType.PSBT_OUT_AMOUNT,
                b"",
                struct.pack("<Q", output_info["amount"]),
            )

            if output_type == OutputType.SILENT_PAYMENT:
                self._add_silent_payment_output(
                    psbt, output_info, input_data, ecdh_data, scenario
                )
            else:
                # Regular output - just add script
                psbt.add_output_field(
                    idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_info["script"]
                )

    def _add_silent_payment_output(
        self,
        psbt: SilentPaymentPSBT,
        output_info: Dict,
        input_data: List[Dict],
        ecdh_data: Dict,
        scenario: TestScenario,
    ):
        """Add silent payment output with proper BIP-352 script computation"""
        idx = output_info["output_index"]
        scan_pub = output_info["scan_pubkey"]
        spend_pub = output_info["spend_pubkey"]

        if output_info["force_wrong_script"]:
            # Force wrong script for address mismatch tests
            wrong_script = (
                bytes([0x51, 0x20]) + hashlib.sha256(b"wrong_address").digest()
            )
            psbt.add_output_field(idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", wrong_script)
        else:
            # Compute proper BIP-352 script
            eligible_inputs = [
                inp for inp in input_data if inp.get("is_eligible", False)
            ]

            if eligible_inputs and ecdh_data:
                # Create outpoints
                outpoints = [
                    (inp["prevout_txid"], inp["prevout_index"])
                    for inp in eligible_inputs
                ]

                # Sum all eligible input public keys (proper BIP-352 implementation)
                summed_pubkey = None
                for inp in eligible_inputs:
                    if summed_pubkey is None:
                        summed_pubkey = inp["public_key"]
                    else:
                        summed_pubkey = summed_pubkey + inp["public_key"]

                summed_pubkey_bytes = summed_pubkey.bytes

                # Get ECDH share for this scan key - find the scan key ID
                scan_key_id = None
                scan_keys = self._generate_scan_keys(scenario.scan_keys)
                for key_id, (key_scan_pub, _) in scan_keys.items():
                    if key_scan_pub == scan_pub:
                        scan_key_id = key_id
                        break

                if scan_key_id:
                    # Check if ALL eligible inputs have ECDH shares for complete coverage
                    eligible_input_indices = [
                        inp["input_index"] for inp in eligible_inputs
                    ]
                    inputs_with_ecdh = set()
                    summed_ecdh_share = None

                    for (inp_idx, sk_id), (ecdh_result, _) in ecdh_data.items():
                        if sk_id == scan_key_id and inp_idx in eligible_input_indices:
                            inputs_with_ecdh.add(inp_idx)
                            if summed_ecdh_share is None:
                                summed_ecdh_share = ecdh_result
                            else:
                                summed_ecdh_share = summed_ecdh_share + ecdh_result

                    # Only generate output script if ALL eligible inputs have ECDH shares OR force_output_script is set
                    coverage_complete = len(inputs_with_ecdh) == len(
                        eligible_input_indices
                    )

                    if coverage_complete:
                        ecdh_share_bytes = summed_ecdh_share.to_bytes_compressed()

                        # Compute BIP-352 output script
                        output_script = compute_bip352_output_script(
                            outpoints=outpoints,
                            summed_pubkey_bytes=summed_pubkey_bytes,
                            ecdh_share_bytes=ecdh_share_bytes,
                            spend_pubkey_bytes=spend_pub.bytes,
                            k=idx,  # k is the output index
                        )
                        psbt.add_output_field(
                            idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script
                        )
                    elif scenario.force_output_script:
                        wrong_script = (
                            bytes([0x51, 0x20]) + hashlib.sha256(b"wrong_address").digest()
                        )
                        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", wrong_script)
                        

        # Add SP_V0_INFO field (unless error injection says to skip it)
        if not scenario.missing_sp_info_field:
            sp_info = scan_pub.bytes + spend_pub.bytes
            if scenario.wrong_sp_info_size:
                sp_info = sp_info[:65]  # Wrong size (65 instead of 66)

            psbt.add_output_field(idx, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        # Add label if specified (this will create invalid PSBT if SP_V0_INFO is missing)
        if output_info.get("label") is not None:
            psbt.add_output_field(
                idx,
                PSBTKeyType.PSBT_OUT_SP_V0_LABEL,
                b"",
                struct.pack("<I", output_info["label"]),
            )


# ============================================================================
# Configuration-Based Test Generator
# ============================================================================


class ConfigBasedTestGenerator:
    """Generates test vectors from YAML configurations"""

    def __init__(self, base_seed: str = "bip375_deterministic_seed"):
        self.wallet = Wallet(base_seed)
        self.base_seed = base_seed
        self.builder = PSBTBuilder(self.wallet, base_seed)

    def load_test_scenarios_from_config(self, config_path: str) -> List[TestScenario]:
        """Load test scenarios from YAML configuration"""
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        scenarios = []
        for test_config in config.get("test_cases", []):
            scenario = self._parse_test_config(test_config)
            scenarios.append(scenario)

        return scenarios

    def _parse_test_config(self, config: Dict[str, Any]) -> TestScenario:
        """Parse a single test configuration into TestScenario"""
        # Parse inputs
        inputs = []
        for input_config in config.get("inputs", []):
            input_spec = InputSpec(
                input_type=InputType(input_config["type"]),
                amount=input_config.get("amount", 100000),
                sequence=input_config.get("sequence", 0xFFFFFFFE),
                multisig_threshold=input_config.get("multisig_threshold"),
                multisig_pubkey_count=input_config.get("multisig_pubkey_count"),
                key_derivation_suffix=input_config.get("key_derivation_suffix", ""),
            )

            # Handle batch creation
            count = input_config.get("count", 1)
            for i in range(count):
                # Create unique suffix for batch inputs
                batch_spec = InputSpec(
                    input_type=input_spec.input_type,
                    amount=input_spec.amount,
                    sequence=input_spec.sequence,
                    multisig_threshold=input_spec.multisig_threshold,
                    multisig_pubkey_count=input_spec.multisig_pubkey_count,
                    key_derivation_suffix=f"{input_spec.key_derivation_suffix}_batch_{i}",
                )
                inputs.append(batch_spec)

        # Parse outputs
        outputs = []
        for output_config in config.get("outputs", []):
            output_spec = OutputSpec(
                output_type=OutputType(output_config["type"]),
                amount=output_config.get("amount", 95000),
                scan_key_id=output_config.get("scan_key_id"),
                spend_key_id=output_config.get("spend_key_id"),
                label=output_config.get("label"),
                force_wrong_script=output_config.get("force_wrong_script", False),
            )

            # Handle batch creation
            count = output_config.get("count", 1)
            for i in range(count):
                outputs.append(output_spec)

        # Parse scan keys
        scan_keys = []
        for key_config in config.get("scan_keys", [{"key_id": "default"}]):
            scan_key_spec = ScanKeySpec(
                key_id=key_config["key_id"],
                derivation_suffix=key_config.get("derivation_suffix", ""),
            )
            scan_keys.append(scan_key_spec)

        # Parse error injection
        error_injection = config.get("error_injection", {})

        return TestScenario(
            description=config["description"],
            validation_result=ValidationResult(
                config.get("validation_result", "valid")
            ),
            inputs=inputs,
            outputs=outputs,
            scan_keys=scan_keys,
            missing_dleq_for_input=error_injection.get("missing_dleq_for_input"),
            invalid_dleq_for_input=error_injection.get("invalid_dleq_for_input"),
            wrong_sighash_for_input=error_injection.get("wrong_sighash_for_input"),
            missing_ecdh_for_input=error_injection.get("missing_ecdh_for_input"),
            wrong_sp_info_size=error_injection.get("wrong_sp_info_size", False),
            missing_global_dleq=error_injection.get("missing_global_dleq", False),
            use_global_ecdh=error_injection.get("use_global_ecdh", False),
            # New error injection types
            use_segwit_v2_input=error_injection.get("use_segwit_v2_input", False),
            set_tx_modifiable=error_injection.get("set_tx_modifiable", False),
            missing_sp_info_field=error_injection.get("missing_sp_info_field", False),
            wrong_ecdh_share_size=error_injection.get("wrong_ecdh_share_size", False),
            wrong_dleq_proof_size=error_injection.get("wrong_dleq_proof_size", False),
            missing_ecdh_for_scan_key=error_injection.get("missing_ecdh_for_scan_key"),
            missing_dleq_for_scan_key=error_injection.get("missing_dleq_for_scan_key"),
            invalid_dleq_for_scan_key=error_injection.get("invalid_dleq_for_scan_key"),
            inject_ineligible_ecdh=error_injection.get("inject_ineligible_ecdh", False),
            force_output_script=error_injection.get("force_output_script", False),
        )

    def generate_test_vector_from_scenario(
        self, scenario: TestScenario
    ) -> Dict[str, Any]:
        """Generate a test vector from a scenario"""
        # Build PSBT
        psbt_data = self.builder.build_psbt(scenario)
        psbt = psbt_data["psbt"]

        # Convert to GenTestVector format for compatibility
        input_keys = []
        for inp in psbt_data["input_data"]:
            # Handle both single and multi-key inputs
            private_key = None
            public_key = None

            if "private_key" in inp and inp["private_key"] is not None:
                private_key = inp["private_key"]
                public_key = inp["public_key"]
            elif (
                "private_keys" in inp
                and inp["private_keys"]
                and len(inp["private_keys"]) > 0
            ):
                # For multi-key inputs, use the first key
                private_key = inp["private_keys"][0]
                public_key = (
                    inp["public_keys"][0]
                    if inp["public_keys"]
                    else inp.get("public_key")
                )
            elif "public_key" in inp and inp["public_key"] is not None:
                # Use the existing public key but no private key for multisig
                public_key = inp["public_key"]
                private_key = (
                    inp.get("private_keys", [None])[0]
                    if inp.get("private_keys")
                    else None
                )

            if private_key is None or public_key is None:
                # Fallback - create a dummy key
                fallback_priv, fallback_pub = self.builder.wallet.create_key_pair(
                    "dummy", inp["input_index"]
                )
                private_key = private_key or fallback_priv
                public_key = public_key or fallback_pub

            input_key = {
                "input_index": inp["input_index"],
                "private_key": private_key.hex
                if hasattr(private_key, "hex")
                else str(private_key),
                "public_key": public_key.hex
                if hasattr(public_key, "hex")
                else str(public_key),
                "prevout_txid": inp["prevout_txid"].hex(),
                "prevout_index": inp["prevout_index"],
                "prevout_scriptpubkey": inp.get(
                    "witness_script", inp.get("script_pubkey", b"")
                ).hex(),
                "amount": inp["amount"],
                "witness_utxo": inp.get("witness_utxo", inp.get("prev_tx", b"")).hex(),
                "sequence": inp["sequence"],
            }
            input_keys.append(input_key)

        scan_keys = []
        for key_id, (scan_pub, spend_pub) in psbt_data["scan_keys"].items():
            scan_key = {
                "scan_pubkey": scan_pub.hex
                if hasattr(scan_pub, "hex")
                else str(scan_pub),
                "spend_pubkey": spend_pub.hex
                if hasattr(spend_pub, "hex")
                else str(spend_pub),
            }
            scan_keys.append(scan_key)

        expected_ecdh_shares = []
        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in psbt_data[
            "ecdh_data"
        ].items():
            if scan_key_id in psbt_data["scan_keys"]:
                ecdh_share = {
                    "scan_key": psbt_data["scan_keys"][scan_key_id][0].hex
                    if hasattr(psbt_data["scan_keys"][scan_key_id][0], "hex")
                    else str(psbt_data["scan_keys"][scan_key_id][0]),
                    "ecdh_result": ecdh_result.to_bytes_compressed().hex(),
                    "dleq_proof": dleq_proof.hex() if dleq_proof else None,
                    "input_index": input_idx,
                }
                expected_ecdh_shares.append(ecdh_share)

        expected_outputs = []
        for out in psbt_data["output_data"]:
            output = {
                "output_index": out["output_index"],
                "amount": out["amount"],
                "is_silent_payment": out["output_type"] == OutputType.SILENT_PAYMENT,
            }

            if out["output_type"] == OutputType.SILENT_PAYMENT:
                scan_pub = out["scan_pubkey"]
                spend_pub = out["spend_pubkey"]
                output["sp_info"] = (scan_pub.bytes + spend_pub.bytes).hex()
                if out.get("label") is not None:
                    output["sp_label"] = out["label"]
            else:
                output["script"] = out["script"].hex()

            expected_outputs.append(output)

        return {
            "description": scenario.description,
            "psbt": base64.b64encode(psbt.serialize()).decode(),
            "input_keys": input_keys,
            "scan_keys": scan_keys,
            "expected_ecdh_shares": expected_ecdh_shares,
            "expected_outputs": expected_outputs,
            "expected_psbt_id": psbt.compute_unique_id()
            if scenario.validation_result == ValidationResult.VALID
            else None,
        }


# ============================================================================
# Backward Compatibility Layer
# ============================================================================


class TestVectorGenerator:
    """Backward compatibility wrapper for existing interface"""

    def __init__(self, seed: str = "bip375_deterministic_seed"):
        self.config_generator = ConfigBasedTestGenerator(seed)
        self.test_vectors = {
            "description": "BIP-375 Test Vectors (Refactored)",
            "version": "2.0",
            "format_notes": [
                "Generated using configuration-driven approach",
                "All keys are hex-encoded",
                "PSBTs have all necessary fields",
                "Test vectors organized by validation type",
            ],
            "invalid": [],
            "valid": [],
        }

    def generate_all_test_vectors(self) -> Dict:
        """Generate all test vectors using configuration files"""
        # Load test configurations
        test_configs_dir = Path(__file__).parent / "test_configs"

        if not test_configs_dir.exists():
            print(
                f"Warning: {test_configs_dir} does not exist. Creating with sample configs."
            )
            self._create_sample_configs()

        # Load invalid test cases
        invalid_configs = list(test_configs_dir.glob("invalid/**/*.yaml"))
        for config_file in sorted(invalid_configs):
            try:
                scenarios = self.config_generator.load_test_scenarios_from_config(
                    str(config_file)
                )
                for scenario in scenarios:
                    test_vector = (
                        self.config_generator.generate_test_vector_from_scenario(
                            scenario
                        )
                    )
                    self.test_vectors["invalid"].append(test_vector)
            except Exception as e:
                print(f"Error loading {config_file}: {str(e)}")
                import traceback

                traceback.print_exc()

        # Add custom invalid test cases that require manual PSBT construction
        custom_invalid_tests = self.generate_custom_invalid_tests()
        self.test_vectors["invalid"].extend(custom_invalid_tests)

        # Load valid test cases
        valid_configs = list(test_configs_dir.glob("valid/**/*.yaml"))
        for config_file in sorted(valid_configs):
            try:
                scenarios = self.config_generator.load_test_scenarios_from_config(
                    str(config_file)
                )
                for scenario in scenarios:
                    test_vector = (
                        self.config_generator.generate_test_vector_from_scenario(
                            scenario
                        )
                    )
                    self.test_vectors["valid"].append(test_vector)
            except Exception as e:
                print(f"Error loading {config_file}: {str(e)}")
                import traceback

                traceback.print_exc()

        return self.test_vectors

    def _create_sample_configs(self):
        """Create sample configuration files for testing"""
        test_configs_dir = Path(__file__).parent / "test_configs"
        test_configs_dir.mkdir(exist_ok=True)
        (test_configs_dir / "invalid").mkdir(exist_ok=True)
        (test_configs_dir / "valid").mkdir(exist_ok=True)

        # Create a simple sample config
        sample_invalid = {
            "description": "Sample invalid test cases",
            "test_cases": [
                {
                    "description": "Missing DLEQ proof test",
                    "validation_result": "invalid",
                    "inputs": [{"type": "p2wpkh", "amount": 100000}],
                    "outputs": [
                        {
                            "type": "silent_payment",
                            "amount": 95000,
                            "scan_key_id": "default",
                        }
                    ],
                    "scan_keys": [{"key_id": "default"}],
                    "error_injection": {"missing_dleq_for_input": 0},
                }
            ],
        }

        sample_valid = {
            "description": "Sample valid test cases",
            "test_cases": [
                {
                    "description": "Simple valid single input test",
                    "validation_result": "valid",
                    "inputs": [{"type": "p2wpkh", "amount": 100000}],
                    "outputs": [
                        {
                            "type": "silent_payment",
                            "amount": 95000,
                            "scan_key_id": "default",
                        }
                    ],
                    "scan_keys": [{"key_id": "default"}],
                }
            ],
        }

        with open(test_configs_dir / "invalid" / "sample.yaml", "w") as f:
            yaml.dump(sample_invalid, f, default_flow_style=False)

        with open(test_configs_dir / "valid" / "sample.yaml", "w") as f:
            yaml.dump(sample_valid, f, default_flow_style=False)

    def generate_custom_invalid_tests(self) -> List[Dict[str, Any]]:
        """Generate custom invalid test cases that require manual PSBT construction.

        These tests are too complex for the config-driven approach because they require
        specific per-output ECDH share handling that the generic builder cannot express.
        """
        wallet = self.config_generator.wallet
        tests = []

        # Test 15: Two inputs, two outputs with different scan keys;
        # input 1 missing ECDH for scan key B
        tests.append(
            self._generate_incomplete_per_input_ecdh_for_one_scan_key_test(wallet)
        )

        return tests

    def _generate_incomplete_per_input_ecdh_for_one_scan_key_test(
        self, wallet: Wallet
    ) -> Dict[str, Any]:
        """Two inputs, two outputs with different scan keys; input 1 missing ECDH for scan key B.

        This creates an invalid PSBT where:
        - Input 0 has ECDH shares for both scan keys A and B
        - Input 1 has ECDH share only for scan key A (missing B)
        - Output 0 (scan key A) uses correct summed ECDH
        - Output 1 (scan key B) uses incomplete ECDH (only from input 0)
        """
        input0_priv, input0_pub = wallet.input_key_pair(0)
        input1_priv, input1_pub = wallet.input_key_pair(1)

        # Scan key A (default wallet)
        scan_pub_a = wallet.scan_pub
        spend_pub_a = wallet.spend_pub

        # Scan key B (second recipient)
        _, scan_pub_b = wallet.create_key_pair("scan_b", 0)
        _, spend_pub_b = wallet.create_key_pair("spend_b", 0)

        # Input 0: Compute ECDH for both scan keys
        ecdh_result_0a = input0_priv * scan_pub_a
        ecdh_result_0b = input0_priv * scan_pub_b
        random_bytes_0a = hashlib.sha256(b"dleq_0a_custom").digest()
        random_bytes_0b = hashlib.sha256(b"dleq_0b_custom").digest()
        valid_proof_0a = dleq_generate_proof(input0_priv, scan_pub_a, random_bytes_0a)
        valid_proof_0b = dleq_generate_proof(input0_priv, scan_pub_b, random_bytes_0b)

        # Input 1: Compute ECDH only for scan key A (incomplete coverage for B)
        ecdh_result_1a = input1_priv * scan_pub_a
        random_bytes_1a = hashlib.sha256(b"dleq_1a_custom").digest()
        valid_proof_1a = dleq_generate_proof(input1_priv, scan_pub_a, random_bytes_1a)
        # Deliberately NOT computing ECDH for scan key B on input 1

        psbt = SilentPaymentPSBT()

        # Add required global fields for PSBT v2
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_VERSION, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_TX_VERSION, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT, b"", struct.pack("<I", 2)
        )
        psbt.add_global_field(PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE, b"", b"\x00")

        # Add input 0
        prevout_txid_0 = hashlib.sha256(
            "prevout_multi_scan_3a_custom".encode()
        ).digest()
        witness_script_0 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input0_pub.bytes).digest()[:20]
        )
        witness_utxo_0 = create_witness_utxo(50000, witness_script_0)

        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", prevout_txid_0)
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_OUTPUT_INDEX, b"", struct.pack("<I", 0)
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SEQUENCE, b"", struct.pack("<I", 0xFFFFFFFE)
        )
        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", witness_utxo_0)
        fake_derivation_0 = struct.pack("<I", 0x80000000) + struct.pack("<I", 0)
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_BIP32_DERIVATION, input0_pub.bytes, fake_derivation_0
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )

        # Input 0: ECDH shares for both scan keys
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub_a.bytes,
            ecdh_result_0a.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub_a.bytes, valid_proof_0a
        )
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub_b.bytes,
            ecdh_result_0b.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub_b.bytes, valid_proof_0b
        )

        # Add input 1
        prevout_txid_1 = hashlib.sha256(
            "prevout_multi_scan_3b_custom".encode()
        ).digest()
        witness_script_1 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input1_pub.bytes).digest()[:20]
        )
        witness_utxo_1 = create_witness_utxo(50000, witness_script_1)

        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", prevout_txid_1)
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_OUTPUT_INDEX, b"", struct.pack("<I", 0)
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SEQUENCE, b"", struct.pack("<I", 0xFFFFFFFE)
        )
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", witness_utxo_1)
        fake_derivation_1 = struct.pack("<I", 0x80000000) + struct.pack("<I", 1)
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_BIP32_DERIVATION, input1_pub.bytes, fake_derivation_1
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )

        # Input 1: ECDH share only for scan key A (missing B)
        psbt.add_input_field(
            1,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub_a.bytes,
            ecdh_result_1a.to_bytes_compressed(),
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub_a.bytes, valid_proof_1a
        )
        # Deliberately NOT adding ECDH share for scan key B on input 1

        # Sum the ECDH shares and public keys for output computation
        summed_ecdh_a = ecdh_result_0a + ecdh_result_1a
        summed_pubkey = input0_pub + input1_pub
        outpoints = [(prevout_txid_0, 0), (prevout_txid_1, 0)]

        # Output 0: Silent payment to recipient A (valid - has all ECDH shares)
        output_script_a = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=summed_pubkey.to_bytes_compressed(),
            ecdh_share_bytes=summed_ecdh_a.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub_a.bytes,
            k=0,
        )
        sp_info_a = scan_pub_a.bytes + spend_pub_a.bytes
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 45000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script_a)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info_a)

        # Output 1: Silent payment to recipient B (invalid - missing input 1 ECDH)
        # Only have ecdh_result_0b, missing ecdh_result_1b for complete sum
        # Use partial sum which would be incorrect
        output_script_b = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=summed_pubkey.to_bytes_compressed(),
            ecdh_share_bytes=ecdh_result_0b.to_bytes_compressed(),  # Only from input 0
            spend_pubkey_bytes=spend_pub_b.bytes,
            k=0,
        )
        sp_info_b = scan_pub_b.bytes + spend_pub_b.bytes
        psbt.add_output_field(
            1, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 45000)
        )
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script_b)
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info_b)

        return {
            "description": "Reject PSBT with two inputs and two silent payment outputs (different scan keys) where input 1 is missing ECDH share for scan key B",
            "psbt": base64.b64encode(psbt.serialize()).decode(),
            "input_keys": [
                {
                    "input_index": 0,
                    "private_key": input0_priv.hex,
                    "public_key": input0_pub.hex,
                    "prevout_txid": prevout_txid_0.hex(),
                    "prevout_index": 0,
                    "prevout_scriptpubkey": witness_script_0.hex(),
                    "amount": 50000,
                    "witness_utxo": witness_utxo_0.hex(),
                    "sequence": 0xFFFFFFFE,
                },
                {
                    "input_index": 1,
                    "private_key": input1_priv.hex,
                    "public_key": input1_pub.hex,
                    "prevout_txid": prevout_txid_1.hex(),
                    "prevout_index": 0,
                    "prevout_scriptpubkey": witness_script_1.hex(),
                    "amount": 50000,
                    "witness_utxo": witness_utxo_1.hex(),
                    "sequence": 0xFFFFFFFE,
                },
            ],
            "scan_keys": [
                {"scan_pubkey": scan_pub_a.hex, "spend_pubkey": spend_pub_a.hex},
                {"scan_pubkey": scan_pub_b.hex, "spend_pubkey": spend_pub_b.hex},
            ],
            "expected_ecdh_shares": [
                {
                    "scan_key": scan_pub_a.hex,
                    "ecdh_result": ecdh_result_0a.to_bytes_compressed().hex(),
                    "dleq_proof": valid_proof_0a.hex(),
                    "input_index": 0,
                },
                {
                    "scan_key": scan_pub_b.hex,
                    "ecdh_result": ecdh_result_0b.to_bytes_compressed().hex(),
                    "dleq_proof": valid_proof_0b.hex(),
                    "input_index": 0,
                },
                {
                    "scan_key": scan_pub_a.hex,
                    "ecdh_result": ecdh_result_1a.to_bytes_compressed().hex(),
                    "dleq_proof": valid_proof_1a.hex(),
                    "input_index": 1,
                },
                # Note: Missing ECDH share for scan_key_b on input 1
            ],
            "expected_outputs": [
                {
                    "output_index": 0,
                    "amount": 45000,
                    "is_silent_payment": True,
                    "sp_info": sp_info_a.hex(),
                },
                {
                    "output_index": 1,
                    "amount": 45000,
                    "is_silent_payment": True,
                    "sp_info": sp_info_b.hex(),
                },
            ],
            "expected_psbt_id": None,  # Invalid PSBT
        }

    def save_test_vectors(self, filename: str = "test_vectors.json"):
        """Generate and save all test vectors"""
        all_vectors = self.generate_all_test_vectors()

        with open(filename, "w") as f:
            json.dump(all_vectors, f, indent=2)

        print(
            f"Generated {len(all_vectors['invalid'])} invalid and {len(all_vectors['valid'])} valid test vectors"
        )
        print(f"Saved to {filename}")


if __name__ == "__main__":
    from pathlib import Path

    # Create test configs directory structure if it doesn't exist
    test_configs_dir = Path(__file__).parent / "test_configs"
    test_configs_dir.mkdir(exist_ok=True)
    (test_configs_dir / "invalid").mkdir(exist_ok=True)
    (test_configs_dir / "valid").mkdir(exist_ok=True)

    # Default: save to parent directory (bip-0375 root)
    default_output = Path(__file__).parent.parent.parent / "test_vectors.json"

    generator = TestVectorGenerator()
    generator.save_test_vectors(str(default_output))
