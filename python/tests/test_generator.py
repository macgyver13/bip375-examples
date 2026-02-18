#!/usr/bin/env python3
"""
BIP-375 Test Vector Generator

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
from psbt_sp.bip352_crypto import apply_label_to_spend_key, compute_bip352_output_script
from psbt_sp.crypto import Wallet
from psbt_sp.serialization import create_witness_utxo
from psbt_sp.psbt import SilentPaymentPSBT
from psbt_sp.constants import PSBTKeyType
def _deterministic_hash(s: str) -> int:
    """Deterministic hash that is stable across Python sessions (unlike hash())."""
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:4], "big") % 1000


# ============================================================================
# Pure PSBT helper functions
# ============================================================================


def _init_psbt_globals(
    psbt: "SilentPaymentPSBT",
    num_inputs: int,
    num_outputs: int,
    *,
    tx_modifiable: bool = False,
) -> None:
    """Populate the five mandatory PSBT v2 global fields."""
    psbt.add_global_field(PSBTKeyType.PSBT_GLOBAL_VERSION, b"", struct.pack("<I", 2))
    psbt.add_global_field(PSBTKeyType.PSBT_GLOBAL_TX_VERSION, b"", struct.pack("<I", 2))
    psbt.add_global_field(
        PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT, b"", struct.pack("<I", num_inputs)
    )
    psbt.add_global_field(
        PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT, b"", struct.pack("<I", num_outputs)
    )
    psbt.add_global_field(
        PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE, b"", b"\x01" if tx_modifiable else b"\x00"
    )


def _sorted_outpoints_and_input_map(
    eligible_inputs: List[Dict],
) -> tuple:
    """Sort outpoints lexicographically (BIP-352 requirement) and build an index map.

    Returns (sorted_outpoints, outpoint_to_input) where each outpoint is a
    (txid_bytes, vout_int) tuple sorted by (txid, vout).
    """
    outpoints = [
        (inp["prevout_txid"], inp["prevout_index"]) for inp in eligible_inputs
    ]
    outpoints.sort(key=lambda x: (x[0], x[1]))
    outpoint_to_input = {
        (inp["prevout_txid"], inp["prevout_index"]): inp for inp in eligible_inputs
    }
    return outpoints, outpoint_to_input


def _sum_pubkeys_in_outpoint_order(
    outpoints: List[tuple],
    outpoint_to_input: Dict,
):
    """Sum input public keys in sorted outpoint order (BIP-352 requirement)."""
    summed = None
    for outpoint in outpoints:
        pk = outpoint_to_input[outpoint]["public_key"]
        summed = pk if summed is None else summed + pk
    return summed


def _sum_ecdh_shares_for_scan_key(
    outpoints: List[tuple],
    outpoint_to_input: Dict,
    ecdh_data: Dict,
    scan_key_id: str,
) -> tuple:
    """Sum ECDH shares for one scan key in sorted outpoint order.

    Returns (summed_ecdh_point_or_None, coverage_complete) where
    coverage_complete is True only when every outpoint contributed a share.
    """
    inputs_with_ecdh: set = set()
    summed = None
    for outpoint in outpoints:
        inp = outpoint_to_input[outpoint]
        ecdh_key = (inp["input_index"], scan_key_id)
        if ecdh_key in ecdh_data:
            ecdh_result, _ = ecdh_data[ecdh_key]
            inputs_with_ecdh.add(inp["input_index"])
            summed = ecdh_result if summed is None else summed + ecdh_result
    return summed, len(inputs_with_ecdh) == len(outpoints)


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
    use_segwit_v2: bool = False
    multisig_threshold: Optional[int] = None
    multisig_pubkey_count: Optional[int] = None
    key_derivation_suffix: str = ""  # For deterministic key generation


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
    force_k_index: Optional[int] = None
    spend_derivation_suffix: Optional[str] = None  # Override spend key per output
    # Regular output specific
    add_bip32_derivation: bool = (
        False  # Add PSBT_OUT_BIP32_DERIVATION for change identification
    )


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
    # List of explicit validation checks to perform - all checks will be performed if empty
    #  (e.g. ["psbt_structure", "ecdh_coverage", "signer_constraints", "output_scripts"])
    checks: List[str]

    # control override for invalid tests
    missing_dleq_for_input: Optional[int] = None
    invalid_dleq_for_input: Optional[int] = None
    wrong_sighash_for_input: Optional[int] = None
    missing_ecdh_for_input: Optional[int] = None
    wrong_sp_info_size: bool = False
    missing_global_dleq: bool = False
    use_global_ecdh: Optional[List[str]] = None  # list of scan key IDs to use global ECDH
    use_segwit_v2_input: bool = False
    set_tx_modifiable: bool = False
    missing_sp_info_field: bool = False
    wrong_ecdh_share_size: bool = False
    wrong_dleq_proof_size: bool = False
    missing_ecdh_for_scan_key: Optional[str] = None
    missing_dleq_for_scan_key: Optional[str] = None
    invalid_dleq_for_scan_key: Optional[str] = None
    inject_ineligible_ecdh: bool = False
    force_output_script: bool = False
    strip_input_pubkeys_for_input: Optional[int] = None
    invalid_global_dleq: bool = False


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
            "input", _deterministic_hash(key_suffix)
        )

        # Create prevout
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_prevout_{input_index}".encode()
        ).digest()

        # Create P2WPKH script: OP_0 OP_PUSHBYTES_20 <20-byte-hash160(pubkey)>
        # Error injection: Use segwit v2 instead of v0
        segwit_version = 0x52 if spec.use_segwit_v2 else 0x00
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
            "is_eligible": True,
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
                "multisig", _deterministic_hash(key_suffix)
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
                "wsh_multisig", _deterministic_hash(key_suffix)
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

        if spec.spend_derivation_suffix is not None:
            spend_seed = _deterministic_hash(f"spend_{spec.spend_derivation_suffix}")
            _, spend_pub = self.wallet.create_key_pair("spend", spend_seed)

        return {
            "output_index": output_index,
            "output_type": OutputType.SILENT_PAYMENT,
            "amount": spec.amount,
            "scan_pubkey": scan_pub,
            "spend_pubkey": spend_pub,
            "label": spec.label,
            "force_wrong_script": spec.force_wrong_script,
            "force_k_index": spec.force_k_index,
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
            "add_bip32_derivation": spec.add_bip32_derivation,
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
            "add_bip32_derivation": spec.add_bip32_derivation,
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
        self._add_ecdh_shares_to_psbt(psbt, ecdh_data, scenario, input_data)

        # Error injection: strip BIP32_DERIVATION from specified input
        if scenario.strip_input_pubkeys_for_input is not None:
            idx = scenario.strip_input_pubkeys_for_input
            psbt.input_maps[idx] = [
                f for f in psbt.input_maps[idx]
                if f.key_type != PSBTKeyType.PSBT_IN_BIP32_DERIVATION
            ]

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
        _init_psbt_globals(
            psbt, num_inputs, num_outputs,
            tx_modifiable=scenario.set_tx_modifiable,
        )
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
                seed_suffix = _deterministic_hash(f"{spec.key_id}_{spec.derivation_suffix}")
                _, scan_pub = self.wallet.create_key_pair("scan", seed_suffix)
                _, spend_pub = self.wallet.create_key_pair(
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

            # Error injection says to skip this input
            if scenario.missing_ecdh_for_input == input_idx:
                continue

            private_key = input_info["private_key"]

            for scan_key_id, (scan_pub, _) in scan_keys.items():
                # Skip ECDH for specific scan key (affects all inputs)
                if scenario.missing_ecdh_for_scan_key == scan_key_id:
                    continue

                # Compute ECDH share
                ecdh_result = private_key * scan_pub

                # Generate DLEQ proof (with potential Error injection)
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
        self, psbt: SilentPaymentPSBT, ecdh_data: Dict, scenario: TestScenario, input_data: List[Dict]
    ):
        """Add ECDH shares and DLEQ proofs to PSBT"""
        global_scan_keys = scenario.use_global_ecdh or []

        if global_scan_keys:
            global_ecdh = {k: v for k, v in ecdh_data.items() if k[1] in global_scan_keys}
            if global_ecdh:
                self._add_global_ecdh_shares(psbt, global_ecdh, scenario)

        per_input_ecdh = {k: v for k, v in ecdh_data.items() if k[1] not in global_scan_keys}
        if per_input_ecdh:
            self._add_per_input_ecdh_shares(psbt, per_input_ecdh, scenario, input_data)

        # Error injection: Add ECDH share for ineligible input (only when explicitly requested)
        if scenario.inject_ineligible_ecdh:
            self._inject_ineligible_input_ecdh_shares(psbt, scenario)

    def _find_input_info_by_index(self, input_data: List[Dict], input_idx: int) -> Optional[Dict]:
        """Find input info by index"""
        for input_info in input_data:
            if input_info.get("input_index") == input_idx:
                return input_info
        return None

    def _add_per_input_ecdh_shares(
        self, psbt: SilentPaymentPSBT, ecdh_data: Dict, scenario: TestScenario, input_data: List[Dict]
    ):
        """Add per-input ECDH shares"""
        scan_keys = self._generate_scan_keys(scenario.scan_keys)

        # Track which inputs have been processed to add sighash type
        processed_inputs = set()

        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in ecdh_data.items():
            if scan_key_id not in scan_keys:
                continue

            scan_pub = scan_keys[scan_key_id][0]

            # Add ECDH share with potential Error injection
            ecdh_bytes = ecdh_result.to_bytes_compressed()
            if scenario.wrong_ecdh_share_size:
                ecdh_bytes = ecdh_bytes[:32]  # Wrong size: 32 instead of 33 bytes

            psbt.add_input_field(
                input_idx, PSBTKeyType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_bytes
            )

            # Add DLEQ proof (if not missing due to Error injection)
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
                
                if scenario.wrong_sighash_for_input == input_idx or scenario.use_segwit_v2_input:
                    # Partially sign to support correct detection at signed stage
                    input_info = self._find_input_info_by_index(input_data, input_idx)
                    if input_info and input_info.get("is_eligible", False):
                        # Create proper UTXO from input data for signing
                        from psbt_sp.crypto import UTXO
                        utxo = UTXO(
                            txid=input_info["prevout_txid"].hex(),
                            vout=input_info["prevout_index"],
                            amount=input_info["amount"],
                            script_pubkey=input_info.get("witness_script", input_info.get("script_pubkey", b"")).hex(),
                            private_key=input_info["private_key"]
                        )
                        
                        # Sign this specific input to create a partial signature
                        psbt._sign_controlled_inputs([utxo], [input_idx])

                processed_inputs.add(input_idx)

    def _compute_global_dleq_proof(self, scan_key_id: str, summed_private_key, scan_pub) -> bytes:
        """Compute a global DLEQ proof for a scan key using the summed private key"""
        random_bytes = hashlib.sha256(
            f"{self.base_seed}_global_dleq_{scan_key_id}".encode()
        ).digest()
        return dleq_generate_proof(summed_private_key, scan_pub, random_bytes)

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

            # Add global DLEQ proof (if not missing due to Error injection)
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
                    if scenario.invalid_global_dleq:
                        # Use wrong private key for invalid proof
                        wrong_priv, _ = self.wallet.create_key_pair("wrong", 999)
                        global_dleq_proof = self._compute_global_dleq_proof(
                            scan_key_id, wrong_priv, scan_pub
                        )
                    else:
                        global_dleq_proof = self._compute_global_dleq_proof(
                            scan_key_id, summed_private_key, scan_pub
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
                    fake_ecdh_bytes = b"\x02" + hashlib.sha256(
                        f"fake_ecdh_{i}".encode()
                    ).digest()
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
                # Regular output - add script and optional BIP32_DERIVATION
                psbt.add_output_field(
                    idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_info["script"]
                )

                # Add BIP32_DERIVATION if requested (for change identification)
                if output_info.get("add_bip32_derivation", False):
                    self._add_output_bip32_derivation(psbt, idx, input_data)

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
        original_spend_pub = output_info["spend_pubkey"]

        # Apply BIP-352 label if specified
        spend_pub = original_spend_pub
        if output_info.get("label") is not None:
            spend_pub = self._compute_labeled_spend_key(
                psbt, original_spend_pub, output_info["label"]
            )

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
                outpoints, outpoint_to_input = _sorted_outpoints_and_input_map(eligible_inputs)
                summed_pubkey = _sum_pubkeys_in_outpoint_order(outpoints, outpoint_to_input)
                summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

                # Find the scan key ID for this output's scan pub
                scan_key_id = None
                scan_keys = self._generate_scan_keys(scenario.scan_keys)
                for key_id, (key_scan_pub, _) in scan_keys.items():
                    if key_scan_pub == scan_pub:
                        scan_key_id = key_id
                        break

                if scan_key_id:
                    summed_ecdh_share, coverage_complete = _sum_ecdh_shares_for_scan_key(
                        outpoints, outpoint_to_input, ecdh_data, scan_key_id
                    )

                    if coverage_complete and summed_ecdh_share is not None:
                        ecdh_share_bytes = summed_ecdh_share.to_bytes_compressed()

                        # Override k order with index
                        k_index = idx
                        if output_info["force_k_index"] is not None:
                            k_index = output_info["force_k_index"]
                        # Compute BIP-352 output script
                        output_script = compute_bip352_output_script(
                            outpoints=outpoints,
                            summed_pubkey_bytes=summed_pubkey_bytes,
                            ecdh_share_bytes=ecdh_share_bytes,
                            spend_pubkey_bytes=spend_pub.to_bytes_compressed(),
                            k=k_index,  # k is the output index
                        )
                        psbt.add_output_field(
                            idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script
                        )
                    elif scenario.force_output_script:
                        wrong_script = (
                            bytes([0x51, 0x20])
                            + hashlib.sha256(b"wrong_address").digest()
                        )
                        psbt.add_output_field(
                            0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", wrong_script
                        )

        # Add SP_V0_INFO field (unless Error injection says to skip it)
        if not scenario.missing_sp_info_field:
            sp_info = scan_pub.to_bytes_compressed() + spend_pub.to_bytes_compressed()
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

    def _compute_labeled_spend_key(self, psbt: SilentPaymentPSBT, spend_pub, label: int):
        """Compute BIP-352 labeled spend key: B_m = B_spend + hash_BIP0352/Label(b_scan || m) * G"""
        scan_priv_bytes = self.wallet.scan_priv.to_bytes(32, "big")
        return apply_label_to_spend_key(spend_pub, scan_priv_bytes, label)

    def _add_output_bip32_derivation(
        self, psbt: SilentPaymentPSBT, output_idx: int, input_data: List[Dict]
    ):
        """Add PSBT_OUT_BIP32_DERIVATION for change identification"""
        # Use the first input's public key for the derivation (common pattern)
        if input_data and "public_key" in input_data[0]:
            pubkey = input_data[0]["public_key"]

            # Create BIP32 derivation path (master_fingerprint + path)
            # Format: 4-byte fingerprint + 8-byte path (m/0/1 for change)
            master_fingerprint = struct.pack(">I", 0)  # Dummy fingerprint
            derivation_path = struct.pack(">I", 0) + struct.pack(">I", 1)  # m/0/1
            bip32_derivation_value = master_fingerprint + derivation_path

            psbt.add_output_field(
                output_idx,
                PSBTKeyType.PSBT_OUT_BIP32_DERIVATION,
                pubkey.bytes,
                bip32_derivation_value,
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
                force_k_index=output_config.get("force_k_index", None),
                spend_derivation_suffix=output_config.get("spend_derivation_suffix"),
                add_bip32_derivation=output_config.get("add_bip32_derivation", False),
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

        # Parse control override
        control_override = config.get("control_override", {})

        # Parse use_global_ecdh: true -> all scan keys, list -> specific scan keys, absent -> None
        raw_global_ecdh = control_override.get("use_global_ecdh")
        if raw_global_ecdh is True:
            use_global_ecdh = [sk.key_id for sk in scan_keys]
        elif isinstance(raw_global_ecdh, list):
            use_global_ecdh = raw_global_ecdh
        else:
            use_global_ecdh = None

        return TestScenario(
            description=config["description"],
            validation_result=ValidationResult(
                config.get("validation_result", "valid")
            ),
            checks=config.get("checks", []),
            inputs=inputs,
            outputs=outputs,
            scan_keys=scan_keys,
            missing_dleq_for_input=control_override.get("missing_dleq_for_input"),
            invalid_dleq_for_input=control_override.get("invalid_dleq_for_input"),
            wrong_sighash_for_input=control_override.get("wrong_sighash_for_input"),
            missing_ecdh_for_input=control_override.get("missing_ecdh_for_input"),
            wrong_sp_info_size=control_override.get("wrong_sp_info_size", False),
            missing_global_dleq=control_override.get("missing_global_dleq", False),
            use_global_ecdh=use_global_ecdh,
            use_segwit_v2_input=control_override.get("use_segwit_v2_input", False),
            set_tx_modifiable=control_override.get("set_tx_modifiable", False),
            missing_sp_info_field=control_override.get("missing_sp_info_field", False),
            wrong_ecdh_share_size=control_override.get("wrong_ecdh_share_size", False),
            wrong_dleq_proof_size=control_override.get("wrong_dleq_proof_size", False),
            missing_ecdh_for_scan_key=control_override.get("missing_ecdh_for_scan_key"),
            missing_dleq_for_scan_key=control_override.get("missing_dleq_for_scan_key"),
            invalid_dleq_for_scan_key=control_override.get("invalid_dleq_for_scan_key"),
            inject_ineligible_ecdh=control_override.get(
                "inject_ineligible_ecdh", False
            ),
            force_output_script=control_override.get("force_output_script", False),
            strip_input_pubkeys_for_input=control_override.get("strip_input_pubkeys_for_input"),
            invalid_global_dleq=control_override.get("invalid_global_dleq", False),
        )

    # Generate test vector for a given scenario
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
            private_key = ""
            public_key = ""

            if "private_key" in inp and inp["private_key"] is not None:
                private_key = inp["private_key"].hex
                public_key = inp["public_key"].hex

            input_key = {
                "input_index": inp["input_index"],
                "private_key": private_key,
                "public_key": public_key,
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

        global_scan_keys = psbt_data["scenario"].use_global_ecdh or []

        expected_ecdh_shares = []
        # Global ECDH shares: one summed entry per scan key, no input_index
        if global_scan_keys:
            global_sums = {}  # scan_key_id -> summed ecdh_result
            global_priv_sums = {}  # scan_key_id -> summed private key
            for (input_idx, scan_key_id), (ecdh_result, _) in psbt_data["ecdh_data"].items():
                if scan_key_id in global_scan_keys and scan_key_id in psbt_data["scan_keys"]:
                    if scan_key_id not in global_sums:
                        global_sums[scan_key_id] = ecdh_result
                    else:
                        global_sums[scan_key_id] += ecdh_result
                    # Sum private keys for DLEQ proof
                    for inp in psbt_data["input_data"]:
                        if inp["input_index"] == input_idx and inp.get("is_eligible"):
                            if scan_key_id not in global_priv_sums:
                                global_priv_sums[scan_key_id] = inp["private_key"]
                            else:
                                global_priv_sums[scan_key_id] = global_priv_sums[scan_key_id] + inp["private_key"]
            for scan_key_id, summed_ecdh in global_sums.items():
                scan_pub = psbt_data["scan_keys"][scan_key_id][0]
                entry = {
                    "scan_key": scan_pub.hex if hasattr(scan_pub, "hex") else str(scan_pub),
                    "ecdh_result": summed_ecdh.to_bytes_compressed().hex(),
                }
                if scan_key_id in global_priv_sums and not scenario.missing_global_dleq:
                    global_dleq_proof = self.builder._compute_global_dleq_proof(
                        scan_key_id, global_priv_sums[scan_key_id], scan_pub
                    )
                    entry["dleq_proof"] = global_dleq_proof.hex()
                expected_ecdh_shares.append(entry)

        # Per-input ECDH shares: one entry per (input, scan_key), with input_index
        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in psbt_data[
            "ecdh_data"
        ].items():
            if scan_key_id in global_scan_keys:
                continue
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

        test_dict = {
            "description": scenario.description,
            "psbt": base64.b64encode(psbt.serialize()).decode(),
            "input_keys": input_keys,
            "scan_keys": scan_keys,
            "expected_ecdh_shares": expected_ecdh_shares,
            "expected_outputs": expected_outputs,
        }
        if scenario.validation_result == ValidationResult.VALID:
            test_dict["expected_psbt_id"] = psbt.compute_unique_id()
        if scenario.checks:
            test_dict["checks"] = scenario.checks
        return test_dict


# ============================================================================
# Test Vector Generator Section
# ============================================================================


class TestVectorGenerator:
    """Backward compatibility wrapper for existing interface"""

    def __init__(self, seed: str = "bip375_deterministic_seed"):
        self.config_generator = ConfigBasedTestGenerator(seed)
        self.test_vectors = {
            "description": "BIP-375 Test Vectors",
            "version": "1.2",
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
        self.test_vectors["invalid"].insert(9,self._generate_incomplete_per_input_ecdh_for_one_scan_key_test())

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

    def _generate_incomplete_per_input_ecdh_for_one_scan_key_test(
        self
    ) -> Dict[str, Any]:
        """Two inputs, two outputs with different scan keys; input 1 missing ECDH for scan key B.

        This creates an invalid PSBT where:
        - Input 0 has ECDH shares for both scan keys A and B
        - Input 1 has ECDH share only for scan key A (missing B)
        - Output 0 (scan key A) uses correct summed ECDH
        - Output 1 (scan key B) uses incomplete ECDH (only from input 0)
        """
        wallet = self.config_generator.wallet
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
        _init_psbt_globals(psbt, 2, 2)

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
            "description": "ecdh coverage: two inputs/two sp outputs (different scan keys) - full coverage input 0 / partial coverage input 1",
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
