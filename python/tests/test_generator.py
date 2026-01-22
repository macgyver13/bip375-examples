#!/usr/bin/env python3
"""
Complete BIP-375 Test Vector Generator

Implements all test scenarios from test_vectors.json with full PSBT structures
that properly trigger validation rules. Creates both invalid and valid PSBTs
with complete cryptographic material for full DLEQ validation.
"""

import json
import hashlib
import struct
import base64
import sys
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dleq_374 import dleq_generate_proof, dleq_verify_proof
from psbt_sp.bip352_crypto import compute_bip352_output_script
from psbt_sp.crypto import Wallet
from psbt_sp.serialization import create_witness_utxo
from psbt_sp.psbt import SilentPaymentPSBT
from psbt_sp.constants import PSBTKeyType


@dataclass
class GenInputKey:
    """Complete key material for a PSBT input with all necessary fields"""

    input_index: int
    private_key: str  # 32 bytes hex
    public_key: str  # 33 bytes hex (compressed)
    prevout_txid: str  # 32 bytes hex (txid)
    prevout_index: int
    prevout_scriptpubkey: str  # hex
    amount: int
    witness_utxo: Optional[str] = None  # hex serialized witness utxo
    sequence: int = 0xFFFFFFFF


@dataclass
class GenScanKey:
    """Complete silent payment scan/spend key pair with metadata"""

    scan_pubkey: str  # 33 bytes hex (compressed)
    spend_pubkey: str  # 33 bytes hex (compressed)
    label: Optional[int] = None


@dataclass
class GenECDHShare:
    """Complete ECDH computation result with validation data"""

    scan_key: str  # 33 bytes hex (compressed)
    ecdh_result: str  # 33 bytes hex (compressed)
    dleq_proof: Optional[str] = None  # 64 bytes hex
    input_index: Optional[int] = None  # For per-input shares


@dataclass
class GenOutput:
    """Complete output specification"""

    output_index: int
    amount: int
    is_silent_payment: bool
    script: Optional[str] = None  # PSBT_OUT_SCRIPT hex data
    sp_info: Optional[str] = None  # PSBT_OUT_SP_V0_INFO hex data
    sp_label: Optional[int] = None  # PSBT_OUT_SP_V0_LABEL


@dataclass
class GenTestVector:
    """Complete test vector with all cryptographic material and validation data"""

    description: str
    psbt: str  # base64
    input_keys: List[GenInputKey]
    scan_keys: List[GenScanKey]
    expected_ecdh_shares: List[GenECDHShare]
    expected_outputs: List[GenOutput]

    def __post_init__(self):
        """Print description when test vector is created"""
        print(f"{self.description}")


class TestVectorGenerator:
    """Generates complete BIP 375 test vectors for all scenarios"""

    def __init__(self, seed: str = "bip375_complete_seed"):
        """Initialize with deterministic seed for reproducible results"""
        self.wallet = Wallet(seed)
        self.test_vectors = {
            "description": "BIP-375 Test Vectors",
            "version": "1.1",
            "format_notes": [
                "All keys are hex-encoded",
                "PSBTs have all necessary fields",
                "Test vectors are organized into 'invalid' and 'valid' arrays",
            ],
            "invalid": [],
            "valid": [],
        }

    def create_complete_psbt_base(
        self, num_inputs: int, num_outputs: int
    ) -> SilentPaymentPSBT:
        """Create a complete PSBT v2 base structure"""
        psbt = SilentPaymentPSBT()

        # Add required global fields for PSBT v2
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_VERSION, b"", struct.pack("<I", 2)
        )  # PSBT format version
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_TX_VERSION, b"", struct.pack("<I", 2)
        )  # 4 bytes for tx version
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT, b"", struct.pack("<I", num_inputs)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT, b"", struct.pack("<I", num_outputs)
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_TX_MODIFIABLE, b"", b"\x03"
        )  # Allow input/output modification

        return psbt

    def add_base_input_fields(
        self,
        psbt: SilentPaymentPSBT,
        input_index: int,
        prevout_txid: bytes,
        prevout_index: int,
        witness_utxo: bytes,
        sequence: int = 0xFFFFFFFE,
        input_pubkey: bytes = None,
    ):
        """Add required PSBTv2 input fields with BIP32 derivation"""
        # Required PSBTv2 fields
        psbt.add_input_field(
            input_index, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", prevout_txid
        )
        psbt.add_input_field(
            input_index,
            PSBTKeyType.PSBT_IN_OUTPUT_INDEX,
            b"",
            struct.pack("<I", prevout_index),
        )
        psbt.add_input_field(
            input_index, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", witness_utxo
        )
        psbt.add_input_field(
            input_index,
            PSBTKeyType.PSBT_IN_SEQUENCE,
            b"",
            struct.pack("<I", sequence),
        )

        # BIP-174: Add BIP32 derivation for pubkey exposure (standard method)
        # This allows validators to extract the public key for DLEQ verification
        if input_pubkey:
            psbt.add_input_field(
                input_index,
                PSBTKeyType.PSBT_IN_BIP32_DERIVATION,
                input_pubkey,  # key = 33-byte compressed pubkey
                struct.pack(
                    "<I", 0
                ),  # value = 4-byte minimum length empty fingerprint (privacy-preserving, no path disclosure)
            )

    # Invalid Test Case Generators
    def generate_missing_dleq_test(self) -> GenTestVector:
        """Missing DLEQ proof for ECDH share"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub
        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_0".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )  # P2WPKH
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )

        # Add ECDH share WITHOUT DLEQ proof (this should trigger error)
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        # Deliberately omit PSBT_IN_SP_DLEQ (0x1e)
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add silent payment output with properly computed BIP-352 script
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Detect missing PSBT_IN_SP_DLEQ proof field for PSBT_IN_SP_ECDH_SHARE",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=None,  # Missing!
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    def generate_invalid_dleq_test(self) -> GenTestVector:
        """Invalid DLEQ proof"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub

        # Generate COMPLETELY invalid proof by using wrong private key
        wrong_input_priv, _ = self.wallet.create_key_pair("wrong_input", 1)

        # Generate proof with wrong private key - this should be invalid
        invalid_proof = dleq_generate_proof(
            wrong_input_priv, scan_pub, Wallet.random_bytes()
        )

        # Verify the proof is actually invalid when checked against the real input key
        assert not dleq_verify_proof(input_pub, scan_pub, ecdh_result, invalid_proof), (
            "Generated proof should be invalid but isn't"
        )

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_1".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )

        # Add ECDH share WITH INVALID DLEQ proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, invalid_proof
        )  # (invalid)
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add silent payment output with properly computed BIP-352 script
        sp_info = scan_pub.bytes + spend_pub.bytes
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Detect invalid DLEQ proof in PSBT_IN_SP_DLEQ field",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=invalid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_non_sighash_all_test(self) -> GenTestVector:
        """Non-SIGHASH_ALL signature with silent payments"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes(5))

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_2".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )

        # Add NON-SIGHASH_ALL signature type (this should trigger error)
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x02)
        )  # SIGHASH_NONE

        # Add valid ECDH share and proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Add silent payment output with properly computed BIP-352 script
        # (should fail due to SIGHASH_NONE, not address mismatch)
        sp_info = scan_pub.bytes + spend_pub.bytes
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Reject PSBT with non-SIGHASH_ALL signatures and PSBT_OUT_SP_V0_INFO field set",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_mixed_segwit_test(self) -> GenTestVector:
        """Mixed segwit versions with silent payments"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields with HYPOTHETICAL segwit v2 (OP_2 = 0x52)
        # NOTE: Segwit v2 does NOT exist in Bitcoin (only v0 and v1/Taproot are defined)
        # This tests that BIP 375 validation correctly rejects undefined future versions
        prevout_txid = hashlib.sha256("prevout_3".encode()).digest()
        witness_script = (
            bytes([0x52, 0x20]) + hashlib.sha256(b"segwit_v2_script").digest()
        )  # Hypothetical Segwit v2
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add valid ECDH share and proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Add silent payment output with properly computed BIP-352 script
        # (should fail due to unsupported segwit version, not address mismatch)
        sp_info = scan_pub.bytes + spend_pub.bytes
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Detect segwit version greater than 1 in transaction inputs with PSBT_OUT_SP_V0_INFO field set",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_no_ecdh_shares_test(self) -> GenTestVector:
        """Silent payment outputs but no ECDH shares"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields (no ECDH shares)
        prevout_txid = hashlib.sha256("prevout_4".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add silent payment output WITHOUT any ECDH shares (should trigger error)
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = (
            bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_4").digest()
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Detect missing PSBT_IN_SP_ECDH_SHARE with silent payment outputs defined",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[],  # No ECDH shares!
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_missing_global_dleq_test(self) -> GenTestVector:
        """Global ECDH share without DLEQ proof"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub
        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields first
        prevout_txid = hashlib.sha256("prevout_5".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add global ECDH share WITHOUT DLEQ proof (this should trigger error)
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        # Deliberately omit PSBT_GLOBAL_SP_DLEQ (0x08)

        # Add silent payment output with properly computed BIP-352 script
        sp_info = scan_pub.bytes + spend_pub.bytes
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Detect missing PSBT_GLOBAL_SP_DLEQ proof field matching PSBT_GLOBAL_SP_ECDH_SHARE",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=None,  # Missing!
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_wrong_sp_info_size_test(self) -> GenTestVector:
        """Wrong SP_V0_INFO field size"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_6".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add valid ECDH share and proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Add silent payment output with WRONG SIZE SP_V0_INFO (should be 66 bytes)
        wrong_sp_info = scan_pub.bytes + spend_pub.bytes[:32]  # Only 65 bytes
        output_script = (
            bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_6").digest()
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, 0x09, b"", wrong_sp_info
        )  # PSBT_OUT_SP_V0_INFO (wrong size!)

        return GenTestVector(
            description="Detect PSBT_OUT_SP_V0_INFO field with incorrect size",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=wrong_sp_info.hex(),  # Wrong size!
                )
            ],
        )

    def generate_valid_mixed_input_types_test(self) -> GenTestVector:
        """Valid mixed eligible and ineligible input types"""
        input_priv_0, input_pub_0 = self.wallet.input_key_pair(0)
        input_priv_1, input_pub_1 = self.wallet.input_key_pair(1)
        _, input_pub_2 = self.wallet.input_key_pair(2)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Two inputs: one P2WPKH (eligible), one P2SH multisig (ineligible)
        psbt = self.create_complete_psbt_base(2, 1)

        # Input 0: P2WPKH (eligible)
        prevout_txid_0 = hashlib.sha256("prevout_mixed_0".encode()).digest()
        witness_script_0 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub_0.bytes).digest()[:20]
        )
        witness_utxo_0 = create_witness_utxo(100000, witness_script_0)
        self.add_base_input_fields(
            psbt, 0, prevout_txid_0, 0, witness_utxo_0, input_pubkey=input_pub_0.bytes
        )

        # Input 1: P2SH 2-of-2 multisig (ineligible - multiple public keys)
        # Create 2-of-2 multisig redeem script: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        redeem_script = bytes([0x52])  # OP_2
        redeem_script += (
            bytes([0x21]) + input_pub_1.to_bytes_compressed()
        )  # 33-byte pubkey
        redeem_script += (
            bytes([0x21]) + input_pub_2.to_bytes_compressed()
        )  # 33-byte pubkey
        redeem_script += bytes([0x52, 0xAE])  # OP_2 OP_CHECKMULTISIG

        # P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        redeem_script_hash = hashlib.new(
            "ripemd160", hashlib.sha256(redeem_script).digest()
        ).digest()
        script_pubkey = bytes([0xA9, 0x14]) + redeem_script_hash + bytes([0x87])

        # Create non-witness UTXO for P2SH
        prev_tx = bytes([0x02, 0x00, 0x00, 0x00])  # version
        prev_tx += bytes([0x01])  # 1 input
        prev_tx += hashlib.sha256(
            b"p2sh_prev_input"
        ).digest()  # prev txid (not coinbase)
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # prev vout (0)
        prev_tx += bytes([0x00])  # scriptSig length
        prev_tx += bytes([0xFF, 0xFF, 0xFF, 0xFF])  # sequence
        prev_tx += bytes([0x01])  # 1 output
        prev_tx += struct.pack("<Q", 150000)  # amount
        prev_tx += bytes([len(script_pubkey)]) + script_pubkey
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # locktime

        # Compute the txid of prev_tx (double SHA256)
        prevout_txid_1 = hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest()

        # Add required PSBTv2 fields for input 1
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", prevout_txid_1)
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_OUTPUT_INDEX, b"", struct.pack("<I", 0)
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SEQUENCE, b"", struct.pack("<I", 0xFFFFFFFE)
        )
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO, b"", prev_tx)
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_REDEEM_SCRIPT, b"", redeem_script)

        # Only input 0 is eligible, so only use that for ECDH
        ecdh_result = input_priv_0 * scan_pub

        # Add per-input ECDH share for eligible input
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )

        # Generate DLEQ proof for input 0
        dleq_proof = dleq_generate_proof(input_priv_0, scan_pub, Wallet.random_bytes())
        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof)

        # Compute proper BIP-352 output (using only eligible input)
        outpoints = [(prevout_txid_0, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub_0.to_bytes_compressed(),
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.to_bytes_compressed(),
            k=0,
        )

        # Set output
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 90000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)

        # Add sp_info
        sp_info = scan_pub.bytes + spend_pub.to_bytes_compressed()
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Valid PSBT with mixed input types where only eligible P2WPKH inputs contribute ECDH shares (ineligible P2SH multisig excluded)",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv_0.hex,
                    public_key=input_pub_0.hex,
                    prevout_txid=prevout_txid_0.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script_0.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo_0.hex(),
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input_priv_1.hex,
                    public_key=input_pub_1.hex,
                    prevout_txid=prevout_txid_1.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=script_pubkey.hex(),
                    amount=150000,
                    witness_utxo=prev_tx.hex(),  # non-witness UTXO for P2SH multisig
                ),
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=dleq_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=90000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_invalid_mixed_input_types_test(self) -> GenTestVector:
        """Invalid mixed eligible and ineligible input types where ineligible input includes ECDH shares"""
        input_priv_0, input_pub_0 = self.wallet.input_key_pair(0)
        input_priv_1, input_pub_1 = self.wallet.input_key_pair(1)
        _, input_pub_2 = self.wallet.input_key_pair(2)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Two inputs: one P2WPKH (eligible), one P2SH multisig (ineligible)
        psbt = self.create_complete_psbt_base(2, 1)

        # Input 0: P2WPKH (eligible)
        prevout_txid_0 = hashlib.sha256("prevout_mixed_1".encode()).digest()
        witness_script_0 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub_0.bytes).digest()[:20]
        )
        witness_utxo_0 = create_witness_utxo(100000, witness_script_0)
        self.add_base_input_fields(
            psbt, 0, prevout_txid_0, 0, witness_utxo_0, input_pubkey=input_pub_0.bytes
        )

        # Input 1: P2SH 2-of-2 multisig (ineligible - multiple public keys)
        # Create 2-of-2 multisig redeem script: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        redeem_script = bytes([0x52])  # OP_2
        redeem_script += (
            bytes([0x21]) + input_pub_1.to_bytes_compressed()
        )  # 33-byte pubkey
        redeem_script += (
            bytes([0x21]) + input_pub_2.to_bytes_compressed()
        )  # 33-byte pubkey
        redeem_script += bytes([0x52, 0xAE])  # OP_2 OP_CHECKMULTISIG

        # P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        redeem_script_hash = hashlib.new(
            "ripemd160", hashlib.sha256(redeem_script).digest()
        ).digest()
        script_pubkey = bytes([0xA9, 0x14]) + redeem_script_hash + bytes([0x87])

        # Create non-witness UTXO for P2SH
        prev_tx = bytes([0x02, 0x00, 0x00, 0x00])  # version
        prev_tx += bytes([0x01])  # 1 input
        prev_tx += hashlib.sha256(
            b"p2sh_prev_input"
        ).digest()  # prev txid (not coinbase)
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # prev vout (0)
        prev_tx += bytes([0x00])  # scriptSig length
        prev_tx += bytes([0xFF, 0xFF, 0xFF, 0xFF])  # sequence
        prev_tx += bytes([0x01])  # 1 output
        prev_tx += struct.pack("<Q", 150000)  # amount
        prev_tx += bytes([len(script_pubkey)]) + script_pubkey
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # locktime

        # Compute the txid of prev_tx (double SHA256)
        prevout_txid_1 = hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest()

        # Add required PSBTv2 fields for input 1
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", prevout_txid_1)
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_OUTPUT_INDEX, b"", struct.pack("<I", 0)
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SEQUENCE, b"", struct.pack("<I", 0xFFFFFFFE)
        )
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO, b"", prev_tx)
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_REDEEM_SCRIPT, b"", redeem_script)

        # Only input 0 is eligible, so only use that for ECDH
        ecdh_result = input_priv_0 * scan_pub

        # Add per-input ECDH share for eligible input
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            1,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )  # INVALID: ineligible input should NOT have ECDH share

        # Generate DLEQ proof for input 0
        dleq_proof = dleq_generate_proof(input_priv_0, scan_pub, Wallet.random_bytes())
        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof)
        dleq_proof = dleq_generate_proof(input_priv_1, scan_pub, Wallet.random_bytes())
        psbt.add_input_field(1, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof)

        # Compute proper BIP-352 output (using only eligible input)
        outpoints = [(prevout_txid_0, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub_0.to_bytes_compressed(),
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.to_bytes_compressed(),
            k=0,
        )

        # Set output
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 90000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)

        # Add sp_info
        sp_info = scan_pub.bytes + spend_pub.to_bytes_compressed()
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Reject PSBT where ineligible P2SH multisig input incorrectly includes PSBT_IN_SP_ECDH_SHARE field",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv_0.hex,
                    public_key=input_pub_0.hex,
                    prevout_txid=prevout_txid_0.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script_0.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo_0.hex(),
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input_priv_1.hex,
                    public_key=input_pub_1.hex,
                    prevout_txid=prevout_txid_1.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=script_pubkey.hex(),
                    amount=150000,
                    witness_utxo=prev_tx.hex(),  # non-witness UTXO for P2SH multisig
                ),
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=dleq_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=90000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_wrong_ecdh_share_size_test(self) -> GenTestVector:
        """Wrong ECDH share size"""
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Create wrong-sized ECDH share (32 bytes instead of 33)
        ecdh_result = input_priv * scan_pub
        wrong_ecdh = ecdh_result.to_bytes_compressed()[:32]  # Wrong size!

        psbt = self.create_complete_psbt_base(1, 1)

        prevout_txid = hashlib.sha256("prevout_7".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )

        # Add wrong-sized ECDH share
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, wrong_ecdh
        )
        # Generate DLEQ proof for input 0
        dleq_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())
        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof)

        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Detect PSBT_IN_SP_ECDH_SHARE field with incorrect size",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    def generate_wrong_dleq_size_test(self) -> GenTestVector:
        """Wrong DLEQ proof size"""
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        ecdh_result = input_priv * scan_pub
        wrong_dleq = b"\x00" * 63  # Wrong size (63 bytes instead of 64)

        psbt = self.create_complete_psbt_base(1, 1)

        prevout_txid = hashlib.sha256("prevout_8".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )

        # Add valid ECDH share but wrong-sized DLEQ proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, wrong_dleq)

        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Detect PSBT_IN_SP_DLEQ proof field with incorrect size",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    def generate_label_without_info_test(self) -> GenTestVector:
        """Label without SP_V0_INFO"""
        input_priv, input_pub = self.wallet.input_key_pair(0)

        psbt = self.create_complete_psbt_base(1, 1)

        prevout_txid = hashlib.sha256("prevout_9".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )

        # Regular P2TR output script
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"random_output").digest()

        # Add label WITHOUT sp_info (invalid!)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_LABEL, b"", struct.pack("<I", 1)
        )  # Label without info!

        return GenTestVector(
            description="Detect PSBT_OUT_SP_V0_LABEL field present without required PSBT_OUT_SP_V0_INFO field",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[],
            expected_ecdh_shares=[],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=False,
                    sp_info=None,
                )
            ],
        )

    def generate_address_mismatch_test(self) -> GenTestVector:
        """Address mismatch - output script doesn't match computed address"""
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 1)

        prevout_txid = hashlib.sha256("prevout_10".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )

        # Add valid ECDH share and proof
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Use WRONG output script (doesn't match BIP-352 computation)
        wrong_output_script = (
            bytes([0x51, 0x20]) + hashlib.sha256(b"wrong_address").digest()
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", wrong_output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Detect computed output script mismatch in PSBT_OUT_SCRIPT field from transaction inputs and PSBT_IN_SP_ECDH_SHARE field",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=wrong_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    def generate_incomplete_ecdh_with_output_script_test(self) -> GenTestVector:
        """Incomplete ECDH coverage WITH output script set - should be rejected"""
        input1_priv, input1_pub = self.wallet.input_key_pair(0)
        input2_priv, input2_pub = self.wallet.input_key_pair(1)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Only compute ECDH for first input (incomplete coverage!)
        ecdh_result1 = input1_priv * scan_pub
        valid_proof1 = dleq_generate_proof(input1_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(2, 1)

        # Input 0: Add ECDH share and proof
        prevout_txid1 = hashlib.sha256("prevout_12".encode()).digest()
        witness_script1 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input1_pub.bytes).digest()[:20]
        )
        witness_utxo1 = create_witness_utxo(50000, witness_script1)

        self.add_base_input_fields(
            psbt, 0, prevout_txid1, 0, witness_utxo1, input_pubkey=input1_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result1.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof1
        )

        # Input 1: Add base fields but NO ECDH share (incomplete coverage!)
        prevout_txid2 = hashlib.sha256("prevout_13".encode()).digest()
        witness_script2 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input2_pub.bytes).digest()[:20]
        )
        witness_utxo2 = create_witness_utxo(50000, witness_script2)

        self.add_base_input_fields(
            psbt, 1, prevout_txid2, 0, witness_utxo2, input_pubkey=input2_pub.bytes
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )
        # Deliberately NOT adding ECDH share for input 1

        # Compute output script using only input 0 (which would be incorrect anyway)
        outpoints = [(prevout_txid1, 0), (prevout_txid2, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input1_pub.bytes,  # Only input 0 pubkey
            ecdh_share_bytes=ecdh_result1.to_bytes_compressed(),  # Only input 0 ECDH
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        # KEY: Output script IS set despite incomplete coverage
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Reject PSBT with incomplete ECDH coverage when PSBT_OUT_SCRIPT is set: 2 eligible inputs but only input 0 has ECDH share",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input1_priv.hex,
                    public_key=input1_pub.hex,
                    prevout_txid=prevout_txid1.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script1.hex(),
                    amount=50000,
                    witness_utxo=witness_utxo1.hex(),
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input2_priv.hex,
                    public_key=input2_pub.hex,
                    prevout_txid=prevout_txid2.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script2.hex(),
                    amount=50000,
                    witness_utxo=witness_utxo2.hex(),
                ),
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result1.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof1.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    # Valid Test Case Generators

    def generate_incomplete_ecdh_work_in_progress_test(self) -> GenTestVector:
        """Incomplete ECDH coverage without output script - valid work in progress"""
        input1_priv, input1_pub = self.wallet.input_key_pair(0)
        input2_priv, input2_pub = self.wallet.input_key_pair(1)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Only compute ECDH for input #1 (incomplete coverage, but valid because PSBT_OUT_SCRIPT not set)
        ecdh_result2 = input2_priv * scan_pub
        valid_proof2 = dleq_generate_proof(input2_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(2, 1)

        # Input 0: Add base fields but NO ECDH share (incomplete coverage, awaiting next signer)
        prevout_txid1 = hashlib.sha256("prevout_14".encode()).digest()
        witness_script1 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input2_pub.bytes).digest()[:20]
        )
        witness_utxo1 = create_witness_utxo(50000, witness_script1)

        self.add_base_input_fields(
            psbt, 0, prevout_txid1, 0, witness_utxo1, input_pubkey=input1_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )
        # Deliberately NOT adding ECDH share for input 0 - awaiting next party

        # Input 1: Add ECDH share and proof
        prevout_txid2 = hashlib.sha256("prevout_15".encode()).digest()
        witness_script2 = (
            bytes([0x00, 0x14]) + hashlib.sha256(input1_pub.bytes).digest()[:20]
        )
        witness_utxo2 = create_witness_utxo(50000, witness_script2)
        self.add_base_input_fields(
            psbt, 1, prevout_txid2, 0, witness_utxo2, input_pubkey=input2_pub.bytes
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )
        psbt.add_input_field(
            1,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result2.to_bytes_compressed(),
        )
        psbt.add_input_field(
            1, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof2
        )

        # Add output with amount and SP info, but NO output script yet (not computed until coverage complete)
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        # KEY: NO PSBT_OUT_SCRIPT - work in progress!
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", scan_pub.bytes + spend_pub.bytes
        )

        return GenTestVector(
            description="Valid PSBT with incomplete ECDH coverage: 2 eligible inputs but only input 0 has ECDH share, no PSBT_OUT_SCRIPT field",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input1_priv.hex,
                    public_key=input1_pub.hex,
                    prevout_txid=prevout_txid1.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script1.hex(),
                    amount=50000,
                    witness_utxo=witness_utxo1.hex(),
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input2_priv.hex,
                    public_key=input2_pub.hex,
                    prevout_txid=prevout_txid2.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script2.hex(),
                    amount=50000,
                    witness_utxo=witness_utxo2.hex(),
                ),
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result2.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof2.hex(),
                    input_index=1,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=None,  # No script yet - work in progress
                    is_silent_payment=True,
                    sp_info=(scan_pub.bytes + spend_pub.bytes).hex(),
                )
            ],
        )

    def generate_single_signer_global_test(self) -> GenTestVector:
        """Single signer with global ECDH share"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        # Verify proof is valid
        assert dleq_verify_proof(input_pub, scan_pub, ecdh_result, valid_proof)

        psbt = self.create_complete_psbt_base(1, 1)

        # Add global ECDH share (not per-input)
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_10".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Compute proper BIP-352 output script
        outpoints = [(prevout_txid, 0)]
        output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        # Add silent payment output with computed script
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        sp_info = scan_pub.bytes + spend_pub.bytes
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Valid PSBT where a single entity controls all inputs and uses the global ECDH share approach (PSBT_GLOBAL_SP_ECDH_SHARE) for efficiency",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_multi_party_per_input_test(self) -> GenTestVector:
        """Multi-party with per-input ECDH shares"""

        # Use local wallet keys
        input1_priv, input1_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub
        # Two different inputs with different signers
        input2_priv, input2_pub = self.wallet.input_key_pair(1)

        # Compute ECDH shares for both inputs
        ecdh_result1 = input1_priv * scan_pub
        ecdh_result2 = input2_priv * scan_pub

        # Generate valid proofs for both
        valid_proof1 = dleq_generate_proof(input1_priv, scan_pub, Wallet.random_bytes())
        valid_proof2 = dleq_generate_proof(input2_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(2, 1)

        prevout_txids = []
        # Add per-input ECDH shares and proofs
        for i, (ecdh_result, valid_proof, input_pub, prevout_name) in enumerate(
            [
                (ecdh_result1, valid_proof1, input1_pub, "prevout_11"),
                (ecdh_result2, valid_proof2, input2_pub, "prevout_12"),
            ]
        ):
            # Add complete input fields
            prevout_txid = hashlib.sha256(prevout_name.encode()).digest()
            prevout_txids.append((prevout_txid, 0))
            witness_script = (
                bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
            )
            witness_utxo = create_witness_utxo(50000, witness_script)

            self.add_base_input_fields(
                psbt, i, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
            )
            psbt.add_input_field(
                i, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
            )  # SIGHASH_ALL

            # Add per-input ECDH share and DLEQ proof
            psbt.add_input_field(
                i,
                PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
                scan_pub.bytes,
                ecdh_result.to_bytes_compressed(),
            )
            psbt.add_input_field(
                i, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
            )

        # Sum the ECDH shares and public keys for output computation
        summed_ecdh = ecdh_result1 + ecdh_result2
        summed_pubkey = input1_pub + input2_pub

        # Compute proper BIP-352 output script
        output_script = compute_bip352_output_script(
            outpoints=prevout_txids,
            summed_pubkey_bytes=summed_pubkey.to_bytes_compressed(),
            ecdh_share_bytes=summed_ecdh.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )

        # Add silent payment output
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 95000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        sp_info = scan_pub.bytes + spend_pub.bytes
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Valid PSBT with multiple parties (two signers) where each signer contributes per-input ECDH shares (PSBT_IN_SP_ECDH_SHARE) for their respective inputs",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input1_priv.to_bytes(32, "big").hex(),
                    public_key=input1_pub.to_bytes_compressed().hex(),
                    prevout_txid=hashlib.sha256("prevout_11".encode()).digest().hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=(
                        bytes([0x00, 0x14])
                        + hashlib.sha256(input1_pub.to_bytes_compressed()).digest()[:20]
                    ).hex(),
                    amount=50000,
                    witness_utxo=create_witness_utxo(
                        50000,
                        bytes([0x00, 0x14])
                        + hashlib.sha256(input1_pub.to_bytes_compressed()).digest()[
                            :20
                        ],
                    ).hex(),
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input2_priv.to_bytes(32, "big").hex(),
                    public_key=input2_pub.to_bytes_compressed().hex(),
                    prevout_txid=hashlib.sha256("prevout_12".encode()).digest().hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=(
                        bytes([0x00, 0x14])
                        + hashlib.sha256(input2_pub.to_bytes_compressed()).digest()[:20]
                    ).hex(),
                    amount=50000,
                    witness_utxo=create_witness_utxo(
                        50000,
                        bytes([0x00, 0x14])
                        + hashlib.sha256(input2_pub.to_bytes_compressed()).digest()[
                            :20
                        ],
                    ).hex(),
                ),
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result1.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof1.hex(),
                    input_index=0,
                ),
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result2.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof2.hex(),
                    input_index=1,
                ),
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=95000,
                    script=output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                )
            ],
        )

    def generate_silent_payment_with_change_test(self) -> GenTestVector:
        """P2WPKH to silent payment with change detection"""
        from secp256k1_374 import G

        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        scan_priv = self.wallet.scan_priv
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 2)  # 1 input, 2 outputs

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_13".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add per-input ECDH share and DLEQ proof (not global for this test)
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Apply label to spend key: B_m = B_spend + hash_BIP0352/Label(b_scan || m) * G
        label = 1
        tag_data = b"BIP0352/Label"
        tag_hash = hashlib.sha256(tag_data).digest()
        label_preimage = (
            tag_hash
            + tag_hash
            + scan_priv.to_bytes(32, "big")
            + struct.pack("<I", label)
        )
        label_tweak = int.from_bytes(hashlib.sha256(label_preimage).digest(), "big")
        labeled_spend_key = spend_pub + (label_tweak * G)

        # Compute proper BIP-352 output script with labeled spend key
        outpoints = [(prevout_txid, 0)]
        sp_output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=labeled_spend_key.to_bytes_compressed(),
            k=0,
        )
        label_value = struct.pack("<I", label)

        # Add silent payment output with label
        # sp_info contains the labeled spend key (what the sender received in the address)
        sp_info = scan_pub.bytes + labeled_spend_key.to_bytes_compressed()
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 50000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", sp_output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_LABEL, b"", label_value)

        # Add change output with BIP32 derivation
        change_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(b"change_script").digest()[:20]
        )  # P2WPKH
        master_fingerprint = struct.pack(">I", 0)  # 4-byte fingerprint
        derivation_path = struct.pack(">I", 0) + struct.pack(">I", 1)  # m/0/1
        bip32_derivation_value = master_fingerprint + derivation_path

        psbt.add_output_field(
            1, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 45000)
        )  # Change
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SCRIPT, b"", change_script)
        psbt.add_output_field(
            1,
            PSBTKeyType.PSBT_OUT_BIP32_DERIVATION,
            input_pub.bytes,
            bip32_derivation_value,
        )

        return GenTestVector(
            description="Valid PSBT sending from P2WPKH to silent payment address with change output, using PSBT_OUT_SP_V0_LABEL for labeled silent payment and PSBT_OUT_BIP32_DERIVATION for change identification",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(
                    scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex, label=1
                )
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=50000,
                    script=sp_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                    sp_label=1,
                ),
                GenOutput(
                    output_index=1,
                    amount=45000,
                    script=change_script.hex(),
                    is_silent_payment=False,
                ),
            ],
        )

    def generate_sp_change_label_zero_test(self) -> GenTestVector:
        """Silent payment to recipient with SP change (label=0)"""
        from secp256k1_374 import G

        # Sender wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub_sender = self.wallet.scan_pub
        scan_priv_sender = self.wallet.scan_priv
        spend_pub_sender = self.wallet.spend_pub

        # Recipient wallet keys (separate wallet)
        recipient_wallet = Wallet("recipient_wallet_seed")
        scan_pub_recipient = recipient_wallet.scan_pub
        spend_pub_recipient = recipient_wallet.spend_pub

        # Compute ECDH share with valid proof
        # For recipient output, we need ECDH with recipient's scan key
        ecdh_result_recipient = input_priv * scan_pub_recipient
        valid_proof = dleq_generate_proof(
            input_priv, scan_pub_recipient, Wallet.random_bytes()
        )

        psbt = self.create_complete_psbt_base(1, 2)  # 1 input, 2 outputs

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_sp_change".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add per-input ECDH share and DLEQ proof for recipient's scan key
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub_recipient.bytes,
            ecdh_result_recipient.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub_recipient.bytes, valid_proof
        )

        # Also add ECDH share for sender's own scan key (for change output)
        ecdh_result_sender = input_priv * scan_pub_sender
        sender_proof = dleq_generate_proof(
            input_priv, scan_pub_sender, Wallet.random_bytes()
        )
        psbt.add_input_field(
            0,
            PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
            scan_pub_sender.bytes,
            ecdh_result_sender.to_bytes_compressed(),
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub_sender.bytes, sender_proof
        )

        # === Output 0: Payment to recipient (unlabeled) ===
        outpoints = [(prevout_txid, 0)]
        recipient_output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result_recipient.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub_recipient.to_bytes_compressed(),
            k=0,
        )

        # sp_info contains recipient's unlabeled address
        sp_info_recipient = (
            scan_pub_recipient.bytes + spend_pub_recipient.to_bytes_compressed()
        )
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 40000)
        )
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", recipient_output_script
        )
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info_recipient
        )
        # NO PSBT_OUT_SP_V0_LABEL for recipient's unlabeled address

        # === Output 1: Change to sender (label=0) ===
        # Apply label=0 to sender's spend key: B_m = B_spend + hash_BIP0352/Label(b_scan || 0) * G
        label = 0
        tag_data = b"BIP0352/Label"
        tag_hash = hashlib.sha256(tag_data).digest()
        label_preimage = (
            tag_hash
            + tag_hash
            + scan_priv_sender.to_bytes(32, "big")
            + struct.pack("<I", label)
        )
        label_tweak = int.from_bytes(hashlib.sha256(label_preimage).digest(), "big")
        labeled_spend_key_change = spend_pub_sender + (label_tweak * G)

        # Compute BIP-352 output script for change with labeled spend key
        change_output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result_sender.to_bytes_compressed(),
            spend_pubkey_bytes=labeled_spend_key_change.to_bytes_compressed(),
            k=0,
        )

        # sp_info contains sender's scan key + labeled spend key
        sp_info_change = (
            scan_pub_sender.bytes + labeled_spend_key_change.to_bytes_compressed()
        )
        label_value = struct.pack("<I", 0)  # Label 0 for change

        psbt.add_output_field(
            1, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 55000)
        )
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SCRIPT, b"", change_output_script)
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info_change)
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SP_V0_LABEL, b"", label_value)

        return GenTestVector(
            description="Valid PSBT demonstrating BIP-352 label=0 convention for silent payments change where output 0 (recipient) has no PSBT_OUT_SP_V0_LABEL field and output 1 (change) has PSBT_OUT_SP_V0_LABEL=0",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                # Sender's keys (for detecting change output)
                GenScanKey(
                    scan_pubkey=scan_pub_sender.hex,
                    spend_pubkey=labeled_spend_key_change.to_bytes_compressed().hex(),  # Labeled spend key
                    label=0,  # Change label
                ),
                # Recipient's keys (for detecting payment output)
                GenScanKey(
                    scan_pubkey=scan_pub_recipient.hex,
                    spend_pubkey=spend_pub_recipient.to_bytes_compressed().hex(),
                    label=None,  # Unlabeled
                ),
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub_recipient.hex,
                    ecdh_result=ecdh_result_recipient.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                ),
                GenECDHShare(
                    scan_key=scan_pub_sender.hex,
                    ecdh_result=ecdh_result_sender.to_bytes_compressed().hex(),
                    dleq_proof=sender_proof.hex(),
                    input_index=0,
                ),
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=40000,
                    script=recipient_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info_recipient.hex(),
                    sp_label=None,  # No label for recipient
                ),
                GenOutput(
                    output_index=1,
                    amount=55000,
                    script=change_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info_change.hex(),
                    sp_label=0,  # Label 0 for change
                ),
            ],
        )

    def generate_multiple_silent_payment_outputs_test(self) -> GenTestVector:
        """Multiple silent payment outputs to same scan key"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 2)  # 1 input, 2 outputs

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_14".encode()).digest()
        witness_script = (
            bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(
            psbt, 0, prevout_txid, 0, witness_utxo, input_pubkey=input_pub.bytes
        )
        psbt.add_input_field(
            0, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", 0x01)
        )  # SIGHASH_ALL

        # Add global ECDH share and DLEQ proof
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE,
            scan_pub.bytes,
            ecdh_result.to_bytes_compressed(),
        )
        psbt.add_global_field(
            PSBTKeyType.PSBT_GLOBAL_SP_DLEQ, scan_pub.bytes, valid_proof
        )

        # Compute proper BIP-352 output scripts with k=0 and k=1
        outpoints = [(prevout_txid, 0)]
        sp1_output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=0,
        )
        sp2_output_script = compute_bip352_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=input_pub.bytes,
            ecdh_share_bytes=ecdh_result.to_bytes_compressed(),
            spend_pubkey_bytes=spend_pub.bytes,
            k=1,
        )

        # Add first silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        psbt.add_output_field(
            0, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 40000)
        )
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SCRIPT, b"", sp1_output_script)
        psbt.add_output_field(0, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        # Add second silent payment output to same scan key (different k value)
        psbt.add_output_field(
            1, PSBTKeyType.PSBT_OUT_AMOUNT, b"", struct.pack("<Q", 55000)
        )
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SCRIPT, b"", sp2_output_script)
        psbt.add_output_field(1, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

        return GenTestVector(
            description="Valid PSBT with multiple silent payment outputs to the same scan key, using different k values to generate distinct output scripts",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input_priv.hex,
                    public_key=input_pub.hex,
                    prevout_txid=prevout_txid.hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=witness_script.hex(),
                    amount=100000,
                    witness_utxo=witness_utxo.hex(),
                )
            ],
            scan_keys=[
                GenScanKey(scan_pubkey=scan_pub.hex, spend_pubkey=spend_pub.hex)
            ],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof.hex(),
                    input_index=0,
                )
            ],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=40000,
                    script=sp1_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                ),
                GenOutput(
                    output_index=1,
                    amount=55000,
                    script=sp2_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                ),
            ],
        )

    def generate_all_test_vectors(self) -> Dict:
        """Generate all test vectors with complete PSBT structures"""

        # Invalid cases
        invalid_vectors = [
            asdict(self.generate_missing_dleq_test()),
            asdict(self.generate_invalid_dleq_test()),
            asdict(self.generate_non_sighash_all_test()),
            asdict(self.generate_mixed_segwit_test()),
            asdict(self.generate_no_ecdh_shares_test()),
            # TODO: asdict(self.generate_invalid_mixed_input_types_test()),
            asdict(self.generate_missing_global_dleq_test()),
            asdict(self.generate_wrong_sp_info_size_test()),
            asdict(self.generate_wrong_ecdh_share_size_test()),
            asdict(self.generate_wrong_dleq_size_test()),
            asdict(self.generate_label_without_info_test()),
            asdict(self.generate_address_mismatch_test()),
            asdict(self.generate_incomplete_ecdh_with_output_script_test()),
        ]

        # Valid cases
        valid_vectors = [
            asdict(self.generate_single_signer_global_test()),
            asdict(self.generate_multi_party_per_input_test()),
            asdict(self.generate_incomplete_ecdh_work_in_progress_test()),
            asdict(self.generate_silent_payment_with_change_test()),
            asdict(self.generate_sp_change_label_zero_test()),
            asdict(self.generate_multiple_silent_payment_outputs_test()),
            asdict(self.generate_valid_mixed_input_types_test()),
        ]

        self.test_vectors["invalid"] = invalid_vectors
        self.test_vectors["valid"] = valid_vectors

        return self.test_vectors

    def save_test_vectors(self, filename: str = "test_vectors.json"):
        """Save complete test vectors to file"""
        vectors = self.generate_all_test_vectors()
        with open(filename, "w") as f:
            json.dump(vectors, f, indent=2)
        print(f"Complete test vectors saved to {filename}")
        print(
            f"Generated {len(vectors['invalid'])} invalid and {len(vectors['valid'])} valid test cases"
        )
        return vectors


if __name__ == "__main__":
    from pathlib import Path

    # Default: save to parent directory (bip-0375 root)
    default_output = Path(__file__).parent.parent.parent / "test_vectors.json"

    generator = TestVectorGenerator()
    generator.save_test_vectors(str(default_output))
