#!/usr/bin/env python3
"""
PSBT Silent Payment (psbt_sp) Package

Clean Python package for BIP 375 - Sending Silent Payments with PSBTs
Provides PSBT v2 implementation with silent payment extensions.
"""

# Constants
from .constants import PSBTFieldType

# Core PSBT functionality
from .psbt import SilentPaymentPSBT, SilentPaymentAddress, ECDHShare, validate_psbt_silent_payments

# Cryptographic utilities
from .crypto import Wallet

# Serialization utilities (for advanced usage)
from .serialization import PSBTField, PSBTv2, compact_size_uint, create_witness_utxo, parse_psbt_bytes

# BIP 352 cryptographic functions
from .bip352_crypto import (
    compute_label_tweak,
    compute_shared_secret_tweak,
    apply_label_to_spend_key,
    derive_silent_payment_output_pubkey,
    pubkey_to_p2wpkh_script
)

# PSBT utilities
from .psbt_utils import (
    extract_input_pubkey,
    extract_combined_input_pubkeys,
    check_ecdh_coverage,
    extract_scan_keys_from_outputs
)

# File I/O
from .psbt_io import save_psbt_to_file, load_psbt_from_file

# Role-based classes
from .roles import (
    PSBTCreator,
    PSBTConstructor,
    PSBTUpdater,
    PSBTSigner,
    PSBTInputFinalizer,
    PSBTExtractor
)

# Convenience re-exports of extractor methods
extract_transaction = PSBTExtractor.extract_transaction
save_transaction = PSBTExtractor.save_transaction

__version__ = "1.0.0"
__author__ = "BIP 375 Implementation"
__description__ = "PSBT v2 with BIP 375 Silent Payment extensions"

# Public API - what gets imported with "from psbt_sp import *"
__all__ = [
    # Constants
    "PSBTFieldType",

    # Core classes
    "SilentPaymentPSBT",
    "SilentPaymentAddress",
    "ECDHShare",
    "Wallet",

    # Role-based classes
    "PSBTCreator",
    "PSBTConstructor",
    "PSBTUpdater",
    "PSBTSigner",
    "PSBTInputFinalizer",
    "PSBTExtractor",

    # Serialization classes
    "PSBTField",
    "PSBTv2",

    # BIP 352 crypto functions
    "compute_label_tweak",
    "compute_shared_secret_tweak",
    "apply_label_to_spend_key",
    "derive_silent_payment_output_pubkey",
    "pubkey_to_p2wpkh_script",

    # PSBT utility functions
    "extract_input_pubkey",
    "extract_combined_input_pubkeys",
    "check_ecdh_coverage",
    "extract_scan_keys_from_outputs",

    # Transaction functions
    "extract_transaction",
    "save_transaction",

    # File I/O functions
    "save_psbt_to_file",
    "load_psbt_from_file",

    # Other utilities
    "compact_size_uint",
    "create_witness_utxo",
    "parse_psbt_bytes",
    "validate_psbt_silent_payments",

    # Package metadata
    "__version__",
    "__author__",
    "__description__"
]