#!/usr/bin/env python3
"""
PSBT File I/O Utilities

Functions for saving and loading PSBTs to/from files with metadata.
"""

import json
import base64
import datetime
from typing import Dict, List, Tuple, Optional
from .serialization import PSBTField, parse_psbt_bytes


def save_psbt_to_file(
    psbt: str,
    filename: str,
    metadata: Optional[Dict] = None,
    psbt_json: Optional[Dict] = None
) -> None:
    """
    Save PSBT to JSON file with metadata for multi-signer workflows

    Args:
        psbt: Base64-encoded PSBT (source of truth)
        filename: File path to save to
        metadata: Optional metadata dict with step info, completed_by, etc.
        psbt_json: Optional JSON representation from psbt.to_json() for human inspection
                   (derived data, not used programmatically)

    Note:
        The psbt_json parameter should be derived from psbt.to_json() and is included
        only for human readability. All programmatic operations should use psbt.
    """
    # Create default metadata if none provided
    if metadata is None:
        metadata = {}

    # Add timestamp
    metadata['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'

    # Prepare JSON data
    json_data = {
        'psbt': psbt,
        'metadata': metadata
    }

    # Add human-readable PSBT representation if provided
    if psbt_json:
        json_data['psbt_json'] = psbt_json

    # Write to file
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=2)


def load_psbt_from_file(filename: str) -> Tuple[List[PSBTField], List[List[PSBTField]], List[List[PSBTField]], Dict]:
    """
    Load PSBT from JSON file with metadata

    Args:
        filename: File path to load from

    Returns:
        Tuple of (global_fields, input_maps, output_maps, metadata)
    """
    with open(filename, 'r') as f:
        json_data = json.load(f)

    # Decode PSBT from base64
    psbt_data = base64.b64decode(json_data['psbt'])

    # Parse PSBT structure
    global_fields, input_maps, output_maps = parse_psbt_bytes(psbt_data)

    metadata = json_data.get('metadata', {})

    return global_fields, input_maps, output_maps, metadata
