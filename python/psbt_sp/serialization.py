#!/usr/bin/env python3
"""
PSBT v2 serialization utilities for BIP 375
"""

import struct
from typing import List, Tuple


def compact_size_uint(n: int) -> bytes:
    """Encode integer as Bitcoin compact size uint"""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<L', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def read_compact_size_uint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Read compact size uint from bytes, return (value, new_offset)"""
    if offset >= len(data):
        raise ValueError("Not enough data")
    
    first_byte = data[offset]
    if first_byte < 0xfd:
        return first_byte, offset + 1
    elif first_byte == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
    elif first_byte == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<L', data[offset+1:offset+5])[0], offset + 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9


def write_keydata(key_data: bytes) -> bytes:
    """Write key data with length prefix"""
    return compact_size_uint(len(key_data)) + key_data


def write_valuedata(value_data: bytes) -> bytes:
    """Write value data with length prefix"""
    return compact_size_uint(len(value_data)) + value_data


def write_psbt_field(key_type: int, key_data: bytes, value_data: bytes) -> bytes:
    """Write a PSBT field in the format: key_len + key_type + key_data + value_len + value_data"""
    key_full = bytes([key_type]) + key_data
    return write_keydata(key_full) + write_valuedata(value_data)


def ser_uint32(n: int) -> bytes:
    """Serialize 32-bit unsigned integer in little-endian"""
    return struct.pack('<I', n)


def create_outpoint(txid: bytes, vout: int) -> bytes:
    """Create a Bitcoin outpoint (32 byte txid + 4 byte vout)"""
    return txid + struct.pack('<I', vout)


def create_witness_utxo(amount: int, script_pubkey: bytes) -> bytes:
    """Create witness UTXO field value"""
    return struct.pack('<Q', amount) + compact_size_uint(len(script_pubkey)) + script_pubkey


class PSBTField:
    """Represents a single PSBT field"""
    
    def __init__(self, key_type: int, key_data: bytes, value_data: bytes):
        self.key_type = key_type
        self.key_data = key_data
        self.value_data = value_data
    
    def serialize(self) -> bytes:
        """Serialize this field to PSBT format"""
        return write_psbt_field(self.key_type, self.key_data, self.value_data)


class PSBTv2:
    """
    Basic PSBT v2 implementation for BIP 375 test vector generation
    """
    
    def __init__(self):
        self.global_fields: List[PSBTField] = []
        self.input_maps: List[List[PSBTField]] = []
        self.output_maps: List[List[PSBTField]] = []
    
    def add_global_field(self, key_type: int, key_data: bytes, value_data: bytes):
        """Add a global field"""
        self.global_fields.append(PSBTField(key_type, key_data, value_data))
    
    def add_input_field(self, input_index: int, key_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific input"""
        # Extend input_maps if needed
        while len(self.input_maps) <= input_index:
            self.input_maps.append([])
        
        self.input_maps[input_index].append(PSBTField(key_type, key_data, value_data))
    
    def add_output_field(self, output_index: int, key_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific output"""
        # Extend output_maps if needed
        while len(self.output_maps) <= output_index:
            self.output_maps.append([])
        
        self.output_maps[output_index].append(PSBTField(key_type, key_data, value_data))
    
    def serialize_section(self, fields: List[PSBTField]) -> bytes:
        """Serialize a section (global, input, or output)"""
        result = b''
        for field in fields:
            result += field.serialize()
        # End with separator (empty key)
        result += b'\x00'
        return result
    
    def serialize(self) -> bytes:
        """Serialize entire PSBT to bytes"""
        result = b'psbt\xff'  # PSBT magic
        
        # Global section
        result += self.serialize_section(self.global_fields)
        
        # Input sections
        for input_fields in self.input_maps:
            result += self.serialize_section(input_fields)
        
        # Output sections
        for output_fields in self.output_maps:
            result += self.serialize_section(output_fields)

        return result


def parse_psbt_bytes(psbt_data: bytes) -> Tuple[List['PSBTField'], List[List['PSBTField']], List[List['PSBTField']]]:
    """
    Parse PSBT bytes into field lists

    Args:
        psbt_data: Raw PSBT bytes (must start with magic b'psbt\\xff')

    Returns:
        Tuple of (global_fields, input_maps, output_maps)

    Raises:
        ValueError: If PSBT data is invalid or truncated
    """
    from .constants import PSBTKeyType

    if len(psbt_data) < 5 or psbt_data[:5] != b'psbt\xff':
        raise ValueError("Invalid PSBT magic")

    def parse_compact_size_uint(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse compact size uint, returns (value, new_offset)"""
        if offset >= len(data):
            raise ValueError("Not enough data")

        first_byte = data[offset]
        if first_byte < 0xfd:
            return first_byte, offset + 1
        elif first_byte == 0xfd:
            return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
        elif first_byte == 0xfe:
            return struct.unpack('<L', data[offset+1:offset+5])[0], offset + 5
        else:
            return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9

    def parse_section(data: bytes, offset: int) -> Tuple[List[PSBTField], int]:
        """Parse a PSBT section (global, input, or output)"""
        fields = []

        while offset < len(data):
            # Read key length
            key_len, offset = parse_compact_size_uint(data, offset)
            if key_len == 0:  # End of section
                break

            # Read key data
            if offset + key_len > len(data):
                raise ValueError("Truncated key data")
            key_data = data[offset:offset + key_len]
            offset += key_len

            # Read value length
            value_len, offset = parse_compact_size_uint(data, offset)

            # Read value data
            if offset + value_len > len(data):
                raise ValueError("Truncated value data")
            value_data = data[offset:offset + value_len]
            offset += value_len

            # Extract key type and create PSBTField
            if key_data:
                # Destructure into key_type and key_data
                key_type = key_data[0] # First byte is key_type
                key_data = key_data[1:] if len(key_data) > 1 else b''
                fields.append(PSBTField(key_type, key_data, value_data))

        return fields, offset

    offset = 5  # Skip magic

    # Parse global section
    global_fields, offset = parse_section(psbt_data, offset)

    # Determine number of inputs and outputs
    num_inputs = 1  # Default
    num_outputs = 1  # Default

    for field in global_fields:
        if field.key_type == PSBTKeyType.PSBT_GLOBAL_INPUT_COUNT:
            num_inputs = field.value_data[0] if len(field.value_data) > 0 else 1
        elif field.key_type == PSBTKeyType.PSBT_GLOBAL_OUTPUT_COUNT:
            num_outputs = field.value_data[0] if len(field.value_data) > 0 else 1

    # Parse input sections
    input_maps = []
    for _ in range(num_inputs):
        input_fields, offset = parse_section(psbt_data, offset)
        input_maps.append(input_fields)

    # Parse output sections
    output_maps = []
    for _ in range(num_outputs):
        output_fields, offset = parse_section(psbt_data, offset)
        output_maps.append(output_fields)

    return global_fields, input_maps, output_maps