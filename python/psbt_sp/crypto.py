#!/usr/bin/env python3
"""
Deterministic cryptographic utilities for BIP 375

"""

from dataclasses import dataclass
import hashlib
import hmac
import struct
from typing import Tuple, Optional
from secp256k1_374 import GE, G


class PrivateKey(int):
    """Private key that inherits from int with convenient format methods"""
    
    def __new__(cls, value: int):
        return super().__new__(cls, value)
    
    @property
    def bytes(self) -> bytes:
        """Get as 32-byte big-endian bytes"""
        return super().to_bytes(32, 'big')
    
    @property
    def hex(self) -> str:
        """Get as hex string"""
        return self.bytes.hex()
    
    def __mul__(self, other):
        """Allow multiplication (for ECDH) - return GE point when multiplied with PublicKey"""
        result = super().__mul__(other)
        # Return PrivateKey if multiplying with another int, otherwise return the result
        return PrivateKey(result) if isinstance(other, int) else result
    
    def __repr__(self):
        """String representation"""
        return f"PrivateKey({int(self)})"


class PublicKey(GE):
    """Public key that inherits from GE with convenient format methods"""
    
    def __new__(cls, point: GE):
        # Create a new instance bypassing __init__
        obj = object.__new__(cls)
        # Directly copy all attributes from the source point
        if hasattr(point, 'infinity'):
            obj.infinity = point.infinity
        if hasattr(point, 'x'):
            obj.x = point.x
        if hasattr(point, 'y'):
            obj.y = point.y
        return obj
    
    def __init__(self, point: GE):
        # Override __init__ to do nothing since we handle everything in __new__
        pass
    
    @property
    def bytes(self) -> bytes:
        """Get as compressed bytes (33 bytes)"""
        return self.to_bytes_compressed()
    
    @property
    def bytes_uncompressed(self) -> bytes:
        """Get as uncompressed bytes (65 bytes)"""
        return self.to_bytes_uncompressed()
    
    @property
    def bytes_xonly(self) -> bytes:
        """Get as x-only bytes (32 bytes)"""
        return self.to_bytes_xonly()
    
    @property
    def hex(self) -> str:
        """Get as compressed hex string"""
        return self.bytes.hex()
    
    @property
    def hex_uncompressed(self) -> str:
        """Get as uncompressed hex string"""
        return self.bytes_uncompressed.hex()
    
    @property
    def hex_xonly(self) -> str:
        """Get as x-only hex string"""
        return self.bytes_xonly.hex()

    def __add__(self, other):
        """Override addition - prioritize EC point addition, allow concatenation for bytes"""
        if isinstance(other, (PublicKey, GE)):
            # This is elliptic curve point addition
            result = super().__add__(other)
            return PublicKey(result)
        elif isinstance(other, bytes):
            # Concatenate with raw bytes
            return self.bytes + other
        else:
            # Try elliptic curve addition as fallback
            result = super().__add__(other)
            return PublicKey(result)
    
    def __sub__(self, other):
        """Override subtraction to return PublicKey"""
        result = super().__sub__(other)
        return PublicKey(result) if not result.infinity else PublicKey(result)
    
    def __mul__(self, other):
        """Override multiplication to return PublicKey when multiplied by int"""
        if isinstance(other, int):
            # This is scalar multiplication: PublicKey * int
            result = super().__mul__(other)
            return PublicKey(result)
        else:
            # Not supported - let Python handle the error
            return NotImplemented
    
    def __rmul__(self, other):
        """Override right multiplication to return PublicKey when int * PublicKey"""
        if isinstance(other, int):
            # This is scalar multiplication: int * PublicKey
            result = super().__rmul__(other)
            return PublicKey(result)
        else:
            # Let the other object handle the multiplication
            return NotImplemented
    
    def __neg__(self):
        """Override negation to return PublicKey"""
        result = super().__neg__()
        return PublicKey(result)
    
    def __len__(self):
        """Return length of bytes"""
        return len(self.bytes)

    def __repr__(self):
        """String representation"""
        if self.infinity:
            return "PublicKey(infinity)"
        else:
            return f"PublicKey({self.hex})"


class Wallet:
    """Deterministic wallet for generating silent payment keys
    
    Supports both simple seed-based derivation (for testing) and BIP39 mnemonic
    with BIP32 hierarchical deterministic derivation (for production use).
    
    BIP352 Silent Payments Derivation Paths:
    - Scan key:  m/352'/0'/0'/1'/0
    - Spend key: m/352'/0'/0'/0'/0
    """
    
    def __init__(self, seed: str = "bip375_complete_seed", mnemonic: str = None, 
                 account: int = 0, coin_type: int = 0):
        """
        Initialize wallet from seed or BIP39 mnemonic
        
        Args:
            seed: Simple seed string (for testing/demo, backward compatibility)
            mnemonic: BIP39 mnemonic phrase (12 or 24 words, for production)
            account: BIP32 account number (default: 0)
            coin_type: BIP32 coin type (default: 0 for Bitcoin mainnet)
        """
        self.seed = seed
        self.mnemonic = mnemonic
        self.account = account
        self.coin_type = coin_type
        self.bip39_seed = None
        
        if mnemonic:
            # Use BIP39 to convert mnemonic to seed
            try:
                from mnemonic import Mnemonic
                mnemo = Mnemonic("english")
                
                # Validate mnemonic
                if not mnemo.check(mnemonic):
                    raise ValueError("Invalid BIP39 mnemonic phrase")
                
                # Convert mnemonic to seed (512 bits / 64 bytes)
                self.bip39_seed = mnemo.to_seed(mnemonic, passphrase="")
                
                # Derive scan and spend keys using BIP32 paths
                self.scan_priv, self.scan_pub = self._derive_bip32_key(
                    path=f"m/352'/{coin_type}'/{account}'/1'/0"  # Scan key path
                )
                self.spend_priv, self.spend_pub = self._derive_bip32_key(
                    path=f"m/352'/{coin_type}'/{account}'/0'/0"  # Spend key path
                )
                
            except ImportError:
                raise ImportError(
                    "BIP39 support requires 'mnemonic' library. "
                    "Install with: pip install mnemonic"
                )
        else:
            # Backward compatibility: use simple deterministic derivation
            self.scan_priv, self.scan_pub = self.create_key_pair("scan", 0)
            self.spend_priv, self.spend_pub = self.create_key_pair("spend", 0)
        
        self.input_keys = []

    def _derive_bip32_key(self, path: str) -> Tuple[PrivateKey, PublicKey]:
        """
        Derive a key pair using BIP32 hierarchical deterministic derivation
        
        Args:
            path: BIP32 derivation path (e.g., "m/352'/0'/0'/1'/0")
        
        Returns:
            Tuple of (private_key, public_key)
        """
        if self.bip39_seed is None:
            raise ValueError("BIP32 derivation requires BIP39 seed")
        
        # Parse the path
        if not path.startswith("m/"):
            raise ValueError("Path must start with 'm/'")
        
        path_parts = path[2:].split("/")
        
        # Start with master key from seed
        # BIP32 master key derivation: HMAC-SHA512(key="Bitcoin seed", data=seed)
        import hmac
        import hashlib
        
        hmac_result = hmac.new(
            b"Bitcoin seed",
            self.bip39_seed,
            hashlib.sha512
        ).digest()
        
        # Split into master private key (32 bytes) and chain code (32 bytes)
        master_private_key = int.from_bytes(hmac_result[:32], 'big')
        chain_code = hmac_result[32:]
        
        # Derive child keys along the path
        private_key = master_private_key
        current_chain_code = chain_code
        
        for part in path_parts:
            if not part:
                continue
                
            # Check if hardened derivation (ends with ')
            if part.endswith("'"):
                hardened = True
                index = int(part[:-1])
            else:
                hardened = False
                index = int(part)
            
            # Derive child key
            private_key, current_chain_code = self._derive_child_key(
                private_key, current_chain_code, index, hardened
            )
        
        # Create public key from final private key
        public_point = private_key * G
        
        return PrivateKey(private_key), PublicKey(public_point)
    
    def _derive_child_key(self, parent_key: int, chain_code: bytes, 
                         index: int, hardened: bool) -> Tuple[int, bytes]:
        """
        Derive a child key using BIP32 CKD (Child Key Derivation)
        
        Args:
            parent_key: Parent private key as integer
            chain_code: Parent chain code (32 bytes)
            index: Child index
            hardened: Whether to use hardened derivation
        
        Returns:
            Tuple of (child_private_key, child_chain_code)
        """
        import hmac
        import hashlib
        
        if hardened:
            # Hardened child: HMAC-SHA512(chain_code, 0x00 || parent_key || index)
            index_with_flag = index + 0x80000000  # Set hardened bit
            data = b'\x00' + parent_key.to_bytes(32, 'big') + index_with_flag.to_bytes(4, 'big')
        else:
            # Normal child: HMAC-SHA512(chain_code, parent_pubkey || index)
            parent_pubkey = (parent_key * G).to_bytes_compressed()
            data = parent_pubkey + index.to_bytes(4, 'big')
        
        hmac_result = hmac.new(chain_code, data, hashlib.sha512).digest()
        
        # Split result
        tweak = int.from_bytes(hmac_result[:32], 'big')
        child_chain_code = hmac_result[32:]
        
        # Child private key = (tweak + parent_key) mod n
        child_private_key = (tweak + parent_key) % GE.ORDER
        
        if child_private_key == 0 or tweak >= GE.ORDER:
            raise ValueError("Invalid child key derivation (try next index)")
        
        return child_private_key, child_chain_code

    def deterministic_private_key(self, purpose: str, index: int = 0) -> int:
        """Generate deterministic private key from seed (simple mode only)"""
        if self.bip39_seed is not None:
            raise ValueError(
                "Cannot use deterministic_private_key with BIP39 mnemonic. "
                "Use BIP32 derivation paths instead."
            )
        
        data = f"{self.seed}_{purpose}_{index}".encode()
        hash_result = hashlib.sha256(data).digest()
        # Ensure it's in valid range for secp256k1
        return int.from_bytes(hash_result, 'big') % GE.ORDER

    def create_key_pair(self, purpose: str, index: int = 0) -> Tuple[PrivateKey, PublicKey]:
        """Create deterministic key pair (simple mode only)"""
        private_int = self.deterministic_private_key(purpose, index)
        public_point = private_int * G
        return PrivateKey(private_int), PublicKey(public_point)
    
    def input_key_pair(self, index: int = 0) -> Tuple[PrivateKey, PublicKey]:
        """
        Generate input key pair for specific index
        
        For BIP39 wallets, derives from m/84'/0'/0'/0/index (BIP84 native segwit)
        For simple seed wallets, uses deterministic derivation
        """
        # Create all missing keys up to and including the requested index
        while len(self.input_keys) <= index:
            key_index = len(self.input_keys)
            
            if self.bip39_seed is not None:
                # BIP84 path for native segwit: m/84'/coin_type'/account'/change/index
                # Using change=0 (external addresses)
                key_pair = self._derive_bip32_key(
                    path=f"m/84'/{self.coin_type}'/{self.account}'/0/{key_index}"
                )
            else:
                # Simple deterministic derivation
                key_pair = self.create_key_pair("input", key_index)
            
            self.input_keys.append(key_pair)
        
        return self.input_keys[index]
    
    @staticmethod
    def random_bytes(salt: int = 0) -> bytes:
        hash_result = hashlib.sha256(f"{salt}".encode()).digest()
        return (int.from_bytes(hash_result, 'big') % GE.ORDER).to_bytes(32)

@dataclass
class UTXO:
    """Represents an unspent transaction output with spending information"""
    txid: str                    # 32-byte transaction ID (hex)
    vout: int                    # Output index
    amount: int                  # Value in satoshis
    script_pubkey: str           # Spending conditions (hex)
    private_key: Optional[PrivateKey] = None       # Key to spend this UTXO
    sequence: int = 0xfffffffe   # Optional sequence number

    @property
    def txid_bytes(self) -> bytes:
        """Get txid as bytes"""
        return bytes.fromhex(self.txid)

    @property 
    def script_pubkey_bytes(self) -> bytes:
        """Get script_pubkey as bytes"""
        return bytes.fromhex(self.script_pubkey)


# Bitcoin Transaction Signing Functions
# =====================================

def deterministic_nonce(private_key: int, message_hash: bytes) -> int:
    """
    Generate deterministic nonce k for ECDSA signing (RFC 6979 style)
    
    Args:
        private_key: Private key as integer
        message_hash: 32-byte hash to sign
    
    Returns:
        Deterministic nonce k in range [1, GE.ORDER-1]
    """
    if len(message_hash) != 32:
        raise ValueError("Message hash must be 32 bytes")
    
    private_key_bytes = private_key.to_bytes(32, 'big')
    
    # RFC 6979 simplified implementation
    v = b'\x01' * 32
    k = b'\x00' * 32
    
    # Step 1: K = HMAC_K(V || 0x00 || private_key || message_hash)
    k = hmac.new(k, v + b'\x00' + private_key_bytes + message_hash, hashlib.sha256).digest()
    
    # Step 2: V = HMAC_K(V)
    v = hmac.new(k, v, hashlib.sha256).digest()
    
    # Step 3: K = HMAC_K(V || 0x01 || private_key || message_hash)  
    k = hmac.new(k, v + b'\x01' + private_key_bytes + message_hash, hashlib.sha256).digest()
    
    # Step 4: V = HMAC_K(V)
    v = hmac.new(k, v, hashlib.sha256).digest()
    
    # Generate candidate k values until we find a valid one
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate_k = int.from_bytes(v, 'big')
        
        # k must be in range [1, GE.ORDER-1]
        if 1 <= candidate_k < GE.ORDER:
            return candidate_k
        
        # If candidate is invalid, update K and V and try again
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(private_key: int, message_hash: bytes) -> Tuple[int, int]:
    """
    Sign a message hash using ECDSA
    
    Args:
        private_key: Private key as integer
        message_hash: 32-byte hash to sign
    
    Returns:
        (r, s) signature components as integers
    """
    if not (1 <= private_key < GE.ORDER):
        raise ValueError("Private key must be in range [1, n-1]")
    
    if len(message_hash) != 32:
        raise ValueError("Message hash must be 32 bytes")
    
    z = int.from_bytes(message_hash, 'big')
    
    while True:
        # Generate deterministic nonce
        k = deterministic_nonce(private_key, message_hash)
        
        # Calculate R = k * G
        R = k * G
        if R.infinity:
            continue  # Retry with different k
            
        r = int(R.x) % GE.ORDER
        if r == 0:
            continue  # Retry with different k
        
        # Calculate s = k^(-1) * (z + r * private_key) mod n
        k_inv = pow(k, -1, GE.ORDER)  # Modular inverse
        s = (k_inv * (z + r * private_key)) % GE.ORDER
        
        if s == 0:
            continue  # Retry with different k
        
        # Use low-S form (BIP 62)
        if s > GE.ORDER // 2:
            s = GE.ORDER - s
        
        return (r, s)


def der_encode_signature(r: int, s: int) -> bytes:
    """
    DER encode ECDSA signature for Bitcoin transactions
    
    Args:
        r: r component of signature
        s: s component of signature
    
    Returns:
        DER-encoded signature bytes
    """
    def encode_integer(value: int) -> bytes:
        # Convert to minimal bytes representation
        byte_length = (value.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        value_bytes = value.to_bytes(byte_length, 'big')
        
        # Add padding byte if high bit is set (to keep it positive)
        if value_bytes[0] & 0x80:
            value_bytes = b'\x00' + value_bytes
        
        return b'\x02' + bytes([len(value_bytes)]) + value_bytes
    
    r_encoded = encode_integer(r)
    s_encoded = encode_integer(s)
    
    # Construct full DER sequence
    content = r_encoded + s_encoded
    return b'\x30' + bytes([len(content)]) + content


def sighash_all(transaction_data: dict, input_index: int, script_code: bytes, amount: int) -> bytes:
    """
    Compute SIGHASH_ALL hash for P2WPKH input signing
    
    Args:
        transaction_data: Dict with 'inputs' and 'outputs' lists
        input_index: Index of input being signed
        script_code: Script code for the input (P2WPKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG)
        amount: Amount of the UTXO being spent
    
    Returns:
        32-byte SIGHASH_ALL hash
    """
    # Simplified SIGHASH_ALL for P2WPKH (BIP 143)
    inputs = transaction_data['inputs']
    outputs = transaction_data['outputs']
    
    # Version (4 bytes, little-endian)
    version = struct.pack('<I', 2)  # Transaction version 2
    
    # Prevouts hash (32 bytes)
    prevouts_data = b''
    for inp in inputs:
        prevouts_data += bytes.fromhex(inp.txid)[::-1]  # Reverse for little-endian
        prevouts_data += struct.pack('<I', inp.vout)
    prevouts_hash = hashlib.sha256(hashlib.sha256(prevouts_data).digest()).digest()
    
    # Sequences hash (32 bytes)  
    sequences_data = b''
    for inp in inputs:
        sequences_data += struct.pack('<I', inp.sequence)
    sequences_hash = hashlib.sha256(hashlib.sha256(sequences_data).digest()).digest()
    
    # Current input outpoint (36 bytes)
    current_input = inputs[input_index]
    outpoint = bytes.fromhex(current_input.txid)[::-1] + struct.pack('<I', current_input.vout)
    
    # Script code (variable length)
    script_code_with_length = bytes([len(script_code)]) + script_code
    
    # Amount (8 bytes, little-endian)
    amount_bytes = struct.pack('<Q', amount)
    
    # Sequence (4 bytes, little-endian)
    sequence = struct.pack('<I', current_input.sequence)
    
    # Outputs hash (32 bytes)
    outputs_data = b''
    for out in outputs:
        outputs_data += struct.pack('<Q', out['amount'])
        if 'script_pubkey' in out:
            script = bytes.fromhex(out['script_pubkey'])
        else:
            # For silent payment outputs, use empty script (will be computed later)
            script = b''
        outputs_data += bytes([len(script)]) + script
    outputs_hash = hashlib.sha256(hashlib.sha256(outputs_data).digest()).digest()
    
    # Locktime (4 bytes, little-endian)
    locktime = struct.pack('<I', 0)
    
    # SIGHASH_ALL (4 bytes, little-endian)
    sighash_type = struct.pack('<I', 1)
    
    # Combine all components
    preimage = (version + prevouts_hash + sequences_hash + outpoint + 
                script_code_with_length + amount_bytes + sequence + 
                outputs_hash + locktime + sighash_type)
    
    # Double SHA256
    return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()


def sign_p2wpkh_input(private_key: int, transaction_data: dict, input_index: int, 
                      pubkey_hash: bytes, amount: int) -> bytes:
    """
    Sign a P2WPKH input with SIGHASH_ALL
    
    Args:
        private_key: Private key as integer
        transaction_data: Transaction data dict
        input_index: Index of input to sign
        pubkey_hash: 20-byte hash160 of public key
        amount: Amount of UTXO being spent
    
    Returns:
        Complete signature with SIGHASH_ALL byte appended
    """
    # P2WPKH script code: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    script_code = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    
    # Compute SIGHASH_ALL hash
    sighash = sighash_all(transaction_data, input_index, script_code, amount)
    
    # Sign the hash
    r, s = ecdsa_sign(private_key, sighash)
    
    # DER encode and append SIGHASH_ALL byte
    der_sig = der_encode_signature(r, s)
    return der_sig + b'\x01'  # SIGHASH_ALL