// Error types for UniFFI bindings

use std::fmt;

#[derive(Debug, Clone)]
pub enum Bip375Error {
    InvalidData,
    SerializationError,
    CryptoError,
    IoError,
    ValidationError,
    InvalidAddress,
    InvalidKey,
    InvalidProof,
    SigningError,
    PsbtError,
}

impl fmt::Display for Bip375Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Bip375Error::InvalidData => write!(f, "Invalid data"),
            Bip375Error::SerializationError => write!(f, "Serialization error"),
            Bip375Error::CryptoError => write!(f, "Cryptographic operation failed"),
            Bip375Error::IoError => write!(f, "I/O operation failed"),
            Bip375Error::ValidationError => write!(f, "Validation failed"),
            Bip375Error::InvalidAddress => write!(f, "Invalid address"),
            Bip375Error::InvalidKey => write!(f, "Invalid key"),
            Bip375Error::InvalidProof => write!(f, "Invalid proof"),
            Bip375Error::SigningError => write!(f, "Signing failed"),
            Bip375Error::PsbtError => write!(f, "PSBT operation failed"),
        }
    }
}

impl std::error::Error for Bip375Error {}

// Conversion from core errors
impl From<bip375_core::Error> for Bip375Error {
    fn from(err: bip375_core::Error) -> Self {
        match err {
            bip375_core::Error::InvalidFieldData(_) => Bip375Error::InvalidData,
            bip375_core::Error::Serialization(_) => Bip375Error::SerializationError,
            bip375_core::Error::Deserialization(_) => Bip375Error::SerializationError,
            bip375_core::Error::InvalidAddress(_) => Bip375Error::InvalidAddress,
            bip375_core::Error::InvalidSignature(_) => Bip375Error::InvalidProof,
            bip375_core::Error::DleqVerificationFailed(_) => Bip375Error::InvalidProof,
            _ => Bip375Error::PsbtError,
        }
    }
}

// Conversion from crypto errors
impl From<bip375_crypto::CryptoError> for Bip375Error {
    fn from(err: bip375_crypto::CryptoError) -> Self {
        match err {
            bip375_crypto::CryptoError::InvalidPrivateKey => Bip375Error::InvalidKey,
            bip375_crypto::CryptoError::InvalidPublicKey => Bip375Error::InvalidKey,
            bip375_crypto::CryptoError::InvalidSignature => Bip375Error::InvalidProof,
            bip375_crypto::CryptoError::DleqGenerationFailed(_) => Bip375Error::SigningError,
            bip375_crypto::CryptoError::DleqVerificationFailed => Bip375Error::InvalidProof,
            _ => Bip375Error::CryptoError,
        }
    }
}

// Conversion from I/O errors
impl From<bip375_io::IoError> for Bip375Error {
    fn from(err: bip375_io::IoError) -> Self {
        match err {
            bip375_io::IoError::Io(_) => Bip375Error::IoError,
            bip375_io::IoError::Psbt(e) => e.into(),
            bip375_io::IoError::InvalidFormat(_) => Bip375Error::ValidationError,
            bip375_io::IoError::NotFound(_) => Bip375Error::IoError,
            _ => Bip375Error::IoError,
        }
    }
}

// Standard I/O error conversion
impl From<std::io::Error> for Bip375Error {
    fn from(_: std::io::Error) -> Self {
        Bip375Error::IoError
    }
}

// Hex decoding error
impl From<hex::FromHexError> for Bip375Error {
    fn from(_: hex::FromHexError) -> Self {
        Bip375Error::InvalidData
    }
}
