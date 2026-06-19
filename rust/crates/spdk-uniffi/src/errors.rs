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

impl From<psbt::Error> for Bip375Error {
    fn from(err: psbt::Error) -> Self {
        match err {
            psbt::Error::InvalidFieldData(_) => Bip375Error::InvalidData,
            psbt::Error::InvalidFieldType(_) => Bip375Error::InvalidData,
            psbt::Error::MissingField(_) => Bip375Error::InvalidData,
            psbt::Error::InvalidPsbtState(_) => Bip375Error::ValidationError,
            psbt::Error::Serialization(_) => Bip375Error::SerializationError,
            psbt::Error::Deserialization(_) => Bip375Error::SerializationError,
            psbt::Error::InvalidMagic => Bip375Error::SerializationError,
            psbt::Error::InvalidVersion { .. } => Bip375Error::SerializationError,
            psbt::Error::InvalidAddress(_) => Bip375Error::InvalidAddress,
            psbt::Error::InvalidPublicKey => Bip375Error::InvalidKey,
            psbt::Error::InvalidSignature(_) => Bip375Error::InvalidProof,
            psbt::Error::DleqVerificationFailed(_) => Bip375Error::InvalidProof,
            psbt::Error::InvalidEcdhShare(_) => Bip375Error::InvalidProof,
            psbt::Error::ExtractionFailed(_) => Bip375Error::PsbtError,
            psbt::Error::InvalidInputIndex(_) => Bip375Error::InvalidData,
            psbt::Error::InvalidOutputIndex(_) => Bip375Error::InvalidData,
            psbt::Error::IncompleteEcdhCoverage(_) => Bip375Error::ValidationError,
            psbt::Error::StandardFieldNotAllowed(_) => Bip375Error::InvalidData,
            psbt::Error::Bitcoin(_) => Bip375Error::PsbtError,
            psbt::Error::Secp256k1(_) => Bip375Error::CryptoError,
            psbt::Error::Hex(_) => Bip375Error::InvalidData,
            psbt::Error::Io(_) => Bip375Error::IoError,
            psbt::Error::Other(_) => Bip375Error::PsbtError,
        }
    }
}

// Conversion from bip375-helpers I/O errors
impl From<bip375_helpers::io::IoError> for Bip375Error {
    fn from(err: bip375_helpers::io::IoError) -> Self {
        use bip375_helpers::io::IoError;
        match err {
            IoError::Io(_) => Bip375Error::IoError,
            IoError::Json(_) => Bip375Error::SerializationError,
            IoError::Psbt(e) => e.into(),
            IoError::Hex(_) => Bip375Error::InvalidData,
            IoError::InvalidFormat(_) => Bip375Error::ValidationError,
            IoError::NotFound(_) => Bip375Error::IoError,
            IoError::Other(_) => Bip375Error::IoError,
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
