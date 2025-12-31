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

// Conversion from spdk-core errors
impl From<spdk_core::psbt::Error> for Bip375Error {
    fn from(err: spdk_core::psbt::Error) -> Self {
        match err {
            // Field and data errors
            spdk_core::psbt::Error::InvalidFieldData(_) => Bip375Error::InvalidData,
            spdk_core::psbt::Error::InvalidFieldType(_) => Bip375Error::InvalidData,
            spdk_core::psbt::Error::MissingField(_) => Bip375Error::InvalidData,

            // Serialization errors
            spdk_core::psbt::Error::Serialization(_) => Bip375Error::SerializationError,
            spdk_core::psbt::Error::Deserialization(_) => Bip375Error::SerializationError,
            spdk_core::psbt::Error::InvalidMagic => Bip375Error::SerializationError,
            spdk_core::psbt::Error::InvalidVersion { .. } => Bip375Error::SerializationError,

            // Address and key errors
            spdk_core::psbt::Error::InvalidAddress(_) => Bip375Error::InvalidAddress,
            spdk_core::psbt::Error::InvalidPublicKey => Bip375Error::InvalidKey,

            // Signature and proof errors
            spdk_core::psbt::Error::InvalidSignature(_) => Bip375Error::InvalidProof,
            spdk_core::psbt::Error::DleqVerificationFailed(_) => Bip375Error::InvalidProof,
            spdk_core::psbt::Error::InvalidEcdhShare(_) => Bip375Error::InvalidProof,

            // PSBT operation errors
            spdk_core::psbt::Error::ExtractionFailed(_) => Bip375Error::PsbtError,
            spdk_core::psbt::Error::InvalidInputIndex(_) => Bip375Error::InvalidData,
            spdk_core::psbt::Error::InvalidOutputIndex(_) => Bip375Error::InvalidData,
            spdk_core::psbt::Error::IncompleteEcdhCoverage(_) => Bip375Error::ValidationError,
            spdk_core::psbt::Error::StandardFieldNotAllowed(_) => Bip375Error::InvalidData,

            // Wrapped errors
            spdk_core::psbt::Error::Bitcoin(_) => Bip375Error::PsbtError,
            spdk_core::psbt::Error::Secp256k1(_) => Bip375Error::CryptoError,
            spdk_core::psbt::Error::Hex(_) => Bip375Error::InvalidData,
            spdk_core::psbt::Error::Io(_) => Bip375Error::IoError,
            spdk_core::psbt::Error::Other(_) => Bip375Error::PsbtError,
        }
    }
}

// Conversion from spdk-core crypto errors
impl From<spdk_core::psbt::crypto::CryptoError> for Bip375Error {
    fn from(err: spdk_core::psbt::crypto::CryptoError) -> Self {
        use spdk_core::psbt::crypto::CryptoError;
        match err {
            CryptoError::InvalidPrivateKey | CryptoError::InvalidPublicKey => Bip375Error::InvalidKey,
            CryptoError::InvalidSignature => Bip375Error::InvalidProof,
            CryptoError::DleqGenerationFailed(_) => Bip375Error::SigningError,
            CryptoError::DleqVerificationFailed => Bip375Error::InvalidProof,
            CryptoError::InvalidEcdh => Bip375Error::CryptoError,
            CryptoError::InvalidDleqProofLength(_) => Bip375Error::InvalidProof,
            CryptoError::HashError(_) => Bip375Error::CryptoError,
            CryptoError::Secp256k1(_) => Bip375Error::CryptoError,
            CryptoError::Other(_) => Bip375Error::CryptoError,
        }
    }
}

// Conversion from spdk-core I/O errors
impl From<spdk_core::psbt::io::IoError> for Bip375Error {
    fn from(err: spdk_core::psbt::io::IoError) -> Self {
        use spdk_core::psbt::io::IoError;
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
