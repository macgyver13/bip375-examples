// Error types for UniFFI bindings

use std::fmt;

#[derive(Debug, Clone)]
pub enum Bip375Error {
    InvalidData,
    SerializationError,
    CryptoError,
    IoError { message: String },
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
            Bip375Error::IoError { message } => write!(f, "I/O operation failed: {message}"),
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

impl From<psbt::roles::SpSignerError> for Bip375Error {
    fn from(err: psbt::roles::SpSignerError) -> Self {
        match err {
            
            psbt::roles::SpSignerError::SharesAlreadyPresent
            | psbt::roles::SpSignerError::MixedShareState
            | psbt::roles::SpSignerError::AlreadySigned { .. }
            | psbt::roles::SpSignerError::NoOwnedInputs
            | psbt::roles::SpSignerError::MissingShare { .. }
            | psbt::roles::SpSignerError::MissingDleqProof { .. } => Bip375Error::ValidationError,
            psbt::roles::SpSignerError::KeyResolution { .. } => Bip375Error::InvalidKey,
            _ => Bip375Error::PsbtError,
        }
    }
}

impl From<psbt_v2::DeserializeError> for Bip375Error {
    fn from(_: psbt_v2::DeserializeError) -> Self {
        Bip375Error::SerializationError
    }
}

// Conversion from bip375-helpers I/O errors
impl From<bip375_helpers::io::IoError> for Bip375Error {
    fn from(err: bip375_helpers::io::IoError) -> Self {
        use bip375_helpers::io::IoError;
        match err {
            IoError::Io(e) => Bip375Error::IoError {
                message: e.to_string(),
            },
            IoError::Json(_) => Bip375Error::SerializationError,
            IoError::Psbt(e) => e.into(),
            IoError::Hex(_) => Bip375Error::InvalidData,
            IoError::InvalidFormat(_) => Bip375Error::ValidationError,
            IoError::NotFound(message) | IoError::Other(message) => {
                Bip375Error::IoError { message }
            }
        }
    }
}

// Standard I/O error conversion
impl From<std::io::Error> for Bip375Error {
    fn from(err: std::io::Error) -> Self {
        Bip375Error::IoError {
            message: err.to_string(),
        }
    }
}

// Hex decoding error
impl From<hex::FromHexError> for Bip375Error {
    fn from(_: hex::FromHexError) -> Self {
        Bip375Error::InvalidData
    }
}
