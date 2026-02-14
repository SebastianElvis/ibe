//! Error types for the IBE library.

use core::fmt;

/// Errors that can occur in the IBE scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbeError {
    /// Hash-to-curve failed after maximum iterations.
    HashToCurveError,
    /// Ciphertext has invalid structure or failed deserialization.
    InvalidCiphertext,
    /// Deserialization of a key or ciphertext failed.
    DeserializationError,
    /// Decryption verification failed (FullIdent CCA check).
    DecryptionVerificationFailed,
    /// Message exceeds the maximum size for BasicIdent.
    MessageTooLarge { max: usize, got: usize },
}

impl fmt::Display for IbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IbeError::HashToCurveError => {
                write!(f, "hash-to-curve failed after maximum iterations")
            }
            IbeError::InvalidCiphertext => write!(f, "invalid ciphertext"),
            IbeError::DeserializationError => write!(f, "deserialization failed"),
            IbeError::DecryptionVerificationFailed => {
                write!(f, "decryption verification failed (CCA check)")
            }
            IbeError::MessageTooLarge { max, got } => {
                write!(f, "message too large: max {max} bytes, got {got} bytes")
            }
        }
    }
}

impl std::error::Error for IbeError {}
