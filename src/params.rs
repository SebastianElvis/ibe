//! System parameters, master secret key, and public parameters for the IBE scheme.

use crate::types::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master secret key for the IBE system.
///
/// This is the PKG's (Private Key Generator) secret. It must be kept confidential
/// and is zeroized on drop to prevent key material from lingering in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecretKey {
    /// The secret scalar `s` in Fr.
    pub(crate) s: ScalarField,
}

impl MasterSecretKey {
    /// Create a new master secret key from a scalar.
    pub(crate) fn new(s: ScalarField) -> Self {
        Self { s }
    }
}

/// Public parameters broadcast to all users of the IBE system.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams {
    /// Generator P of G2.
    pub generator: G2Aff,
    /// P_pub = s * P in G2.
    pub public_key: G2Aff,
}

/// Complete system parameters combining public params with scheme configuration.
#[derive(Clone, Debug)]
pub struct SystemParams {
    /// The public parameters.
    pub public: PublicParams,
    /// Block size in bytes for BasicIdent messages (default: 32).
    pub message_block_size: usize,
}

impl SystemParams {
    /// Default message block size (32 bytes = 256 bits, matching SHA-256 output).
    pub const DEFAULT_BLOCK_SIZE: usize = 32;

    /// Create system params with the default block size.
    pub fn new(public: PublicParams) -> Self {
        Self {
            public,
            message_block_size: Self::DEFAULT_BLOCK_SIZE,
        }
    }

    /// Create system params with a custom block size.
    pub fn with_block_size(public: PublicParams, block_size: usize) -> Self {
        Self {
            public,
            message_block_size: block_size,
        }
    }
}
