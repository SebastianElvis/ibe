//! Identity representation and private key types for the IBE scheme.

use crate::error::IbeError;
use crate::hash::hash_to_g1;
use crate::types::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// An identity in the IBE system (e.g., an email address, username, etc.).
///
/// The identity is an arbitrary byte string that gets hashed to a point in G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity(Vec<u8>);

impl Identity {
    /// Create a new identity from any byte-representable value.
    pub fn new(id: impl AsRef<[u8]>) -> Self {
        Self(id.as_ref().to_vec())
    }

    /// Compute Q_ID = H1(ID), the public point for this identity in G1.
    pub fn derive_public_point(&self) -> Result<G1Aff, IbeError> {
        hash_to_g1(&self.0)
    }

    /// Get the raw identity bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Private key for an identity: d_ID = s * Q_ID in G1.
///
/// Extracted by the PKG using the master secret key.
/// The key material is zeroized on drop.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey {
    /// The private key point d_ID = s * H1(ID) in G1.
    pub(crate) d_id: G1Aff,
}

impl PrivateKey {
    /// Create a new private key from a G1 affine point.
    pub(crate) fn new(d_id: G1Aff) -> Self {
        Self { d_id }
    }

    /// Get the private key point in affine form.
    pub fn as_affine(&self) -> &G1Aff {
        &self.d_id
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Overwrite the point with the identity element.
        // G1Affine doesn't implement Zeroize, so we do it manually
        // by replacing with a default value.
        self.d_id = G1Aff::default();
    }
}
