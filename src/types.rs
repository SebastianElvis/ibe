//! Type aliases wrapping ark-bn254 types for the IBE scheme.
//!
//! This module isolates the rest of the crate from direct arkworks imports,
//! making a future curve swap feasible with minimal changes.

pub use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
pub use ark_ec::pairing::{Pairing, PairingOutput};

/// Scalar field of BN254 (order of G1, G2, GT).
pub type ScalarField = Fr;

/// Base field of BN254 G1.
pub type BaseField = Fq;

/// G1 group element in projective coordinates (used for identity hashes and private keys).
pub type G1 = G1Projective;

/// G1 group element in affine coordinates (used for serialization).
pub type G1Aff = G1Affine;

/// G2 group element in projective coordinates (used for system generator and public key).
pub type G2 = G2Projective;

/// G2 group element in affine coordinates (used for serialization).
pub type G2Aff = G2Affine;

/// Pairing target group element.
pub type GT = PairingOutput<Bn254>;

/// The pairing engine type.
pub type E = Bn254;
