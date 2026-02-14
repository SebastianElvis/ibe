//! Cryptographic hash functions for the Boneh-Franklin IBE scheme.
//!
//! - **H1**: Maps an identity string to a point in G1 (try-and-increment).
//! - **H2**: Maps a GT element to a byte string of arbitrary length (counter-mode SHA-256).
//! - **H3**: Maps (sigma, message) to a scalar in Fr (FullIdent only).
//! - **H4**: Maps sigma to a byte string of arbitrary length (FullIdent only).
//!
//! All functions use domain separation tags to prevent cross-function collisions.

use crate::error::IbeError;
use crate::types::*;
use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha256};

/// Domain separation tags.
const DST_H1: &[u8] = b"IBE-BN254-H1";
const DST_H2: u8 = 0x02;
const DST_H3: u8 = 0x03;
const DST_H4: u8 = 0x04;

/// Maximum number of iterations for try-and-increment in H1.
const H1_MAX_ITERATIONS: u32 = 256;

/// H1: Hash an identity to a point in G1.
///
/// Uses the try-and-increment method:
/// 1. For counter = 0, 1, 2, ...:
///    - x = SHA-256(DST || identity || counter) mod p
///    - Check if x³ + 3 (the BN254 G1 curve equation y² = x³ + 3) has a square root
///    - If yes, return the point (x, y)
///
/// # Security Note
/// Try-and-increment is NOT constant-time with respect to the identity input.
/// This is acceptable because identities are public information in IBE.
pub fn hash_to_g1(identity: &[u8]) -> Result<G1Aff, IbeError> {
    // BN254 G1 curve: y² = x³ + 3
    let b = BaseField::from(3u64);

    for counter in 0u32..H1_MAX_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(DST_H1);
        hasher.update(identity);
        hasher.update(counter.to_le_bytes());
        let hash_output = hasher.finalize();

        // Interpret hash output as a field element mod p
        let x = BaseField::from_le_bytes_mod_order(&hash_output);

        // Compute y² = x³ + 3
        let x3 = x * x * x;
        let rhs = x3 + b;

        // Check if rhs is a quadratic residue and get the square root
        if let Some(y) = rhs.sqrt() {
            // Construct the affine point
            let point = G1Aff::new_unchecked(x, y);

            // Verify the point is on the curve and in the correct subgroup
            if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
                return Ok(point);
            }
        }
    }

    Err(IbeError::HashToCurveError)
}

/// H2: Map a GT element to a byte string of the given length.
///
/// Uses counter-mode SHA-256:
/// For each 32-byte block i: SHA-256(0x02 || serialized_gt || i)
fn sha256_kdf(domain_tag: u8, input: &[u8], len: usize) -> Vec<u8> {
    let num_blocks = len.div_ceil(32);
    let mut output = Vec::with_capacity(num_blocks * 32);

    for i in 0u32..num_blocks as u32 {
        let mut hasher = Sha256::new();
        hasher.update([domain_tag]);
        hasher.update(input);
        hasher.update(i.to_le_bytes());
        output.extend_from_slice(&hasher.finalize());
    }

    output.truncate(len);
    output
}

/// H2: Map a GT element to a byte mask of the specified length.
pub fn hash_gt_to_bytes(gt: &GT, len: usize) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;

    let mut gt_bytes = Vec::new();
    gt.0.serialize_compressed(&mut gt_bytes)
        .expect("GT serialization should not fail");

    sha256_kdf(DST_H2, &gt_bytes, len)
}

/// H3: Map (sigma, message) to a scalar in Fr.
///
/// Used in the FullIdent scheme to derive deterministic randomness.
pub fn h3(sigma: &[u8], message: &[u8]) -> ScalarField {
    let mut hasher = Sha256::new();
    hasher.update([DST_H3]);
    hasher.update((sigma.len() as u64).to_le_bytes());
    hasher.update(sigma);
    hasher.update(message);
    let hash_output = hasher.finalize();

    ScalarField::from_le_bytes_mod_order(&hash_output)
}

/// H4: Map sigma to a byte string of the specified length.
///
/// Used in the FullIdent scheme to mask the message with sigma.
pub fn h4(sigma: &[u8], len: usize) -> Vec<u8> {
    sha256_kdf(DST_H4, sigma, len)
}

/// XOR two byte slices of equal length.
///
/// # Panics
/// Panics if the slices have different lengths.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "xor_bytes: length mismatch");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    #[test]
    fn h1_produces_valid_g1_point() {
        let point = hash_to_g1(b"alice@example.com").unwrap();
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn h1_is_deterministic() {
        let p1 = hash_to_g1(b"bob@example.com").unwrap();
        let p2 = hash_to_g1(b"bob@example.com").unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn h1_different_identities_produce_different_points() {
        let p1 = hash_to_g1(b"alice@example.com").unwrap();
        let p2 = hash_to_g1(b"bob@example.com").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn h1_empty_identity() {
        let point = hash_to_g1(b"").unwrap();
        assert!(point.is_on_curve());
    }

    #[test]
    fn h2_output_length() {
        use ark_ec::pairing::Pairing;
        // Create a GT element from pairing of generators
        let g1 = G1Aff::generator();
        let g2 = G2Aff::generator();
        let gt = E::pairing(g1, g2);

        let out_32 = hash_gt_to_bytes(&gt, 32);
        assert_eq!(out_32.len(), 32);

        let out_64 = hash_gt_to_bytes(&gt, 64);
        assert_eq!(out_64.len(), 64);

        let out_1 = hash_gt_to_bytes(&gt, 1);
        assert_eq!(out_1.len(), 1);
    }

    #[test]
    fn h2_is_deterministic() {
        use ark_ec::pairing::Pairing;
        let g1 = G1Aff::generator();
        let g2 = G2Aff::generator();
        let gt = E::pairing(g1, g2);

        let a = hash_gt_to_bytes(&gt, 32);
        let b = hash_gt_to_bytes(&gt, 32);
        assert_eq!(a, b);
    }

    #[test]
    fn h3_output_is_valid_scalar() {
        let sigma = [0xABu8; 32];
        let message = b"hello world";
        let scalar = h3(&sigma, message);
        // Verify it's a valid scalar by checking it's less than the field modulus
        let repr = scalar.into_bigint();
        assert!(repr < ScalarField::MODULUS);
    }

    #[test]
    fn h3_is_deterministic() {
        let sigma = [0x42u8; 32];
        let msg = b"test message";
        let s1 = h3(&sigma, msg);
        let s2 = h3(&sigma, msg);
        assert_eq!(s1, s2);
    }

    #[test]
    fn h4_output_length() {
        let sigma = [0xFFu8; 32];
        assert_eq!(h4(&sigma, 32).len(), 32);
        assert_eq!(h4(&sigma, 100).len(), 100);
        assert_eq!(h4(&sigma, 1).len(), 1);
    }

    #[test]
    fn xor_roundtrip() {
        let a = vec![0x01, 0x02, 0x03, 0x04];
        let b = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let c = xor_bytes(&a, &b);
        let d = xor_bytes(&c, &b);
        assert_eq!(a, d);
    }
}
