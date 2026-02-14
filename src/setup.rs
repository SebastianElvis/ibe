//! IBE Setup and Extract algorithms.
//!
//! - **Setup**: Generate system parameters and master secret key.
//! - **Extract**: Derive a private key for an identity using the master secret.

use crate::error::IbeError;
use crate::identity::{Identity, PrivateKey};
use crate::params::{MasterSecretKey, PublicParams, SystemParams};
use crate::types::*;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::{CryptoRng, Rng};

/// Run the IBE Setup algorithm.
///
/// Generates a fresh master secret key and public system parameters.
/// The generator is the standard G2 generator for BN254.
///
/// # Returns
/// A tuple of (SystemParams, MasterSecretKey).
pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (SystemParams, MasterSecretKey) {
    // Use the standard BN254 G2 generator
    let generator = G2Aff::generator();

    // Generate random master secret s ∈ Fr
    let s = ScalarField::rand(rng);

    // Compute P_pub = s * P in G2
    let public_key = (G2::from(generator) * s).into_affine();

    let public = PublicParams {
        generator,
        public_key,
    };

    let params = SystemParams::new(public);
    let master = MasterSecretKey::new(s);

    (params, master)
}

/// Extract a private key for the given identity.
///
/// Computes d_ID = s * H1(ID) where s is the master secret.
///
/// # Errors
/// Returns `IbeError::HashToCurveError` if hashing the identity to G1 fails.
pub fn extract(master: &MasterSecretKey, identity: &Identity) -> Result<PrivateKey, IbeError> {
    // Q_ID = H1(ID) ∈ G1
    let q_id = identity.derive_public_point()?;

    // d_ID = s * Q_ID ∈ G1
    let d_id = (G1::from(q_id) * master.s).into_affine();

    Ok(PrivateKey::new(d_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::Pairing;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn setup_produces_valid_params() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _master) = setup(&mut rng);

        // Generator should be the standard G2 generator
        assert_eq!(params.public.generator, G2Aff::generator());
        // Public key should be on the G2 curve
        assert!(params.public.public_key.is_on_curve());
    }

    #[test]
    fn extract_produces_valid_private_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let private_key = extract(&master, &identity).unwrap();
        assert!(private_key.as_affine().is_on_curve());
    }

    #[test]
    fn extract_is_deterministic() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let pk1 = extract(&master, &identity).unwrap();
        let pk2 = extract(&master, &identity).unwrap();
        assert_eq!(pk1.as_affine(), pk2.as_affine());
    }

    #[test]
    fn pairing_consistency_check() {
        // Verify the fundamental IBE equation:
        // e(d_ID, P) == e(Q_ID, P_pub)
        // where d_ID = s * Q_ID and P_pub = s * P
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("bob@example.com");

        let q_id = identity.derive_public_point().unwrap();
        let d_id = extract(&master, &identity).unwrap();

        let lhs = E::pairing(d_id.as_affine(), params.public.generator);
        let rhs = E::pairing(q_id, params.public.public_key);

        assert_eq!(
            lhs, rhs,
            "Pairing consistency check failed: e(d_ID, P) != e(Q_ID, P_pub)"
        );
    }

    #[test]
    fn different_identities_get_different_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_params, master) = setup(&mut rng);

        let pk_alice = extract(&master, &Identity::new("alice")).unwrap();
        let pk_bob = extract(&master, &Identity::new("bob")).unwrap();

        assert_ne!(pk_alice.as_affine(), pk_bob.as_affine());
    }
}
