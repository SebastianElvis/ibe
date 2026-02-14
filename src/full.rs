//! FullIdent: IND-ID-CCA secure identity-based encryption.
//!
//! This implements the Boneh-Franklin IBE scheme with the Fujisaki-Okamoto
//! transform, providing chosen-ciphertext security. It supports arbitrary-length
//! messages (unlike BasicIdent which is limited to the block size).
//!
//! The ciphertext has three components: (U, V, W).
//! - U = r * P ∈ G2
//! - V = σ ⊕ H2(e(Q_ID, P_pub)^r)
//! - W = M ⊕ H4(σ)
//!
//! Where σ is a random value and r = H3(σ, M) is derived deterministically.

use crate::error::IbeError;
use crate::hash::{h3, h4, hash_gt_to_bytes, xor_bytes};
use crate::identity::{Identity, PrivateKey};
use crate::params::SystemParams;
use crate::types::*;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use rand::{CryptoRng, Rng};

/// Maximum allowed byte length for deserialized byte vectors (1 MB).
const MAX_BYTE_VEC_LEN: u64 = 1_048_576;

/// Ciphertext for FullIdent: (U, V, W).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullCiphertext {
    /// U = r * P ∈ G2, where r = H3(σ, M).
    pub u: G2Aff,
    /// V = σ ⊕ H2(e(Q_ID, P_pub)^r).
    pub v: Vec<u8>,
    /// W = M ⊕ H4(σ).
    pub w: Vec<u8>,
}

impl Valid for FullCiphertext {
    fn check(&self) -> Result<(), SerializationError> {
        self.u.check()
    }
}

impl CanonicalSerialize for FullCiphertext {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.u.serialize_with_mode(&mut writer, compress)?;
        (self.v.len() as u64).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&self.v)?;
        (self.w.len() as u64).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&self.w)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.u.serialized_size(compress) + 8 + self.v.len() + 8 + self.w.len()
    }
}

impl CanonicalDeserialize for FullCiphertext {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let u = G2Aff::deserialize_with_mode(&mut reader, compress, validate)?;
        let v_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        if v_len > MAX_BYTE_VEC_LEN {
            return Err(SerializationError::InvalidData);
        }
        let mut v = vec![0u8; v_len as usize];
        reader.read_exact(&mut v)?;
        let w_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        if w_len > MAX_BYTE_VEC_LEN {
            return Err(SerializationError::InvalidData);
        }
        let mut w = vec![0u8; w_len as usize];
        reader.read_exact(&mut w)?;
        Ok(FullCiphertext { u, v, w })
    }
}

/// Encrypt a message for the given identity using FullIdent.
///
/// Unlike BasicIdent, FullIdent supports arbitrary-length messages and provides
/// CCA security through the Fujisaki-Okamoto transform.
///
/// # Arguments
/// - `params`: System parameters from Setup.
/// - `identity`: The recipient's identity.
/// - `message`: The plaintext message (arbitrary length).
/// - `rng`: Cryptographically secure random number generator.
///
/// # Errors
/// Returns `IbeError::HashToCurveError` if hashing the identity fails.
pub fn encrypt<R: Rng + CryptoRng>(
    params: &SystemParams,
    identity: &Identity,
    message: &[u8],
    rng: &mut R,
) -> Result<FullCiphertext, IbeError> {
    let n = params.message_block_size;

    // Q_ID = H1(ID) ∈ G1
    let q_id = identity.derive_public_point()?;

    // σ ← random n-byte string
    let mut sigma = vec![0u8; n];
    rng.fill(sigma.as_mut_slice());

    // r = H3(σ, M) ∈ Fr (deterministic randomness)
    let r = h3(&sigma, message);

    // U = r * P ∈ G2
    let u = (G2::from(params.public.generator) * r).into_affine();

    // g_id = e(Q_ID, P_pub) ∈ GT
    let g_id = E::pairing(q_id, params.public.public_key);

    // g_id_r = g_id^r ∈ GT
    let g_id_r = g_id * r;

    // V = σ ⊕ H2(g_id_r)
    let mask_v = hash_gt_to_bytes(&g_id_r, n);
    let v = xor_bytes(&sigma, &mask_v);

    // W = M ⊕ H4(σ)
    let mask_w = h4(&sigma, message.len());
    let w = xor_bytes(message, &mask_w);

    Ok(FullCiphertext { u, v, w })
}

/// Decrypt a FullIdent ciphertext using a private key.
///
/// Includes the CCA verification step: after recovering σ and M, we re-derive
/// r = H3(σ, M) and verify that U == r * P. If verification fails, the ciphertext
/// has been tampered with.
///
/// # Arguments
/// - `params`: System parameters from Setup.
/// - `private_key`: The recipient's private key (extracted by PKG).
/// - `ciphertext`: The ciphertext to decrypt.
///
/// # Errors
/// Returns `IbeError::DecryptionVerificationFailed` if the CCA check fails.
/// Returns `IbeError::InvalidCiphertext` if the ciphertext structure is invalid.
pub fn decrypt(
    params: &SystemParams,
    private_key: &PrivateKey,
    ciphertext: &FullCiphertext,
) -> Result<Vec<u8>, IbeError> {
    let n = params.message_block_size;

    if ciphertext.v.len() != n {
        return Err(IbeError::InvalidCiphertext);
    }

    // e(d_ID, U) = e(s*Q_ID, r*P) = g_id^r
    let pairing_val = E::pairing(private_key.as_affine(), ciphertext.u);

    // σ = V ⊕ H2(e(d_ID, U))
    let mask_v = hash_gt_to_bytes(&pairing_val, n);
    let sigma = xor_bytes(&ciphertext.v, &mask_v);

    // M = W ⊕ H4(σ)
    let mask_w = h4(&sigma, ciphertext.w.len());
    let message = xor_bytes(&ciphertext.w, &mask_w);

    // CCA Verification: r' = H3(σ, M), check U == r' * P
    let r_prime = h3(&sigma, &message);
    let u_prime = (G2::from(params.public.generator) * r_prime).into_affine();

    if u_prime != ciphertext.u {
        return Err(IbeError::DecryptionVerificationFailed);
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{extract, setup};
    use ark_ec::AffineRepr;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"hello, full identity-based encryption!";
        let ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();
        let decrypted = decrypt(&params, &private_key, &ciphertext).unwrap();

        assert_eq!(&decrypted, message);
    }

    #[test]
    fn arbitrary_length_messages() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        // Test various message lengths
        for len in [0, 1, 16, 32, 33, 64, 100, 256, 1000] {
            let message: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let ciphertext = encrypt(&params, &identity, &message, &mut rng).unwrap();
            let decrypted = decrypt(&params, &private_key, &ciphertext).unwrap();
            assert_eq!(decrypted, message, "Failed for message length {len}");
        }
    }

    #[test]
    fn tampered_u_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"CCA security test";
        let mut ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();

        // Tamper with U by replacing it with a different G2 point
        ciphertext.u = (G2::from(ciphertext.u) + G2::from(G2Aff::generator())).into_affine();

        let result = decrypt(&params, &private_key, &ciphertext);
        assert!(
            matches!(result, Err(IbeError::DecryptionVerificationFailed)),
            "Tampered U should be rejected"
        );
    }

    #[test]
    fn tampered_v_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"CCA security test";
        let mut ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();

        // Tamper with V
        ciphertext.v[0] ^= 0xFF;

        let result = decrypt(&params, &private_key, &ciphertext);
        assert!(
            matches!(result, Err(IbeError::DecryptionVerificationFailed)),
            "Tampered V should be rejected"
        );
    }

    #[test]
    fn tampered_w_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"CCA security test";
        let mut ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();

        // Tamper with W
        ciphertext.w[0] ^= 0xFF;

        let result = decrypt(&params, &private_key, &ciphertext);
        assert!(
            matches!(result, Err(IbeError::DecryptionVerificationFailed)),
            "Tampered W should be rejected"
        );
    }

    #[test]
    fn wrong_key_fails_cca_check() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);

        let alice = Identity::new("alice@example.com");
        let bob = Identity::new("bob@example.com");
        let bob_key = extract(&master, &bob).unwrap();

        let message = b"secret for alice";
        let ciphertext = encrypt(&params, &alice, message, &mut rng).unwrap();

        // Bob's key should fail the CCA verification
        let result = decrypt(&params, &bob_key, &ciphertext);
        assert!(
            matches!(result, Err(IbeError::DecryptionVerificationFailed)),
            "Wrong key should fail CCA check"
        );
    }

    #[test]
    fn empty_message() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"";
        let ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();
        let decrypted = decrypt(&params, &private_key, &ciphertext).unwrap();

        assert_eq!(decrypted, message.to_vec());
    }
}
