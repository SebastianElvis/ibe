//! BasicIdent: IND-ID-CPA secure identity-based encryption.
//!
//! This implements the basic Boneh-Franklin IBE scheme without the
//! Fujisaki-Okamoto transform. It provides chosen-plaintext security.
//!
//! # Message Size
//! Messages are limited to `SystemParams::message_block_size` bytes (default 32).
//! For arbitrary-length messages, use the FullIdent scheme.

use crate::error::IbeError;
use crate::hash::{hash_gt_to_bytes, xor_bytes};
use crate::identity::{Identity, PrivateKey};
use crate::params::SystemParams;
use crate::types::*;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use rand::{CryptoRng, Rng};

/// Maximum allowed byte length for deserialized byte vectors (1 MB).
const MAX_BYTE_VEC_LEN: u64 = 1_048_576;

/// Ciphertext for BasicIdent: (U, V).
///
/// - `U = r * P` in G2 (where P is the system generator).
/// - `V = M ⊕ H2(e(Q_ID, P_pub)^r)` is the masked message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicCiphertext {
    /// U = r * P ∈ G2.
    pub u: G2Aff,
    /// V = M ⊕ H2(g_id^r) where g_id = e(Q_ID, P_pub).
    pub v: Vec<u8>,
}

impl Valid for BasicCiphertext {
    fn check(&self) -> Result<(), SerializationError> {
        self.u.check()
    }
}

impl CanonicalSerialize for BasicCiphertext {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.u.serialize_with_mode(&mut writer, compress)?;
        (self.v.len() as u64).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&self.v)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.u.serialized_size(compress) + 8 + self.v.len()
    }
}

impl CanonicalDeserialize for BasicCiphertext {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let u = G2Aff::deserialize_with_mode(&mut reader, compress, validate)?;
        let len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        if len > MAX_BYTE_VEC_LEN {
            return Err(SerializationError::InvalidData);
        }
        let mut v = vec![0u8; len as usize];
        reader.read_exact(&mut v)?;
        Ok(BasicCiphertext { u, v })
    }
}

/// Encrypt a message for the given identity using BasicIdent.
///
/// # Arguments
/// - `params`: System parameters from Setup.
/// - `identity`: The recipient's identity.
/// - `message`: The plaintext message (must be ≤ `params.message_block_size` bytes).
/// - `rng`: Cryptographically secure random number generator.
///
/// # Errors
/// Returns `IbeError::MessageTooLarge` if the message exceeds the block size.
/// Returns `IbeError::HashToCurveError` if hashing the identity fails.
pub fn encrypt<R: Rng + CryptoRng>(
    params: &SystemParams,
    identity: &Identity,
    message: &[u8],
    rng: &mut R,
) -> Result<BasicCiphertext, IbeError> {
    if message.len() > params.message_block_size {
        return Err(IbeError::MessageTooLarge {
            max: params.message_block_size,
            got: message.len(),
        });
    }

    // Pad message to block size
    let mut padded_msg = vec![0u8; params.message_block_size];
    padded_msg[..message.len()].copy_from_slice(message);

    // Q_ID = H1(ID) ∈ G1
    let q_id = identity.derive_public_point()?;

    // r ← random scalar in Fr
    let r = ScalarField::rand(rng);

    // U = r * P ∈ G2
    let u = (G2::from(params.public.generator) * r).into_affine();

    // g_id = e(Q_ID, P_pub) ∈ GT
    let g_id = E::pairing(q_id, params.public.public_key);

    // g_id_r = g_id^r ∈ GT
    // PairingOutput implements Group with scalar multiplication
    let g_id_r = g_id * r;

    // V = padded_msg ⊕ H2(g_id_r)
    let mask = hash_gt_to_bytes(&g_id_r, params.message_block_size);
    let v = xor_bytes(&padded_msg, &mask);

    Ok(BasicCiphertext { u, v })
}

/// Decrypt a BasicIdent ciphertext using a private key.
///
/// # Arguments
/// - `params`: System parameters from Setup.
/// - `private_key`: The recipient's private key (extracted by PKG).
/// - `ciphertext`: The ciphertext to decrypt.
///
/// # Returns
/// The decrypted padded message (always `params.message_block_size` bytes).
/// The caller is responsible for removing padding.
pub fn decrypt(
    params: &SystemParams,
    private_key: &PrivateKey,
    ciphertext: &BasicCiphertext,
) -> Result<Vec<u8>, IbeError> {
    if ciphertext.v.len() != params.message_block_size {
        return Err(IbeError::InvalidCiphertext);
    }

    // e(d_ID, U) = e(s*Q_ID, r*P) = e(Q_ID, P)^{sr} = g_id^r
    let pairing_val = E::pairing(private_key.as_affine(), ciphertext.u);

    // M = V ⊕ H2(e(d_ID, U))
    let mask = hash_gt_to_bytes(&pairing_val, params.message_block_size);
    let plaintext = xor_bytes(&ciphertext.v, &mask);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{extract, setup};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let private_key = extract(&master, &identity).unwrap();

        let message = b"hello, identity-based encryption";
        assert!(message.len() <= params.message_block_size);

        let ciphertext = encrypt(&params, &identity, message, &mut rng).unwrap();
        let decrypted = decrypt(&params, &private_key, &ciphertext).unwrap();

        // The decrypted message is padded to block size
        assert_eq!(&decrypted[..message.len()], &message[..]);
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, master) = setup(&mut rng);

        let alice = Identity::new("alice@example.com");
        let bob = Identity::new("bob@example.com");
        let bob_key = extract(&master, &bob).unwrap();

        let message = b"secret for alice only";
        let ciphertext = encrypt(&params, &alice, message, &mut rng).unwrap();

        // Bob's key should not decrypt Alice's ciphertext correctly
        let decrypted = decrypt(&params, &bob_key, &ciphertext).unwrap();
        assert_ne!(&decrypted[..message.len()], &message[..]);
    }

    #[test]
    fn different_randomness_produces_different_ciphertexts() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let message = b"same message twice";
        let ct1 = encrypt(&params, &identity, message, &mut rng).unwrap();
        let ct2 = encrypt(&params, &identity, message, &mut rng).unwrap();

        // U values should differ (different random r)
        assert_ne!(ct1.u, ct2.u);
    }

    #[test]
    fn message_too_large() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let message = vec![0xAB; params.message_block_size + 1];
        let result = encrypt(&params, &identity, &message, &mut rng);
        assert!(matches!(result, Err(IbeError::MessageTooLarge { .. })));
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

        // Empty message means all padding zeros
        assert_eq!(&decrypted[..message.len()], &message[..]);
    }
}
