//! Serialization helpers for IBE types.
//!
//! Provides convenience functions wrapping arkworks' `CanonicalSerialize`
//! and `CanonicalDeserialize` traits.

use crate::error::IbeError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Serialize any `CanonicalSerialize` type to a byte vector.
pub fn to_bytes<T: CanonicalSerialize>(val: &T) -> Result<Vec<u8>, IbeError> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .map_err(|_| IbeError::DeserializationError)?;
    Ok(buf)
}

/// Deserialize a value from bytes.
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, IbeError> {
    T::deserialize_compressed(bytes).map_err(|_| IbeError::DeserializationError)
}

/// Serialize with uncompressed representation (larger but faster).
pub fn to_bytes_uncompressed<T: CanonicalSerialize>(val: &T) -> Result<Vec<u8>, IbeError> {
    let mut buf = Vec::new();
    val.serialize_uncompressed(&mut buf)
        .map_err(|_| IbeError::DeserializationError)?;
    Ok(buf)
}

/// Deserialize from uncompressed bytes.
pub fn from_bytes_uncompressed<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, IbeError> {
    T::deserialize_uncompressed(bytes).map_err(|_| IbeError::DeserializationError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::BasicCiphertext;
    use crate::full::FullCiphertext;
    use crate::identity::PrivateKey;
    use crate::params::PublicParams;
    use crate::setup::{extract, setup};
    use crate::Identity;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn public_params_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _) = setup(&mut rng);

        let bytes = to_bytes(&params.public).unwrap();
        let recovered: PublicParams = from_bytes(&bytes).unwrap();
        assert_eq!(params.public, recovered);
    }

    #[test]
    fn private_key_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, master) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");
        let pk = extract(&master, &identity).unwrap();

        let bytes = to_bytes(&pk).unwrap();
        let recovered: PrivateKey = from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_affine(), recovered.as_affine());
    }

    #[test]
    fn basic_ciphertext_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let ct =
            crate::basic::encrypt(&params, &identity, b"test message for basic", &mut rng).unwrap();

        let bytes = to_bytes(&ct).unwrap();
        let recovered: BasicCiphertext = from_bytes(&bytes).unwrap();
        assert_eq!(ct, recovered);
    }

    #[test]
    fn full_ciphertext_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (params, _) = setup(&mut rng);
        let identity = Identity::new("alice@example.com");

        let ct =
            crate::full::encrypt(&params, &identity, b"test message for full", &mut rng).unwrap();

        let bytes = to_bytes(&ct).unwrap();
        let recovered: FullCiphertext = from_bytes(&bytes).unwrap();
        assert_eq!(ct, recovered);
    }

    #[test]
    fn invalid_bytes_return_error() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result: Result<PublicParams, _> = from_bytes(&garbage);
        assert!(result.is_err());

        let result: Result<BasicCiphertext, _> = from_bytes(&garbage);
        assert!(result.is_err());

        let result: Result<FullCiphertext, _> = from_bytes(&garbage);
        assert!(result.is_err());
    }
}
