//! Serialization round-trip integration tests.

use ibe::basic;
use ibe::full;
use ibe::serialize::{from_bytes, to_bytes};
use ibe::{extract, setup, Identity, PrivateKey, PublicParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn public_params_serialize_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, _) = setup(&mut rng);

    let bytes = to_bytes(&params.public).unwrap();
    let recovered: PublicParams = from_bytes(&bytes).unwrap();

    assert_eq!(params.public, recovered);
}

#[test]
fn private_key_serialize_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    let bytes = to_bytes(&pk).unwrap();
    let recovered: PrivateKey = from_bytes(&bytes).unwrap();

    assert_eq!(pk.as_affine(), recovered.as_affine());
}

#[test]
fn basic_ciphertext_serialize_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    let message = b"test message for serialization";
    let ct = basic::encrypt(&params, &identity, message, &mut rng).unwrap();

    let bytes = to_bytes(&ct).unwrap();
    let recovered: basic::BasicCiphertext = from_bytes(&bytes).unwrap();

    assert_eq!(ct, recovered);

    // Verify recovered ciphertext is still decryptable
    let decrypted = basic::decrypt(&params, &pk, &recovered).unwrap();
    assert_eq!(&decrypted[..message.len()], &message[..]);
}

#[test]
fn full_ciphertext_serialize_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    let message = b"test message for serialization";
    let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    let bytes = to_bytes(&ct).unwrap();
    let recovered: full::FullCiphertext = from_bytes(&bytes).unwrap();

    assert_eq!(ct, recovered);

    // Verify recovered ciphertext is still decryptable
    let decrypted = full::decrypt(&params, &pk, &recovered).unwrap();
    assert_eq!(&decrypted, message);
}

#[test]
fn garbage_bytes_rejected() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    assert!(from_bytes::<PublicParams>(&garbage).is_err());
    assert!(from_bytes::<PrivateKey>(&garbage).is_err());
    assert!(from_bytes::<basic::BasicCiphertext>(&garbage).is_err());
    assert!(from_bytes::<full::FullCiphertext>(&garbage).is_err());
}

#[test]
fn empty_bytes_rejected() {
    let empty: Vec<u8> = vec![];

    assert!(from_bytes::<PublicParams>(&empty).is_err());
    assert!(from_bytes::<PrivateKey>(&empty).is_err());
    assert!(from_bytes::<basic::BasicCiphertext>(&empty).is_err());
    assert!(from_bytes::<full::FullCiphertext>(&empty).is_err());
}
