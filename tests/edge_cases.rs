//! Edge case tests for the IBE scheme.

use ibe::basic;
use ibe::full;
use ibe::{extract, setup, Identity};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn empty_identity_string() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);

    let identity = Identity::new("");
    let pk = extract(&master, &identity).unwrap();

    let message = b"message for empty identity";
    let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();
    let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(&decrypted, message);
}

#[test]
fn very_long_identity() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);

    // 10KB identity
    let long_id = vec![b'A'; 10_000];
    let identity = Identity::new(&long_id);
    let pk = extract(&master, &identity).unwrap();

    let message = b"message for long identity";
    let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();
    let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(&decrypted, message);
}

#[test]
fn identity_with_special_characters() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);

    let special_ids = [
        "user@example.com",
        "user+tag@example.com",
        "名前@例.jp",
        "null\x00byte",
        &"\u{1F600}".repeat(100), // emoji string
    ];

    for id_str in &special_ids {
        let identity = Identity::new(id_str);
        let pk = extract(&master, &identity).unwrap();

        let message = b"special character test";
        let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();
        let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

        assert_eq!(&decrypted, message, "Failed for identity: {id_str:?}");
    }
}

#[test]
fn basic_max_size_message() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    // Message exactly equal to block size
    let message = vec![0xAB; params.message_block_size];
    let ct = basic::encrypt(&params, &identity, &message, &mut rng).unwrap();
    let decrypted = basic::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(decrypted, message);
}

#[test]
fn basic_message_too_large_by_one() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, _master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");

    let message = vec![0xAB; params.message_block_size + 1];
    let result = basic::encrypt(&params, &identity, &message, &mut rng);

    assert!(matches!(result, Err(ibe::IbeError::MessageTooLarge { .. })));
}

#[test]
fn full_large_message() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    // 10KB message
    let message: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let ct = full::encrypt(&params, &identity, &message, &mut rng).unwrap();
    let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(decrypted, message);
}

#[test]
fn multiple_extractions_same_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");

    let pk1 = extract(&master, &identity).unwrap();
    let pk2 = extract(&master, &identity).unwrap();

    assert_eq!(pk1.as_affine(), pk2.as_affine());
}

#[test]
fn all_zero_message() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    let message = vec![0u8; 32];
    let ct = full::encrypt(&params, &identity, &message, &mut rng).unwrap();
    let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(decrypted, message);
}

#[test]
fn all_ff_message() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    let message = vec![0xFF; 32];
    let ct = full::encrypt(&params, &identity, &message, &mut rng).unwrap();
    let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

    assert_eq!(decrypted, message);
}
