//! Round-trip integration tests for BasicIdent and FullIdent.

use ibe::basic;
use ibe::full;
use ibe::{extract, setup, Identity};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn basic_roundtrip_various_message_sizes() {
    let mut rng = ChaCha20Rng::seed_from_u64(100);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    for len in [0, 1, 8, 16, 31, 32] {
        let message: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let ct = basic::encrypt(&params, &identity, &message, &mut rng).unwrap();
        let decrypted = basic::decrypt(&params, &pk, &ct).unwrap();
        assert_eq!(
            &decrypted[..message.len()],
            &message[..],
            "BasicIdent roundtrip failed for message length {len}"
        );
    }
}

#[test]
fn full_roundtrip_various_message_sizes() {
    let mut rng = ChaCha20Rng::seed_from_u64(100);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();

    for len in [0, 1, 8, 16, 31, 32, 33, 64, 100, 256, 1000] {
        let message: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
        let ct = full::encrypt(&params, &identity, &message, &mut rng).unwrap();
        let decrypted = full::decrypt(&params, &pk, &ct).unwrap();
        assert_eq!(
            decrypted, message,
            "FullIdent roundtrip failed for message length {len}"
        );
    }
}

#[test]
fn multiple_identities_same_system() {
    let mut rng = ChaCha20Rng::seed_from_u64(200);
    let (params, master) = setup(&mut rng);

    let identities = [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "dave@test.org",
    ];

    for id_str in &identities {
        let identity = Identity::new(id_str);
        let pk = extract(&master, &identity).unwrap();

        let message = format!("Secret message for {id_str}");
        let ct = full::encrypt(&params, &identity, message.as_bytes(), &mut rng).unwrap();
        let decrypted = full::decrypt(&params, &pk, &ct).unwrap();

        assert_eq!(decrypted, message.as_bytes());
    }
}

#[test]
fn cross_identity_decryption_fails() {
    let mut rng = ChaCha20Rng::seed_from_u64(300);
    let (params, master) = setup(&mut rng);

    let alice = Identity::new("alice@example.com");
    let bob = Identity::new("bob@example.com");

    let alice_key = extract(&master, &alice).unwrap();
    let bob_key = extract(&master, &bob).unwrap();

    // Encrypt for Alice
    let message = b"secret for alice only";
    let ct_full = full::encrypt(&params, &alice, message, &mut rng).unwrap();

    // Bob cannot decrypt Alice's FullIdent ciphertext (CCA check fails)
    let result = full::decrypt(&params, &bob_key, &ct_full);
    assert!(result.is_err());

    // Alice can decrypt
    let decrypted = full::decrypt(&params, &alice_key, &ct_full).unwrap();
    assert_eq!(&decrypted, message);
}

#[test]
fn different_system_params_incompatible() {
    let mut rng = ChaCha20Rng::seed_from_u64(400);

    // Two independent system setups
    let (_params1, master1) = setup(&mut rng);
    let (params2, master2) = setup(&mut rng);

    let identity = Identity::new("alice@example.com");

    // Extract key from system 1
    let pk1 = extract(&master1, &identity).unwrap();

    // Encrypt under system 2
    let message = b"cross-system test";
    let ct = full::encrypt(&params2, &identity, message, &mut rng).unwrap();

    // Decryption with system 1's key should fail
    let result = full::decrypt(&params2, &pk1, &ct);
    assert!(result.is_err());

    // Correct: extract key from system 2 and decrypt
    let pk2 = extract(&master2, &identity).unwrap();
    let decrypted = full::decrypt(&params2, &pk2, &ct).unwrap();
    assert_eq!(&decrypted, message);
}

#[test]
fn repeated_encryption_produces_different_ciphertexts() {
    let mut rng = ChaCha20Rng::seed_from_u64(500);
    let (params, _master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");

    let message = b"same message encrypted twice";

    let ct1 = full::encrypt(&params, &identity, message, &mut rng).unwrap();
    let ct2 = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Ciphertexts should differ due to random sigma
    assert_ne!(ct1, ct2);
}
