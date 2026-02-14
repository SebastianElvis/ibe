//! CCA security tests for FullIdent — verifying that tampered ciphertexts are rejected.

use ibe::full::{self, FullCiphertext};
use ibe::serialize::{from_bytes, to_bytes};
use ibe::{extract, setup, Identity};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn setup_test() -> (ibe::SystemParams, ibe::PrivateKey, Identity, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("alice@example.com");
    let pk = extract(&master, &identity).unwrap();
    (params, pk, identity, rng)
}

#[test]
fn tamper_u_component() {
    let (params, pk, identity, mut rng) = setup_test();

    let message = b"CCA security test - tamper U";
    let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Serialize, tamper U bytes, deserialize
    let mut bytes = to_bytes(&ct).unwrap();
    // Flip a bit in the U component (first few bytes are the G2 point)
    bytes[5] ^= 0x01;

    // Deserialization might fail or produce invalid ciphertext
    if let Ok(tampered_ct) = from_bytes::<FullCiphertext>(&bytes) {
        let result = full::decrypt(&params, &pk, &tampered_ct);
        assert!(result.is_err(), "Tampered U should be rejected");
    }
    // If deserialization fails, that's also acceptable
}

#[test]
fn tamper_v_component() {
    let (params, pk, identity, mut rng) = setup_test();

    let message = b"CCA security test - tamper V";
    let mut ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Flip a bit in V
    ct.v[0] ^= 0xFF;

    let result = full::decrypt(&params, &pk, &ct);
    assert!(result.is_err(), "Tampered V should fail CCA verification");
}

#[test]
fn tamper_w_component() {
    let (params, pk, identity, mut rng) = setup_test();

    let message = b"CCA security test - tamper W";
    let mut ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Flip a bit in W
    ct.w[0] ^= 0xFF;

    let result = full::decrypt(&params, &pk, &ct);
    assert!(result.is_err(), "Tampered W should fail CCA verification");
}

#[test]
fn tamper_v_and_w_simultaneously() {
    let (params, pk, identity, mut rng) = setup_test();

    let message = b"CCA security test - tamper V+W";
    let mut ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Flip bits in both V and W
    ct.v[0] ^= 0x01;
    ct.w[0] ^= 0x01;

    let result = full::decrypt(&params, &pk, &ct);
    assert!(result.is_err(), "Tampered V+W should fail CCA verification");
}

#[test]
fn truncated_v_rejected() {
    let (params, pk, identity, mut rng) = setup_test();

    let message = b"CCA security test - truncate V";
    let mut ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Truncate V to be shorter than expected
    ct.v.truncate(ct.v.len() / 2);

    let result = full::decrypt(&params, &pk, &ct);
    assert!(result.is_err(), "Truncated V should be rejected");
}

#[test]
fn swapped_ciphertexts_rejected() {
    let (params, pk, identity, mut rng) = setup_test();

    let msg1 = b"message one";
    let msg2 = b"message two";

    let ct1 = full::encrypt(&params, &identity, msg1, &mut rng).unwrap();
    let ct2 = full::encrypt(&params, &identity, msg2, &mut rng).unwrap();

    // Construct a Frankenstein ciphertext: U from ct1, V from ct1, W from ct2
    let franken = FullCiphertext {
        u: ct1.u,
        v: ct1.v.clone(),
        w: ct2.w.clone(),
    };

    let result = full::decrypt(&params, &pk, &franken);
    assert!(
        result.is_err(),
        "Mixed components from different ciphertexts should be rejected"
    );
}

#[test]
fn replay_with_different_identity_rejected() {
    let (params, _pk, identity, mut rng) = setup_test();
    let (_, master) = setup(&mut ChaCha20Rng::seed_from_u64(42));

    let bob = Identity::new("bob@example.com");
    let bob_key = extract(&master, &bob).unwrap();

    let message = b"confidential message for alice";
    let ct = full::encrypt(&params, &identity, message, &mut rng).unwrap();

    // Bob tries to decrypt Alice's ciphertext
    let result = full::decrypt(&params, &bob_key, &ct);
    assert!(
        result.is_err(),
        "Bob should not be able to decrypt Alice's ciphertext"
    );
}
