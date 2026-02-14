#![no_main]

use libfuzzer_sys::fuzz_target;

use ibe::basic::{self, BasicCiphertext};
use ibe::serialize::from_bytes;
use ibe::{extract, setup, Identity};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    // Set up a deterministic system for fuzzing
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let (params, master) = setup(&mut rng);
    let identity = Identity::new("fuzz@test.com");
    let pk = extract(&master, &identity).unwrap();

    // Try to deserialize fuzz data as a BasicCiphertext and decrypt it.
    // This must never panic, only return Ok or Err.
    if let Ok(ct) = from_bytes::<BasicCiphertext>(data) {
        let _ = basic::decrypt(&params, &pk, &ct);
    }
});
