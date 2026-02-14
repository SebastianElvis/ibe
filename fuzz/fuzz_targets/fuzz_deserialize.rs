#![no_main]

use libfuzzer_sys::fuzz_target;

use ibe::basic::BasicCiphertext;
use ibe::full::FullCiphertext;
use ibe::serialize::from_bytes;
use ibe::{PrivateKey, PublicParams};

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize random bytes as each of the major types.
    // None of these should ever panic.
    let _ = from_bytes::<PublicParams>(data);
    let _ = from_bytes::<PrivateKey>(data);
    let _ = from_bytes::<BasicCiphertext>(data);
    let _ = from_bytes::<FullCiphertext>(data);
});
