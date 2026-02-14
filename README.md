# ibe

> **Disclaimer**: This entire codebase was AI-generated. It has **not** been audited and is intended for educational and research purposes only. **Do not use in production.**

Boneh-Franklin **Identity-Based Encryption** (IBE) over the BN254 pairing curve, implemented in Rust.

Based on the seminal paper:

> Dan Boneh and Matthew Franklin. *"Identity-Based Encryption from the Weil Pairing."*
> SIAM Journal on Computing, 32(3):586-615, 2003.

## What is Identity-Based Encryption?

In a traditional public-key system, a sender needs the recipient's public key (a certificate) to encrypt.
In IBE, the recipient's **identity** (email address, username, phone number, ...) *is* the public key.
A trusted Private Key Generator (PKG) holds a master secret and can issue private keys for any identity on demand.

```text
         PKG
        /   \
  master     extract("alice@example.com")
  secret            |
                private key
                    |
  Sender -----> [ encrypt ] ----> Ciphertext ----> [ decrypt ] ----> Plaintext
         identity                                 private key
```

## Schemes

| Scheme | Security | Message size | Module |
|--------|----------|--------------|--------|
| **BasicIdent** | IND-ID-CPA (chosen-plaintext) | Fixed block (default 32 bytes) | `ibe::basic` |
| **FullIdent** | IND-ID-CCA (chosen-ciphertext) | Arbitrary length | `ibe::full` |

FullIdent applies the [Fujisaki-Okamoto transform](https://link.springer.com/chapter/10.1007/978-3-540-48405-9_36) to BasicIdent,
providing resistance against active (chosen-ciphertext) attackers. **Use FullIdent for all production applications.**

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ibe = { git = "https://github.com/SebastianElvis/ibe.git" }
rand = "0.8"
```

### FullIdent (recommended)

```rust
use ibe::{setup, extract, Identity};
use ibe::full;

let mut rng = rand::thread_rng();

// 1. PKG generates system parameters and master secret
let (params, master_secret) = setup(&mut rng);

// 2. User registers their identity
let identity = Identity::new("alice@example.com");

// 3. PKG extracts a private key for Alice (delivered securely)
let private_key = extract(&master_secret, &identity).unwrap();

// 4. Anyone can encrypt a message using only Alice's identity
let message = b"Hello, Alice!";
let ciphertext = full::encrypt(&params, &identity, message, &mut rng).unwrap();

// 5. Alice decrypts with her private key
let decrypted = full::decrypt(&params, &private_key, &ciphertext).unwrap();
assert_eq!(&decrypted, message);
```

### BasicIdent

```rust
use ibe::{setup, extract, Identity};
use ibe::basic;

let mut rng = rand::thread_rng();
let (params, master_secret) = setup(&mut rng);
let identity = Identity::new("bob@example.com");
let private_key = extract(&master_secret, &identity).unwrap();

// Messages are limited to params.message_block_size (32 bytes by default)
let message = b"short secret";
let ciphertext = basic::encrypt(&params, &identity, message, &mut rng).unwrap();

// Decrypt returns zero-padded plaintext of block size
let decrypted = basic::decrypt(&params, &private_key, &ciphertext).unwrap();
assert_eq!(&decrypted[..message.len()], &message[..]);
```

### Serialization

All keys and ciphertexts can be serialized to bytes for storage or transmission:

```rust
use ibe::serialize::{to_bytes, from_bytes};
use ibe::full::FullCiphertext;

// Serialize
let bytes = to_bytes(&ciphertext).unwrap();

// Deserialize
let recovered: FullCiphertext = from_bytes(&bytes).unwrap();
```

## Architecture

```
src/
  lib.rs          Public API and crate documentation
  types.rs        Type aliases wrapping ark-bn254 (G1, G2, GT, Fr)
  error.rs        IbeError enum
  hash.rs         Hash functions H1 (hash-to-G1), H2 (GT->bytes), H3, H4
  params.rs       MasterSecretKey, PublicParams, SystemParams
  identity.rs     Identity wrapper, PrivateKey (zeroized on drop)
  setup.rs        Setup and Extract algorithms
  basic.rs        BasicIdent encrypt/decrypt (IND-ID-CPA)
  full.rs         FullIdent encrypt/decrypt (IND-ID-CCA)
  serialize.rs    Bounded serialization helpers
```

## Cryptographic Details

### Curve & Pairing

- **Curve**: BN254 (alt_bn128), the same curve used in Ethereum precompiles
- **Pairing**: Optimal Ate pairing `e: G1 x G2 -> GT`
- **Security**: ~100-bit (post-exTNFS). Not 128-bit; see [Security Considerations](#security-considerations)

### Asymmetric Pairing Adaptation

The original Boneh-Franklin paper uses a symmetric pairing `e: G x G -> GT`.
BN254 has an asymmetric pairing, so we adapt:

| Component | Group | Rationale |
|-----------|-------|-----------|
| System generator `P` | G2 | Pairing input |
| Public key `P_pub = s*P` | G2 | Same group as generator |
| Identity hash `Q_ID = H1(ID)` | G1 | Maps to the "cheaper" group |
| Private key `d_ID = s*Q_ID` | G1 | Same group as identity hash |
| Ciphertext `U = r*P` | G2 | Same group as generator |

Correctness: `e(d_ID, U) = e(s*Q_ID, r*P) = e(Q_ID, P)^{sr} = e(Q_ID, P_pub)^r`

### Hash Functions

| Function | Domain | Codomain | Method |
|----------|--------|----------|--------|
| H1 | `{0,1}*` | G1 | Try-and-increment with SHA-256 |
| H2 | GT | `{0,1}^n` | Counter-mode SHA-256 KDF |
| H3 | `{0,1}^n x {0,1}*` | Fr | SHA-256 + reduction mod q |
| H4 | `{0,1}^n` | `{0,1}^m` | Counter-mode SHA-256 |

All hash functions use distinct domain separation tags to prevent cross-function collisions.

## Testing

```bash
# Run all 61 tests (unit + integration + doctests)
cargo test

# Run clippy
cargo clippy -- -D warnings

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run fuzz_deserialize -- -max_total_time=60
cargo +nightly fuzz run fuzz_basic_decrypt -- -max_total_time=60
cargo +nightly fuzz run fuzz_full_decrypt -- -max_total_time=60
```

### Test Coverage

| Suite | Count | What it tests |
|-------|-------|---------------|
| Unit tests | 32 | Individual module correctness |
| CCA security | 7 | Tampered ciphertexts are rejected |
| Edge cases | 9 | Empty/long identities, boundary messages, special chars |
| Round-trip | 6 | Cross-identity, cross-system, various message sizes |
| Serialization | 6 | Serialize/deserialize round-trips, garbage rejection |
| Doc tests | 1 | Code example in crate docs |
| Fuzz targets | 3 | Deserialize, BasicIdent decrypt, FullIdent decrypt |

## Security Considerations

- **BN254 provides ~100-bit security**, not 128-bit, due to the Kim-Barbulescu exTNFS attack.
  For 128-bit security, consider BLS12-381 (which would require changing the curve backend).

- **H1 (hash-to-curve) is not constant-time** with respect to the identity.
  This is acceptable because identities are public in IBE. Do not use H1 to hash secrets.

- **Master secret key is zeroized on drop** via the `zeroize` crate.
  The master secret's compromise allows derivation of *all* private keys in the system.

- **Deserialization is bounded** to 1 MB per byte vector to prevent memory exhaustion attacks.

- **Security proofs** are in the Random Oracle Model (ROM) under the Bilinear Diffie-Hellman (BDH) assumption.

- **FullIdent provides CCA security** via the Fujisaki-Okamoto transform. Always prefer FullIdent over BasicIdent.

## Specification

See [`SPEC.md`](SPEC.md) for the full cryptographic specification including algorithms,
serialization formats, and security analysis.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `ark-bn254` | 0.5 | BN254 curve implementation |
| `ark-ec` | 0.5 | Elliptic curve and pairing traits |
| `ark-ff` | 0.5 | Finite field arithmetic |
| `ark-serialize` | 0.5 | Canonical serialization |
| `ark-std` | 0.5 | Standard library utilities |
| `sha2` | 0.10 | SHA-256 for all hash functions |
| `rand` | 0.8 | Randomness generation |
| `zeroize` | 1 | Secure memory clearing |

## References

1. D. Boneh, M. Franklin. ["Identity-Based Encryption from the Weil Pairing."](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) SIAM J. Computing, 2003.
2. E. Fujisaki, T. Okamoto. "Secure Integration of Asymmetric and Symmetric Encryption Schemes." CRYPTO 1999.
3. [RFC 5091 - Identity-Based Cryptography Standard (IBCS) #1](https://datatracker.ietf.org/doc/html/rfc5091)
4. [RFC 5409 - Using the Boneh-Franklin and Boneh-Boyen IBE with CMS](https://www.rfc-editor.org/rfc/rfc5409/)

## License

Licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](http://opensource.org/licenses/MIT)

at your option.
