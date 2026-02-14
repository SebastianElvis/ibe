//! Boneh-Franklin Identity-Based Encryption over BN254.
//!
//! This crate implements both BasicIdent (IND-ID-CPA) and FullIdent (IND-ID-CCA)
//! variants of the Boneh-Franklin IBE scheme using the BN254 pairing-friendly curve.
//!
//! # Overview
//!
//! Identity-Based Encryption (IBE) allows a sender to encrypt a message using only
//! the recipient's identity (e.g., email address) as the public key. A trusted
//! Private Key Generator (PKG) holds a master secret and can extract private keys
//! for any identity.
//!
//! # Schemes
//!
//! - **BasicIdent**: Provides IND-ID-CPA security (chosen-plaintext attack).
//!   Messages are limited to the block size (default 32 bytes).
//!
//! - **FullIdent**: Provides IND-ID-CCA security (chosen-ciphertext attack)
//!   via the Fujisaki-Okamoto transform. Supports arbitrary-length messages.
//!
//! # Example
//!
//! ```rust
//! use ibe::{setup, extract, Identity};
//! use ibe::full;
//! use rand::thread_rng;
//!
//! let mut rng = rand::thread_rng();
//!
//! // PKG runs Setup
//! let (params, master_secret) = setup(&mut rng);
//!
//! // User's identity
//! let identity = Identity::new("alice@example.com");
//!
//! // PKG extracts private key for Alice
//! let private_key = extract(&master_secret, &identity).unwrap();
//!
//! // Anyone can encrypt a message for Alice using her identity
//! let message = b"Hello, Alice!";
//! let ciphertext = full::encrypt(&params, &identity, message, &mut rng).unwrap();
//!
//! // Alice decrypts with her private key
//! let decrypted = full::decrypt(&params, &private_key, &ciphertext).unwrap();
//! assert_eq!(&decrypted, message);
//! ```

pub mod basic;
pub mod error;
pub mod full;
pub mod hash;
pub mod identity;
pub mod params;
pub mod serialize;
pub mod setup;
pub mod types;

// Re-export key types at crate root for convenience.
pub use error::IbeError;
pub use identity::{Identity, PrivateKey};
pub use params::{MasterSecretKey, PublicParams, SystemParams};
pub use setup::{extract, setup};
