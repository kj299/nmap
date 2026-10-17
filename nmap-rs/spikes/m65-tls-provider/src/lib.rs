//! M6.5 step 0, the D3 spike: a first-party rustls `CryptoProvider` that
//! verifies handshake signatures, behind a verifier that applies nmap's rules
//! (`client.rs`). See `docs/M6.5-ANALYSIS.md` §11 step 0 and the write-up this
//! spike feeds.
#![forbid(unsafe_code)]

pub mod aead;
pub mod client;
pub mod hash;
pub mod hmac;
pub mod kx;
pub mod provider;
pub mod rand;
pub mod rsa;
pub mod sign;
pub mod spki;
pub mod verify;
