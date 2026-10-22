//! The TLS client's randomness: the one seam of the `openssl` module
//! (`core::nse::openssl::rand`, E3), the operating system's CSPRNG. rustls
//! draws its client random and nonces through [`OsRandom`]; the key-exchange
//! crates draw ephemeral secrets through [`Rng`], their `rand_core` shape.

use nmap_core::nse::openssl::rand::fill;
use rustls::crypto::{GetRandomFailed, SecureRandom};

#[derive(Debug)]
pub(crate) struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        if fill(buf) {
            Ok(())
        } else {
            Err(GetRandomFailed)
        }
    }
}

/// The seam as a `rand_core` generator, for `EphemeralSecret::random`.
/// Each key exchange first draws through [`available`], so a source that
/// fails refuses the handshake instead of reaching `fill_bytes`, which has
/// no way to report it.
pub(crate) struct Rng;

/// Whether the source gives bytes now.
pub(crate) fn available() -> bool {
    fill(&mut [0u8; 8])
}

impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // `available()` succeeded just before; a source that fails between
        // the two draws leaves no secret to use, and the handshake must not
        // go on with a predictable one.
        assert!(fill(dest), "the OS random source failed mid-handshake");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if fill(dest) {
            Ok(())
        } else {
            Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
                    .unwrap_or(core::num::NonZeroU32::MIN),
            ))
        }
    }
}

impl rand_core::CryptoRng for Rng {}
