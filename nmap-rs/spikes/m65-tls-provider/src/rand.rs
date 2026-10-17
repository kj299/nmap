//! One OS CSPRNG (E3): rustls's `SecureRandom`, and the `rand_core` shape the
//! RustCrypto key-exchange constructors want, both over `getrandom`.

use rustls::crypto::{GetRandomFailed, SecureRandom};

#[derive(Debug)]
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::getrandom(buf).map_err(|_| GetRandomFailed)
    }
}

/// `getrandom` as a `rand_core` generator, for `EphemeralSecret::random`.
pub struct Rng;

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
        getrandom::getrandom(dest).expect("the OS random source");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(rand_core::Error::new)
    }
}

impl rand_core::CryptoRng for Rng {}
