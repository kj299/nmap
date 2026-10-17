//! The one randomness seam of the `openssl` module (`docs/M6.5-ANALYSIS.md`
//! §10, E3): every random byte the module uses — `bignum_rand` and
//! `bignum_pseudo_rand` now, the Miller-Rabin witnesses of `is_prime`, and
//! later `rand_bytes`, `rand_pseudo_bytes` and the TLS provider — comes
//! from [`fill`], which is the operating system's CSPRNG (`getrandom`).
//!
//! The C draws `bignum_*rand` and the witnesses from OpenSSL's DRBG, and
//! `rand_pseudo_bytes` from nbase's non-cryptographic ARC4
//! (`nbase/nbase_rnd.c:112-196`); the port is the same source for all of
//! them, and no weaker anywhere. A seeded generator replaces the OS only in
//! this crate's own unit tests ([`seed_for_tests`]), so that a test can count
//! what a primality test draws; nothing outside `cfg(test)` can reach it.

use super::bn::Random;

#[cfg(test)]
thread_local! {
    /// The xorshift state of the seeded generator, when a test set one.
    static SEEDED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Fill `buf` with random bytes, or say that the source failed.
#[must_use]
pub fn fill(buf: &mut [u8]) -> bool {
    #[cfg(test)]
    if let Some(mut x) = SEEDED.with(std::cell::Cell::get) {
        for b in buf.iter_mut() {
            // xorshift64*: fast, deterministic, and good enough to pick
            // witnesses in a test.
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *b = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes()[0];
        }
        SEEDED.with(|c| c.set(Some(x)));
        return true;
    }
    getrandom::getrandom(buf).is_ok()
}

/// **Tests only.** Replace the OS source on this thread with a generator
/// seeded by `seed` (`None` restores the OS).
#[cfg(test)]
pub(crate) fn seed_for_tests(seed: Option<u64>) {
    SEEDED.with(|c| c.set(seed.map(|s| s | 1)));
}

/// The seam as a [`Random`], for the pure BIGNUM layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct Os;

impl Random for Os {
    fn fill(&mut self, buf: &mut [u8]) -> bool {
        fill(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E3's non-constancy gate: two 32-byte draws differ, and a large draw is
    /// not all one byte. A source that returned zeros, or the same block
    /// twice, fails here.
    #[test]
    fn the_os_source_is_not_constant() {
        seed_for_tests(None);
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        assert!(fill(&mut a) && fill(&mut b));
        assert_ne!(a, b);
        let mut big = vec![0u8; if cfg!(miri) { 4096 } else { 1 << 20 }];
        assert!(fill(&mut big));
        assert!(big.iter().any(|&x| x != big[0]));
    }

    #[test]
    fn a_seeded_source_repeats_and_restores() {
        let draw = || {
            let mut b = [0u8; 16];
            assert!(fill(&mut b));
            b
        };
        seed_for_tests(Some(7));
        let first = draw();
        seed_for_tests(Some(7));
        assert_eq!(draw(), first);
        seed_for_tests(None);
        assert_ne!(draw(), draw());
    }
}
