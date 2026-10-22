//! RSA signature verification, first-party over `num-bigint` (RFC 8017:
//! RSASSA-PKCS1-v1_5, and RSASSA-PSS with MGF1 and a salt the length of the
//! hash, which is what TLS 1.2's `rsa_pss_rsae_*` and TLS 1.3 require and
//! what OpenSSL verifies them with). Public data only, so constant time is
//! not needed (§6). The `rsa` crate is not used: it carries
//! RUSTSEC-2023-0071 and fails `cargo deny`.
//!
//! As OpenSSL checks them (`crypto/rsa/rsa_sign.c`, `rsa_pss.c` at 3.0.13):
//! the signature is exactly the modulus's length and below it; a PKCS#1
//! signature's decoding is compared whole with the one expected, so the
//! DigestInfo's NULL parameter is required; PSS's salt is the hash's length.

use num_bigint::BigUint;
use sha2::Digest;

/// A public key, from the modulus and exponent `core`'s key decoder read
/// (`PubKey::rsa`).
pub(crate) struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
    /// The modulus's length in bytes.
    k: usize,
    bits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub(crate) fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                let mut h = sha2::Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            HashAlg::Sha384 => {
                let mut h = sha2::Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            HashAlg::Sha512 => {
                let mut h = sha2::Sha512::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
        }
    }

    fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// The DigestInfo prefix of RFC 8017 §9.2, note 1.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

impl RsaPublicKey {
    /// The key with modulus `n` and exponent `e`, big-endian magnitudes;
    /// `None` for a zero modulus or exponent, which verifies nothing.
    pub(crate) fn new(n: &[u8], e: &[u8]) -> Option<Self> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        if n.bits() == 0 || e.bits() == 0 {
            return None;
        }
        let bits = n.bits();
        let k = usize::try_from(bits.div_ceil(8)).ok()?;
        Some(Self { n, e, k, bits })
    }

    /// RSAVP1, then I2OSP to `len` bytes.
    fn recover(&self, sig: &[u8], len: usize) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = BigUint::from_bytes_be(sig);
        if s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        let pad = len.checked_sub(m.len())?;
        let mut em = vec![0u8; pad];
        em.extend_from_slice(&m);
        Some(em)
    }

    pub(crate) fn verify_pkcs1(&self, hash: HashAlg, message: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.recover(sig, self.k) else {
            return false;
        };
        let t_len = hash.digest_info_prefix().len().saturating_add(hash.len());
        let Some(ps_len) = self.k.checked_sub(t_len.saturating_add(3)) else {
            return false;
        };
        if ps_len < 8 {
            return false;
        }
        let mut expected = vec![0x00, 0x01];
        expected.resize(ps_len.saturating_add(2), 0xff);
        expected.push(0x00);
        expected.extend_from_slice(hash.digest_info_prefix());
        expected.extend_from_slice(&hash.digest(&[message]));
        em == expected
    }

    pub(crate) fn verify_pss(&self, hash: HashAlg, message: &[u8], sig: &[u8]) -> bool {
        let h_len = hash.len();
        let s_len = h_len;
        let Some(em_bits) = self.bits.checked_sub(1).and_then(|b| usize::try_from(b).ok()) else {
            return false;
        };
        let em_len = em_bits.div_ceil(8);
        // RFC 8017 §9.1.2 step 3: emLen < hLen + sLen + 2 is "inconsistent".
        let Some(db_len) = em_len.checked_sub(h_len.saturating_add(1)) else {
            return false;
        };
        let Some(ps_len) = db_len.checked_sub(s_len.saturating_add(1)) else {
            return false;
        };
        // RSAVP1 gives an integer below n; I2OSP to emLen fails if it does not
        // fit, which happens when the modulus is a whole number of bytes and
        // the top byte is non-zero.
        let Some(em) = self.recover(sig, self.k) else {
            return false;
        };
        let Some(lead) = self.k.checked_sub(em_len) else {
            return false;
        };
        if em[..lead].iter().any(|&b| b != 0) {
            return false;
        }
        let em = &em[lead..];
        if em.last() != Some(&0xbc) {
            return false;
        }
        let m_hash = hash.digest(&[message]);
        let (masked_db, rest) = em.split_at(db_len);
        let h = &rest[..h_len];
        // 8·emLen − emBits leftmost bits of maskedDB must be zero.
        let top_bits = em_len.saturating_mul(8).saturating_sub(em_bits);
        let top_mask: u8 = 0xff_u8.checked_shr(u32::try_from(top_bits).unwrap_or(8)).unwrap_or(0);
        if masked_db.first().is_some_and(|&b| b & !top_mask != 0) {
            return false;
        }
        let mut db: Vec<u8> = mgf1(hash, h, db_len)
            .iter()
            .zip(masked_db)
            .map(|(m, d)| m ^ d)
            .collect();
        if let Some(first) = db.first_mut() {
            *first &= top_mask;
        }
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return false;
        }
        let salt = &db[ps_len.saturating_add(1)..];
        let h2 = hash.digest(&[&[0u8; 8], &m_hash, salt]);
        h2.as_slice() == h
    }
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.saturating_add(hash.len()));
    let mut counter: u32 = 0;
    while out.len() < len {
        out.extend(hash.digest(&[seed, &counter.to_be_bytes()]));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degenerate_keys_verify_nothing() {
        assert!(RsaPublicKey::new(&[], &[1]).is_none());
        assert!(RsaPublicKey::new(&[0, 0], &[3]).is_none());
        assert!(RsaPublicKey::new(&[0xc3], &[]).is_none());
        // A tiny modulus: every length check refuses before any arithmetic
        // could go wrong.
        let k = RsaPublicKey::new(&[0xc3], &[3]).expect("key");
        assert!(!k.verify_pkcs1(HashAlg::Sha256, b"m", &[1]));
        assert!(!k.verify_pss(HashAlg::Sha256, b"m", &[1]));
        assert!(!k.verify_pss(HashAlg::Sha256, b"m", &[]));
    }

    #[test]
    fn mgf1_is_rfc_8017s() {
        // MGF1-SHA256 of "foo", 3 bytes (a known prefix: SHA-256("foo"||0^4)).
        let full = HashAlg::Sha256.digest(&[b"foo", &[0, 0, 0, 0]]);
        assert_eq!(mgf1(HashAlg::Sha256, b"foo", 3), full[..3]);
        assert_eq!(mgf1(HashAlg::Sha256, b"foo", 40).len(), 40);
    }
}
