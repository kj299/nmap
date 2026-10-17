//! RSA signature verification, first-party over `num-bigint` (RFC 8017: RSASSA-
//! PKCS1-v1_5 and RSASSA-PSS with MGF1 and a salt the length of the hash, which
//! is what TLS 1.2 `rsa_pss_rsae_*` and TLS 1.3 require). Public data only, so
//! constant time is not needed (§6). The `rsa` crate is not used: it carries
//! RUSTSEC-2023-0071 and would fail `cargo deny`.

use num_bigint::BigUint;
use num_traits::Zero;
use sha2::Digest;

pub struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
    /// The modulus length in bytes.
    k: usize,
    bits: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
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

    /// The digest of one message.
    pub fn digest_of(self, msg: &[u8]) -> Vec<u8> {
        self.digest(&[msg])
    }

    fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// The DigestInfo prefix of RFC 8017 §9.2 note 1.
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

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
pub fn parse_rsa_public_key(der: &[u8]) -> Result<RsaPublicKey, &'static str> {
    fn int(buf: &[u8], at: usize) -> Result<(&[u8], usize), &'static str> {
        if buf.get(at) != Some(&0x02) {
            return Err("not an INTEGER");
        }
        let first = *buf.get(at + 1).ok_or("truncated")?;
        let (len, body) = if first < 0x80 {
            (first as usize, at + 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err("bad length");
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | *buf.get(at + 2 + i).ok_or("truncated")? as usize;
            }
            (len, at + 2 + n)
        };
        let end = body + len;
        if end > buf.len() || len == 0 {
            return Err("truncated");
        }
        if buf[body] & 0x80 != 0 {
            return Err("negative");
        }
        Ok((&buf[body..end], end))
    }
    if der.first() != Some(&0x30) {
        return Err("not a SEQUENCE");
    }
    let first = *der.get(1).ok_or("truncated")?;
    let body = if first < 0x80 {
        2
    } else {
        2 + (first & 0x7f) as usize
    };
    let (n, after_n) = int(der, body)?;
    let (e, after_e) = int(der, after_n)?;
    if after_e != der.len() {
        return Err("trailing bytes");
    }
    let n = BigUint::from_bytes_be(n);
    let e = BigUint::from_bytes_be(e);
    if n.is_zero() || e.is_zero() {
        return Err("zero");
    }
    let bits = n.bits();
    Ok(RsaPublicKey {
        k: ((bits + 7) / 8) as usize,
        n,
        e,
        bits,
    })
}

impl RsaPublicKey {
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// RSAVP1 then I2OSP to `len` bytes.
    fn recover(&self, sig: &[u8], len: usize) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = BigUint::from_bytes_be(sig);
        if s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        if m.len() > len {
            return None;
        }
        let mut em = vec![0u8; len - m.len()];
        em.extend_from_slice(&m);
        Some(em)
    }

    pub fn verify_pkcs1(&self, hash: HashAlg, message: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.recover(sig, self.k) else {
            return false;
        };
        let t_len = hash.digest_info_prefix().len() + hash.len();
        if self.k < t_len + 11 {
            return false;
        }
        let mut expected = vec![0x00, 0x01];
        expected.extend(std::iter::repeat(0xff).take(self.k - t_len - 3));
        expected.push(0x00);
        expected.extend_from_slice(hash.digest_info_prefix());
        expected.extend_from_slice(&hash.digest(&[message]));
        em == expected
    }

    pub fn verify_pss(&self, hash: HashAlg, message: &[u8], sig: &[u8]) -> bool {
        let h_len = hash.len();
        let s_len = h_len;
        let em_bits = (self.bits - 1) as usize;
        let em_len = (em_bits + 7) / 8;
        let Some(em) = self.recover(sig, em_len) else {
            return false;
        };
        if em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let m_hash = hash.digest(&[message]);
        let db_len = em_len - h_len - 1;
        let (masked_db, rest) = em.split_at(db_len);
        let h = &rest[..h_len];
        let top_bits = 8 * em_len - em_bits;
        if top_bits > 0 && masked_db[0] >> (8 - top_bits) != 0 {
            return false;
        }
        let mut db: Vec<u8> = mgf1(hash, h, db_len)
            .iter()
            .zip(masked_db)
            .map(|(m, d)| m ^ d)
            .collect();
        if top_bits > 0 {
            db[0] &= 0xff >> top_bits;
        }
        let ps_len = em_len - h_len - s_len - 2;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return false;
        }
        let salt = &db[ps_len + 1..];
        let h2 = hash.digest(&[&[0u8; 8], &m_hash, salt]);
        h2.as_slice() == h
    }
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.len());
    let mut counter: u32 = 0;
    while out.len() < len {
        out.extend(hash.digest(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(len);
    out
}
