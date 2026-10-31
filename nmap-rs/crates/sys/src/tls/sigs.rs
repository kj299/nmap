//! Handshake signature verification: what OpenSSL's client checks of a
//! ServerKeyExchange (`statem_clnt.c:2302-2306`) or a TLS 1.3
//! CertificateVerify (`statem_lib.c:532-538`) whatever the verify mode.
//!
//! - RSA PKCS#1 v1.5 and PSS, first-party ([`super::rsa`]);
//! - ECDSA on P-256, P-384 and P-521 over the RustCrypto curves, the
//!   signature in strict DER (`ECDSA_verify` re-encodes what it decoded and
//!   refuses a signature that differs);
//! - Ed25519 with `verify_strict` only (LESSONS #037).
//!
//! The key is the one `core`'s key decoder read from the certificate
//! ([`PeerKey::from_cert`]), so the certificate is read once, by the reader
//! `parse_ssl_certificate` uses.

use nmap_core::nse::openssl::pubkey::{DsaKey, EcInfo, Kind};
use nmap_core::nse::openssl::x509::Cert;
use rustls::SignatureScheme;

use super::rsa::{HashAlg, RsaPublicKey};

/// The NIDs of the curves the client offers.
const NID_P256: u16 = 415;
const NID_P384: u16 = 715;
const NID_P521: u16 = 716;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }
}

/// A peer's key, as far as the handshake can use it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeerKey {
    /// RSA: modulus and exponent.
    Rsa(Vec<u8>, Vec<u8>),
    /// ECDSA on a curve the client verifies: the encoded point.
    Ec(Curve, Vec<u8>),
    Ed25519([u8; 32]),
    /// DSA (M6.7 step e): its domain parameters and `y`. TLS 1.2 only.
    Dsa(DsaKey),
    /// A type OpenSSL's TLS takes as a certificate key (`ssl_cert_lookup_by_pkey`:
    /// RSA-PSS, DSA, EC on another curve, Ed448) but that no scheme the
    /// client offers can verify: every signature fails, as the C fails it
    /// further on (no shared signature algorithm, or a curve it did not offer).
    Unverifiable,
}

/// Why a certificate's key cannot be used at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRefused {
    /// No key decoded: OpenSSL's "unable to find public key parameters"
    /// (alert 80).
    Missing,
    /// A key type no TLS certificate may carry (DH, X25519, X448, SM2):
    /// "unknown certificate type" (alert 47).
    Type,
}

impl PeerKey {
    /// The key of a decoded certificate, refused as `tls_process_server_certificate`
    /// refuses it (`statem_clnt.c:1903-1915`).
    pub(crate) fn from_cert(cert: &Cert) -> Result<Self, KeyRefused> {
        let key = cert.spki.key.as_ref().ok_or(KeyRefused::Missing)?;
        Ok(match key.kind {
            Kind::Rsa => match &key.rsa {
                Some((n, e)) => PeerKey::Rsa(n.clone(), e.clone()),
                None => return Err(KeyRefused::Missing),
            },
            Kind::Ec => {
                let curve = match key.ec {
                    Some(EcInfo::Named(NID_P256)) => Some(Curve::P256),
                    Some(EcInfo::Named(NID_P384)) => Some(Curve::P384),
                    Some(EcInfo::Named(NID_P521)) => Some(Curve::P521),
                    _ => None,
                };
                match curve {
                    Some(c) => PeerKey::Ec(c, cert.spki.bits.clone()),
                    None => PeerKey::Unverifiable,
                }
            }
            Kind::Ed25519 => match <[u8; 32]>::try_from(cert.spki.bits.as_slice()) {
                Ok(k) => PeerKey::Ed25519(k),
                Err(_) => return Err(KeyRefused::Missing),
            },
            Kind::Dsa => match &key.dsa {
                Some(d) => PeerKey::Dsa(d.clone()),
                None => return Err(KeyRefused::Missing),
            },
            Kind::RsaPss | Kind::Ed448 => PeerKey::Unverifiable,
            Kind::Dh | Kind::Dhx | Kind::X25519 | Kind::X448 | Kind::Sm2 => {
                return Err(KeyRefused::Type)
            }
        })
    }
}

/// The hash a scheme names. For ECDSA in TLS 1.2 that is all it names:
/// OpenSSL signs with `ecdsa_secp256r1_sha256` under a P-384 key, the curve
/// coming from the key (`tls1_lookup_sigalg` binds the curve in TLS 1.3
/// only).
fn hash_for(scheme: SignatureScheme) -> Option<HashAlg> {
    Some(match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PSS_SHA256 => HashAlg::Sha256,
        SignatureScheme::ECDSA_NISTP384_SHA384
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PSS_SHA384 => HashAlg::Sha384,
        SignatureScheme::ECDSA_NISTP521_SHA512
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA512 => HashAlg::Sha512,
        _ => return None,
    })
}

/// Why a handshake signature was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigError {
    /// The key cannot make signatures of this scheme: its family differs,
    /// or (TLS 1.3) its curve. OpenSSL's "wrong certificate type" or "wrong
    /// signature type", both alert 47.
    Mismatch,
    /// The signature does not verify: alert 51.
    Bad,
}

/// Verify `sig` over `msg` under `scheme` with `key`. In TLS 1.3 an ECDSA
/// scheme names its curve too, and the key must be on it.
pub(crate) fn verify(
    scheme: SignatureScheme,
    key: &PeerKey,
    msg: &[u8],
    sig: &[u8],
    tls13: bool,
) -> Result<(), SigError> {
    use SigError::{Bad, Mismatch};
    match (scheme, key) {
        (
            SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512,
            PeerKey::Rsa(n, e),
        ) => {
            let k = RsaPublicKey::new(n, e).ok_or(Bad)?;
            k.verify_pkcs1(hash_for(scheme).ok_or(Mismatch)?, msg, sig)
                .then_some(())
                .ok_or(Bad)
        }
        (
            SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512,
            PeerKey::Rsa(n, e),
        ) => {
            let k = RsaPublicKey::new(n, e).ok_or(Bad)?;
            k.verify_pss(hash_for(scheme).ok_or(Mismatch)?, msg, sig)
                .then_some(())
                .ok_or(Bad)
        }
        (
            SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512,
            PeerKey::Ec(curve, point),
        ) => {
            if tls13 {
                let bound = match scheme {
                    SignatureScheme::ECDSA_NISTP256_SHA256 => Curve::P256,
                    SignatureScheme::ECDSA_NISTP384_SHA384 => Curve::P384,
                    _ => Curve::P521,
                };
                if bound != *curve {
                    return Err(Mismatch);
                }
            }
            ecdsa(*curve, hash_for(scheme).ok_or(Mismatch)?, point, msg, sig).map_err(|()| Bad)
        }
        (SignatureScheme::Unknown(code @ (0x0302 | 0x0402 | 0x0502 | 0x0602)), PeerKey::Dsa(k)) => {
            // TLS 1.3 has no DSA (RFC 8446 §4.2.3).
            if tls13 {
                return Err(Mismatch);
            }
            dsa(code, k, msg, sig).map_err(|()| Bad)
        }
        (SignatureScheme::ED25519, PeerKey::Ed25519(k)) => {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(k).map_err(|_| Bad)?;
            let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| Bad)?;
            vk.verify_strict(msg, &sig).map_err(|_| Bad)
        }
        _ => Err(Mismatch),
    }
}

fn ecdsa(curve: Curve, hash: HashAlg, point: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    // FIPS 186-4 §6.4: e is the leftmost min(N, hashlen) bits of the hash,
    // as an integer. The `ecdsa` crate refuses a prehash shorter than half
    // the field (SHA-256 under P-521), so a short one is left-padded to the
    // field's size, which is the same integer.
    let mut prehash = hash.digest(&[msg]);
    if let Some(pad) = curve.field_len().checked_sub(prehash.len()) {
        let mut padded = vec![0u8; pad];
        padded.extend_from_slice(&prehash);
        prehash = padded;
    }
    match curve {
        Curve::P256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| ())?;
            let sig = p256::ecdsa::Signature::from_der(sig).map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
        Curve::P384 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| ())?;
            let sig = p384::ecdsa::Signature::from_der(sig).map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
        Curve::P521 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| ())?;
            let sig = p521::ecdsa::Signature::from_der(sig).map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
    }
}

/// The digest a `dsa_*` scheme names (RFC 5246 §7.4.1.4.1).
fn dsa_digest(code: u16, msg: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest;
    Some(match code {
        0x0302 => sha2::Sha224::digest(msg).to_vec(),
        0x0402 => sha2::Sha256::digest(msg).to_vec(),
        0x0502 => sha2::Sha384::digest(msg).to_vec(),
        0x0602 => sha2::Sha512::digest(msg).to_vec(),
        _ => return None,
    })
}

/// A DER INTEGER's content as OpenSSL writes it: the magnitude's bytes, a
/// leading zero only when the top bit is set, at least one byte.
fn der_int(n: &num_bigint::BigUint, out: &mut Vec<u8>) {
    let mut b = n.to_bytes_be();
    if b.first().is_some_and(|f| f & 0x80 != 0) {
        b.insert(0, 0);
    }
    out.push(0x02);
    der_len(b.len(), out);
    out.extend_from_slice(&b);
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let b = len.to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        out.push(0x80 | u8::try_from(b.len().saturating_sub(skip)).unwrap_or(0));
        out.extend_from_slice(b.get(skip..).unwrap_or_default());
    }
}

/// One DER element at the front of `p`: its tag, its content, the rest.
fn der_take(p: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, p) = p.split_first()?;
    let (&first, p) = p.split_first()?;
    let (len, p) = if first < 0x80 {
        (usize::from(first), p)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || p.len() < n {
            return None;
        }
        let (lb, rest) = p.split_at(n);
        (
            lb.iter().fold(0usize, |a, &b| (a << 8) | usize::from(b)),
            rest,
        )
    };
    if p.len() < len {
        return None;
    }
    let (content, rest) = p.split_at(len);
    Some((tag, content, rest))
}

/// `DSA_verify` (`dsa_sign.c`, `dsa_ossl.c` at 3.0.13): the signature is
/// `SEQUENCE { r INTEGER, s INTEGER }`, which must re-encode to exactly the
/// bytes given; `q` must be 160, 224 or 256 bits and `p` at most 10,000;
/// 0 < r, s < q; the digest is cut to `q`'s length; and
/// `((g^u1 * y^u2) mod p) mod q == r`. Public data only, so `num-bigint`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "num-bigint arithmetic on unbounded integers cannot overflow; the shift is below the digest's length"
)]
fn dsa(code: u16, k: &DsaKey, msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    use num_bigint::BigUint;
    let (tag, body, rest) = der_take(sig).ok_or(())?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(());
    }
    let (t1, r, body) = der_take(body).ok_or(())?;
    let (t2, s, body) = der_take(body).ok_or(())?;
    if t1 != 0x02 || t2 != 0x02 || !body.is_empty() {
        return Err(());
    }
    let (r, s) = (BigUint::from_bytes_be(r), BigUint::from_bytes_be(s));
    // Strict DER: a negative or non-minimal encoding does not re-encode to
    // the same bytes (OpenSSL compares `i2d` of what it decoded).
    let mut re = Vec::new();
    der_int(&r, &mut re);
    der_int(&s, &mut re);
    let mut whole = vec![0x30];
    der_len(re.len(), &mut whole);
    whole.extend_from_slice(&re);
    if whole != sig {
        return Err(());
    }
    let p = BigUint::from_bytes_be(&k.p);
    let q = BigUint::from_bytes_be(&k.q);
    let g = BigUint::from_bytes_be(&k.g);
    let y = BigUint::from_bytes_be(&k.y);
    if !matches!(q.bits(), 160 | 224 | 256) || p.bits() > 10_000 {
        return Err(());
    }
    let zero = BigUint::from(0u8);
    if r == zero || s == zero || r >= q || s >= q {
        return Err(());
    }
    let h = dsa_digest(code, msg).ok_or(())?;
    let hbits = u64::try_from(h.len()).map_err(|_| ())? * 8;
    let mut z = BigUint::from_bytes_be(&h);
    if hbits > q.bits() {
        z >>= hbits - q.bits();
    }
    let w = s.modinv(&q).ok_or(())?;
    let u1 = (&z * &w) % &q;
    let u2 = (&r * &w) % &q;
    let v = ((g.modpow(&u1, &p) * y.modpow(&u2, &p)) % &p) % &q;
    if v == r {
        Ok(())
    } else {
        Err(())
    }
}
