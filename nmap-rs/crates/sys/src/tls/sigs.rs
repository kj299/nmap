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

use nmap_core::nse::openssl::pubkey::{EcInfo, Kind};
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
            Kind::RsaPss | Kind::Dsa | Kind::Ed448 => PeerKey::Unverifiable,
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
