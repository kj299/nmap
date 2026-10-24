//! The certificate rules nmap's TLS client applies (`docs/M6.5-ANALYSIS.md`
//! §1.3). nmap sets `SSL_VERIFY_NONE`, which in OpenSSL 3.0.13 turns off
//! chain verification and nothing else (`statem_clnt.c:1888`). What still
//! runs, and what this verifier does in its place:
//!
//! - every certificate entry decodes with `d2i_X509` and fills its entry
//!   exactly (`:1808-1816`), read by `core`'s reader, the one
//!   `parse_ssl_certificate` uses;
//! - the leaf has a key, of a type a TLS certificate may carry (`:1903-1915`);
//! - the ServerKeyExchange or CertificateVerify signature verifies under
//!   that key, whose type must match the scheme ([`super::sigs`]); in TLS 1.2
//!   that is also how a key that does not match the suite is refused
//!   (`:1918-1922`), since rustls holds the scheme to the suite.
//!
//! No name, date, issuer, key size or signature on a certificate is ever
//! checked: an expired, self-signed, MD5-signed or 512-bit certificate is
//! accepted, as 7.94 accepts it.
//!
//! OpenSSL keeps the leaf as the peer's certificate as soon as those
//! certificate checks pass (`tls_post_process_server_certificate`), so
//! `get_ssl_certificate` has it even when the handshake fails afterwards (a
//! bad signature, a server that goes away). rustls keeps it only once the
//! handshake's signature verifies, so each connection's verifier records it
//! itself, in a [`PeerLeaf`].

use std::sync::{Arc, Mutex};

use nmap_core::nse::openssl::x509::d2i_x509_len;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, PeerMisbehaved, SignatureScheme};

use super::sigs::{verify, KeyRefused, PeerKey, SigError};

/// The leaf one connection's handshake accepted, as OpenSSL's
/// `SSL_get_peer_certificate` would give it: none until the certificate
/// checks pass, and none again if TLS 1.2's key turns out not to fit the
/// suite (OpenSSL checks that before it keeps the leaf).
#[derive(Clone, Debug, Default)]
pub struct PeerLeaf(Arc<Mutex<Option<Vec<u8>>>>);

impl PeerLeaf {
    /// The leaf's DER.
    #[must_use]
    pub fn get(&self) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set(&self, leaf: Option<Vec<u8>>) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = leaf;
    }
}

#[derive(Debug, Default)]
pub(crate) struct NmapVerifier {
    /// Where the leaf goes once accepted.
    pub(crate) leaf: PeerLeaf,
}

/// One certificate entry: it decodes, and nothing follows it.
fn entry(der: &[u8]) -> Result<nmap_core::nse::openssl::x509::Cert, Error> {
    match d2i_x509_len(der) {
        None => Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        // OpenSSL's alert here is 50, which no certificate error of rustls
        // sends (`nse-tls-alert-numbers`); 42, as for an undecodable one.
        Some((_, used)) if used != der.len() => {
            Err(Error::InvalidCertificate(CertificateError::BadEncoding))
        }
        Some((c, _)) => Ok(c),
    }
}

/// A refusal, with OpenSSL's reason for it.
#[derive(Debug)]
struct Refusal(&'static str);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refusal {}

/// Sent as alert 46; OpenSSL's 80 for a missing key is out of the
/// verifier's reach (`nse-tls-alert-numbers`).
fn refused(reason: &'static str) -> Error {
    Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(
        std::sync::Arc::new(Refusal(reason)),
    )))
}

fn key_of(cert: &nmap_core::nse::openssl::x509::Cert) -> Result<PeerKey, Error> {
    PeerKey::from_cert(cert).map_err(|r| match r {
        KeyRefused::Missing => refused("unable to find public key parameters"),
        // OpenSSL's "unknown certificate type" is alert 47, which rustls
        // sends for a peer that misbehaved.
        KeyRefused::Type => {
            rustls::Error::PeerMisbehaved(PeerMisbehaved::SignedKxWithWrongAlgorithm)
        }
    })
}

impl NmapVerifier {
    /// The handshake's signature `sig`, by `scheme`, over `message`.
    pub(crate) fn check(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        scheme: SignatureScheme,
        sig: &[u8],
        tls13: bool,
    ) -> Result<HandshakeSignatureValid, Error> {
        let key = key_of(&entry(cert.as_ref())?)?;
        verify(scheme, &key, message, sig, tls13)
            .map(|()| HandshakeSignatureValid::assertion())
            .map_err(|e| match e {
                // "wrong certificate type" (TLS 1.2: the key does not fit
                // the suite) or "wrong signature type": alert 47.
                SigError::Mismatch => {
                    // In TLS 1.2 rustls holds the scheme to the suite, so
                    // this is OpenSSL's "wrong certificate type", refused
                    // before the leaf is kept; in TLS 1.3 it is "wrong
                    // signature type", after.
                    if !tls13 {
                        self.leaf.set(None);
                    }
                    Error::PeerMisbehaved(PeerMisbehaved::SignedKxWithWrongAlgorithm)
                }
                // "bad signature": alert 51.
                SigError::Bad => Error::InvalidCertificate(CertificateError::BadSignature),
            })
    }
}

impl ServerCertVerifier for NmapVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // OpenSSL decodes every entry, the leaf first, before it looks at
        // the leaf's key.
        let leaf = entry(end_entity.as_ref())?;
        for c in intermediates {
            entry(c.as_ref())?;
        }
        key_of(&leaf)?;
        self.leaf.set(Some(end_entity.as_ref().to_vec()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.check(message, cert, dss.scheme, dss.signature(), false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.check(message, cert, dss.scheme, dss.signature(), true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        super::provider::CLIENT_SIG_SCHEMES.to_vec()
    }
}
