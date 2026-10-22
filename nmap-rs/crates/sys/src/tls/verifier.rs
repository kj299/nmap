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

use nmap_core::nse::openssl::x509::d2i_x509_len;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, PeerMisbehaved, SignatureScheme};

use super::sigs::{verify, KeyRefused, PeerKey, SigError};

#[derive(Debug)]
pub(crate) struct NmapVerifier;

/// One certificate entry: it decodes, and nothing follows it.
fn entry(der: &[u8]) -> Result<nmap_core::nse::openssl::x509::Cert, Error> {
    match d2i_x509_len(der) {
        None => Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        // OpenSSL's alert here is 50, which no certificate error of rustls
        // sends (`nse-tls-alert-numbers`); 42, as for an undecodable one.
        Some((_, used)) if used != der.len() => Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
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
        KeyRefused::Type => rustls::Error::PeerMisbehaved(PeerMisbehaved::SignedKxWithWrongAlgorithm),
    })
}

impl NmapVerifier {
    fn check(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        tls13: bool,
    ) -> Result<HandshakeSignatureValid, Error> {
        let key = key_of(&entry(cert.as_ref())?)?;
        verify(dss.scheme, &key, message, dss.signature(), tls13)
            .map(|()| HandshakeSignatureValid::assertion())
            .map_err(|e| match e {
                // "wrong certificate type" (TLS 1.2: the key does not fit
                // the suite) or "wrong signature type": alert 47.
                SigError::Mismatch => {
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
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Self::check(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Self::check(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        super::provider::CLIENT_SIG_SCHEMES.to_vec()
    }
}
