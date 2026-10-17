//! The verifier nmap's rules need (`docs/M6.5-ANALYSIS.md` §1.3): no chain
//! verification at all (`SSL_VERIFY_NONE`), yet every certificate entry must
//! parse with an exact length (`statem_clnt.c:1808-1816`), the key must be
//! present and of a type OpenSSL's TLS accepts (`:1903-1909`), the key type
//! must match the signature scheme (`:1918-1922`), and the ServerKeyExchange
//! or CertificateVerify signature must verify (`:2302-2306`,
//! `statem_lib.c:532-538`).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use crate::spki::{parse_certificate, KeyType, Spki};
use crate::verify::{key_type_for, verify_with_key};

#[derive(Debug)]
pub struct NmapVerifier {
    pub schemes: Vec<SignatureScheme>,
}

fn entry(cert: &CertificateDer<'_>) -> Result<Spki, Error> {
    let spki = parse_certificate(cert)
        .map_err(|e| Error::General(format!("nmap: undecodable certificate ({e})")))?;
    if spki.consumed != cert.len() {
        return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
    }
    Ok(spki)
}

fn accepted_key(kt: &KeyType) -> bool {
    matches!(
        kt,
        KeyType::Rsa | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 | KeyType::Ed25519
    )
}

impl NmapVerifier {
    /// OpenSSL's rule for the key behind a scheme: the family must match in
    /// both versions; the ECDSA curve only in TLS 1.3 (`tls1_lookup_sigalg`'s
    /// curve check runs for TLS 1.3 sigalgs only).
    fn check_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        tls13: bool,
    ) -> Result<HandshakeSignatureValid, Error> {
        let spki = entry(cert)?;
        let Some(needed) = key_type_for(dss.scheme) else {
            return Err(Error::General(format!(
                "nmap: scheme {:?} not offered",
                dss.scheme
            )));
        };
        let ecdsa = matches!(needed, KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521);
        let family_ok = if ecdsa {
            matches!(
                spki.key_type,
                KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521
            )
        } else {
            spki.key_type == needed
        };
        if !family_ok || (tls13 && spki.key_type != needed) {
            return Err(Error::General(format!(
                "nmap: key type {:?} does not match signature scheme {:?}",
                spki.key_type, dss.scheme
            )));
        }
        verify_with_key(
            dss.scheme,
            &spki.key_type,
            &spki.public_key,
            message,
            dss.signature(),
        )
        .map(|()| HandshakeSignatureValid::assertion())
        .map_err(|()| Error::InvalidCertificate(CertificateError::BadSignature))
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
        for c in intermediates {
            entry(c)?;
        }
        let spki = entry(end_entity)?;
        if !accepted_key(&spki.key_type) {
            return Err(Error::General(format!(
                "nmap: key type {:?} not accepted",
                spki.key_type
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.check_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.check_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A client configuration over the provider and this verifier.
pub fn client_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
    groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
) -> ClientConfig {
    let mut provider = crate::provider::provider();
    if let Some(groups) = groups {
        provider.kx_groups = groups;
    }
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("versions the provider supports")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NmapVerifier {
            schemes: crate::provider::CLIENT_SIG_SCHEMES.to_vec(),
        }))
        .with_no_client_auth()
}
