//! The TLS client (M6.5 step f1; D3 and D10, `docs/M6.5-ANALYSIS.md` §9,
//! §14.1): rustls 0.23 over a first-party `CryptoProvider`, with the
//! certificate rules nmap's OpenSSL client applies. Shared by NSE's sockets
//! (`sys::nsenet`) and, later, `-sV`'s SSL tunnels.
//!
//! What it is, against 7.94's client (`nsock/src/nsock_ssl.c` at
//! `3be01efb1`, OpenSSL 3.0.13):
//!
//! - TLS 1.3 and 1.2, ECDHE with AES-GCM and ChaCha20-Poly1305, on X25519,
//!   P-256, P-521 and P-384, in 7.94's order ([`provider`]); no TLS 1.0 or
//!   1.1, CBC, RSA key exchange, DHE or FFDHE (`nse-tls-modern-only`);
//! - no chain verification, but every check OpenSSL makes regardless of the
//!   verify mode ([`verifier`]);
//! - no session reuse (7.94's NSE never sets a session);
//! - the server name nmap's rules give it, where rustls can send it
//!   ([`stream::server_name`]).
//!
//! The randomness is `core`'s one seam (E3). Nothing here is `unsafe`.
#![forbid(unsafe_code)]

mod aead;
mod hash;
mod hmac;
mod kx;
pub mod provider;
mod rand;
mod rsa;
mod sigs;
pub mod stream;
mod verifier;

use std::sync::{Arc, OnceLock};

pub use stream::{server_name, ReadEvent, TlsStream};

/// The client configuration every connection shares.
#[must_use]
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap_or_else(|_| unreachable!("the provider carries TLS 1.2 and 1.3 suites"))
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier::NmapVerifier))
                .with_no_client_auth();
            cfg.resumption = rustls::client::Resumption::disabled();
            cfg.enable_sni = true;
            Arc::new(cfg)
        })
        .clone()
}

/// The verifier's rules on bytes from anywhere, for the fuzz targets
/// (`fuzz/fuzz_targets/nse_tls_verifier.rs`); not an API.
#[doc(hidden)]
pub mod fuzzing {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::sigs::{verify, PeerKey};
    use super::verifier::NmapVerifier;

    /// Whether the verifier takes `chain` (the leaf first) as a server's.
    #[must_use]
    pub fn accepts_chain(chain: &[&[u8]]) -> bool {
        let Some((leaf, rest)) = chain.split_first() else {
            return false;
        };
        let mids: Vec<CertificateDer<'_>> = rest.iter().map(|c| CertificateDer::from(*c)).collect();
        let Ok(name) = ServerName::try_from("fuzz.test") else {
            return false;
        };
        NmapVerifier
            .verify_server_cert(
                &CertificateDer::from(*leaf),
                &mids,
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .is_ok()
    }

    /// Whether `sig` over `msg` verifies under scheme `scheme` (its code
    /// point) with the key of certificate `cert`.
    #[must_use]
    pub fn verifies(cert: &[u8], scheme: u16, msg: &[u8], sig: &[u8], tls13: bool) -> bool {
        let Some(c) = nmap_core::nse::openssl::x509::d2i_x509(cert) else {
            return false;
        };
        let Ok(key) = PeerKey::from_cert(&c) else {
            return false;
        };
        verify(rustls::SignatureScheme::from(scheme), &key, msg, sig, tls13).is_ok()
    }
}

#[cfg(test)]
mod tests;
