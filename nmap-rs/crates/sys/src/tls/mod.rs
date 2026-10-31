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
mod x448;

use std::sync::{Arc, OnceLock};

pub use stream::{server_name, ReadEvent, TlsStream};
pub use verifier::PeerLeaf;

/// The client configuration every connection shares, but for its verifier
/// ([`connection_config`]).
#[must_use]
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut cfg =
                rustls::ClientConfig::builder_with_provider(Arc::new(provider::provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                    .unwrap_or_else(|_| unreachable!("the provider carries TLS 1.2 and 1.3 suites"))
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier::NmapVerifier::default()))
                    .with_no_client_auth();
            cfg.resumption = rustls::client::Resumption::disabled();
            cfg.enable_sni = true;
            Arc::new(cfg)
        })
        .clone()
}

/// One connection's configuration: [`client_config`] with a verifier that
/// records the leaf it accepts in `leaf`.
#[must_use]
pub fn connection_config(leaf: &PeerLeaf) -> Arc<rustls::ClientConfig> {
    let mut cfg = (*client_config()).clone();
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(verifier::NmapVerifier { leaf: leaf.clone() }));
    Arc::new(cfg)
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
        NmapVerifier::default()
            .verify_server_cert(
                &CertificateDer::from(*leaf),
                &mids,
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .is_ok()
    }

    /// Key agreement with a peer's share: `selector` picks X448 or one of
    /// the five FFDHE groups (its low bits) and TLS 1.2 or 1.3 (bit 3).
    /// Whether the share was taken.
    #[must_use]
    pub fn agree(selector: u8, peer: &[u8]) -> bool {
        use rustls::crypto::SupportedKxGroup;
        let groups: [&dyn SupportedKxGroup; 6] = [
            &super::provider::X448,
            &super::provider::FFDHE2048,
            &super::provider::FFDHE3072,
            &super::provider::FFDHE4096,
            &super::provider::FFDHE6144,
            &super::provider::FFDHE8192,
        ];
        let Some(group) = groups.get(
            usize::from(selector & 7)
                .checked_rem(groups.len())
                .unwrap_or(0),
        ) else {
            return false;
        };
        let Ok(kx) = group.start() else {
            return false;
        };
        let version = if selector & 8 == 0 {
            &rustls::version::TLS13
        } else {
            &rustls::version::TLS12
        };
        kx.complete_for_tls_version(peer, version).is_ok()
    }

    /// A TLS 1.2 record of `body` through the decrypter of one of the step-a
    /// AEADs (`selector`: AES-128/256-CCM, -CCM-8, ARIA-128/256-GCM), keyed
    /// with fixed bytes. Whether it opened.
    #[must_use]
    pub fn open_tls12(selector: u8, body: &mut [u8]) -> bool {
        use super::aead::{
            decrypter12, Aes128Ccm, Aes128Ccm8, Aes256Ccm, Aes256Ccm8, Aria128Gcm, Aria256Gcm,
        };
        use rustls::crypto::cipher::InboundOpaqueMessage;
        let key = [0x42u8; 32];
        let salt = [1, 2, 3, 4];
        let dec = match selector % 6 {
            0 => decrypter12::<Aes128Ccm>(&key[..16], salt),
            1 => decrypter12::<Aes256Ccm>(&key, salt),
            2 => decrypter12::<Aes128Ccm8>(&key[..16], salt),
            3 => decrypter12::<Aes256Ccm8>(&key, salt),
            4 => decrypter12::<Aria128Gcm>(&key[..16], salt),
            _ => decrypter12::<Aria256Gcm>(&key, salt),
        };
        let Some(mut dec) = dec else {
            return false;
        };
        let msg = InboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            rustls::ProtocolVersion::TLSv1_2,
            body,
        );
        dec.decrypt(msg, 0).is_ok()
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
