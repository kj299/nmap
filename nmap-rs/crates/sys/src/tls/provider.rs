//! The provider: suites in 7.94's ClientHello order
//! (`tests/differential/m6/m65_tls/clienthello_suites_794.txt`) restricted to
//! what rustls can carry (the TLS 1.3 three, then ECDHE with GCM and
//! ChaCha20); groups in 7.94's order (x25519, P-256, P-521, P-384; no x448);
//! no FFDHE (§6). Within the ECDHE suites the RSA-signed ones go before the
//! ECDSA-signed ones: 7.94 offers DHE-RSA before any ECDHE suite, so against
//! a server holding both an RSA and an ECDSA certificate and honouring client
//! preference it gets the RSA one, and so must the port (`ssl-cert` prints
//! it; the `dual-tls12-clientpref` fixture).

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    CryptoProvider, KeyExchangeAlgorithm, KeyProvider, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::sign::SigningKey;
use rustls::{CipherSuite, Error, SignatureScheme, SupportedCipherSuite};
use rustls::{CipherSuiteCommon, Tls12CipherSuite, Tls13CipherSuite};
use std::sync::Arc;

use super::{aead, hash, hmac, kx, rand};

pub(crate) static SHA256: hash::Sha256 = hash::Sha256;
pub(crate) static SHA384: hash::Sha384 = hash::Sha384;
pub(crate) static HMAC_SHA256: hmac::HmacSha256 = hmac::HmacSha256;
pub(crate) static HMAC_SHA384: hmac::HmacSha384 = hmac::HmacSha384;

static AES128_GCM_13: aead::Aead13<aes_gcm::Aes128Gcm> = aead::Aead13::new();
static AES256_GCM_13: aead::Aead13<aes_gcm::Aes256Gcm> = aead::Aead13::new();
static CHACHA_13: aead::Aead13<chacha20poly1305::ChaCha20Poly1305> = aead::Aead13::new();
static AES128_GCM_12: aead::Gcm12<aes_gcm::Aes128Gcm> = aead::Gcm12::new();
static AES256_GCM_12: aead::Gcm12<aes_gcm::Aes256Gcm> = aead::Gcm12::new();
static CHACHA_12: aead::Chacha12 = aead::Chacha12;

pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA384),
        aead_alg: &AES256_GCM_13,
        quic: None,
    });
pub(crate) static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
        aead_alg: &CHACHA_13,
        quic: None,
    });
pub(crate) static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
        aead_alg: &AES128_GCM_13,
        quic: None,
    });

/// The order 7.94's ClientHello lists them in (`clienthello_suites.txt`, from
/// `s_server -trace`): PSS before PKCS#1, each SHA-512 before SHA-384 before
/// SHA-256, as OpenSSL's default sigalgs list has them.
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
];

macro_rules! tls12 {
    ($name:ident, $suite:ident, $hash:ident, $hmac:ident, $schemes:ident, $aead:ident, $limit:expr) => {
        pub static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$suite,
                hash_provider: &$hash,
                confidentiality_limit: $limit,
            },
            prf_provider: &PrfUsingHmac(&$hmac),
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $schemes,
            aead_alg: &$aead,
        });
    };
}

tls12!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    AES256_GCM_12,
    1 << 24
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_ECDSA_SCHEMES,
    AES256_GCM_12,
    1 << 24
);
tls12!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    CHACHA_12,
    u64::MAX
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    CHACHA_12,
    u64::MAX
);
tls12!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_GCM_12,
    1 << 24
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES128_GCM_12,
    1 << 24
);

pub(crate) static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
];

pub(crate) static X25519: kx::X25519 = kx::X25519;
pub(crate) static SECP256R1: kx::Secp256r1 = kx::Secp256r1;
pub(crate) static SECP384R1: kx::Secp384r1 = kx::Secp384r1;
pub(crate) static SECP521R1: kx::Secp521r1 = kx::Secp521r1;

pub(crate) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[&X25519, &SECP256R1, &SECP521R1, &SECP384R1];

/// The provider's table for rustls's own WebPKI verifier, which this client
/// never uses: its verifier ([`super::verifier::NmapVerifier`]) verifies
/// every signature itself, with the key `core` read.
static NO_WEBPKI_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[],
    mapping: &[],
};

/// The signature_algorithms extension, in 7.94's order (OpenSSL's default
/// client list, minus what the provider cannot verify: Ed448, rsa_pss_pss_*,
/// SHA-224, DSA).
pub(crate) static CLIENT_SIG_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// The client never presents a certificate, so no private key is ever loaded.
#[derive(Debug)]
pub(crate) struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(
        &self,
        _: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("this provider loads no private keys".into()))
    }
}

/// The provider every TLS connection uses.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: NO_WEBPKI_ALGS,
        secure_random: &rand::OsRandom,
        key_provider: &NoKeys,
    }
}
