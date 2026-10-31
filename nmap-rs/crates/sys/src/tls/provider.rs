//! The provider: suites in 7.94's ClientHello order
//! (`tests/differential/m6/m65_tls/clienthello_suites_794.txt`) restricted to
//! what it carries: the TLS 1.3 three, then ECDHE and DHE-RSA with AES-GCM,
//! ChaCha20-Poly1305, AES-CCM, AES-CCM-8 and ARIA-GCM (M6.7 step a), then RSA
//! key exchange with the same AEADs but ChaCha20 (step c, through the vendored
//! rustls's patch 0002). CBC and DSA follow in steps d and e. Groups in
//! 7.94's order: x25519, P-256, x448, P-521, P-384, then ffdhe2048 to 8192.
//!
//! One change to 7.94's order: each ECDHE-ECDSA suite goes after the
//! ECDHE-RSA suite that follows it in 7.94's list, so the RSA-signed suite of
//! each kind comes first. 7.94 offers DHE-RSA-AES128-SHA (CBC) before any
//! AEAD suite, so against a server holding both an RSA and an ECDSA
//! certificate and honouring client preference it gets the RSA one, and so
//! must the port (`ssl-cert` prints it; the `dual-tls12-clientpref`
//! fixture). Step d, which brings CBC, ends the exception.

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    CryptoProvider, KeyExchangeAlgorithm, KeyProvider, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::sign::SigningKey;
use rustls::{CipherSuite, Error, NamedGroup, SignatureScheme, SupportedCipherSuite};
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
static AES128_GCM_12: aead::Aead12<aes_gcm::Aes128Gcm> = aead::Aead12::new();
static AES256_GCM_12: aead::Aead12<aes_gcm::Aes256Gcm> = aead::Aead12::new();
static CHACHA_12: aead::Chacha12 = aead::Chacha12;
static ARIA128_GCM_12: aead::Aead12<aead::Aria128Gcm> = aead::Aead12::new();
static ARIA256_GCM_12: aead::Aead12<aead::Aria256Gcm> = aead::Aead12::new();
static AES128_CCM_12: aead::Aead12<aead::Aes128Ccm> = aead::Aead12::new();
static AES256_CCM_12: aead::Aead12<aead::Aes256Ccm> = aead::Aead12::new();
static AES128_CCM8_12: aead::Aead12<aead::Aes128Ccm8> = aead::Aead12::new();
static AES256_CCM8_12: aead::Aead12<aead::Aes256Ccm8> = aead::Aead12::new();

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
    ($name:ident, $hash:ident, $hmac:ident, $schemes:ident, $aead:ident, $limit:expr, $kx:ident) => {
        pub static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$name,
                hash_provider: &$hash,
                confidentiality_limit: $limit,
            },
            prf_provider: &PrfUsingHmac(&$hmac),
            kx: KeyExchangeAlgorithm::$kx,
            sign: $schemes,
            aead_alg: &$aead,
        });
    };
}

tls12!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    AES256_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_ECDSA_SCHEMES,
    AES256_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    AES256_GCM_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    CHACHA_12,
    u64::MAX,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    CHACHA_12,
    u64::MAX,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    CHACHA_12,
    u64::MAX,
    DHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES256_CCM8_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES256_CCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_256_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES256_CCM8_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_256_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES256_CCM_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    ARIA256_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_ECDSA_SCHEMES,
    ARIA256_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    ARIA256_GCM_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES128_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_GCM_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES128_CCM8_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    AES128_CCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_128_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_CCM8_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_DHE_RSA_WITH_AES_128_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_CCM_12,
    1 << 24,
    DHE
);
tls12!(
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    ARIA128_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    ARIA128_GCM_12,
    1 << 24,
    ECDHE
);
tls12!(
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    ARIA128_GCM_12,
    1 << 24,
    DHE
);

// RSA key exchange (M6.7 step c; the vendored rustls's patch 0002), after
// every ECDHE and DHE suite, as 7.94 offers them.
tls12!(
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    AES256_GCM_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_AES_256_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES256_CCM8_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_AES_256_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES256_CCM_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_ARIA_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    ARIA256_GCM_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_GCM_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_AES_128_CCM_8,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_CCM8_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_AES_128_CCM,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    AES128_CCM_12,
    1 << 24,
    RSA
);
tls12!(
    TLS_RSA_WITH_ARIA_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    ARIA128_GCM_12,
    1 << 24,
    RSA
);

pub(crate) static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TLS_DHE_RSA_WITH_AES_256_CCM,
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TLS_DHE_RSA_WITH_AES_128_CCM,
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_256_CCM_8,
    TLS_RSA_WITH_AES_256_CCM,
    TLS_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_128_CCM_8,
    TLS_RSA_WITH_AES_128_CCM,
    TLS_RSA_WITH_ARIA_128_GCM_SHA256,
];

pub(crate) static X25519: kx::X25519 = kx::X25519;
pub(crate) static SECP256R1: kx::Secp256r1 = kx::Secp256r1;
pub(crate) static SECP384R1: kx::Secp384r1 = kx::Secp384r1;
pub(crate) static SECP521R1: kx::Secp521r1 = kx::Secp521r1;

pub(crate) static X448: kx::X448 = kx::X448;

macro_rules! ffdhe {
    ($name:ident, $group:ident, $bits:expr) => {
        pub(crate) static $name: kx::Ffdhe = kx::Ffdhe {
            name: NamedGroup::$group,
            group: rustls::ffdhe_groups::$name,
            exp_bits: $bits,
        };
    };
}
ffdhe!(FFDHE2048, FFDHE2048, 225);
ffdhe!(FFDHE3072, FFDHE3072, 275);
ffdhe!(FFDHE4096, FFDHE4096, 325);
ffdhe!(FFDHE6144, FFDHE6144, 375);
ffdhe!(FFDHE8192, FFDHE8192, 400);

pub(crate) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &X25519, &SECP256R1, &X448, &SECP521R1, &SECP384R1, &FFDHE2048, &FFDHE3072, &FFDHE4096,
    &FFDHE6144, &FFDHE8192,
];

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
        rsa_key_transport: Some(&RsaTransport),
    }
}

/// RSA key transport (RFC 5246 §7.4.7.1): the premaster rustls draws,
/// encrypted RSAES-PKCS1-v1_5 to the leaf's key as OpenSSL's
/// `tls_construct_cke_rsa` does. The key is read by the reader the verifier
/// uses ([`super::sigs::PeerKey::from_cert`]); a leaf whose key is not RSA
/// cannot carry this key exchange (OpenSSL: "wrong certificate type").
#[derive(Debug)]
pub(crate) struct RsaTransport;

impl rustls::crypto::RsaKeyTransport for RsaTransport {
    fn encrypt_premaster(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        premaster: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cert = nmap_core::nse::openssl::x509::d2i_x509_len(end_entity.as_ref())
            .ok_or(Error::General(
                "RSA key exchange: the leaf does not decode".into(),
            ))?
            .0;
        let Ok(super::sigs::PeerKey::Rsa(n, e)) = super::sigs::PeerKey::from_cert(&cert) else {
            return Err(Error::General(
                "RSA key exchange: the leaf's key is not RSA".into(),
            ));
        };
        let key = super::rsa::RsaPublicKey::new(&n, &e).ok_or(Error::General(
            "RSA key exchange: a degenerate RSA key".into(),
        ))?;
        key.encrypt_pkcs1(premaster, |buf| {
            rustls::crypto::SecureRandom::fill(&rand::OsRandom, buf).is_ok()
        })
        .ok_or(Error::General(
            "RSA key exchange: the key is too short for the premaster".into(),
        ))
    }
}
