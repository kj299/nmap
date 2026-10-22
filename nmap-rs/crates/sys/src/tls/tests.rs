//! The client's own checks: what its verifier refuses and accepts, its
//! signature verification against OpenSSL's signatures, the server name,
//! fresh key shares, and whole handshakes in memory against a rustls server
//! over the same provider. The fixture gate (`gen_m65_tls.py --check`)
//! holds the client to nmap 7.94; these hold each rule to itself, and the
//! cheap ones run under Miri.
// Offsets into fixed fixtures and the client's own ClientHello: an overflow
// would only fail the test.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use nmap_core::nse::openssl::x509::d2i_x509;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ClientConnection, ServerConnection, SignatureAlgorithm, SignatureScheme};
use sigs::{verify, PeerKey};
use verifier::NmapVerifier;

/// The step-a fixture certificates, compiled in (Miri runs isolated).
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/differential/m6/m65_tls/certs/",
            $name
        ))
        .as_slice()
    };
}

fn cert(name: &str) -> Vec<u8> {
    match name {
        "rsa2048.der" => fixture!("rsa2048.der"),
        "ecp256.der" => fixture!("ecp256.der"),
        "ed25519.der" => fixture!("ed25519.der"),
        "x25519.der" => fixture!("x25519.der"),
        "dh.der" => fixture!("dh.der"),
        "unknownoid.der" => fixture!("unknownoid.der"),
        other => panic!("no fixture {other}"),
    }
    .to_vec()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn verify_leaf(der: &[u8], intermediates: &[Vec<u8>]) -> Result<(), rustls::Error> {
    let mids: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    NmapVerifier
        .verify_server_cert(
            &CertificateDer::from(der),
            &mids,
            &ServerName::try_from("x.test").expect("name"),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::ZERO),
        )
        .map(|_| ())
}

// ---- the verifier: OpenSSL's checks without chain verification ------------

#[test]
fn any_decodable_certificate_with_a_tls_key_is_accepted() {
    // Self-signed, expired for all the verifier cares: no chain, name or
    // date is looked at.
    for c in ["rsa2048.der", "ecp256.der", "ed25519.der"] {
        assert!(verify_leaf(&cert(c), &[]).is_ok(), "{c}");
    }
}

#[test]
fn a_certificate_entry_must_be_exactly_a_certificate() {
    let mut trailing = cert("rsa2048.der");
    trailing.push(0);
    let e = verify_leaf(&trailing, &[]).expect_err("a trailing byte is refused");
    assert_eq!(
        e,
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    );
    // ... in an intermediate too.
    assert!(verify_leaf(&cert("rsa2048.der"), &[trailing.clone()]).is_err());
    // An undecodable entry.
    assert!(verify_leaf(b"\x30\x03\x02\x01\x00", &[]).is_err());
    assert!(verify_leaf(&[], &[]).is_err());
    // `parse_ssl_certificate` ignores the byte the handshake refuses.
    assert!(d2i_x509(&trailing).is_some());
}

#[test]
fn keys_tls_refuses_are_refused() {
    // "unknown certificate type": alert 47, as 7.94 sends it.
    for c in ["x25519.der", "dh.der"] {
        let e = verify_leaf(&cert(c), &[]).expect_err(c);
        assert!(matches!(e, rustls::Error::PeerMisbehaved(_)), "{c}: {e}");
    }
    let e = verify_leaf(&cert("unknownoid.der"), &[]).expect_err("no key");
    assert!(
        e.to_string()
            .contains("unable to find public key parameters"),
        "{e}"
    );
}

#[test]
fn peer_keys_are_typed_as_openssl_types_them() {
    let key = |c: &str| PeerKey::from_cert(&d2i_x509(&cert(c)).expect("decodes"));
    assert!(matches!(key("rsa2048.der"), Ok(PeerKey::Rsa(..))));
    assert!(matches!(
        key("ecp256.der"),
        Ok(PeerKey::Ec(sigs::Curve::P256, _))
    ));
    assert!(matches!(key("ed25519.der"), Ok(PeerKey::Ed25519(_))));
    assert_eq!(key("x25519.der"), Err(sigs::KeyRefused::Type));
}

// ---- signatures, against OpenSSL's own ---------------------------------------

fn scheme(name: &str) -> SignatureScheme {
    match name {
        "RSA_PKCS1_SHA256" => SignatureScheme::RSA_PKCS1_SHA256,
        "RSA_PKCS1_SHA384" => SignatureScheme::RSA_PKCS1_SHA384,
        "RSA_PKCS1_SHA512" => SignatureScheme::RSA_PKCS1_SHA512,
        "RSA_PSS_SHA256" => SignatureScheme::RSA_PSS_SHA256,
        "RSA_PSS_SHA384" => SignatureScheme::RSA_PSS_SHA384,
        "RSA_PSS_SHA512" => SignatureScheme::RSA_PSS_SHA512,
        "ECDSA_NISTP256_SHA256" => SignatureScheme::ECDSA_NISTP256_SHA256,
        "ECDSA_NISTP384_SHA384" => SignatureScheme::ECDSA_NISTP384_SHA384,
        "ECDSA_NISTP521_SHA512" => SignatureScheme::ECDSA_NISTP521_SHA512,
        "ED25519" => SignatureScheme::ED25519,
        other => panic!("scheme {other}"),
    }
}

#[test]
#[cfg_attr(miri, ignore = "RSA and ECDSA arithmetic is too slow under Miri")]
fn signatures_verify_as_openssl_verifies_them() {
    let vectors = include_str!("testdata/vectors.txt");
    let mut n = 0;
    for line in vectors.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, sch, der, msg, sig, expect) = (
            f[0],
            scheme(f[1]),
            unhex(f[2]),
            unhex(f[3]),
            unhex(f[4]),
            f[5],
        );
        let key = PeerKey::from_cert(&d2i_x509(&der).expect("decodes")).expect("a TLS key");
        let v12 = verify(sch, &key, &msg, &sig, false).is_ok();
        let v13 = verify(sch, &key, &msg, &sig, true).is_ok();
        match expect {
            "ok" => assert!(v12 && v13, "{name}"),
            "bad" => assert!(!v12 && !v13, "{name}"),
            // The curve is bound to the scheme in TLS 1.3 only.
            "tls12" => assert!(v12 && !v13, "{name}"),
            other => panic!("{other}"),
        }
        // One bit of the signature, and of the message, breaks it.
        if expect != "bad" {
            let mut s2 = sig.clone();
            let last = s2.len() - 1;
            s2[last] ^= 1;
            assert!(
                verify(sch, &key, &msg, &s2, false).is_err(),
                "{name}: signature bit"
            );
            let mut m2 = msg.clone();
            m2[0] ^= 1;
            assert!(
                verify(sch, &key, &m2, &sig, false).is_err(),
                "{name}: message bit"
            );
        }
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
#[cfg_attr(miri, ignore = "RSA and ECDSA arithmetic is too slow under Miri")]
fn a_key_is_held_to_its_family() {
    let vectors = include_str!("testdata/vectors.txt");
    let row = |name: &str| {
        let f: Vec<String> = vectors
            .lines()
            .find(|l| l.starts_with(&format!("{name} ")))
            .expect("vector")
            .split(' ')
            .map(str::to_owned)
            .collect();
        f
    };
    let rsa = row("rsa-pkcs1-sha256");
    let ec = row("ecdsa-p256");
    let rsa_key = PeerKey::from_cert(&d2i_x509(&unhex(&rsa[2])).expect("decodes")).expect("key");
    let ec_key = PeerKey::from_cert(&d2i_x509(&unhex(&ec[2])).expect("decodes")).expect("key");
    // An RSA signature presented under an ECDSA key, and the reverse: the
    // key does not fit (alert 47), whatever the signature.
    let mismatch = Err(sigs::SigError::Mismatch);
    assert_eq!(
        verify(
            SignatureScheme::RSA_PKCS1_SHA256,
            &ec_key,
            &unhex(&rsa[3]),
            &unhex(&rsa[4]),
            false
        ),
        mismatch
    );
    assert_eq!(
        verify(
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &rsa_key,
            &unhex(&ec[3]),
            &unhex(&ec[4]),
            false
        ),
        mismatch
    );
    assert_eq!(
        verify(SignatureScheme::ED25519, &rsa_key, b"m", &[0; 64], false),
        mismatch
    );
    assert_eq!(
        verify(
            SignatureScheme::RSA_PKCS1_SHA256,
            &PeerKey::Unverifiable,
            b"m",
            &[0; 256],
            false
        ),
        mismatch
    );
    // A P-256 key under a P-384 scheme: TLS 1.3 binds the curve.
    assert_eq!(
        verify(
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &ec_key,
            &unhex(&ec[3]),
            &unhex(&ec[4]),
            true
        ),
        mismatch
    );
    // A key that fits and a signature that does not.
    assert_eq!(
        verify(
            SignatureScheme::RSA_PKCS1_SHA256,
            &rsa_key,
            b"other",
            &unhex(&rsa[4]),
            false
        ),
        Err(sigs::SigError::Bad)
    );
}

// ---- the server name -------------------------------------------------------------

#[test]
fn the_server_name_is_sent_where_rustls_can_send_it() {
    let peer = std::net::IpAddr::from([127, 0, 0, 1]);
    let dns = |n: &[u8]| matches!(server_name(Some(n), peer), ServerName::DnsName(_));
    assert!(dns(b"localhost"));
    assert!(dns(b"example.test"));
    // nse-tls-sni-rustls-names: an IP literal, a name rustls refuses, bytes
    // that are not UTF-8: no server_name at all.
    assert!(!dns(b"127.0.0.1"));
    assert!(!dns(b"::1"));
    assert!(!dns(b"bad name x"));
    assert!(!dns(b"\xff\xfe"));
    assert!(matches!(server_name(None, peer), ServerName::IpAddress(_)));
}

// ---- the ClientHello ---------------------------------------------------------------

/// The first flight: the ClientHello record.
fn client_hello() -> Vec<u8> {
    let mut c = ClientConnection::new(
        client_config(),
        ServerName::try_from("x.test").expect("name"),
    )
    .expect("connection");
    let mut out = Vec::new();
    c.write_tls(&mut out).expect("hello");
    out
}

/// The `key_share` extension's first entry, and the random.
fn share_and_random(hello: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // record(5) handshake(4) version(2) random(32) session_id
    let random = hello[11..43].to_vec();
    let mut at = 43;
    let sid = usize::from(hello[at]);
    at += 1 + sid;
    let suites = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2 + suites;
    let comp = usize::from(hello[at]);
    at += 1 + comp;
    let ext_end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    while at < ext_end {
        let typ = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
        if typ == 0x0033 {
            // list length(2), group(2), key length(2), key
            let body = &hello[at + 4..at + 4 + len];
            let klen = usize::from(u16::from_be_bytes([body[4], body[5]]));
            return (body[6..6 + klen].to_vec(), random);
        }
        at += 4 + len;
    }
    panic!("no key_share");
}

#[test]
#[cfg_attr(miri, ignore = "X25519 key generation is slow under Miri")]
fn every_handshake_draws_a_fresh_key_share_and_random() {
    let (k1, r1) = share_and_random(&client_hello());
    let (k2, r2) = share_and_random(&client_hello());
    assert_eq!(k1.len(), 32, "an X25519 share first, as 7.94 sends");
    assert_ne!(k1, k2, "a fixed ephemeral key");
    assert_ne!(r1, r2, "a fixed client random");
}

#[test]
#[cfg_attr(miri, ignore = "X25519 key generation is slow under Miri")]
fn the_hello_offers_7_94s_suites_in_its_order() {
    let hello = client_hello();
    let at = 44 + usize::from(hello[43]);
    let n = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    let suites: Vec<u16> = hello[at + 2..at + 2 + n]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    // TLS 1.3, then the ECDHE AEAD suites: RSA before ECDSA at each strength
    // (the dual-certificate rule), then the renegotiation SCSV rustls adds.
    assert_eq!(
        suites,
        [0x1302, 0x1303, 0x1301, 0xc030, 0xc02c, 0xcca8, 0xcca9, 0xc02f, 0xc02b, 0x00ff]
    );
}

// ---- whole handshakes, in memory ----------------------------------------------------

/// A P-256 signer for the test server, which can corrupt what it signs.
#[derive(Debug, Clone)]
struct P256 {
    key: p256::ecdsa::SigningKey,
    corrupt: bool,
}

impl SigningKey for P256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for P256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(message);
        let mut der = sig.to_der().as_bytes().to_vec();
        if self.corrupt {
            let n = der.len() - 1;
            der[n] ^= 1;
        }
        Ok(der)
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn server(version: &'static rustls::SupportedProtocolVersion, corrupt: bool) -> ServerConnection {
    let scalar = unhex(
        std::str::from_utf8(fixture!("ecp256.scalar"))
            .expect("hex")
            .trim(),
    );
    let key = P256 {
        key: p256::ecdsa::SigningKey::from_slice(&scalar).expect("P-256 scalar"),
        corrupt,
    };
    let ck = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert("ecp256.der"))],
        Arc::new(key),
    ));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider::provider()))
        .with_protocol_versions(&[version])
        .expect("version")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(ck)));
    ServerConnection::new(Arc::new(cfg)).expect("server")
}

/// Shuttle records between the two until the client is done or fails.
fn handshake(mut s: ServerConnection) -> Result<ClientConnection, rustls::Error> {
    let mut c = ClientConnection::new(
        client_config(),
        ServerName::try_from("x.test").expect("name"),
    )
    .expect("client");
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).expect("client writes");
        }
        if !buf.is_empty() {
            let mut rd = buf.as_slice();
            while !rd.is_empty() {
                s.read_tls(&mut rd).expect("server reads");
            }
            let _ = s.process_new_packets();
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).expect("server writes");
        }
        if !buf.is_empty() {
            let mut rd = buf.as_slice();
            while !rd.is_empty() {
                c.read_tls(&mut rd).expect("client reads");
            }
            c.process_new_packets()?;
        }
        if !c.is_handshaking() {
            return Ok(c);
        }
    }
    panic!("no progress");
}

#[test]
#[cfg_attr(miri, ignore = "whole handshakes are too slow under Miri")]
fn handshakes_complete_and_carry_the_leaf() {
    for v in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let c = handshake(server(v, false)).expect("handshake");
        let leaf = c.peer_certificates().and_then(|l| l.first()).expect("leaf");
        assert_eq!(leaf.as_ref(), cert("ecp256.der").as_slice());
    }
}

#[test]
#[cfg_attr(miri, ignore = "whole handshakes are too slow under Miri")]
fn a_bad_handshake_signature_fails_the_handshake() {
    // TLS 1.3's CertificateVerify and TLS 1.2's ServerKeyExchange.
    for v in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let e = handshake(server(v, true)).expect_err("a corrupt signature");
        assert!(e.to_string().contains("BadSignature"), "{e}");
    }
}

// ---- the record layer's lengths ------------------------------------------------------

#[test]
fn a_record_shorter_than_its_tag_is_a_decrypt_error() {
    use rustls::crypto::cipher::{
        AeadKey, InboundOpaqueMessage, Iv, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    };
    use rustls::{ContentType, ProtocolVersion};
    let key = AeadKey::from([7u8; 32]);
    let mut d13 =
        aead::Aead13::<chacha20poly1305::ChaCha20Poly1305>::new().decrypter(key, Iv::new([0; 12]));
    let mut d12 =
        aead::Gcm12::<aes_gcm::Aes256Gcm>::new().decrypter(AeadKey::from([7u8; 32]), &[0; 4]);
    for n in [0usize, 1, 15, 23] {
        let mut p = vec![0u8; n];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut p,
        );
        let r13 = d13.decrypt(m, 0);
        assert!(r13.is_err(), "TLS 1.3, {n} bytes");
        let mut p = vec![0u8; n];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut p,
        );
        assert!(d12.decrypt(m, 0).is_err(), "TLS 1.2 GCM, {n} bytes");
    }
}
