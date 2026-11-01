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
    NmapVerifier::default()
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
    // OpenSSL's "cert length mismatch": decode_error (50), not
    // bad_certificate (42).
    let e = verify_leaf(&trailing, &[]).expect_err("a trailing byte is refused");
    assert!(matches!(e, rustls::Error::InvalidMessage(_)), "{e}");
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
    // internal_error (80), as 7.94 sends it.
    assert!(matches!(e, rustls::Error::Other(_)), "{e}");
    assert!(
        e.to_string()
            .contains("unable to find public key parameters"),
        "{e}"
    );
}

/// OpenSSL keeps the leaf as the peer's certificate once its checks pass
/// (`tls_post_process_server_certificate`), before any signature is looked
/// at, and `get_ssl_certificate` returns it after a handshake that fails
/// later (measured: `cert-fake-badsig`, `cert-bad13-corrupt`). A TLS 1.2 key
/// that does not fit the suite is refused before it is kept.
#[test]
fn the_leaf_is_kept_once_its_checks_pass() {
    let v = NmapVerifier::default();
    let name = ServerName::try_from("x.test").expect("name");
    let at = |v: &NmapVerifier, der: &[u8]| {
        v.verify_server_cert(
            &CertificateDer::from(der),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::ZERO),
        )
        .map(|_| ())
    };
    let mut trailing = cert("ecp256.der");
    trailing.push(0);
    for refused in [trailing, cert("x25519.der"), cert("unknownoid.der")] {
        assert!(at(&v, &refused).is_err());
        assert_eq!(v.leaf.get(), None);
    }
    let ec = cert("ecp256.der");
    let leaf = CertificateDer::from(ec.as_slice());
    at(&v, &ec).expect("accepted");
    assert_eq!(v.leaf.get().as_deref(), Some(ec.as_slice()));
    // "bad signature": kept, in either version.
    for tls13 in [false, true] {
        let e = v
            .check(
                b"m",
                &leaf,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                b"\x30\x00",
                tls13,
            )
            .expect_err("bad signature");
        assert_eq!(
            e,
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        );
        assert_eq!(v.leaf.get().as_deref(), Some(ec.as_slice()));
    }
    // TLS 1.3, a scheme of another key type: "wrong signature type", kept.
    assert!(v
        .check(b"m", &leaf, SignatureScheme::RSA_PSS_SHA256, b"x", true)
        .is_err());
    assert_eq!(v.leaf.get().as_deref(), Some(ec.as_slice()));
    // TLS 1.2: the scheme is the suite's, so the key does not fit the suite,
    // "wrong certificate type": dropped.
    assert!(v
        .check(b"m", &leaf, SignatureScheme::RSA_PSS_SHA256, b"x", false)
        .is_err());
    assert_eq!(v.leaf.get(), None);
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
        "DSA_SHA224" => SignatureScheme::Unknown(0x0302),
        "DSA_SHA256" => SignatureScheme::Unknown(0x0402),
        "DSA_SHA384" => SignatureScheme::Unknown(0x0502),
        "DSA_SHA512" => SignatureScheme::Unknown(0x0602),
        "ED448" => SignatureScheme::ED448,
        "RSA_PSS_PSS_SHA256" => SignatureScheme::Unknown(0x0809),
        "RSA_PSS_PSS_SHA384" => SignatureScheme::Unknown(0x080a),
        "RSA_PSS_PSS_SHA512" => SignatureScheme::Unknown(0x080b),
        "RSA_PKCS1_SHA224" => SignatureScheme::Unknown(0x0301),
        "ECDSA_SHA224" => SignatureScheme::Unknown(0x0303),
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
    assert_eq!(n, 28);
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
fn the_server_name_is_sent_as_it_is() {
    // 7.94 sends the target's name as OpenSSL takes it: an IP literal, a
    // name rustls's DnsName refuses, a trailing dot (patch 0007).
    let leaf = PeerLeaf::default();
    for n in [
        &b"localhost"[..],
        b"127.0.0.1",
        b"::1",
        b"bad name x",
        b"LocalHost.",
        b"\xff\xfe",
    ] {
        assert_eq!(
            connection_config(&leaf, Some(n)).raw_server_name.as_deref(),
            Some(n)
        );
    }
    // A host table with no name: none.
    assert_eq!(connection_config(&leaf, None).raw_server_name, None);
    // On the wire: server_name first, as OpenSSL puts it, carrying the bytes
    // as they are.
    for n in [&b"127.0.0.1"[..], b"LocalHost.", b"bad name x"] {
        let mut c = ClientConnection::new(
            connection_config(&leaf, Some(n)),
            ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into()),
        )
        .expect("connection");
        let mut hello = Vec::new();
        c.write_tls(&mut hello).expect("hello");
        let ext = extensions(&hello);
        assert_eq!(ext[0].0, 0x0000, "server_name first");
        // list length(2), type host_name(1), name length(2), name
        assert_eq!(
            ext[0].1[0..3],
            [0, u8::try_from(n.len() + 3).expect("short"), 0]
        );
        assert_eq!(&ext[0].1[5..], n);
    }
    assert!(extensions(&hello_without_sni())
        .iter()
        .all(|(t, _)| *t != 0));
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
    // 7.94's ClientHello as captured (`spikes/m67-legacy-tls/clienthello_794.txt`),
    // exactly, since M6.7 step e: all 77 suites and the renegotiation SCSV
    // last, where rustls adds it.
    let captured = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spikes/m67-legacy-tls/clienthello_794.txt"
    ));
    let want: Vec<u16> = captured
        .lines()
        .filter_map(|l| l.strip_prefix("suite 0x"))
        .map(|h| u16::from_str_radix(h, 16).expect("hex"))
        .collect();
    assert_eq!(want.len(), 78);
    assert_eq!(suites, want);
}

/// The supported_groups extension: 7.94's list and order
/// (`spikes/m67-legacy-tls/clienthello_794.txt`), x25519 first, then P-256,
/// X448, P-521, P-384 and the five RFC 7919 groups; the key share is x25519's.
#[test]
#[cfg_attr(miri, ignore = "X25519 key generation is slow under Miri")]
fn the_hello_offers_7_94s_groups_in_its_order() {
    let hello = client_hello();
    let groups = extension(&hello, 10).expect("supported_groups");
    let n = usize::from(u16::from_be_bytes([groups[0], groups[1]]));
    let got: Vec<u16> = groups[2..2 + n]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        got,
        [0x001d, 0x0017, 0x001e, 0x0019, 0x0018, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104]
    );
    let shares = extension(&hello, 51).expect("key_share");
    assert_eq!(&shares[2..4], &[0x00, 0x1d], "the one share is x25519's");
    assert_eq!(
        usize::from(u16::from_be_bytes([shares[0], shares[1]])),
        4 + 32
    );
}

/// A connection's ClientHello record with no server name, as the capture
/// was taken (the probe connects to an address).
fn hello_without_sni() -> Vec<u8> {
    let leaf = PeerLeaf::default();
    let mut c = ClientConnection::new(
        connection_config(&leaf, None),
        ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into()),
    )
    .expect("connection");
    let mut out = Vec::new();
    c.write_tls(&mut out).expect("hello");
    out
}

/// The extensions of a ClientHello record, in order: type and body.
fn extensions(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut at = 44 + usize::from(hello[43]);
    at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 1 + usize::from(hello[at]);
    let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    let mut out = Vec::new();
    while at + 4 <= end {
        let t = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
        out.push((t, hello[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    out
}

/// M6.7 step f: the ClientHello is 7.94's in every field that does not
/// change between runs (`spikes/m67-legacy-tls/clienthello_794.txt`): its
/// length, the session id's, the extensions in OpenSSL's order with
/// OpenSSL's contents, the signature algorithms, and the padding that brings
/// it to 512 bytes.
#[test]
#[cfg_attr(miri, ignore = "X25519 key generation is slow under Miri")]
fn the_hello_is_7_94s() {
    let captured = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spikes/m67-legacy-tls/clienthello_794.txt"
    ));
    let field = |k: &str| {
        captured
            .lines()
            .find_map(|l| l.trim().strip_prefix(k))
            .unwrap_or_else(|| panic!("{k}"))
            .trim()
            .to_owned()
    };
    let hello = hello_without_sni();
    // record(5), then the handshake message.
    assert_eq!((hello.len() - 5).to_string(), field("handshake_length "));
    assert_eq!(hello[43].to_string(), field("session_id_length "));
    let ext = extensions(&hello);
    let names: Vec<&str> = ext
        .iter()
        .map(|(t, _)| match t {
            0x000b => "ec_point_formats",
            0x000a => "supported_groups",
            0x0023 => "session_ticket",
            0x0016 => "encrypt_then_mac",
            0x0017 => "extended_master_secret",
            0x000d => "signature_algorithms",
            0x002b => "supported_versions",
            0x002d => "psk_key_exchange_modes",
            0x0033 => "key_share",
            0x0015 => "padding",
            _ => "other",
        })
        .collect();
    let want: Vec<&str> = captured
        .lines()
        .filter_map(|l| l.strip_prefix("ext "))
        .collect();
    assert_eq!(names, want);
    let body = |t: u16| &ext.iter().find(|(x, _)| *x == t).expect("present").1;
    assert_eq!(hex(&body(0x000b)[1..]), field("formats "));
    assert!(body(0x0023).is_empty() && body(0x0016).is_empty() && body(0x0017).is_empty());
    assert_eq!(body(0x0015).len().to_string(), field("length "));
    assert!(body(0x0015).iter().all(|&b| b == 0));
    // The signature algorithms by name, in order.
    let sig_name = |c: u16| match c {
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0303 => "ecdsa_sha224",
        0x0301 => "rsa_pkcs1_sha224",
        0x0302 => "dsa_sha224",
        0x0402 => "dsa_sha256",
        0x0502 => "dsa_sha384",
        0x0602 => "dsa_sha512",
        _ => "other",
    };
    let sigs: Vec<&str> = body(0x000d)[2..]
        .chunks(2)
        .map(|c| sig_name(u16::from_be_bytes([c[0], c[1]])))
        .collect();
    assert_eq!(sigs.join(" "), field("sigalgs "));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The body of extension `typ` in a ClientHello handshake message.
fn extension(hello: &[u8], typ: u16) -> Option<Vec<u8>> {
    let mut at = 44 + usize::from(hello[43]);
    at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 1 + usize::from(hello[at]);
    let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    while at + 4 <= end {
        let t = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
        if t == typ {
            return Some(hello[at + 4..at + 4 + len].to_vec());
        }
        at += 4 + len;
    }
    None
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
        aead::Aead12::<aes_gcm::Aes256Gcm>::new().decrypter(AeadKey::from([7u8; 32]), &[0; 4]);
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

// ---- RSA key exchange (M6.7 step c) -------------------------------------------------

fn rsa2048() -> rsa::RsaPublicKey {
    let Ok(PeerKey::Rsa(n, e)) =
        PeerKey::from_cert(&d2i_x509(fixture!("rsa2048.der")).expect("decodes"))
    else {
        panic!("an RSA key");
    };
    rsa::RsaPublicKey::new(&n, &e).expect("key")
}

/// The premaster 03 03 01..2e under the fixture's RSA-2048 key, PS all 0xab.
/// The expected ciphertext was computed with Python's `pow`, and OpenSSL
/// 3.0.13 decrypts it to the premaster with the fixture's private key
/// (`openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1`).
#[test]
#[cfg_attr(miri, ignore = "a 2,048-bit exponentiation is slow under Miri")]
fn rsa_kx_encrypts_as_openssl_decrypts() {
    let mut pm = vec![3u8, 3];
    pm.extend(1..=46u8);
    let c = rsa2048()
        .encrypt_pkcs1(&pm, |b| {
            b.fill(0xab);
            true
        })
        .expect("encrypts");
    assert_eq!(c.len(), 256);
    assert_eq!(c, unhex("0cba7265774b94345fd2d53eeb9dc2a4423f469da588484cb0f1b8179f28e91328525ecf45b12f2cc0b398a504279a43c6fce20770d16cf458a9401b6084d37f607465978e48561a5c1136b96ff8a2f4e3a478e5685226f7f87742d9acea5c8287586c81471526334c242f646111055f971d354c57e52331af41e17eb6a7892472959049e1df8e1eb627e705b95b0c4be0bc546641bd6a314f605762b4417332fe426b295b3edb6550d90c41d7d6e2b046485a914eae7932c87fddb0ec94da00915f326e0f67461b4d74b7849c6b75cc90ce44e84cc3c4a34321569fb89cda975a96d51b97cd497e75be19d58bc643741723315419224942337a6fc9be9ca639"));
}

/// The padding source: a refusal fails the encryption, a zero is drawn
/// again, and a source that gives only zeros fails rather than spins.
#[test]
#[cfg_attr(miri, ignore = "a 2,048-bit exponentiation is slow under Miri")]
fn rsa_kx_padding_is_nonzero_and_bounded() {
    let key = rsa2048();
    let pm = [3u8; 48];
    assert!(key.encrypt_pkcs1(&pm, |_| false).is_none());
    assert!(key
        .encrypt_pkcs1(&pm, |b| {
            b.fill(0);
            true
        })
        .is_none());
    // Zeros at first, then nonzero bytes: the result is the all-0xab one's
    // with a different PS, so only check it encrypts and is k bytes.
    let mut calls = 0u32;
    let c = key
        .encrypt_pkcs1(&pm, |b| {
            calls += 1;
            b.fill(if calls == 1 { 0 } else { 0xab });
            true
        })
        .expect("encrypts");
    assert_eq!(c.len(), 256);
    assert!(calls > 1, "the zeros were drawn again");
    // A modulus too short for 00 02, eight PS bytes, 00 and 48 bytes.
    let short = rsa::RsaPublicKey::new(&[0xc3; 58], &[1, 0, 1]).expect("key");
    assert!(short
        .encrypt_pkcs1(&pm, |b| {
            b.fill(1);
            true
        })
        .is_none());
}

/// The provider's hook: the leaf's key must be RSA (an ECDSA leaf is
/// refused: OpenSSL's "wrong certificate type").
#[test]
#[cfg_attr(miri, ignore = "a 2,048-bit exponentiation is slow under Miri")]
fn rsa_kx_needs_an_rsa_leaf() {
    use rustls::crypto::RsaKeyTransport;
    let pm = [3u8; 48];
    let rsa = provider::RsaTransport
        .encrypt_premaster(&CertificateDer::from(fixture!("rsa2048.der")), &pm);
    assert_eq!(rsa.expect("an RSA leaf").len(), 256);
    let ec = provider::RsaTransport
        .encrypt_premaster(&CertificateDer::from(fixture!("ecp256.der")), &pm);
    assert!(ec.is_err());
}

/// Encrypt-then-MAC (RFC 7366): requested, empty, as 7.94 requests it
/// (`clienthello_794.txt`: `ext encrypt_then_mac`), since the port offers CBC
/// suites (M6.7 step d).
#[test]
#[cfg_attr(miri, ignore = "X25519 key generation is slow under Miri")]
fn the_hello_requests_encrypt_then_mac() {
    let hello = client_hello();
    assert_eq!(extension(&hello, 0x0016), Some(vec![]));
}

/// The fuzz target's own-group seeds (`fuzz/gen_tls_seeds.py`): the good
/// group and share are taken, each edge OpenSSL refuses is refused.
#[test]
#[cfg_attr(
    miri,
    ignore = "2,048-bit modular exponentiation is too slow under Miri"
)]
fn the_own_group_seeds_meet_openssls_checks() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/seeds/nse_tls_kx_aead/"
    );
    for (name, taken) in [
        ("own2048-share", true),
        ("own2048-gpm1", false),
        ("own2048-even", false),
        ("own2048-ypm1", false),
        ("own1024", false),
    ] {
        let seed = std::fs::read(format!("{dir}{name}")).expect("seed");
        assert_eq!(seed.first(), Some(&0x40), "{name}");
        assert_eq!(super::fuzzing::own_dh(&seed[1..]), taken, "{name}");
    }
}

/// DSA's r and s are taken only below q: r + q and s + q verify in the
/// arithmetic (mod q), and are refused as OpenSSL refuses them.
#[test]
#[cfg_attr(miri, ignore = "DSA arithmetic is too slow under Miri")]
fn dsa_refuses_r_or_s_not_below_q() {
    use num_bigint::BigUint;
    fn int(n: &BigUint) -> Vec<u8> {
        let mut b = n.to_bytes_be();
        if b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        let mut out = vec![0x02, u8::try_from(b.len()).expect("short")];
        out.extend(b);
        out
    }
    fn seq(r: &BigUint, s: &BigUint) -> Vec<u8> {
        let mut body = int(r);
        body.extend(int(s));
        let mut out = vec![0x30, u8::try_from(body.len()).expect("short")];
        out.extend(body);
        out
    }
    let vectors = include_str!("testdata/vectors.txt");
    let f: Vec<&str> = vectors
        .lines()
        .find(|l| l.starts_with("dsa-sha256 "))
        .expect("vector")
        .split(' ')
        .collect();
    let (sch, der, msg, sig) = (scheme(f[1]), unhex(f[2]), unhex(f[3]), unhex(f[4]));
    let key = PeerKey::from_cert(&d2i_x509(&der).expect("decodes")).expect("a TLS key");
    let PeerKey::Dsa(k) = &key else {
        panic!("a DSA key")
    };
    let q = BigUint::from_bytes_be(&k.q);
    // The vector's (r, s): a SEQUENCE of two short INTEGERs.
    let (rl, sl) = (
        usize::from(sig[3]),
        usize::from(sig[5 + usize::from(sig[3])]),
    );
    let r = BigUint::from_bytes_be(&sig[4..4 + rl]);
    let s = BigUint::from_bytes_be(&sig[6 + rl..6 + rl + sl]);
    assert_eq!(seq(&r, &s), sig, "re-encodes");
    assert!(verify(sch, &key, &msg, &seq(&r, &s), false).is_ok());
    assert!(
        verify(sch, &key, &msg, &seq(&r, &(&s + &q)), false).is_err(),
        "s + q"
    );
    assert!(
        verify(sch, &key, &msg, &seq(&(&r + &q), &s), false).is_err(),
        "r + q"
    );
}

/// Ed448's S is taken only below the group's order L, as OpenSSL takes it:
/// S + L verifies in the arithmetic ([S + L]B = [S]B) and is refused. A
/// flipped sign bit in R, and an R that is not canonical, are refused too.
#[test]
#[cfg_attr(miri, ignore = "Ed448 arithmetic is too slow under Miri")]
fn ed448_refuses_s_not_below_l_and_a_bent_r() {
    use num_bigint::BigUint;
    let vectors = include_str!("testdata/vectors.txt");
    let f: Vec<&str> = vectors
        .lines()
        .find(|l| l.starts_with("ed448 "))
        .expect("vector")
        .split(' ')
        .collect();
    let (der, msg, sig) = (unhex(f[2]), unhex(f[3]), unhex(f[4]));
    let key = PeerKey::from_cert(&d2i_x509(&der).expect("decodes")).expect("a TLS key");
    assert!(verify(SignatureScheme::ED448, &key, &msg, &sig, true).is_ok());
    let l = BigUint::parse_bytes(
        b"3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
        16,
    )
    .expect("L");
    let s = BigUint::from_bytes_le(&sig[57..]) + &l;
    let mut bent = sig[..57].to_vec();
    let mut sb = s.to_bytes_le();
    sb.resize(57, 0);
    bent.extend(sb);
    assert!(
        verify(SignatureScheme::ED448, &key, &msg, &bent, true).is_err(),
        "S + L"
    );
    let mut flipped = sig.clone();
    flipped[56] ^= 0x80;
    assert!(
        verify(SignatureScheme::ED448, &key, &msg, &flipped, true).is_err(),
        "R's sign"
    );
    // Ed448 under any other scheme, and another key under ed448: no.
    assert!(verify(SignatureScheme::ED25519, &key, &msg, &sig, true).is_err());
}
