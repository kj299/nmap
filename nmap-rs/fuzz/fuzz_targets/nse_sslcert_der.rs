// cargo-fuzz target for `nmap_core::nse::openssl::{asn1, x509, pubkey, ext}`,
// the certificate reader behind `parse_ssl_certificate` (M6.5 step e). Its
// input is a peer's: the DER a TLS server sends in its Certificate message,
// which ssl-cert, ssl-enum-ciphers and the rest parse (`docs/M6.5-ANALYSIS.md`
// §5).
//
// Checked, on arbitrary bytes:
//   * nothing panics, at any depth of indefinite-length or constructed-string
//     nesting (the seeds carry 6 and 10,000 levels) and for OIDs of any length
//     (the seeds carry 587 and 5,000 bytes);
//   * a certificate that decodes re-encodes (`i2d_X509`) to bytes that decode
//     to the same certificate and re-encode to themselves, except where
//     OpenSSL's own re-encoding does not decode: a signature algorithm
//     parameter of universal tag 0, which `d2i_X509` reads from a constructed
//     header (`20 00`) and `i2d_X509` writes primitive, as an EOC (`00 00`;
//     7.94's PEM shows it, and the `k-sigalg` rows pin it);
//   * its PEM is 64-column base64 of those bytes between the two markers;
//   * every extension prints (or fails) within a linear bound on its value's
//     length, and any error it raises is one `ERR_error_string` names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::asn1::Prim;
use nmap_core::nse::openssl::{err, ext, x509};

fn unbase64(lines: &[u8]) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => u32::from(c - b'A'),
        b'a'..=b'z' => u32::from(c - b'a') + 26,
        b'0'..=b'9' => u32::from(c - b'0') + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!("not base64: {c:#x}"),
    };
    let mut out = Vec::new();
    let s: Vec<u8> = lines.iter().copied().filter(|&c| c != b'\n').collect();
    assert_eq!(s.len() % 4, 0, "base64 in quads");
    for q in s.chunks(4) {
        let pad = q.iter().filter(|&&c| c == b'=').count();
        let n = q
            .iter()
            .map(|&c| if c == b'=' { 0 } else { val(c) })
            .fold(0u32, |n, v| (n << 6) | v);
        let b = n.to_be_bytes();
        out.extend_from_slice(&b[1..4 - pad]);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Some(cert) = x509::d2i_x509(data) else {
        return;
    };
    let enc = x509::i2d_x509(&cert);
    match x509::d2i_x509(&enc) {
        Some(again) => {
            assert_eq!(again, cert, "the re-encoding is the same certificate");
            assert_eq!(x509::i2d_x509(&again), enc, "re-encoding is idempotent");
        }
        None => assert!(
            matches!(cert.sig_alg.param, Some(Prim::Str { utype: 0, .. })),
            "only a tag-0 parameter re-encodes to what does not decode"
        ),
    }

    let pem = x509::pem(&enc);
    let body = pem
        .strip_prefix(b"-----BEGIN CERTIFICATE-----\n".as_slice())
        .and_then(|r| r.strip_suffix(b"-----END CERTIFICATE-----\n".as_slice()))
        .expect("PEM markers");
    for line in body.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        assert!(line.len() <= 64, "PEM lines are 64 columns");
    }
    assert_eq!(unbase64(body), enc, "PEM is the re-encoding");

    for e in cert.extensions.iter().flatten() {
        let p = ext::print(&e.oid, &e.value);
        if let Some(v) = &p.value {
            assert!(v.len() <= 64 * e.value.len() + 4096, "linear output");
        }
        if let Some(code) = p.error {
            let s = err::error_string(code);
            assert!(!s.contains("lib(") && !s.contains("reason("), "{s}");
        }
    }
});
