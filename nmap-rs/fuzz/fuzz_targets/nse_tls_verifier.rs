// cargo-fuzz target for `nmap_sys::tls`'s verifier and signature checks
// (M6.5 step f1): what nmap's OpenSSL client checks of a server's
// certificates and handshake signature whatever the verify mode, on
// arbitrary bytes (`docs/M6.5-ANALYSIS.md` §1.3). The input is a peer's.
//
// Layout: one byte of flags (bit 0: TLS 1.3), two of signature scheme, then
// length-prefixed fields (two-byte big-endian lengths): the certificates,
// leaf first, until an empty one; the signed message; the signature.
//
// Checked, besides no panic:
//   * a chain is accepted only if each entry is exactly one certificate
//     that `d2i_X509` decodes (`parse_ssl_certificate` ignores trailing
//     bytes; the handshake must not);
//   * a signature verifies only if the leaf's certificate decodes, and the
//     same check gives the same answer twice (no state, no randomness).
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::x509::d2i_x509_len;
use nmap_sys::tls::fuzzing::{accepts_chain, verifies};

fn field<'a>(d: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = d.split_first_chunk::<2>()?;
    let n = usize::from(u16::from_be_bytes(*len));
    let f = rest.get(..n)?;
    *d = &rest[n..];
    Some(f)
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let Some((scheme, mut d)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let scheme = u16::from_be_bytes(*scheme);
    let mut chain = Vec::new();
    while let Some(c) = field(&mut d) {
        if c.is_empty() {
            break;
        }
        chain.push(c);
    }
    let msg = field(&mut d).unwrap_or_default();
    let sig = field(&mut d).unwrap_or_default();

    if accepts_chain(&chain) {
        for c in &chain {
            let (_, used) = d2i_x509_len(c).expect("an accepted entry decodes");
            assert_eq!(used, c.len(), "an accepted entry is exactly a certificate");
        }
    }
    if let Some(leaf) = chain.first() {
        let tls13 = flags & 1 == 1;
        let v = verifies(leaf, scheme, msg, sig, tls13);
        if v {
            assert!(d2i_x509_len(leaf).is_some(), "a key from an undecodable certificate");
        }
        assert_eq!(v, verifies(leaf, scheme, msg, sig, tls13), "deterministic");
    }
});
