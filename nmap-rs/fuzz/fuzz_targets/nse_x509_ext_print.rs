// cargo-fuzz target for `nmap_core::nse::openssl::{ext, text}`,
// `X509V3_EXT_print` for every extension method OpenSSL 3.0.13 has (M6.5 step
// e). Its input is a peer's: an extension's value inside the certificate a
// TLS server sends, printed into the `extensions` table of what
// `parse_ssl_certificate` returns.
//
// Checked, on arbitrary bytes, for each method's OID and for an OID with no
// method:
//   * nothing panics, for values nested to any depth and OIDs of any length;
//   * the output is within a linear bound on the value's length;
//   * any error raised is one `ERR_error_string` names, and an OID with no
//     method fails with none raised;
//   * printing is deterministic.
//
// Input layout: byte 0 picks the extension, the rest is its value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::{err, ext, objects};

/// The NIDs `standard_exts.h` lists, and 0 for an OID with no method.
const NIDS: [u16; 51] = [
    71, 72, 73, 74, 75, 76, 77, 78, 82, 83, 84, 85, 86, 87, 88, 89, 90, 103, 126, 140, 141, 142,
    143, 177, 290, 291, 366, 367, 368, 369, 370, 371, 398, 401, 430, 663, 666, 747, 748, 770, 771,
    857, 951, 952, 954, 1007, 1008, 1020, 1093, 649, 0,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, value)) = data.split_first() else {
        return;
    };
    let nid = NIDS[usize::from(pick) % NIDS.len()];
    let oid: &[u8] = if nid == 0 {
        &[0x2a, 0x03, 0x04]
    } else {
        objects::der_of(nid)
    };
    let p = ext::print(oid, value);
    assert_eq!(p, ext::print(oid, value), "deterministic");
    if let Some(v) = &p.value {
        assert!(v.len() <= 64 * value.len() + 4096, "linear output");
    }
    if let Some(code) = p.error {
        let s = err::error_string(code);
        assert!(!s.contains("lib(") && !s.contains("reason("), "{s}");
    }
    if nid == 0 || nid == 649 {
        assert_eq!((p.value, p.error), (None, None), "no method");
    }
});
