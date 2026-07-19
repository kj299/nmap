// cargo-fuzz target for `nmap_core::headers::icmpv4`. Parsing an attacker-controlled
// ICMP header (incl. any/unknown type) must be total — never panic/abort/UB. This is
// the M4 threat-model property that closes the netutil_fatal DoS class for this
// parser.
//
// Note: serialize() emits only the 8-byte standard header; for types whose header is
// longer (timestamp=20, mask=12) the extra bytes are payload the caller owns, so a
// serialize->parse roundtrip only holds for 8-byte-header types. We assert the
// roundtrip just for those; the universal invariant is "parse never panics".
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::icmpv4::{header_len_for_type, Icmpv4Header};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Icmpv4Header::parse(data) {
        assert!(h.header_len() >= 8);
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 8);
        // Only the standard-length types round-trip through the 8-byte serialization.
        if header_len_for_type(h.icmp_type) == 8 {
            let reparsed = Icmpv4Header::parse(&bytes).expect("std-header type re-parses");
            assert_eq!(reparsed.icmp_type, h.icmp_type);
            assert_eq!(reparsed.code, h.code);
        }
    }
});
