// cargo-fuzz target for `nmap_core::headers::tcp`. Parsing an attacker-controlled
// TCP header (from a captured packet) must be total — never panic/UB/OOB — and the
// safe options walker must never infinite-loop or read past the options area on any
// bytes. Asserts the serialize->parse roundtrip on accepted headers, and drains the
// options iterator (which must always terminate).
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::tcp::TcpHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = TcpHeader::parse(data) {
        assert!(h.header_len() >= 20);
        assert!(h.data_offset >= 5);
        // The options walk must terminate on any bytes (no infinite loop / OOB).
        let _n = h.options_iter().count();
        let bytes = h.serialize();
        assert!(bytes.len() >= h.header_len());
        let reparsed = TcpHeader::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
    }
});
