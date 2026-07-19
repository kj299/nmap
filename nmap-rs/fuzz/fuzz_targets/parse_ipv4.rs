// cargo-fuzz target for `nmap_core::headers::ipv4` — the first M4 packet-parse
// fuzz target.
//
// The contract: parsing an attacker-controlled captured packet must be **total** —
// never a panic, an abort, UB, or an OOB read on any byte sequence. Every captured
// packet is chosen by whoever is on the wire, so this is the M4 hostile-input
// boundary (PLAYBOOK Phase 4, gate 3). The C's IPv4Header overlays a packed struct
// on a fixed buffer and reads fields the caller "validated" separately; this port
// replaces that with a checked cursor, and the fuzzer proves the reject path can
// never be driven into UB.
//
// Beyond "no panic", we assert the round-trip invariant: any header the parser
// accepts must re-serialize to at least its header_len bytes and re-parse to an
// equal value — so a subtle field-decode bug surfaces as a mismatch, not just a
// crash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::ipv4::Ipv4Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Ipv4Header::parse(data) {
        // Accepted headers must be self-consistent.
        assert!(h.header_len() >= 20);
        assert_eq!(h.version, 4);
        assert!(h.ihl >= 5);
        let bytes = h.serialize();
        assert!(bytes.len() >= h.header_len());
        // Re-parsing our own serialization yields an equal header.
        let reparsed = Ipv4Header::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
    }
});
