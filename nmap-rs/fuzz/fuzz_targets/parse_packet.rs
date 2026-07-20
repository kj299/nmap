// cargo-fuzz target for `nmap_core::packet_parser`. The multi-header walk over an
// attacker-controlled frame must be TOTAL: never panic, always terminate, always
// account for every byte, and never exceed the header bound. First byte of the input
// selects the start layer so the fuzzer explores both the eth-included and
// network-start paths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::packet_parser::{parse_packet, Header, MAX_HEADERS_IN_PACKET};

fuzz_target!(|data: &[u8]| {
    let eth_included = data.first().is_some_and(|b| b & 1 == 0);
    let body = data.get(1..).unwrap_or(&[]);

    let hs = parse_packet(body, eth_included);

    // The walk is bounded.
    assert!(hs.len() <= MAX_HEADERS_IN_PACKET);

    // Every recorded header's length is within the packet, and the offsets are
    // monotone and never run past the end.
    let mut off = 0usize;
    for h in &hs {
        let len = h.len();
        off = off.checked_add(len).expect("offset overflow");
        assert!(off <= body.len(), "header {} runs past end", h.kind_str());
    }

    // When the walk did not hit the header bound, it accounts for every byte.
    if hs.len() < MAX_HEADERS_IN_PACKET {
        let total: usize = hs.iter().map(Header::len).sum();
        assert_eq!(total, body.len(), "byte accounting incomplete");
    }
});
