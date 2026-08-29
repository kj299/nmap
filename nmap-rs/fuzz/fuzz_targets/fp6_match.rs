// cargo-fuzz target for `nmap_core::fp6_match::is_response`.
//
// The received packet is attacker-controlled, so the property is totality: for any sent
// probe and any received bytes, is_response returns a bool without panicking or reading
// out of bounds. The fuzzer splits its input into two packets (a length-prefixed "sent"
// and the rest as "rcvd") so it explores both arguments, and checks the match relation is
// symmetric in the trivial identity sense and stable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::fp6_match::is_response;

fuzz_target!(|data: &[u8]| {
    // First two bytes: how many of the remaining bytes form the "sent" packet.
    let split = usize::from(u16::from_le_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]));
    let body = data.get(2..).unwrap_or(&[]);
    let cut = split.min(body.len());
    let sent = &body[..cut];
    let rcvd = &body[cut..];

    let a = is_response(sent, rcvd);
    // Determinism.
    assert_eq!(a, is_response(sent, rcvd), "not deterministic");
    // A packet never answers itself unless it happens to satisfy the mirror, but
    // is_response must at least not panic on the self-pairing.
    let _ = is_response(sent, sent);
    let _ = is_response(rcvd, rcvd);
});
