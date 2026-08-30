// cargo-fuzz target for `nmap_core::ndp::parse_neighbor_advertisement` /
// `resolve_from_frame`.
//
// This is the exact surface where nmap reads out of bounds. `accept_ns()` admits a
// capture holding only the IPv6 + ICMPv6 headers, and `read_ns_reply_pcap()` then reads
// the 16-byte target address past it — so a truncated Neighbor Advertisement, which any
// host on the local link can send, walks off the end of the captured data. The property
// asserted here is totality: for ANY frame bytes and ANY datalink offset, parsing
// returns without panicking, and a resolved MAC is only ever produced together with a
// matching target.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::ndp::{parse_neighbor_advertisement, resolve_from_frame};

fuzz_target!(|data: &[u8]| {
    // First byte selects the datalink offset, so the fuzzer explores Ethernet (14),
    // raw IP (0) and every misaligned value in between.
    let offset = usize::from(data.first().copied().unwrap_or(0));
    let frame = data.get(1..).unwrap_or(&[]);

    let parsed = parse_neighbor_advertisement(frame, offset);
    // Determinism.
    assert_eq!(
        parsed,
        parse_neighbor_advertisement(frame, offset),
        "not deterministic"
    );

    if let Some(na) = parsed {
        // Resolving against the address the advertisement names must agree with the
        // parse: a MAC comes back exactly when the advertisement carried one.
        assert_eq!(
            resolve_from_frame(frame, offset, na.target),
            na.mac,
            "resolve disagrees with parse for the advertised target"
        );
        // Any other address must resolve nothing, however well-formed the frame is.
        let mut other = na.target;
        other[0] ^= 0xff;
        if other != na.target {
            assert_eq!(
                resolve_from_frame(frame, offset, other),
                None,
                "resolved a MAC for an address the advertisement is not about"
            );
        }
    } else {
        // A frame that does not parse can never resolve anything.
        assert_eq!(resolve_from_frame(frame, offset, [0u8; 16]), None);
    }

    // Offsets far past the frame must be handled, not overflow.
    let _ = parse_neighbor_advertisement(frame, usize::MAX);
    let _ = parse_neighbor_advertisement(frame, frame.len().wrapping_add(offset));
});
