// cargo-fuzz target for `nmap_core::osprobe::analyze::tcp_option_string`.
//
// This one is squarely untrusted input: the bytes are a TCP segment received from the
// target host during OS detection, and the host chooses every one of them. The C walks
// the option block with pointer arithmetic and writes the summary into a fixed 512-byte
// stack buffer, checking for room before each write — and when that check fails it stops
// the walk but reports success, silently truncating the result.
//
// Enforced here: summarising is TOTAL (no panic on any segment), the output is bounded,
// it contains only the alphabet the fingerprint grammar allows, and it is deterministic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osprobe::analyze::tcp_option_string;

/// Every character the C's encoder can emit: the option letters plus uppercase hex.
const ALPHABET: &[u8] = b"LNMWST0123456789ABCDEF";

fuzz_target!(|data: &[u8]| {
    let Ok(summary) = tcp_option_string(data) else {
        return;
    };

    // Options are capped at 40 bytes by the 4-bit data offset, and the densest encoding
    // is MSS at 4 bytes in / 5 chars out, so the summary can never run away.
    assert!(
        summary.len() <= 80,
        "summary too long ({} chars) for a 40-byte option block",
        summary.len()
    );

    // The value is fed straight to `osdb::expr` as an attribute to match, so anything
    // outside this alphabet would be a byte the fingerprint grammar cannot express.
    for b in summary.bytes() {
        assert!(
            ALPHABET.contains(&b),
            "summary contains {b:?}, which is outside the fingerprint alphabet"
        );
    }

    // Deterministic: the same segment must always summarise the same way.
    assert_eq!(
        tcp_option_string(data).ok().as_deref(),
        Some(summary.as_str())
    );

    // Truncating the segment must never panic either — a short capture is normal.
    for cut in [0usize, 1, 12, 20, 21] {
        if cut <= data.len() {
            let _ = tcp_option_string(&data[..cut]);
        }
    }
});
