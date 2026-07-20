// cargo-fuzz target for `nmap_core::recv_validate`. Validating an attacker-controlled
// captured packet must be TOTAL: never panic, never loop (the TCP-option walk is the
// classic length-underflow hazard), and any accept must report a data offset within
// the buffer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::recv_validate::{validate_packet, validate_tcp_header};

fuzz_target!(|data: &[u8]| {
    // The whole-packet validator.
    if let Ok(v) = validate_packet(data) {
        assert!(v.data_offset <= data.len(), "data offset past buffer");
        assert_eq!(v.version, 4);
    }
    // The TCP-option walk directly, over arbitrary bytes (the untrusted-input core).
    let _ = validate_tcp_header(data);
});
