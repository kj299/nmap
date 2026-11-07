// cargo-fuzz target for `nmap_core::recv_validate`. Validating an attacker-controlled
// captured packet must be TOTAL: never panic, never loop (the TCP-option walk is the
// classic length-underflow hazard; the IPv6 extension-header walk, whose lengths the
// sender chooses, is the other), and any accept must describe the buffer it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::recv_validate::{ipv6_payload, validate_packet, validate_tcp_header, Reject};

fuzz_target!(|data: &[u8]| {
    // The whole-packet validator.
    if let Ok(v) = validate_packet(data) {
        assert!(v.data_offset <= data.len(), "data offset past buffer");
        assert!(v.captured_len <= data.len(), "length past buffer");
        match v.version {
            4 => assert!(v.data_offset >= 20, "inside the IPv4 header"),
            6 => {
                // The walk ends on a byte of the buffer, past the fixed header, on
                // a protocol the C takes as upper-layer; the length ends no
                // earlier than the header.
                assert!(v.data_offset >= 40 && v.data_offset < data.len());
                assert!(v.captured_len >= 40);
                assert!(matches!(v.proto, 1 | 6 | 17 | 58 | 59 | 132), "{}", v.proto);
                assert_eq!(ipv6_payload(data), Ok((v.proto, v.data_offset)));
            }
            other => panic!("accepted IP version {other}"),
        }
    }
    // The IPv6 walk directly: on any bytes, an answer within the buffer.
    match ipv6_payload(data) {
        Ok((_, off)) => assert!(off >= 40 && off < data.len()),
        Err(
            Reject::TooShort
            | Reject::Fragment
            | Reject::Ipv6ChainTruncated
            | Reject::Ipv6UnknownPayload(_),
        ) => {}
        Err(other) => panic!("the walk cannot reject as {other:?}"),
    }
    // The TCP-option walk directly, over arbitrary bytes (the untrusted-input core).
    let _ = validate_tcp_header(data);
});
