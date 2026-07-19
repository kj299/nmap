// cargo-fuzz target for `nmap_core::headers::udp`. Parsing must be total on any
// bytes, and computing the checksum over an arbitrary payload must never panic or
// overflow — the property the C's fixed-aux[65527] setSum violates
// (udp-checksum-no-fixed-buffer). Asserts serialize->parse roundtrip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::udp::UdpHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = UdpHeader::parse(data) {
        assert_eq!(h.header_len(), 8);
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 8);
        let reparsed = UdpHeader::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
        // Checksum over the trailing bytes as payload must be total (no fixed buffer).
        let payload = &data[h.header_len().min(data.len())..];
        let _ = h.computed_checksum([1, 2, 3, 4], [5, 6, 7, 8], payload);
    }
});
