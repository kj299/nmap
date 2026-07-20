// cargo-fuzz target for `nmap_core::headers::ipv6`. Parsing an attacker-controlled
// IPv6 base header must be total on any bytes; the bit-field accessors
// (version/traffic_class/flow_label) must never panic; serialize->parse roundtrips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::ipv6::Ipv6Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Ipv6Header::parse(data) {
        assert_eq!(h.header_len(), 40);
        // Bit-field decoders must be total and self-consistent.
        assert!(h.version() <= 0x0F);
        assert!(h.flow_label() <= 0xF_FFFF);
        let _ = h.traffic_class();
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 40);
        let reparsed = Ipv6Header::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
    }
});
