// cargo-fuzz target for `nmap_core::headers::ethernet`. Parsing an attacker-
// controlled L2 frame must be total on any bytes; serialize->parse roundtrips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::ethernet::EthernetHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = EthernetHeader::parse(data) {
        assert_eq!(h.header_len(), 14);
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 14);
        let reparsed = EthernetHeader::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
    }
});
