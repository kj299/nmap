// cargo-fuzz target for `nmap_core::headers::arp`. Parsing an attacker-controlled
// ARP frame must be total on any bytes; the address accessors must never panic;
// serialize->parse roundtrips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::arp::ArpHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = ArpHeader::parse(data) {
        assert_eq!(h.header_len(), 28);
        // The Ethernet/IPv4 accessors index into the fixed 20-byte block; total.
        let _ = (h.sender_mac(), h.sender_ip(), h.target_mac(), h.target_ip());
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 28);
        let reparsed = ArpHeader::parse(&bytes).expect("serialize -> parse roundtrips");
        assert_eq!(reparsed, h);
    }
});
