// cargo-fuzz target for `nmap_core::synscan::match_syn_response`. Matching a captured
// reply against our outstanding SYN probes runs over an **attacker-controlled frame**
// (anything on the wire the scan is listening to), so it must be TOTAL: never panic,
// never loop, never index out of bounds — through the link-layer walk, the IPv4 or
// IPv6 validation (extension headers whose lengths the sender chooses), the ICMP or
// ICMPv6 quote, and the sequence-reflection decode. Any match it returns must name an
// in-range attempt, and only a SYN/ACK can say open: no ICMP error, ICMPv6 Parameter
// Problem included (classify6-param-problem-field-filtered), may.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::classify::PortState;
use nmap_core::model::Reason;
use nmap_core::synscan::{match_syn_response, MatchCtx, SynReply};

fn check<A>(reply: Option<SynReply<A>>, max_tryno: u32) {
    if let Some(r) = reply {
        assert!(r.tryno <= max_tryno, "tryno out of range");
        if r.state == PortState::Open {
            assert_eq!(r.reason, Reason::ConnAccept, "open from {:?}", r.reason);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let v4 = MatchCtx {
        our_ip: [10, 0, 0, 1],
        base_port: 40000,
        seqmask: 0xABCD_1234,
        max_tryno: 11,
    };
    let v6 = MatchCtx {
        our_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        base_port: 40000,
        seqmask: 0xABCD_1234,
        max_tryno: 11,
    };
    // Both framings: link-layer-included (pcap on lo/Ethernet) and bare IP.
    for eth in [true, false] {
        check(match_syn_response(data, eth, &v4), v4.max_tryno);
        check(match_syn_response(data, eth, &v6), v6.max_tryno);
    }
});
