// cargo-fuzz target for `nmap_core::udpscan::match_udp_response`. Matching a captured
// UDP-scan reply runs over an attacker-controlled frame — including the ICMP path,
// which parses a *nested* packet quoted inside the ICMP error: IPv4/UDP in ICMPv4, or
// IPv6/UDP behind its own extension headers in ICMPv6. Both the outer and the
// embedded parse must be TOTAL: never panic, never index out of bounds. Any match must
// name an in-range attempt, and only a datagram back can say open: no ICMP error,
// ICMPv6 Parameter Problem included (classify6-param-problem-field-filtered), may.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::classify::PortState;
use nmap_core::model::Reason;
use nmap_core::udpscan::{match_udp_response, UdpMatchCtx, UdpReply};

fn check<A>(reply: Option<UdpReply<A>>, max_tryno: u32) {
    if let Some(r) = reply {
        assert!(r.tryno <= max_tryno, "tryno out of range");
        if r.state == PortState::Open {
            assert_eq!(r.reason, Reason::UdpResponse, "open from {:?}", r.reason);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let v4 = UdpMatchCtx {
        our_ip: [10, 0, 0, 1],
        base_port: 40000,
        max_tryno: 11,
    };
    let v6 = UdpMatchCtx {
        our_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        base_port: 40000,
        max_tryno: 11,
    };
    for eth in [true, false] {
        check(match_udp_response(data, eth, &v4), v4.max_tryno);
        check(match_udp_response(data, eth, &v6), v6.max_tryno);
    }
});
