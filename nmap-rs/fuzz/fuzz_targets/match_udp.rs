// cargo-fuzz target for `nmap_core::udpscan::match_udp_response`. Matching a captured
// UDP-scan reply runs over an attacker-controlled frame — including the ICMP path,
// which parses a *nested* IPv4/UDP packet quoted inside the ICMP error. Both the outer
// and the embedded parse must be TOTAL: never panic, never index out of bounds. Any
// match must name an in-range attempt.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::udpscan::{match_udp_response, UdpMatchCtx};

fuzz_target!(|data: &[u8]| {
    let ctx = UdpMatchCtx {
        base_port: 40000,
        max_tryno: 11,
        target: [10, 0, 0, 2],
    };
    for eth in [true, false] {
        if let Some(reply) = match_udp_response(data, eth, &ctx) {
            assert!(reply.tryno <= ctx.max_tryno, "tryno out of range");
        }
    }
});
