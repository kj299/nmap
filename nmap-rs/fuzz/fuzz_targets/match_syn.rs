// cargo-fuzz target for `nmap_core::synscan::match_syn_response`. Matching a captured
// reply against our outstanding SYN probes runs over an **attacker-controlled frame**
// (anything on the wire the scan is listening to), so it must be TOTAL: never panic,
// never loop, never index out of bounds — through the link-layer walk, the IPv4/TCP
// validation, and the sequence-reflection decode. Any match it returns must name a
// port and an in-range attempt.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::synscan::{match_syn_response, MatchCtx};

fuzz_target!(|data: &[u8]| {
    let ctx = MatchCtx {
        base_port: 40000,
        seqmask: 0xABCD_1234,
        max_tryno: 11,
    };
    // Both framings: link-layer-included (pcap on lo/Ethernet) and bare IP.
    for eth in [true, false] {
        if let Some(reply) = match_syn_response(data, eth, &ctx) {
            assert!(reply.tryno <= ctx.max_tryno, "tryno out of range");
        }
    }
});
