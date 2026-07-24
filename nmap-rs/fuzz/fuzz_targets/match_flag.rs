// cargo-fuzz target for `nmap_core::flagscan::match_flag_response`. Matching a captured
// flag-scan reply runs over an attacker-controlled frame; it must be TOTAL for every
// scan type (never panic, never index out of bounds). Any match must name an in-range
// attempt.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::classify::ScanType;
use nmap_core::flagscan::{match_flag_response, FlagMatchCtx};

fuzz_target!(|data: &[u8]| {
    for scan in [
        ScanType::Ack,
        ScanType::Window,
        ScanType::Maimon,
        ScanType::Fin,
        ScanType::Null,
        ScanType::Xmas,
    ] {
        let ctx = FlagMatchCtx {
            scan,
            base_port: 40000,
            max_tryno: 11,
        };
        for eth in [true, false] {
            if let Some(reply) = match_flag_response(data, eth, &ctx) {
                assert!(reply.tryno <= ctx.max_tryno, "tryno out of range");
            }
        }
    }
});
