// cargo-fuzz target for `nmap_core::flagscan::match_flag_response`. Matching a captured
// flag-scan reply runs over an attacker-controlled frame, IPv4 or IPv6; it must be
// TOTAL for every scan type (never panic, never index out of bounds). Any match must
// name an in-range attempt, and only a RST (the Window scan's, with a window) can say
// open: no ICMP error may.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::classify::{PortState, ScanType};
use nmap_core::flagscan::{match_flag_response, FlagMatchCtx, FlagReply};
use nmap_core::model::Reason;

fn check<A>(reply: Option<FlagReply<A>>, max_tryno: u32) {
    if let Some(r) = reply {
        assert!(r.tryno <= max_tryno, "tryno out of range");
        if r.state == PortState::Open {
            assert_eq!(r.reason, Reason::Reset, "open from {:?}", r.reason);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    for scan in [
        ScanType::Ack,
        ScanType::Window,
        ScanType::Maimon,
        ScanType::Fin,
        ScanType::Null,
        ScanType::Xmas,
    ] {
        let v4 = FlagMatchCtx {
            our_ip: [10, 0, 0, 1],
            seqmask: 0xABCD_1234,
            scan,
            base_port: 40000,
            max_tryno: 11,
        };
        let v6 = FlagMatchCtx {
            our_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            seqmask: 0xABCD_1234,
            scan,
            base_port: 40000,
            max_tryno: 11,
        };
        for eth in [true, false] {
            check(match_flag_response(data, eth, &v4), v4.max_tryno);
            check(match_flag_response(data, eth, &v6), v6.max_tryno);
        }
    }
});
