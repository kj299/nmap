// cargo-fuzz target for `nmap_core::targets::parse_target`.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: the target/host/CIDR spec parser must NEVER panic,
// abort, or exhibit UB on arbitrary bytes — this is the memory-safety guarantee
// the C original (`TargetGroup.cc` / `targets.cc`) couldn't make. A crash here is
// a release blocker (PLAYBOOK Phase 4, gate 3). `parse_target` is a Phase-0
// threat-model boundary: it consumes raw CLI argv, which may be attacker-shaped
// in a wrapper/automation context.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::targets::{parse_target, TargetSpec};

fuzz_target!(|data: &[u8]| {
    // parse_target takes &str; feed it any UTF-8 slice of the input. Non-UTF-8
    // bytes can't reach the parser via argv on the platforms we target, so
    // restricting to valid UTF-8 matches the real input domain without hiding
    // panics.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Exercise both address families — the netmask/family handling differs.
    for want_ipv6 in [false, true] {
        // Must return Result, never panic. Overflow-checks are on in this
        // crate, so an arithmetic overflow would surface here as a crash.
        if let Ok(TargetSpec::Ipv4(ranges)) = parse_target(text, want_ipv6) {
            // Enumerating an IPv4 range walks the odometer iterator and the
            // netmask/count arithmetic — bound the drain so a `/0` (2^32 hosts)
            // can't turn a panic-hunt into a timeout, while still driving the
            // count() math and a prefix of the iterator on every accepted spec.
            let _ = ranges.count();
            for _addr in ranges.iter().take(64) {}
        }
    }
});
