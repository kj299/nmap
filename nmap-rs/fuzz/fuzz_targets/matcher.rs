// cargo-fuzz target for `nmap_core::matcher` — the #1 Milestone-3 fuzz target.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: matching an attacker-chosen banner against the
// service-detection engine must be **total and bounded** — never a panic, an
// abort, UB, an OOM, or unbounded backtracking (ReDoS against the scanner). Every
// byte the engine matches is chosen by whoever runs on the scanned port, so this
// is the hostile-input boundary the whole M3 threat model is about. A crash or
// hang here is a release blocker (PLAYBOOK Phase 4, gate 3).
//
// Strategy: compile a small probe DB *from part of the fuzz input* (so patterns
// vary) and match the *rest* of the input as a banner. This fuzzes the compile
// path (arbitrary regex bodies) and the match path (arbitrary banners) together.
// The compiled real DB is expensive to build per-run, so patterns come from the
// input; a separate corpus test covers the real 2.5 MB DB.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::matcher::CompiledRule;
use nmap_core::probedb::MatchRule;

fuzz_target!(|data: &[u8]| {
    // Split: first line (up to \n) is the regex body, the rest is the banner.
    let split = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let (pat_bytes, rest) = data.split_at(split);
    let banner = rest.strip_prefix(b"\n").unwrap_or(rest);

    // The regex body must be valid UTF-8 (it comes from a text DB file).
    let Ok(pattern) = std::str::from_utf8(pat_bytes) else {
        return;
    };

    let rule = MatchRule {
        soft: false,
        service: "fuzz".into(),
        pattern: pattern.to_string(),
        ..MatchRule::default()
    };

    // Compilation may legitimately fail (bad/empty-matching pattern) — that must
    // be a clean Err, never a panic.
    if let Ok(compiled) = CompiledRule::compile(&rule) {
        // Matching an arbitrary banner must be total and bounded.
        let _ = compiled.captures(banner);
    }
});
