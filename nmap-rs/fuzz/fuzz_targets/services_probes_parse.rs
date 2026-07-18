// cargo-fuzz target for `nmap_core::probedb::ProbeDb::parse`.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: the `nmap-service-probes` parser must NEVER panic,
// abort, or exhibit UB on arbitrary bytes — the memory-safety guarantee the C
// original (`service_scan.cc`, `next_template`, `cstring_unescape`) can't make
// (it `fatal()`s and does raw pointer/`strchr` walks). A crash here is a release
// blocker (PLAYBOOK Phase 4, gate 3).
//
// This is a Phase-0 threat-model boundary: `--versiondb <file>` makes the probe
// database attacker-supplyable, and it is parsed before any scanning. The
// deliberate divergence (DIVERGENCES.md `probedb-parse-degrade`) is that a
// malformed line is *skipped with a warning* instead of aborting — so the fuzzer
// also confirms the degrade path itself stays panic-free on hostile input,
// including the byte-escape decoder and the delimiter/flag walkers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::model::Protocol;
use nmap_core::probedb::ProbeDb;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let db = ProbeDb::parse(text);

    // Drive the query paths too — exclusion lookups do bounded work over the
    // parsed port lists.
    for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Sctp] {
        let _ = db.is_excluded(0, proto);
        let _ = db.is_excluded(65535, proto);
    }
    // Touch the parsed structure so the optimizer can't elide the parse.
    let _ = db.probes.len();
    let _ = db.null_probe.is_some();
    let _ = db.warnings.len();
});
