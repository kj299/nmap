// cargo-fuzz target for `nmap_core::ports::ServiceTable::parse`.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: the `nmap-services` file parser must NEVER panic,
// abort, or exhibit UB on arbitrary bytes — the memory-safety guarantee the C
// original (`services.cc`) couldn't make. A crash here is a release blocker
// (PLAYBOOK Phase 4, gate 3). This is a Phase-0 threat-model boundary: the
// services file is a data file that may be attacker-supplied (custom
// `--servicedb`, a poisoned system copy) and is parsed before any privilege drop.
//
// Note a deliberate divergence from C: our parser *skips* malformed lines rather
// than calling `fatal()` (DIVERGENCES.md `services-parse-degrade`), so the fuzzer
// also confirms that degraded parsing stays panic-free on hostile input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::model::Protocol;
use nmap_core::ports::ServiceTable;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let table = ServiceTable::parse(text);

    // Drive the query paths too: name lookup and the top-ports ranking, which
    // sorts by frequency and does bounded arithmetic. `n` is capped so a huge
    // parsed table can't turn this into a timeout.
    let _ = table.len();
    for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Sctp] {
        let _ = table.service_name(80, proto);
        let _ = table.top_ports(proto, 16);
    }
});
