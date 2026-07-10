// cargo-fuzz target for `nmap_core::ports::parse_port_spec`.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: the `-p` port-spec grammar parser (ranges, lists,
// `T:`/`U:`/`S:` protocol prefixes, open ranges, `-p-`, service-name lookups)
// must NEVER panic, abort, or exhibit UB on arbitrary bytes — the memory-safety
// guarantee the C original (`scan_lists.cc` getpts_aux) couldn't make. A crash
// here is a release blocker (PLAYBOOK Phase 4, gate 3). This is a Phase-0
// threat-model boundary: `-p` values come straight from untrusted CLI argv.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nmap_core::ports::{parse_port_spec, ServiceTable};

/// A small service table so the service-name lookup branch (`-p http`) is
/// exercised, not just the numeric grammar. Built once (parsing it every
/// iteration would dominate runtime and starve the grammar of coverage).
fn table() -> &'static ServiceTable {
    static TABLE: OnceLock<ServiceTable> = OnceLock::new();
    TABLE.get_or_init(|| ServiceTable::parse("http 80/tcp\nhttps 443/tcp\ndomain 53/udp\n"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Both with and without a service table: the no-table path must reject
    // service names cleanly rather than panic.
    let _ = parse_port_spec(text, Some(table()));
    let _ = parse_port_spec(text, None);
});
