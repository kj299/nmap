// cargo-fuzz target for `nmap_core::pcre_translate::translate`.
// Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh, then specialized.
//
// The contract this enforces: the PCRE→Rust syntax translator must be **total** —
// any &str in, a String out, never a panic, abort, or UB, and no unchecked index
// or unbounded arithmetic. Its input is regex bodies from `nmap-service-probes`,
// which `--versiondb <file>` makes attacker-supplyable, so a crash here is a
// release blocker (PLAYBOOK Phase 4, gate 3).
//
// Beyond "does not panic", the target checks two invariants the module promises:
//   * idempotence — translating already-translated output is a no-op (the rewrites
//     must not re-fire on their own escapes), and
//   * the output is always valid UTF-8 (guaranteed by construction; asserted).
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::pcre_translate::translate;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let once = translate(text);
    // Idempotence: a second pass must not change anything.
    let twice = translate(&once);
    assert_eq!(once, twice, "translate is not idempotent on {text:?}");
});
