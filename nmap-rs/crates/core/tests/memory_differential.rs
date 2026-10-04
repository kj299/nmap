//! M6.4b differential: what a script sees when memory runs out, against
//! nmap's own Lua.
//!
//! `tests/differential/m6/m64_memory_*.txt` is 41 chunks, each run by
//! `liblua/` in a process of its own under `ulimit -v`, and here in a fresh VM
//! under a memory budget of [`BUDGET`] bytes. The limits differ and so do the
//! heaps, so the cases are built not to depend on where memory runs out (see
//! `oracle/gen_m64_memory.py`): requests no limit allows, allocations that
//! grow without end, and work well within any limit. What is compared is what
//! a script observes: that running out is the catchable string "not enough
//! memory", where it surfaces, that message handlers do not see it, and that
//! the script runs on — every value and message, with no exemption list.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

mod m6_eval;

use m6_eval::{eval_limited, quietly, rows, unhex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The VM's memory budget for every case: 32 MiB.
const BUDGET: usize = 32 << 20;

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

#[test]
fn running_out_of_memory_matches_nmaps_own_lua() {
    let golden: HashMap<_, _> = rows(&corpus("m64_memory_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m64_memory_cases.txt"));
    assert!(cases.len() >= 41, "corpus shrank to {}", cases.len());

    let mut mismatches = Vec::new();
    quietly(|| {
        for (name, chunk_hex, note) in &cases {
            let (status, value) = eval_limited(&unhex(chunk_hex), Some(BUDGET));
            let want = golden
                .get(name)
                .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
            if (status.as_str(), value.as_str()) != (want.0.as_str(), want.1.as_str()) {
                mismatches.push(format!(
                    "  {name} ({note}):\n      lua  = {} {}\n      port = {status} {value}",
                    want.0, want.1
                ));
            }
        }
    });
    assert!(
        mismatches.is_empty(),
        "{} of {} diverge:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches[..mismatches.len().min(30)].join("\n")
    );
}
