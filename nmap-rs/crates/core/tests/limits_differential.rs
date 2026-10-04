//! M6.4b differential: the limits PUC-Lua puts on a running state, against
//! nmap's own Lua.
//!
//! `tests/differential/m6/m64_limits_*.txt` is 335 chunks run by `liblua/`
//! from this repository:
//!
//! - every way a call takes a level of PUC-Lua's C stack (a call from a C
//!   function, a metamethod, a `for` iterator, a coroutine resume), recursed
//!   until "C stack overflow" from inside every kind of caller, message
//!   handlers included, comparing how many levels each reached;
//! - runaway Lua recursion ending in a catchable "stack overflow";
//! - `__index` / `__newindex` chains either side of `MAXTAGLOOP`; and
//! - the results `table.unpack` and `string.byte` may push.
//!
//! Every value and every error message is compared, positions included, with
//! no exemption list. The eval harness starts each chunk under the C calls the
//! oracle's chunk runs under ([`m6_eval::ORACLE_CCALLS`]).
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

mod m6_eval;

use m6_eval::{eval, quietly, rows, unhex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

#[test]
fn limits_match_nmaps_own_lua() {
    let golden: HashMap<_, _> = rows(&corpus("m64_limits_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m64_limits_cases.txt"));
    assert!(cases.len() >= 335, "corpus shrank to {}", cases.len());

    let mut mismatches = Vec::new();
    quietly(|| {
        for (name, chunk_hex, note) in &cases {
            let (status, value) = eval(&unhex(chunk_hex));
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
