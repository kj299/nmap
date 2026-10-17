//! Differential: the M6.5 `openssl` corpus, every row of step b (`BIGNUM`).
//!
//! `tests/differential/m6/m65_cases.txt` is run by nmap 7.94 into
//! `m65_golden.txt` (`oracle/gen_m65.py`, step a). This gate runs every row
//! tagged `b` — the 19 `bignum_*` functions, the 11 methods, their argument
//! checks and the random bignums — and the `bnmeta` row (the `BIGNUM`
//! metatable) through the port, with the test-only registration
//! (`openssl::register_for_tests`), by the same case runner the oracle used
//! (`oracle/m65_core.lua`, `runner`), and compares status and values byte
//! for byte with the golden.
//!
//! - **Not compared:** `q=N`, how many stale entries OpenSSL's error queue
//!   held after the case. The port has no queue, and its staleness is not
//!   reproduced (E4); the runner skips the drain (`drain = false`).
//! - **Random rows** (`nondet:random`) are compared on status and shape, as
//!   `gen_m65.py`'s `shape` compares two 7.94 runs: each value's type and
//!   length, a bignum's sign; the rows themselves check the bit bound.
//! - **`nondet:alias-name`** rows (an argument error of `bignum_rand` or
//!   `bignum_pseudo_rand`) compare with the two names equal: 7.94 names the
//!   one C function by Lua's hash order, the port by the name called
//!   (`nse-openssl-rand-alias-name`).
//! - **No other exemption.** Every other row must agree exactly; a row
//!   tagged `ub:` would never reach here (none is in step b).
#![cfg(not(miri))] // reads the corpus from disk; minutes of VM time under Miri

mod m65;

use regex::Regex;

/// The fewest rows the gate must run: 11,170 tagged `b`, and `bnmeta`. A
/// weakened generator regenerated in place would otherwise pass on what is
/// left.
const MIN_ROWS: usize = 11_171;

#[test]
fn every_bignum_row_matches_nmap_794() {
    let alias = Regex::new(r"'openssl\.bignum_(?:pseudo_)?rand'").expect("regex");
    m65::run_step(
        MIN_ROWS,
        |row| row.tags[0] == "b" || (row.fields[2] == "meta" && row.fields[3] == "bnmeta"),
        |row, got, want| {
            if row.tags.contains(&"nondet:alias-name") {
                for a in [got, want] {
                    a.values = alias
                        .replace_all(&a.values, "'openssl.bignum_rand'")
                        .into_owned();
                }
            }
        },
    );
}
