// cargo-fuzz target for `nmap_core::osdb::expr::expr_match`.
//
// This is the hostile-input heart of OS detection. Both sides are attacker-influenced:
// the *expression* comes from `nmap-os-db`, which `--osscandb` lets a user point at any
// file, and the *value* is built from packets the scanned host sent us. The C original
// is 200 lines of raw pointer walking (its author's comment: `/* OHHHH
// YEEEAAAAAHHHH!#!@#$!% */`) that `assert()`s — aborts — on an expression with an
// unterminated `[`, and computes `NULL - ptr` under NDEBUG.
//
// The contract enforced here: `expr_match` is TOTAL. For any two byte strings and
// either nesting mode it returns a bool — never panics, never reads out of bounds,
// never recurses without bound.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::expr::expr_match;

fuzz_target!(|data: &[u8]| {
    // Split the input into (value, expression) on the first NUL so the fuzzer controls
    // both sides independently; without a NUL, treat the whole input as the expression
    // matched against a few fixed values.
    match data.iter().position(|&b| b == 0) {
        Some(i) => {
            let (val, rest) = data.split_at(i);
            let expr = &rest[1..];
            for nested in [false, true] {
                let _ = expr_match(val, expr, nested);
            }
            // Self-consistency: matching a value against itself as a literal expression
            // holds whenever the value contains no metacharacter.
            if !val.is_empty() && !val.iter().any(|b| b"|[]-<>0".contains(b)) {
                assert!(
                    expr_match(val, val, false),
                    "a metacharacter-free value must match itself literally"
                );
            }
        }
        None => {
            for v in [&b""[..], b"0", b"5", b"FF", b"M5B4ST11NW7"] {
                for nested in [false, true] {
                    let _ = expr_match(v, data, nested);
                }
            }
        }
    }
});
