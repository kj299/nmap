//! Differential: Lua patterns — `string.find`, `match`, `gmatch`, `gsub` —
//! against nmap's own Lua.
//!
//! `core::nse::stdlib::pattern` is a port of `liblua/lstrlib.c:347-947`, and
//! the corpus in `tests/differential/m6/m6_pattern_*.txt` is what `liblua/`,
//! built from this repository, does with each case. Every case runs end to
//! end — through the VM, the string metatable, the binding's argument
//! conversions, the `gsub` sequence's calls back into the VM, and the pure
//! matcher.
//!
//! No exemption list. Unlike the coercion and strpack corpora, an error's
//! **message** is compared too, because for the matcher the message is the
//! behaviour: "malformed pattern (missing ']')" against a plain miss is what a
//! lazy-error case is about, and every message the matcher raises comes from
//! `luaL_error` inside a C function, which adds no position prefix. The one
//! kind compared by status alone is `luaL_argerror`'s "bad argument #n to
//! 'f'": its function name depends on how the call was made (a tail call names
//! `string.find`, a direct one `find`), which is call-site bookkeeping, not
//! the function's behaviour.
//!
//! One prefix is discounted, and only on an error that escaped the chunk:
//! `luaL_error` starts its message with the position of the *calling* Lua
//! function — `chunk:1: malformed pattern ...` — which the vendored VM never
//! adds (DIVERGENCES.md, `error_string_gets_position`). Errors caught inside a
//! chunk are not touched: the generator makes those calls through `pcall`
//! directly, where the C adds no prefix either, so their messages are compared
//! byte for byte.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

mod m6_eval;

use m6_eval::{eval, hex, quietly, rows, unhex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The oracle's top-level error message without the `chunk:N: ` position
/// `luaL_error` gives it. Hex in, hex out.
fn without_position(msg_hex: &str) -> String {
    let msg = unhex(msg_hex);
    let Some(rest) = msg.strip_prefix(b"chunk:") else {
        return msg_hex.to_string();
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    match rest.get(digits..) {
        Some(tail) if digits > 0 && tail.starts_with(b": ") => hex(&tail[2..]),
        _ => msg_hex.to_string(),
    }
}

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

#[test]
fn patterns_match_nmaps_own_lua_exactly() {
    run_corpus();
}

/// The same corpus with the failure memo recording from the very first
/// computation, so that every case runs through it rather than only the slow
/// ones. The memo is meant to change no answer and no error; this is where
/// that is held to the oracle (`pattern-worst-case-time-is-bounded`).
#[test]
fn patterns_match_nmaps_own_lua_exactly_with_the_memo_always_on() {
    nmap_core::nse::stdlib::pattern::set_memo_after(Some(0));
    run_corpus();
    nmap_core::nse::stdlib::pattern::set_memo_after(None);
}

fn run_corpus() {
    let golden: HashMap<_, _> = rows(&corpus("m6_pattern_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m6_pattern_cases.txt"));
    assert!(
        cases.len() >= 11_000,
        "corpus shrank to {} cases — regenerate with regen_m6_pattern.sh",
        cases.len()
    );
    let bad_argument = hex(b"bad argument");

    let mismatches: Vec<String> = quietly(|| {
        cases
            .into_iter()
            .filter_map(|(name, chunk_hex, note)| {
                let (status, value) = eval(&unhex(&chunk_hex));
                let want = golden
                    .get(&name)
                    .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
                let ok = if want.0 != "error" {
                    status == want.0 && value == want.1
                } else {
                    let msg = without_position(&want.1);
                    status == "error" && (msg.starts_with(&bad_argument) || value == msg)
                };
                (!ok).then(|| {
                    format!(
                        "  {name} ({note}):\n      lua     = {} {}\n      piccolo = {status} {value}",
                        want.0, want.1
                    )
                })
            })
            .collect()
    });

    assert!(
        mismatches.is_empty(),
        "{} of the pattern corpus diverge from nmap's own Lua:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
