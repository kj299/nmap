//! Differential: `string.format` against nmap's own Lua.
//!
//! `core::nse::stdlib::strformat` is a port of `liblua/lstrlib.c:990-1376`
//! together with the glibc `printf` behaviour behind it, and the corpus in
//! `tests/differential/m6/m6_format_*.txt` is what `liblua/`, built from this
//! repository on Linux, does with each case. Every case runs end to end —
//! through the VM, the binding's argument conversions, the sequence that calls
//! `__tostring` back in the VM, and the pure formatter.
//!
//! No exemption list, and error **messages** are compared byte for byte:
//! most cases batch calls through `pcall(string.format, ...)` and return each
//! result or message as a value. The generator rewrites one thing in those
//! messages, in the chunk itself and documented there: `'string.format'`
//! becomes `'format'`, because `luaL_argerror` names a function called by
//! `pcall` by its global path and the binding always says `'format'`. An
//! escaped "bad argument" error is compared by status, as in the pattern gate.
//!
//! One prefix is discounted, and only on an error that escaped the chunk:
//! `luaL_error` starts its message with the position of the *calling* Lua
//! function — `chunk:1: invalid conversion ...` — which the vendored VM never
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
fn format_matches_nmaps_own_lua_exactly() {
    let golden: HashMap<_, _> = rows(&corpus("m6_format_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m6_format_cases.txt"));
    assert!(
        cases.len() >= 6_000,
        "corpus shrank to {} cases — regenerate with regen_m6_format.sh",
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
        "{} of the format corpus diverge from nmap's own Lua:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
