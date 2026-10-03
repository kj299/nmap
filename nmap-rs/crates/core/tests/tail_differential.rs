//! Differential: the tail of the standard library against nmap's own Lua.
//!
//! `core::nse::stdlib::base` binds `_G`, `rawequal`, `xpcall`, `load` and
//! `coroutine.wrap`; `core::nse::stdlib::strrep` ports `string.rep`. The corpus
//! in `tests/differential/m6/m6_tail_*.txt` is what `liblua/`, built from this
//! repository, does with each case, and every case runs end to end through the
//! VM and the bindings.
//!
//! No exemption list, and error **messages** are compared byte for byte. The
//! generator keeps three things out of the comparison, each in the chunk and
//! in the open (see `oracle/gen_m6_tail.py`): the function name in an argument
//! error (`'string.rep'` there, `'rep'` here); the wording of a syntax error,
//! of which only the `chunkid:line:` prefix is compared; and the message for
//! a binary chunk the mode allows, which the port refuses outright. An escaped
//! "bad argument" error is compared by status, and an escaped error's
//! `chunk:N: ` position is discounted, as in the pattern gate
//! (DIVERGENCES.md, `error_string_gets_position`).
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
fn the_tail_matches_nmaps_own_lua_exactly() {
    let golden: HashMap<_, _> = rows(&corpus("m6_tail_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m6_tail_cases.txt"));
    assert!(
        cases.len() >= 1_000,
        "corpus shrank to {} cases — regenerate with regen_m6_tail.sh",
        cases.len()
    );
    // A case the oracle could not even compile tests nothing.
    let unloadable: Vec<_> = golden
        .iter()
        .filter(|(_, (s, _))| s == "loaderror")
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        unloadable.is_empty(),
        "cases nmap's Lua cannot load: {unloadable:?}"
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
        "{} of the tail corpus diverge from nmap's own Lua:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
