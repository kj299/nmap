//! Differential: the tail of the standard library against nmap's own Lua.
//!
//! `core::nse::stdlib::base` binds the base library (`lbaselib.c`), the
//! coroutine library (`lcorolib.c`), `string.char`, the string metatable's
//! arithmetic and the argument checks of `table.insert`, `table.remove` and
//! `table.concat`; `core::nse::stdlib::strrep` ports `string.rep`. The corpus
//! in `tests/differential/m6/m6_tail_*.txt` is what `liblua/`, built from this
//! repository, does with each case, and every case runs end to end through the
//! VM and the bindings.
//!
//! No exemption list, and error **messages** are compared byte for byte,
//! positions included: these functions raise with `luaL_where(L, 1)`'s
//! position as the C does, so an error that escapes a case must be the C's
//! exactly. The generator keeps three things out of the comparison, each in
//! the chunk and in the open (see `oracle/gen_m6_tail.py`): the library prefix
//! of the function name in an argument error raised through `pcall`
//! (`'string.rep'` and `'coroutine.status'` there, `'rep'` and `'status'`
//! here); the wording of a syntax error, of which only the `chunkid:line:`
//! prefix is compared; and the message for a binary chunk the mode allows,
//! which the port refuses outright.
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
fn the_tail_matches_nmaps_own_lua_exactly() {
    let golden: HashMap<_, _> = rows(&corpus("m6_tail_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m6_tail_cases.txt"));
    assert!(
        cases.len() >= 2_700,
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

    let mismatches: Vec<String> = quietly(|| {
        cases
            .into_iter()
            .filter_map(|(name, chunk_hex, note)| {
                let (status, value) = eval(&unhex(&chunk_hex));
                let want = golden
                    .get(&name)
                    .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
                let ok = status == want.0 && value == want.1;
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
