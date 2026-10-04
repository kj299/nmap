//! M6.4c differential: `utf8`, `os` (the clock), `io` (files) and
//! `debug.getinfo`, against nmap's own Lua.
//!
//! `tests/differential/m6/m64_stdlib_*.txt` is 2,012 chunks run by `liblua/`
//! under `TZ=UTC`, with `fixtures/io/` to read and `/tmp/m64io/` to write; the
//! port runs each with the same files in memory (`m6_eval/memfs.rs`). Every
//! value and message is compared, with two allowances for what the first-party
//! stdlib does not do, both ledgered and both checked rather than ignored:
//!
//! - **a position**: `luaL_error` prefixes `chunk:LINE:`; these bindings do
//!   not (`stdlib-errors-have-no-position`). A message may differ from nmap's
//!   only by that prefix.
//! - **a function's name**: `luaL_argerror` names a function by where it was
//!   found — `'utf8.len'` — and these bindings by their own name — `'len'`.
//!
//! A method call shifts PUC-Lua's argument numbers (`f:read('x')` is
//! "bad argument #1"); the bindings do not know they were called as methods.
//! The cases that show it are pinned, and must differ only in that.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

mod m6_eval;

use m6_eval::{eval, quietly, rows, unhex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Method calls whose bad-argument message PUC-Lua numbers one lower, or
/// names `'?'`.
const METHOD_NAMING: &[&str] = &[
    "io_read_bad_format",
    "io_read_bad_format_star",
    "io_read_bad_format_type",
    "io_read_frac_count",
    "io_seek_bad_whence",
    "io_seek_frac",
    "io_write_bad",
    "io_write_nil",
    "io_bad_self",
    "io_setvbuf",
];

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

/// `msg` with `'lib.name'` written `'name'`.
fn unqualified(msg: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(msg).into_owned();
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some((head, tail)) = rest.split_once(" to '") {
        out.push_str(head);
        out.push_str(" to '");
        rest = tail;
        if let Some(end) = rest.find('\'') {
            let name = &rest[..end];
            out.push_str(name.rsplit('.').next().unwrap_or(name));
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out.into_bytes()
}

/// `msg` without a leading `chunk:LINE: `.
fn unpositioned(msg: &[u8]) -> &[u8] {
    msg.strip_prefix(b"chunk:")
        .and_then(|r| {
            let digits = r.iter().take_while(|b| b.is_ascii_digit()).count();
            (digits > 0).then(|| r[digits..].strip_prefix(b": "))?
        })
        .unwrap_or(msg)
}

/// Whether the port's message `port` is nmap's `lua`, up to the allowances.
fn same_message(lua: &[u8], port: &[u8]) -> bool {
    let (lua, port) = (unqualified(lua), unqualified(port));
    lua == port || unpositioned(&lua) == port.as_slice()
}

/// Whether two rendered results agree, up to the allowances.
fn same(want: &(String, String), status: &str, value: &str) -> bool {
    if want.0 != status {
        return false;
    }
    if want.1 == value {
        return true;
    }
    if status == "error" {
        return want.1 != "-" && value != "-" && same_message(&unhex(&want.1), &unhex(value));
    }
    let (a, b): (Vec<&str>, Vec<&str>) = (want.1.split(' ').collect(), value.split(' ').collect());
    a.len() == b.len()
        && a.iter().zip(&b).all(|(x, y)| {
            x == y
                || matches!((x.strip_prefix("string:"), y.strip_prefix("string:")),
                    (Some(x), Some(y)) if same_message(&unhex(x), &unhex(y)))
        })
}

/// A message with its argument number and function name blanked.
fn without_naming(msg: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(unpositioned(msg)).into_owned();
    let mut out = String::new();
    let mut rest = s.as_str();
    if let Some((head, tail)) = rest.split_once("bad argument #") {
        out.push_str(head);
        out.push_str("bad argument #");
        rest = tail;
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        rest = &rest[digits..];
        if let Some(r) = rest.strip_prefix(" to '") {
            if let Some(end) = r.find('\'') {
                out.push_str(" to '?");
                rest = &r[end..];
            }
        }
    }
    out.push_str(rest);
    out.into_bytes()
}

#[test]
fn utf8_os_io_and_debug_match_nmaps_own_lua() {
    let golden: HashMap<_, _> = rows(&corpus("m64_stdlib_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m64_stdlib_cases.txt"));
    assert!(cases.len() >= 2_000, "corpus shrank to {}", cases.len());

    let mut mismatches = Vec::new();
    quietly(|| {
        for (name, chunk_hex, note) in &cases {
            let (status, value) = eval(&unhex(chunk_hex));
            let want = golden
                .get(name)
                .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
            let ok = same(want, &status, &value);
            if METHOD_NAMING.contains(&name.as_str()) {
                // Pinned: different, and only in the numbering and naming.
                let blank = |v: &str| -> Vec<Vec<u8>> {
                    v.split(' ')
                        .map(|t| {
                            t.strip_prefix("string:")
                                .map_or(t.as_bytes().to_vec(), |h| without_naming(&unhex(h)))
                        })
                        .collect()
                };
                assert!(!ok, "{name} now matches: remove it from METHOD_NAMING");
                assert_eq!(want.0, status, "{name}: status");
                assert_eq!(
                    blank(&want.1),
                    blank(&value),
                    "{name}: more than naming differs"
                );
            } else if !ok {
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
