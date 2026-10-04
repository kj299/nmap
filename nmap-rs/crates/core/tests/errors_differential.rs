//! M6.4a differential: errors the VM raises, and numeric `for` loops, against
//! nmap's own Lua.
//!
//! `tests/differential/m6/m64_errors_*.txt` is 12,438 chunks run by `liblua/`
//! from this repository: every runtime error over operands of every type,
//! `error` at every level, `assert`, a grid of `for` loops over the integer
//! extremes, floats, numeric strings and wrong types, and errors on later lines.
//!
//! Unlike the earlier corpora, an error that escapes a chunk is compared WITH
//! its `chunk:LINE:` position: the VM adds it now. One thing is discounted, in
//! the open: PUC-Lua describes the culprit of an error — `(local 'x')`,
//! `(global 'f')`, `(field 'k')` — and the VM does not yet
//! (DIVERGENCES.md, `vm-error-varinfo`); the description is removed from
//! nmap's message before comparing. The two cases where the VM gives a
//! multi-line statement's first line, not the failing instruction's
//! (`vm-error-line-is-the-statements`), are pinned in both directions.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

mod m6_eval;

use m6_eval::{eval, hex, quietly, rows, unhex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cases where the VM reports a different line than nmap's Lua.
const KNOWN_LINE_DIFFERENCES: &[&str] = &["line_multi_call", "line_multi_table"];

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

/// `msg` without PUC-Lua's variable descriptions: ` (local 'x')` and the like.
fn without_varinfo(msg: &[u8]) -> Vec<u8> {
    const KINDS: [&[u8]; 7] = [
        b"local",
        b"global",
        b"field",
        b"method",
        b"upvalue",
        b"constant",
        b"for iterator",
    ];
    // The length of a description starting at the head of `rest`, if one does.
    let description = |rest: &[u8]| -> Option<usize> {
        KINDS.iter().find_map(|kind| {
            let head = [b" (".as_slice(), kind, b" '"].concat();
            let name = rest.strip_prefix(head.as_slice())?;
            let end = name.iter().position(|&b| b == b'\'')?;
            (name.get(end.checked_add(1)?) == Some(&b')'))
                .then(|| head.len().checked_add(end)?.checked_add(2))
                .flatten()
        })
    };
    let mut out = Vec::with_capacity(msg.len());
    let mut rest = msg;
    while let Some((&first, tail)) = rest.split_first() {
        match description(rest) {
            Some(len) => rest = &rest[len..],
            None => {
                out.push(first);
                rest = tail;
            }
        }
    }
    out
}

/// The oracle's rendering with every description removed. Hex in, hex out.
fn strip(status: &str, value: &str) -> String {
    if status == "error" {
        return if value == "-" {
            value.to_string()
        } else {
            hex(&without_varinfo(&unhex(value)))
        };
    }
    value
        .split(' ')
        .map(|t| match t.strip_prefix("string:") {
            Some(h) => format!("string:{}", hex(&without_varinfo(&unhex(h)))),
            None => t.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn vm_errors_and_for_loops_match_nmaps_own_lua() {
    let golden: HashMap<_, _> = rows(&corpus("m64_errors_golden.txt"))
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows(&corpus("m64_errors_cases.txt"));
    assert!(cases.len() >= 12_000, "corpus shrank to {}", cases.len());

    let mut mismatches = Vec::new();
    let mut known_seen = Vec::new();
    quietly(|| {
        for (name, chunk_hex, note) in &cases {
            let (status, value) = eval(&unhex(chunk_hex));
            let want = golden
                .get(name)
                .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
            let ok = status == want.0 && value == strip(&want.0, &want.1);
            if KNOWN_LINE_DIFFERENCES.contains(&name.as_str()) {
                assert!(
                    !ok,
                    "{name} now matches: remove it from KNOWN_LINE_DIFFERENCES"
                );
                known_seen.push(name.clone());
            } else if !ok {
                mismatches.push(format!(
                    "  {name} ({note}):\n      lua  = {} {}\n      port = {status} {value}",
                    want.0, want.1
                ));
            }
        }
    });
    assert_eq!(
        known_seen.len(),
        KNOWN_LINE_DIFFERENCES.len(),
        "a pinned case is missing"
    );
    assert!(
        mismatches.is_empty(),
        "{} of {} diverge:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches[..mismatches.len().min(30)].join("\n")
    );
}

#[test]
fn varinfo_is_stripped_exactly() {
    assert_eq!(
        without_varinfo(b"chunk:1: attempt to index a nil value (local 'x')"),
        b"chunk:1: attempt to index a nil value"
    );
    assert_eq!(
        without_varinfo(b"attempt to call a nil value (global 'a(b)')"),
        b"attempt to call a nil value"
    );
    // Not a description: kept.
    assert_eq!(without_varinfo(b"x (other 'y')"), b"x (other 'y')");
}
