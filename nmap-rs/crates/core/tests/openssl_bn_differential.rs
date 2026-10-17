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

use std::path::{Path, PathBuf};

use nmap_core::nse::openssl::register_for_tests;
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{
    Callback, CallbackReturn, Closure, Executor, Fuel, Function, Lua, StashedExecutor,
    StashedFunction, StashedValue, Table, Value,
};
use regex::Regex;

/// The fewest rows the gate must run: 11,170 tagged `b`, and `bnmeta`. A
/// weakened generator regenerated in place would otherwise pass on what is
/// left.
const MIN_ROWS: usize = 11_171;

fn m6(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

fn read(file: &str) -> String {
    let path = m6(file);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    String::from_utf8(bytes).expect("the corpus is ASCII")
}

/// A state with the stdlib and `openssl`, and the runner's row function:
/// `require "m65_core".runner{ openssl = openssl, drain = false }`.
fn runner() -> (Lua, StashedFunction) {
    let mut lua = Lua::core();
    let core = read("oracle/m65_core.lua");
    let load = lua.enter(|ctx| {
        load_patterns(ctx).expect("string table");
        load_strpack(ctx).expect("string table");
        load_format(ctx).expect("string table");
        load_tail(ctx).expect("string and coroutine tables");
        // The runner's `fn` token is the global `print`, which a bare state
        // lacks: any function does.
        let print = Callback::from_fn(&ctx, |_, _, _| Ok(CallbackReturn::Return));
        ctx.set_global("print", print);
        let c = Closure::load(ctx, Some("@m65_core.lua"), core.as_bytes()).expect("compiles");
        ctx.stash(Executor::start(ctx, c.into(), ()))
    });
    let module = finish(&mut lua, &load).expect("m65_core.lua loads");
    let make = lua.enter(|ctx| {
        let Value::Table(m) = ctx.fetch(&module) else {
            panic!("m65_core.lua returns its table")
        };
        let runner: Function = m.get(ctx, "runner").expect("M.runner");
        let env = Table::new(&ctx);
        env.set_field(ctx, "openssl", register_for_tests(ctx, None));
        env.set_field(ctx, "drain", false);
        ctx.stash(Executor::start(ctx, runner, env))
    });
    let made = finish(&mut lua, &make).expect("runner{...}");
    let row = lua.enter(|ctx| match ctx.fetch(&made) {
        Value::Function(f) => ctx.stash(f),
        v => panic!("runner returns a function, not {v:?}"),
    });
    (lua, row)
}

/// Step `ex` to its end; its first result.
fn finish(lua: &mut Lua, ex: &StashedExecutor) -> Result<StashedValue, String> {
    for _ in 0..100_000 {
        let mut fuel = Fuel::with(1_000_000);
        let done = lua
            .enter(|ctx| ctx.fetch(ex).step(ctx, &mut fuel))
            .map_err(|e| e.to_string())?;
        if done {
            return lua.enter(|ctx| match ctx.fetch(ex).take_result::<Value>(ctx) {
                Ok(Ok(v)) => Ok(ctx.stash(v)),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(e) => Err(e.to_string()),
            });
        }
    }
    Err("did not finish".into())
}

/// Run one case row: the result row, as the runner writes it.
fn run_row(lua: &mut Lua, row: &StashedFunction, line: &str) -> String {
    let ex = lua.enter(|ctx| {
        let f = ctx.fetch(row);
        ctx.stash(Executor::start(
            ctx,
            f,
            Value::String(ctx.intern(line.as_bytes())),
        ))
    });
    let v = finish(lua, &ex).unwrap_or_else(|e| panic!("{line}: {e}"));
    lua.enter(|ctx| match ctx.fetch(&v) {
        Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
        v => panic!("{line}: the runner returned {v:?}"),
    })
}

/// `gen_m65.py`'s `shape`: what a random answer is compared on.
fn shape(values: &str) -> String {
    let tok = Regex::new(
        r#"bn<-?[0-9A-F]+\|-?\d+\|(?:"(?:[^"\\]|\\x..)*"|#\d+:[0-9a-f]+)\|\d+\|\d+>|"(?:[^"\\]|\\x..)*"|#\d+:[0-9a-f]+|\S+"#,
    )
    .expect("regex");
    let esc = Regex::new(r"\\x..").expect("regex");
    tok.find_iter(values)
        .map(|m| {
            let v = m.as_str();
            if let Some(inner) = v.strip_prefix('"') {
                format!(
                    "s{}",
                    esc.replace_all(inner.strip_suffix('"').unwrap_or(inner), ".")
                        .len()
                )
            } else if let Some(n) = v.strip_prefix('#') {
                format!("s{}", n.split(':').next().unwrap_or(""))
            } else if let Some(bn) = v.strip_prefix("bn<") {
                format!("bn{}", if bn.starts_with('-') { "-" } else { "+" })
            } else {
                v.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn every_bignum_row_matches_nmap_794() {
    let golden: std::collections::HashMap<String, (String, String)> = read("m65_golden.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                f[0].to_string(),
                (
                    f[1].to_string(),
                    f.get(2).copied().unwrap_or("").to_string(),
                ),
            )
        })
        .collect();
    let alias = Regex::new(r"'openssl\.bignum_(?:pseudo_)?rand'").expect("regex");
    let (mut lua, row) = runner();
    let (mut ran, mut bad) = (0usize, Vec::new());
    for line in read("m65_cases.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let tags: Vec<&str> = f[1].split(',').collect();
        let bnmeta = f[2] == "meta" && f[3] == "bnmeta";
        if tags[0] != "b" && !bnmeta {
            continue;
        }
        assert!(!tags.iter().any(|t| t.starts_with("ub:")), "{line}");
        ran += 1;
        let got = run_row(&mut lua, &row, line);
        let g: Vec<&str> = got.split('\t').collect();
        assert_eq!(g[0], f[0], "{got}");
        let (mut got_st, mut got_v) = (g[1].to_string(), g[2].to_string());
        let (mut want_st, mut want_v) = golden[f[0]].clone();
        if tags.contains(&"nondet:alias-name") {
            got_v = alias
                .replace_all(&got_v, "'openssl.bignum_rand'")
                .into_owned();
            want_v = alias
                .replace_all(&want_v, "'openssl.bignum_rand'")
                .into_owned();
        }
        if tags
            .iter()
            .any(|t| t.starts_with("nondet:") && *t != "nondet:alias-name")
        {
            got_v = shape(&got_v);
            want_v = shape(&want_v);
        }
        if (&got_st, &got_v) != (&want_st, &want_v) {
            got_st.push(' ');
            want_st.push(' ');
            bad.push(format!(
                "{line}\n  7.94 {want_st}{want_v}\n  port {got_st}{got_v}"
            ));
        }
    }
    assert!(
        ran >= MIN_ROWS,
        "only {ran} rows ran, fewer than {MIN_ROWS}"
    );
    for b in bad.iter().take(30) {
        eprintln!("{b}");
    }
    assert!(
        bad.is_empty(),
        "{} of {ran} rows differ from 7.94",
        bad.len()
    );
    eprintln!("{ran} rows agree with nmap 7.94");
}
