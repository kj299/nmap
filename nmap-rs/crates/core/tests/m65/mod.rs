//! The M6.5 `openssl` corpus harness, shared by the step gates
//! (`openssl_bn_differential`, `openssl_digest_differential`, ...): the
//! port runs each case row through the oracle's own case runner
//! (`oracle/m65_core.lua`, `runner`) with the test-only registration, and
//! [`run_step`] compares status and values with nmap 7.94's golden.
//!
//! - **Not compared:** `q=N`, the stale entries OpenSSL's error queue held
//!   after the case. The port has no queue (E4); the runner skips the drain.
//! - **Random rows** (any `nondet:` tag but `alias-name`) are compared on
//!   status and [`shape`], as `gen_m65.py`'s `shape` compares two 7.94 runs.
//! - Anything else a step normalises, it does in its `adjust`, and names.
//!   A row tagged `ub:` must be among them: the golden holds no 7.94 answer
//!   for it.
//! - [`drift_tree`]: the tree's C's answer on each drift row
//!   (`m65_drift_tree.txt`), which a step holds the port to there (D1 (c)).
#![allow(dead_code)] // each gate uses part of it

use std::path::{Path, PathBuf};

use nmap_core::nse::openssl::cert::parse_for_tests;
use nmap_core::nse::openssl::register_for_tests;
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{
    Callback, CallbackReturn, Closure, Executor, Fuel, Function, Lua, StashedExecutor,
    StashedFunction, StashedValue, Table, Value,
};
use regex::Regex;

pub fn m6(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

pub fn read(file: &str) -> String {
    let path = m6(file);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    String::from_utf8(bytes).expect("the corpus is ASCII")
}

/// A state with the stdlib and `openssl`, and the runner's row function:
/// `require "m65_core".runner{ openssl = openssl, drain = false }`.
pub fn runner() -> (Lua, StashedFunction) {
    runner_with(false)
}

/// [`runner`], and for step e `parse_ssl_certificate` and the certificate
/// corpus: `runner{ ..., parse = parse_ssl_certificate, certs = PATH }`. The
/// runner reads the corpus with `io.lines`, which a bare state lacks; a
/// test-only one serves the file's lines from a table.
pub fn runner_with(certs: bool) -> (Lua, StashedFunction) {
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
        if certs {
            let lines = Table::new(&ctx);
            for (i, l) in read("m65_certs.txt").lines().enumerate() {
                let l = ctx.intern(l.as_bytes());
                lines
                    .set(ctx, i64::try_from(i).unwrap().saturating_add(1), l)
                    .unwrap();
            }
            ctx.set_global("__m65_cert_lines", lines);
            let io = Closure::load(
                ctx,
                Some("=io"),
                &b"io = { lines = function() local t, i = __m65_cert_lines, 0 \
                   return function() i = i + 1 return t[i] end end }"[..],
            )
            .expect("compiles");
            ctx.stash(Executor::start(ctx, io.into(), ()))
        } else {
            let c = Closure::load(ctx, Some("@m65_core.lua"), core.as_bytes()).expect("compiles");
            ctx.stash(Executor::start(ctx, c.into(), ()))
        }
    });
    let load = if certs {
        finish(&mut lua, &load).expect("io.lines");
        lua.enter(|ctx| {
            let c = Closure::load(ctx, Some("@m65_core.lua"), core.as_bytes()).expect("compiles");
            ctx.stash(Executor::start(ctx, c.into(), ()))
        })
    } else {
        load
    };
    let module = finish(&mut lua, &load).expect("m65_core.lua loads");
    let make = lua.enter(|ctx| {
        let Value::Table(m) = ctx.fetch(&module) else {
            panic!("m65_core.lua returns its table")
        };
        let runner: Function = m.get(ctx, "runner").expect("M.runner");
        let env = Table::new(&ctx);
        env.set_field(ctx, "openssl", register_for_tests(ctx, None));
        env.set_field(ctx, "drain", false);
        if certs {
            env.set_field(ctx, "parse", parse_for_tests(ctx));
            env.set_field(ctx, "certs", "m65_certs.txt");
        }
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
pub fn finish(lua: &mut Lua, ex: &StashedExecutor) -> Result<StashedValue, String> {
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
pub fn run_row(lua: &mut Lua, row: &StashedFunction, line: &str) -> String {
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
pub fn shape(values: &str) -> String {
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

/// One case row: its fields and its tags.
pub struct Row<'a> {
    pub line: &'a str,
    pub fields: Vec<&'a str>,
    pub tags: Vec<&'a str>,
}

/// A row's answer: status and rendered values.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: String,
    pub values: String,
}

/// Run every row `select` picks through the port and compare it with the
/// golden, after `adjust` (which may rewrite either answer, and says so in
/// its gate's doc) and the random rows' [`shape`]. Fails with the rows that
/// differ, or if fewer than `min_rows` ran; returns how many ran.
pub fn run_step(
    min_rows: usize,
    select: impl Fn(&Row<'_>) -> bool,
    adjust: impl FnMut(&Row<'_>, &mut Answer, &mut Answer),
) -> usize {
    run_step_with(false, min_rows, select, adjust)
}

/// [`run_step`], with the certificate corpus loaded when `certs`.
pub fn run_step_with(
    certs: bool,
    min_rows: usize,
    select: impl Fn(&Row<'_>) -> bool,
    mut adjust: impl FnMut(&Row<'_>, &mut Answer, &mut Answer),
) -> usize {
    let golden: std::collections::HashMap<String, Answer> = read("m65_golden.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                f[0].to_string(),
                Answer {
                    status: f[1].to_string(),
                    values: f.get(2).copied().unwrap_or("").to_string(),
                },
            )
        })
        .collect();
    let cases = read("m65_cases.txt");
    let (mut lua, runner_row) = runner_with(certs);
    let (mut ran, mut bad) = (0usize, Vec::new());
    for line in cases.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let tags: Vec<&str> = fields[1].split(',').collect();
        let row = Row { line, fields, tags };
        if !select(&row) {
            continue;
        }
        ran = ran.saturating_add(1);
        let out = run_row(&mut lua, &runner_row, line);
        let g: Vec<&str> = out.split('\t').collect();
        assert_eq!(g[0], row.fields[0], "{out}");
        let mut got = Answer {
            status: g[1].to_string(),
            values: g[2].to_string(),
        };
        let mut want = golden[row.fields[0]].clone();
        adjust(&row, &mut got, &mut want);
        // A row where the C is undefined (`ub:`) has no 7.94 answer to hold
        // the port to: its step must say what the port gives there.
        assert_ne!(
            want.status, "ub",
            "{line}: a ub row the step left as it was"
        );
        if row
            .tags
            .iter()
            .any(|t| t.starts_with("nondet:") && *t != "nondet:alias-name")
        {
            got.values = shape(&got.values);
            want.values = shape(&want.values);
        }
        if got != want {
            bad.push(format!(
                "{line}\n  7.94 {} {}\n  port {} {}",
                want.status, want.values, got.status, got.values
            ));
        }
    }
    assert!(
        ran >= min_rows,
        "only {ran} rows ran, fewer than {min_rows}"
    );
    // M65_SHOW_ALL=1 prints every differing row, not the first 30.
    let show = if std::env::var_os("M65_SHOW_ALL").is_some() {
        usize::MAX
    } else {
        30
    };
    for b in bad.iter().take(show) {
        eprintln!("{b}");
    }
    assert!(
        bad.is_empty(),
        "{} of {ran} rows differ from 7.94",
        bad.len()
    );
    eprintln!("{ran} rows agree with nmap 7.94");
    ran
}

/// `m65_core.lua`'s `str`: how the runner renders a string value.
pub fn render_str(s: &[u8]) -> String {
    let mut out = String::from("\"");
    for &c in s {
        if c < 0x20 || c == 0x7f || c == b'"' || c == b'\\' || c >= 0x80 {
            out.push_str(&format!("\\x{c:02x}"));
        } else {
            out.push(char::from(c));
        }
    }
    out.push('"');
    out
}

/// `m65_drift_tree.txt`: the tree's C's answer on each row where it differs
/// from 7.94 by a §2 family (`m65_drift.txt`), by case ID.
pub fn drift_tree() -> std::collections::HashMap<String, Answer> {
    read("m65_drift_tree.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                f[0].to_string(),
                Answer {
                    status: f[1].to_string(),
                    values: f.get(2).copied().unwrap_or("").to_string(),
                },
            )
        })
        .collect()
}

/// `m65_drift.txt`: each drift row's §2 family, by case ID.
pub fn drift_families() -> std::collections::HashMap<String, String> {
    read("m65_drift.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(id, fam)| (id.to_string(), fam.to_string()))
        .collect()
}
