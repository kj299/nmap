//! M6.0 differential: the vendored Lua VM against nmap's own Lua.
//!
//! The corpus and its golden verdicts are derived by
//! `tests/differential/m6/regen_m60.sh`, which builds `liblua/` from this
//! repository and evaluates each case with it. Unlike the M6.1/M6.2 corpora,
//! which gate *parsers* this port wrote, this one gates an *interpreter* this
//! port vendors — so the thing under test is `crates/vendor/piccolo`, reached
//! here as a dev-dependency.
//!
//! Two tests, and the second is the one that matters. The first asserts every
//! case the VM is expected to get right. The second pins the divergence set
//! EXACTLY: a new divergence cannot appear without editing this file, and
//! neither can a fixed one go unrecorded. Every entry is ledgered under
//! "Milestone 6.0 — known defects in the vendored Lua VM" in `DIVERGENCES.md`,
//! which is the one section of that file recording defects rather than choices.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use piccolo::{Closure, Executor, Lua, Value};
use std::path::{Path, PathBuf};

/// Cases where the vendored VM is known to disagree with nmap's Lua.
///
/// Keep this sorted and keep it justified. Each name maps to a `DIVERGENCES.md`
/// entry; shrinking it is progress, growing it is a regression that must be
/// argued for in the same commit.
const KNOWN_DIVERGENCES: &[&str] = &[
    // Integer overflow in the modulus operator: `((a % b) + b) % b` on raw i64.
    // These ABORT THE PROCESS and `pcall` does not contain them.
    "mod_min_by_neg1",
    "mod_neg1_by_min",
    // `1 << -1`: Lua reverses the shift direction, piccolo raises.
    "shl_neg",
    // Integer/float comparison at the extreme: `maxinteger + 0.0 == maxinteger`.
    "max_int_vs_float",
    // Float formatting: Lua keeps the decimal marker, piccolo drops it, so
    // `tostring(1.0)` is "1" and `1.0 .. ''` is "1".
    "float_to_int_concat",
    "tostring_float",
    // String-to-number coercion yields a float where Lua yields an integer.
    "coerce_add",
    "coerce_hex",
    // `("ab"):rep(3)`. NOT a dispatch failure -- the `__index` lookup succeeds
    // and returns nil, because piccolo's string library is seven functions and
    // `rep` is not among them. Closes when the first-party stdlib lands.
    "method_rep_literal",
];

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository layout")
        .join("tests/differential/m6")
}

fn rows(name: &str) -> Vec<(String, String, String)> {
    let text =
        std::fs::read_to_string(corpus_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut f = l.split('\t');
            (
                f.next().unwrap_or_default().to_owned(),
                f.next().unwrap_or_default().to_owned(),
                f.next().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i.checked_add(2)?)?, 16).ok())
        .collect()
}

/// Render a value exactly as `oracle/m60_driver.lua` renders Lua's, so the two
/// can be compared as strings. Numbers carry their `math.type` because NSE's
/// binary libraries branch on integer-vs-float; strings render as hex because
/// they are byte strings.
fn render(v: Value) -> String {
    match v {
        Value::Integer(i) => format!("integer:{i}"),
        Value::Number(n) if n.is_nan() => "float:nan".to_string(),
        Value::Number(n) if n.is_infinite() => {
            format!("float:{}", if n > 0.0 { "inf" } else { "-inf" })
        }
        Value::Number(n) => {
            let s = format!("{n:.14}");
            let s = s.trim_end_matches('0').to_string();
            format!(
                "float:{}",
                if s.ends_with('.') { format!("{s}0") } else { s }
            )
        }
        Value::String(s) => format!("string:{}", hex(s.as_bytes())),
        Value::Nil => "nil:nil".to_string(),
        Value::Boolean(b) => format!("boolean:{b}"),
        Value::Table(_) => "table:<table>".to_string(),
        Value::Function(_) => "function:<function>".to_string(),
        Value::UserData(_) => "userdata:<userdata>".to_string(),
        Value::Thread(_) => "thread:<thread>".to_string(),
    }
}

/// Evaluate one chunk, returning `(status, value)` in the golden's own shape.
///
/// `catch_unwind` is load-bearing rather than defensive: a host-language panic
/// is NOT a Lua error. It escapes `pcall`, so a script cannot defend against
/// it, and in the scanner it takes the process down. Catching it here lets the
/// corpus record it as a distinct verdict instead of killing the test run.
fn eval(src: &[u8]) -> (String, String) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lua = Lua::core();
        let ex = match lua.try_enter(|ctx| {
            let c = Closure::load(ctx, None, src)?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        }) {
            Ok(e) => e,
            Err(e) => return ("loaderror".to_string(), e.to_string()),
        };
        // `finish` returns `Result<(), BadThreadMode>`. Discarding it would mean
        // reading a result that was never produced and reporting it as the VM's
        // answer -- a false PASS, which is the failure this whole corpus exists
        // to prevent.
        if let Err(e) = lua.finish(&ex) {
            return ("error".to_string(), e.to_string());
        }
        lua.enter(|ctx| {
            let e = ctx.fetch(&ex);
            match e.take_result::<Value>(ctx) {
                Ok(Ok(v)) => ("ok".to_string(), render(v)),
                Ok(Err(err)) => ("error".to_string(), err.to_string()),
                Err(err) => ("error".to_string(), err.to_string()),
            }
        })
    }));
    r.unwrap_or_else(|_| ("PANIC".to_string(), "host-language panic".to_string()))
}

fn run_corpus() -> Vec<(String, bool)> {
    let golden: std::collections::HashMap<_, _> = rows("m60_semantics_golden.txt")
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();

    // One hook for the whole run: the panicking cases are expected, and their
    // backtraces would drown the real output.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = rows("m60_semantics_cases.txt")
        .into_iter()
        .map(|(name, chunk_hex, _note)| {
            let got = eval(&unhex(&chunk_hex));
            let want = golden
                .get(&name)
                .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
            let matches = got.0 == want.0 && got.1 == want.1;
            (name, matches)
        })
        .collect();
    std::panic::set_hook(prev);
    out
}

#[test]
fn vm_matches_nmaps_own_lua_except_where_ledgered() {
    let results = run_corpus();
    assert!(
        results.len() >= 68,
        "corpus shrank to {} cases — regenerate with regen_m60.sh",
        results.len()
    );

    let unexpected: Vec<_> = results
        .iter()
        .filter(|(name, ok)| !ok && !KNOWN_DIVERGENCES.contains(&name.as_str()))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        unexpected.is_empty(),
        "new divergence(s) from nmap's own Lua: {unexpected:?}\n\
         Either fix the VM or add the case to KNOWN_DIVERGENCES *and* DIVERGENCES.md."
    );
}

#[test]
fn the_ledgered_divergence_set_is_exact() {
    let results = run_corpus();

    // A divergence that has been FIXED must be removed from the list, or the
    // list quietly becomes a wishlist. This is the half of the gate that
    // catches progress going unrecorded.
    let fixed: Vec<_> = results
        .iter()
        .filter(|(name, ok)| *ok && KNOWN_DIVERGENCES.contains(&name.as_str()))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        fixed.is_empty(),
        "these no longer diverge — remove them from KNOWN_DIVERGENCES: {fixed:?}"
    );

    // Deliberately NOT asserting alphabetical order. The list is grouped by root
    // cause -- the two modulo panics together, the two float-formatting cases
    // together -- because that grouping is what tells a reader which entries one
    // fix will close. Duplicates, though, are a real mistake worth catching.
    let mut seen = std::collections::HashSet::new();
    let dupes: Vec<_> = KNOWN_DIVERGENCES
        .iter()
        .filter(|n| !seen.insert(**n))
        .collect();
    assert!(dupes.is_empty(), "duplicate entries: {dupes:?}");

    // Every name must exist in the corpus, or the list silently accumulates
    // entries that can never fire -- an exemption for a case that is not there
    // reads exactly like an exemption that is working.
    let names: std::collections::HashSet<_> = results.iter().map(|(n, _)| n.as_str()).collect();
    let phantom: Vec<_> = KNOWN_DIVERGENCES
        .iter()
        .filter(|n| !names.contains(*n))
        .collect();
    assert!(
        phantom.is_empty(),
        "KNOWN_DIVERGENCES names no such case: {phantom:?}"
    );
}
