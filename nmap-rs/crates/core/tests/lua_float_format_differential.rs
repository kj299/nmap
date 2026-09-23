//! M6.0 differential: float-to-string, against nmap's own Lua.
//!
//! Lua renders a float with `printf("%.14g")` and then appends `".0"` if the
//! result would read back as an integer (`tostringbuff`, `liblua/lobject.c`).
//! Rust's `Display` for `f64` does neither: it is shortest-round-trip and never
//! uses exponent notation. The two agree on almost nothing —
//!
//!   | value   | Lua                | Rust                       |
//!   |---------|--------------------|----------------------------|
//!   | `1.0`   | `1.0`              | `1`                        |
//!   | `1/3`   | `0.33333333333333` | `0.3333333333333333`       |
//!   | `1e300` | `1e+300`           | 301 digits                 |
//!
//! — and NSE scripts print the numbers they compute, so the difference lands
//! straight in scan output.
//!
//! The port is therefore a reimplementation of a C library conversion, and the
//! only honest gate for one of those is the C library itself. Every case here
//! is an IEEE-754 bit pattern; every expected string is what `liblua/`, built
//! from this repository, printed for it. There is no exemption list: unlike the
//! semantics corpus, this one is expected to be exact.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use piccolo::{meta_ops, Lua, Value};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6")
}

/// `name -> (tostring, concat)` from the golden, or `name -> (bits, note)` from
/// the cases: both files are `name<TAB>a<TAB>b` with `#` comments.
fn rows(file: &str) -> Vec<(String, String, String)> {
    let path = corpus_dir().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} — run tests/differential/m6/regen_m60.sh",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut f = l.splitn(3, '\t');
            let name = f
                .next()
                .expect("splitn always yields one field")
                .to_string();
            let a = f
                .next()
                .unwrap_or_else(|| panic!("{name}: row has no second field"));
            let b = f
                .next()
                .unwrap_or_else(|| panic!("{name}: row has no third field"));
            (name, a.to_string(), b.to_string())
        })
        .collect()
}

/// What the VM produces for each double, on each of the two paths Lua has.
///
/// `tostring` and `..` are genuinely separate code paths — one resolves the
/// `__tostring` metamethod and falls back to `Value::display`, the other is the
/// concatenation operator's own coercion — so a port can fix one and leave the
/// other. `meta_ops` is called directly rather than through a compiled chunk
/// because the values under test are bit patterns: routing one through a
/// numeral would mean testing whatever the lexer parsed instead.
///
/// One `Lua` for the whole corpus: eight thousand arenas is a minute of CI for
/// nothing, and none of these conversions touches interpreter state.
fn render_all(bits: &[u64]) -> Vec<(String, String)> {
    let mut lua = Lua::core();
    lua.enter(|ctx| {
        let empty = Value::String(ctx.intern(b""));
        bits.iter()
            .map(|&b| {
                let x = Value::Number(f64::from_bits(b));
                let tostring = match meta_ops::tostring(ctx, x) {
                    Ok(meta_ops::MetaResult::Value(v)) => v.display().to_string(),
                    // A bare float has no metatable in `Lua::core()`, so
                    // `tostring` cannot ask for a call here. If that ever
                    // changes, say so loudly rather than reporting a
                    // placeholder as the VM's answer.
                    Ok(meta_ops::MetaResult::Call(_)) => "<tostring wanted a call>".to_string(),
                    Err(e) => format!("<{e}>"),
                };
                let concat = match meta_ops::concat(ctx, empty, x) {
                    Ok(meta_ops::MetaResult::Value(v)) => v.display().to_string(),
                    Ok(meta_ops::MetaResult::Call(_)) => "<concat wanted a call>".to_string(),
                    Err(e) => format!("<{e}>"),
                };
                (tostring, concat)
            })
            .collect()
    })
}

#[test]
fn float_formatting_matches_nmaps_own_lua_exactly() {
    let golden: std::collections::HashMap<_, _> = rows("m60_floatfmt_golden.txt")
        .into_iter()
        .map(|(n, ts, cc)| (n, (ts, cc)))
        .collect();
    let cases = rows("m60_floatfmt_cases.txt");
    assert!(
        cases.len() >= 7900,
        "corpus shrank to {} cases — regenerate with regen_m60.sh",
        cases.len()
    );

    let bits: Vec<u64> = cases
        .iter()
        .map(|(name, bits_hex, _note)| {
            u64::from_str_radix(bits_hex, 16)
                .unwrap_or_else(|e| panic!("{name}: {bits_hex:?} is not a bit pattern: {e}"))
        })
        .collect();

    let mut bad = Vec::new();
    for ((name, bits_hex, _note), got) in cases.iter().zip(render_all(&bits)) {
        let want = golden
            .get(name)
            .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
        if got.0 != want.0 || got.1 != want.1 {
            bad.push(format!(
                "{name} ({bits_hex}): tostring got {:?} want {:?}, concat got {:?} want {:?}",
                got.0, want.0, got.1, want.1
            ));
        }
    }

    assert!(
        bad.is_empty(),
        "{} of {} floats print differently from nmap's Lua:\n  {}",
        bad.len(),
        cases.len(),
        bad.iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// The corpus is only a gate if it would fail. `Display for f64` is what the VM
/// used before the port, so re-running the comparison against it must light up
/// — otherwise the test above is passing for some reason other than the
/// conversion being right.
#[test]
fn the_corpus_rejects_rusts_own_float_display() {
    let golden: std::collections::HashMap<_, _> = rows("m60_floatfmt_golden.txt")
        .into_iter()
        .map(|(n, ts, _)| (n, ts))
        .collect();
    let disagreements = rows("m60_floatfmt_cases.txt")
        .into_iter()
        .filter(|(name, bits_hex, _)| {
            let x = f64::from_bits(u64::from_str_radix(bits_hex, 16).expect("hex bits"));
            golden.get(name).is_some_and(|want| format!("{x}") != *want)
        })
        .count();
    assert!(
        disagreements > 5000,
        "only {disagreements} cases distinguish Lua's conversion from Rust's — \
         the corpus is not exercising the difference it exists to catch"
    );
}
