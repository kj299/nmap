//! Differential: `string.pack` / `unpack` / `packsize` against nmap's own Lua.
//!
//! `core::nse::stdlib::strpack` is a port of `liblua/lstrlib.c:1385-1830`, and
//! the corpus in `tests/differential/m6/m6_strpack_*.txt` is what `liblua/`,
//! built from this repository, does with each case. Every case is run end to
//! end — through the VM, the string metatable, the binding's argument
//! conversions and the pure module — because the binding is half of what is
//! being ported: `pack("i4", "10")` works in Lua only because
//! `luaL_checkinteger` coerces the string, and the binding is what has to do
//! that with the VM's own conversion rather than a restated one.
//!
//! No exemption list. The golden records the values each call returns, with
//! their subtype, or that it raised — not the message. PUC-Lua's messages
//! carry the caller's position, which this VM does not add (ledgered as
//! `error_string_gets_position`), and for a missing argument they carry
//! artefacts of the C's own stack layout: `str_pack` pushes a `nil` sentinel,
//! so the first absent value reads as "got nil" and the second as "got light
//! userdata".
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use nmap_core::nse::stdlib::load_strpack;
use piccolo::{Closure, Executor, Lua, Value, Variadic};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6")
}

fn rows(file: &str) -> Vec<(String, String, String)> {
    let path = corpus_dir().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} — run tests/differential/m6/regen_m6_strpack.sh",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut f = l.splitn(3, '\t');
            let name = f.next().expect("splitn yields one field").to_string();
            let a = f
                .next()
                .unwrap_or_else(|| panic!("{name}: no second field"));
            let b = f.next().unwrap_or_else(|| panic!("{name}: no third field"));
            (name, a.to_string(), b.to_string())
        })
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i.checked_add(2)?)?, 16).ok())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// Render one value the way `oracle/m60_coerce_driver.lua` renders Lua's.
fn render_one(v: Value) -> String {
    match v {
        Value::Integer(i) => format!("integer:{i}"),
        Value::Number(n) if n.is_nan() => "float:nan".to_string(),
        Value::Number(_) => format!("float:{}", v.display()),
        Value::String(s) => format!("string:{}", hex(s.as_bytes())),
        Value::Nil => "nil:nil".to_string(),
        Value::Boolean(b) => format!("boolean:{b}"),
        other => format!("{0}:<{0}>", other.type_name()),
    }
}

/// Evaluate one chunk in a VM with the ported functions installed.
///
/// A host-language panic is caught and reported as its own status, because it
/// is not a Lua error: it escapes `pcall`, and in the scanner it would take the
/// process down. The corpus has no case whose golden is "PANIC", so any panic
/// fails the test.
fn eval(src: &[u8]) -> (String, String) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lua = Lua::core();
        let ex = match lua.try_enter(|ctx| {
            load_strpack(ctx).expect("Lua::core() has a string table");
            let c = Closure::load(ctx, None, src)?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        }) {
            Ok(e) => e,
            Err(e) => return ("loaderror".to_string(), e.to_string()),
        };
        if let Err(e) = lua.finish(&ex) {
            return ("error".to_string(), e.to_string());
        }
        lua.enter(|ctx| {
            let e = ctx.fetch(&ex);
            match e.take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => (
                    "ok".to_string(),
                    vs.0.into_iter()
                        .map(render_one)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                Ok(Err(_)) | Err(_) => ("error".to_string(), "-".to_string()),
            }
        })
    }));
    r.unwrap_or_else(|_| ("PANIC".to_string(), "host-language panic".to_string()))
}

#[test]
fn strpack_matches_nmaps_own_lua_exactly() {
    let golden: std::collections::HashMap<_, _> = rows("m6_strpack_golden.txt")
        .into_iter()
        .map(|(n, s, v)| (n, (s, v)))
        .collect();
    let cases = rows("m6_strpack_cases.txt");
    assert!(
        cases.len() >= 4800,
        "corpus shrank to {} cases — regenerate with regen_m6_strpack.sh",
        cases.len()
    );

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mismatches: Vec<String> = cases
        .into_iter()
        .filter_map(|(name, chunk_hex, note)| {
            let (status, value) = eval(&unhex(&chunk_hex));
            let want = golden
                .get(&name)
                .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
            let ok = if want.0 == "error" {
                status == "error"
            } else {
                status == want.0 && value == want.1
            };
            (!ok).then(|| {
                format!(
                    "  {name} ({note}):\n      lua     = {} {}\n      piccolo = {status} {value}",
                    want.0, want.1
                )
            })
        })
        .collect();
    std::panic::set_hook(prev);

    assert!(
        mismatches.is_empty(),
        "{} of the strpack corpus diverge from nmap's own Lua:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
