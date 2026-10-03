//! Evaluate a Lua chunk with the first-party NSE stdlib installed, and render
//! what it returned the way `tests/differential/m6/oracle/m6_pattern_driver.lua`
//! renders what nmap's own Lua returned for the same chunk.
//!
//! Shared by the `pattern_differential` gate and the `m6_eval` example, which
//! runs any cases file through the port so that a new case can be checked
//! against the oracle before it is added to a corpus.
#![allow(dead_code)] // each user takes a different subset

use nmap_core::nse::stdlib::{load_patterns, load_strpack};
use piccolo::{Closure, Error, Executor, Lua, Value, Variadic};
use std::path::Path;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i.checked_add(2)?)?, 16).ok())
        .collect()
}

/// The non-comment rows of a corpus file, as `(name, field 2, field 3)`.
pub fn rows(path: &Path) -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
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

/// One value, as the driver's `render_one` renders it.
pub fn render_one(v: Value) -> String {
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

/// An error, as the driver renders it: a string message in hex, anything
/// else as `-`.
fn render_error(e: &Error) -> String {
    match e {
        Error::Lua(l) => match l.0 {
            Value::String(s) => hex(s.as_bytes()),
            _ => "-".to_string(),
        },
        // A Rust-side error inside the VM. nmap's Lua would have raised a
        // string; rendering this one's text makes a mismatch readable.
        Error::Runtime(r) => hex(format!("{r:#}").as_bytes()),
    }
}

/// Evaluate one chunk in a fresh VM with the ported functions installed, and
/// return `(status, value)` as the driver would print them.
///
/// A host-language panic is reported as its own status: it is not a Lua
/// error, it escapes `pcall`, and in the scanner it would take the process
/// down. No golden row says "PANIC", so any panic is a mismatch.
pub fn eval(src: &[u8]) -> (String, String) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lua = Lua::core();
        let ex = match lua.try_enter(|ctx| {
            load_patterns(ctx).expect("Lua::core() has a string table");
            load_strpack(ctx).expect("Lua::core() has a string table");
            let c = Closure::load(ctx, Some("=chunk"), src)?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        }) {
            Ok(e) => e,
            Err(_) => return ("loaderror".to_string(), "-".to_string()),
        };
        if let Err(e) = lua.finish(&ex) {
            return ("error".to_string(), hex(e.to_string().as_bytes()));
        }
        lua.enter(
            |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => (
                    "ok".to_string(),
                    vs.0.into_iter()
                        .map(render_one)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                Ok(Err(e)) => ("error".to_string(), render_error(&e)),
                Err(_) => ("error".to_string(), "-".to_string()),
            },
        )
    }));
    r.unwrap_or_else(|_| ("PANIC".to_string(), "host-language panic".to_string()))
}

/// Run `f` with the default panic hook silenced, so that a corpus run that
/// catches panics does not print one backtrace per case.
pub fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = f();
    std::panic::set_hook(prev);
    r
}
