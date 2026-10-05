//! Evaluate a Lua chunk with the first-party NSE stdlib installed, and render
//! what it returned the way `tests/differential/m6/oracle/m6_pattern_driver.lua`
//! renders what nmap's own Lua returned for the same chunk.
//!
//! Shared by the `pattern_differential` gate and the `m6_eval` example, which
//! runs any cases file through the port so that a new case can be checked
//! against the oracle before it is added to a corpus.
#![allow(dead_code)] // each user takes a different subset

mod memfs;

use nmap_core::nse::stdlib::debuglib::load_debug;
use nmap_core::nse::stdlib::iolib::load_io;
use nmap_core::nse::stdlib::oslib::{load_os, OsEnv};
use nmap_core::nse::stdlib::utf8lib::load_utf8;
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{Closure, Error, Executor, Fuel, Lua, Table, Thread, Value, Variadic};
use std::path::Path;
use std::rc::Rc;

/// The fixture files the `io` corpus reads.
fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6/fixtures/io")
}

/// `time(NULL)` and `clock()`, from the host, for `os`.
fn os_env() -> OsEnv {
    OsEnv {
        now: Box::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        }),
        cpu_seconds: Box::new(|| 0.0),
        home: None,
    }
}

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

/// How much fuel one case may burn before it is reported as `TIMEOUT`. The
/// heaviest case in the pattern corpus needs well under a hundredth of this.
///
/// Without a budget, a regression that loops — `gsub` repeating an empty
/// match forever, say — would hang the gate until the CI job's timeout instead
/// of failing it. `gsub` spends fuel per replacement, so that one becomes a
/// mismatch in seconds; a loop inside a single match spends none, but the
/// matcher has no unbounded loop to regress into.
const FUEL_BUDGET: u64 = 50_000_000;

/// The C calls (`nCcalls`) a chunk runs under in the oracle: `lua.c` calls
/// `pmain` with `lua_pcall`, `pmain` runs the driver with another, and the
/// driver calls each chunk with `pcall`. Starting the port's chunk at the same
/// depth makes "C stack overflow" fall at the same depth on both sides.
pub const ORACLE_CCALLS: u32 = 3;

/// Evaluate one chunk in a fresh VM with the ported functions installed, and
/// return `(status, value)` as the driver would print them.
///
/// A host-language panic is reported as its own status: it is not a Lua
/// error, it escapes `pcall`, and in the scanner it would take the process
/// down. No golden row says "PANIC" or "TIMEOUT", so either is a mismatch.
pub fn eval(src: &[u8]) -> (String, String) {
    eval_limited(src, None)
}

/// [`eval`], with the VM's memory budget set to `limit` bytes.
pub fn eval_limited(src: &[u8], limit: Option<usize>) -> (String, String) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lua = Lua::core();
        if let Some(limit) = limit {
            lua.set_memory_limit(limit);
        }
        let ex = match lua.try_enter(|ctx| {
            load_patterns(ctx).expect("Lua::core() has a string table");
            load_strpack(ctx).expect("Lua::core() has a string table");
            load_format(ctx).expect("Lua::core() has a string table");
            load_tail(ctx).expect("Lua::core() has string and coroutine tables");
            load_io(ctx, Rc::new(memfs::MemFs::with_fixtures(&fixtures())));
            load_os(ctx, Rc::new(os_env()));
            load_utf8(ctx);
            // `package.loaded`, for `traceback`'s global names.
            let loaded = Table::new(&ctx);
            for lib in [
                "_G",
                "string",
                "table",
                "math",
                "coroutine",
                "io",
                "os",
                "utf8",
            ] {
                let v = if lib == "_G" {
                    Value::Table(ctx.globals())
                } else {
                    ctx.globals().get_value(ctx, lib)
                };
                loaded.set(ctx, lib, v).expect("string key");
            }
            load_debug(ctx, loaded);
            let c = Closure::load(ctx, Some("=chunk"), src)?;
            let thread = Thread::new(ctx);
            thread.start(ctx, c.into(), ())?;
            thread.set_ccalls(&ctx, ORACLE_CCALLS)?;
            Ok(ctx.stash(Executor::run(&ctx, thread)?))
        }) {
            Ok(e) => e,
            Err(_) => return ("loaderror".to_string(), "-".to_string()),
        };
        const SLICE: i32 = 4096;
        let mut spent: u64 = 0;
        loop {
            let mut fuel = Fuel::with(SLICE);
            match lua.enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel)) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => return ("error".to_string(), hex(e.to_string().as_bytes())),
            }
            spent = spent.saturating_add(SLICE.unsigned_abs().into());
            if spent > FUEL_BUDGET {
                return ("TIMEOUT".to_string(), format!("over {FUEL_BUDGET} fuel"));
            }
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
