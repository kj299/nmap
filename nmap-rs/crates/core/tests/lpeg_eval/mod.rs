//! A Lua state with the first-party stdlib and the **test-only** `lpeg`
//! registration ([`nmap_core::nse::lpeg::register_for_tests`]), and a runner
//! that steps a chunk in slices of fuel, counting the slices.
//!
//! Shared by `lpeg_tree_differential` and `lpeg_tree_limits`.
#![allow(dead_code)] // each user takes a different subset

use nmap_core::nse::lpeg::register_for_tests;
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{Closure, Executor, Fuel, Function, Lua, StashedExecutor, Table, Value, Variadic};

/// A fresh state: `string`, `table`, `math`, `coroutine`, the first-party
/// stdlib, `package.loaded` holding them, and `lpeg` there and as a global.
pub fn new_lua() -> Lua {
    let mut lua = Lua::core();
    lua.enter(|ctx| {
        load_patterns(ctx).expect("Lua::core() has a string table");
        load_strpack(ctx).expect("Lua::core() has a string table");
        load_format(ctx).expect("Lua::core() has a string table");
        load_tail(ctx).expect("Lua::core() has string and coroutine tables");
        let loaded = Table::new(&ctx);
        for lib in ["string", "table", "math", "coroutine"] {
            loaded
                .set(ctx, lib, ctx.globals().get_value(ctx, lib))
                .expect("string key");
        }
        loaded.set(ctx, "_G", ctx.globals()).expect("string key");
        let package = Table::new(&ctx);
        package.set_field(ctx, "loaded", loaded);
        ctx.set_global("package", package);
        let lpeg = register_for_tests(ctx, Some(loaded));
        ctx.set_global("lpeg", lpeg);
    });
    lua
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The results, each as `tostring` shows it (strings lossily).
    Returned(Vec<String>),
    /// The error that escaped, as a string where it is one.
    Raised(String),
    /// Still running after `max_slices`.
    Unfinished,
}

/// Step `ex` in slices of `slice` fuel until it finishes (true) or
/// `max_slices` pass (false); and the slices it took. The result is left in
/// the executor.
pub fn step_only(lua: &mut Lua, ex: &StashedExecutor, slice: i32, max_slices: u64) -> (bool, u64) {
    let mut slices = 0u64;
    loop {
        let mut fuel = Fuel::with(slice);
        let done = lua
            .enter(|ctx| ctx.fetch(ex).step(ctx, &mut fuel))
            .expect("steps");
        slices = slices.saturating_add(1);
        if done {
            return (true, slices);
        }
        if slices >= max_slices {
            return (false, slices);
        }
    }
}

/// What [`step_traced`] saw of a run, slice by slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trace {
    /// It finished within the slices allowed.
    pub done: bool,
    pub slices: u64,
    /// The least fuel left after a slice: how far past its slice the work
    /// done in one went, negated. A slice ends once its fuel is spent, and
    /// what one call spends past that is taken from it too.
    pub deepest: i32,
    /// The most memory the state counted after a slice that did not finish
    /// the run (`Lua::total_memory`, which counts what calls hold between
    /// slices).
    pub pending_peak: usize,
}

/// [`step_only`], tracing each slice.
pub fn step_traced(lua: &mut Lua, ex: &StashedExecutor, slice: i32, max_slices: u64) -> Trace {
    let mut t = Trace {
        done: false,
        slices: 0,
        deepest: slice,
        pending_peak: 0,
    };
    loop {
        let mut fuel = Fuel::with(slice);
        let done = lua
            .enter(|ctx| ctx.fetch(ex).step(ctx, &mut fuel))
            .expect("steps");
        t.slices = t.slices.saturating_add(1);
        t.deepest = t.deepest.min(fuel.remaining());
        if done {
            t.done = true;
            return t;
        }
        t.pending_peak = t.pending_peak.max(lua.total_memory());
        if t.slices >= max_slices {
            return t;
        }
    }
}

/// Step `ex` in slices of `slice` fuel until it finishes or `max_slices`
/// pass; how it ended, and the slices it took.
pub fn step_to_end(
    lua: &mut Lua,
    ex: &StashedExecutor,
    slice: i32,
    max_slices: u64,
) -> (Outcome, u64) {
    let (done, slices) = step_only(lua, ex, slice, max_slices);
    if !done {
        return (Outcome::Unfinished, slices);
    }
    let out = lua.enter(
        |ctx| match ctx.fetch(ex).take_result::<Variadic<Vec<Value>>>(ctx) {
            Ok(Ok(vs)) => Outcome::Returned(vs.0.iter().map(|v| show(*v)).collect()),
            Ok(Err(piccolo::Error::Lua(v))) => Outcome::Raised(show(v.0)),
            Ok(Err(e)) => Outcome::Raised(format!("{e:#}")),
            Err(e) => Outcome::Raised(e.to_string()),
        },
    );
    (out, slices)
}

fn show(v: Value) -> String {
    match v {
        Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
        v => v.display().to_string(),
    }
}

/// Compile `src` (chunk name `=chunk`) and start it.
pub fn start(lua: &mut Lua, src: &str) -> StashedExecutor {
    lua.try_enter(|ctx| {
        let c = Closure::load(ctx, Some("=chunk"), src.as_bytes())?;
        Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
    })
    .unwrap_or_else(|e| panic!("{src}: {e:#}"))
}

/// Run `src` in a fresh state with generous slices.
pub fn run(src: &str) -> Outcome {
    let mut lua = new_lua();
    let ex = start(&mut lua, src);
    step_to_end(&mut lua, &ex, 1_000_000, 100_000).0
}

/// Call the global function `name` of `lua` with `args`.
pub fn call_global(
    lua: &mut Lua,
    name: &'static str,
    args: Vec<Vec<u8>>,
    slice: i32,
) -> (Outcome, u64) {
    let ex = lua.enter(|ctx| {
        let f: Function = ctx.get_global(name).expect("a function");
        let args: Vec<Value> = args.iter().map(|a| Value::String(ctx.intern(a))).collect();
        ctx.stash(Executor::start(ctx, f, Variadic(args)))
    });
    step_to_end(lua, &ex, slice, u64::MAX)
}
