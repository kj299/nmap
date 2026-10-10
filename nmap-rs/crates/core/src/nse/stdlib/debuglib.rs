//! The `debug` library NSE scripts get: `getinfo` and `traceback`.
//!
//! nselib needs two things from `debug`: `strict.lua` asks
//! `debug.getinfo(3, "S").what` whether a global is being assigned from a
//! main chunk, and `nsedebug.lua` and the engine print tracebacks. The rest
//! of `ldblib.c` — reading and writing any function's locals and upvalues,
//! any value's metatable, the registry, hooks — would let a script reach
//! inside every other script and library, and no shipped file uses it; it is
//! not provided (`debug-is-introspection-only`, DIVERGENCES.md).
//!
//! What the VM does not record is reported as PUC-Lua reports it when the
//! information is absent: a function's name and `namewhat` (PUC-Lua recovers
//! them from the calling instruction) come back empty, so a traceback names a
//! Lua function `function <file:line>` unless it is reachable from
//! `package.loaded`, and `lastlinedefined` is the line the function starts on.

use piccolo::thread::FrameInfo;
use piccolo::{
    Callback, CallbackReturn, Context, Error, Execution, Function, Stack, Table, Thread, Value,
};

use super::strpack::PackError;
use super::{lua_error_bytes, LuaArgs};
use piccolo::chunk_id::chunk_id;
use piccolo::compiler::FunctionRef;

/// `LEVELS1` and `LEVELS2` (`lauxlib.c`): how many levels a long traceback
/// keeps from its top and from its bottom.
const LEVELS1: usize = 10;
const LEVELS2: usize = 11;

/// Installs `debug` — `getinfo` and `traceback` — into `ctx`'s globals, and
/// returns it. `loaded` is `package.loaded`, where `traceback` looks for a
/// function's global name.
pub fn load_debug<'gc>(ctx: Context<'gc>, loaded: Table<'gc>) -> Table<'gc> {
    let debug = Table::new(&ctx);
    debug.set_field(ctx, "getinfo", Callback::from_fn(&ctx, getinfo));
    debug.set_field(
        ctx,
        "traceback",
        Callback::from_fn_with(&ctx, loaded, |&loaded, ctx, exec, mut stack| {
            traceback(ctx, exec, &mut stack, loaded)
        }),
    );
    ctx.set_global("debug", debug);
    debug
}

fn raise<'gc>(ctx: Context<'gc>, name: &str, e: PackError) -> Error<'gc> {
    lua_error_bytes(ctx, &e.lua_message(name))
}

/// `funcinfo` and the rest of `lua_getinfo`, for one function.
struct Info {
    source: Vec<u8>,
    short_src: Vec<u8>,
    what: &'static str,
    linedefined: i64,
    lastlinedefined: i64,
    currentline: i64,
    nups: i64,
    nparams: i64,
    isvararg: bool,
    active_lines: Option<Vec<i64>>,
}

impl Info {
    /// What PUC-Lua reports about `function`, running at `currentline`.
    fn of(function: Option<Function<'_>>, currentline: Option<i64>) -> Info {
        match function {
            Some(Function::Closure(c)) => {
                let proto = c.prototype();
                let source = proto.chunk_name.as_bytes().to_vec();
                let linedefined = match proto.reference {
                    FunctionRef::Chunk => 0,
                    FunctionRef::Named(_, l) | FunctionRef::Expression(l) => {
                        i64::try_from(l.0).unwrap_or(i64::MAX).saturating_add(1)
                    }
                };
                let mut lines: Vec<i64> = proto
                    .opcode_line_numbers
                    .iter()
                    .map(|(_, l)| i64::try_from(l.0).unwrap_or(i64::MAX).saturating_add(1))
                    .collect();
                lines.sort_unstable();
                lines.dedup();
                Info {
                    short_src: chunk_id(&source),
                    source,
                    what: if linedefined == 0 { "main" } else { "Lua" },
                    linedefined,
                    lastlinedefined: linedefined,
                    currentline: currentline.unwrap_or(-1),
                    nups: i64::try_from(proto.upvalues.len()).unwrap_or(i64::MAX),
                    nparams: i64::from(proto.fixed_params),
                    isvararg: proto.has_varargs,
                    active_lines: Some(lines),
                }
            }
            _ => Info {
                source: b"=[C]".to_vec(),
                short_src: b"[C]".to_vec(),
                what: "C",
                linedefined: -1,
                lastlinedefined: -1,
                currentline: -1,
                nups: 0,
                nparams: 0,
                isvararg: true,
                active_lines: None,
            },
        }
    }
}

/// `getthread`: a leading thread argument, and the index of the next one.
fn thread_arg<'gc>(stack: &Stack<'gc, '_>) -> (Option<Thread<'gc>>, usize) {
    match stack.get(0) {
        Value::Thread(t) => (Some(t), 1),
        _ => (None, 0),
    }
}

/// The functions active in the thread being asked about, level 0 first.
fn levels<'gc>(exec: &Execution<'gc, '_>, thread: Option<Thread<'gc>>) -> Vec<FrameInfo<'gc>> {
    match thread {
        // The running thread: level 0 is the running Rust function.
        None => (0..).map_while(|l| exec.frame_info(l)).collect(),
        Some(t) => t
            .frame_infos()
            .unwrap_or_else(|| (0..).map_while(|l| exec.frame_info(l)).collect()),
    }
}

/// `debug.getinfo([thread,] f [, what])`.
#[allow(clippy::arithmetic_side_effects)] // `arg` is 0 or 1
fn getinfo<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let (thread, arg) = thread_arg(&stack);
    let (options, target) = {
        let args = LuaArgs { ctx, stack: &stack };
        let options = match args.get(arg + 2) {
            None | Some(Value::Nil) => b"flnSrtu".to_vec(),
            Some(_) => args
                .string(arg + 2)
                .map_err(|e| raise(ctx, "getinfo", e))?
                .into_owned(),
        };
        if options.first() == Some(&b'>') {
            return Err(raise(
                ctx,
                "getinfo",
                PackError::bad_argument(arg + 2, "invalid option '>'"),
            ));
        }
        let target = match args.get(arg + 1) {
            Some(Value::Function(f)) => Err(f),
            _ => Ok(args
                .check_integer(arg + 1)
                .map_err(|e| raise(ctx, "getinfo", e))?),
        };
        (options, target)
    };
    if options.iter().any(|c| !b"SlnrutfL".contains(c)) {
        return Err(raise(
            ctx,
            "getinfo",
            PackError::bad_argument(arg + 2, "invalid option"),
        ));
    }
    let (function, currentline) = match target {
        Err(f) => (Some(f), None),
        Ok(level) => {
            let frames = levels(&exec, thread);
            let frame = usize::try_from(level).ok().and_then(|l| frames.get(l));
            let Some(frame) = frame else {
                stack.replace(ctx, Value::Nil);
                return Ok(CallbackReturn::Return);
            };
            (frame.function, frame.lua.map(|(_, line)| line))
        }
    };
    let info = Info::of(function, currentline);
    let t = Table::new(&ctx);
    let has = |c: u8| options.contains(&c);
    if has(b'S') {
        t.set(ctx, "source", ctx.intern(&info.source))?;
        t.set(ctx, "short_src", ctx.intern(&info.short_src))?;
        t.set(ctx, "linedefined", info.linedefined)?;
        t.set(ctx, "lastlinedefined", info.lastlinedefined)?;
        t.set(ctx, "what", info.what)?;
    }
    if has(b'l') {
        t.set(ctx, "currentline", info.currentline)?;
    }
    if has(b'u') {
        t.set(ctx, "nups", info.nups)?;
        t.set(ctx, "nparams", info.nparams)?;
        t.set(ctx, "isvararg", info.isvararg)?;
    }
    if has(b'n') {
        // No name is known; `settabss` with a NULL name sets nothing.
        t.set(ctx, "namewhat", "")?;
    }
    if has(b'r') {
        t.set(ctx, "ftransfer", 0)?;
        t.set(ctx, "ntransfer", 0)?;
    }
    if has(b't') {
        t.set(ctx, "istailcall", false)?;
    }
    if has(b'L') {
        if let Some(lines) = &info.active_lines {
            let active = Table::new(&ctx);
            for line in lines {
                active.set(ctx, *line, true)?;
            }
            t.set(ctx, "activelines", active)?;
        }
    }
    if has(b'f') {
        if let Some(f) = function {
            t.set(ctx, "func", f)?;
        }
    }
    stack.replace(ctx, t);
    Ok(CallbackReturn::Return)
}

/// `pushglobalfuncname`: `function`'s name in `package.loaded`, looked for
/// two tables deep, without a leading `_G.`.
fn global_name<'gc>(
    ctx: Context<'gc>,
    loaded: Table<'gc>,
    function: Function<'gc>,
) -> Option<Vec<u8>> {
    let target = Value::Function(function);
    let same = |v: Value<'gc>| match (v, target) {
        (Value::Function(Function::Closure(a)), Value::Function(Function::Closure(b))) => a == b,
        (Value::Function(Function::Callback(a)), Value::Function(Function::Callback(b))) => a == b,
        _ => false,
    };
    for (k, v) in loaded {
        let Value::String(k) = k else { continue };
        if same(v) {
            return Some(k.as_bytes().to_vec());
        }
        if let Value::Table(inner) = v {
            for (k2, v2) in inner {
                let Value::String(k2) = k2 else { continue };
                if same(v2) {
                    let mut name = k.as_bytes().to_vec();
                    name.push(b'.');
                    name.extend_from_slice(k2.as_bytes());
                    if let Some(rest) = name.strip_prefix(b"_G.") {
                        return Some(rest.to_vec());
                    }
                    return Some(name);
                }
            }
        }
    }
    let _ = ctx;
    None
}

/// `pushfuncname`.
fn func_name<'gc>(
    ctx: Context<'gc>,
    loaded: Table<'gc>,
    function: Option<Function<'gc>>,
    info: &Info,
) -> Vec<u8> {
    if let Some(name) = function.and_then(|f| global_name(ctx, loaded, f)) {
        let mut out = b"function '".to_vec();
        out.extend_from_slice(&name);
        out.push(b'\'');
        return out;
    }
    match info.what {
        "main" => b"main chunk".to_vec(),
        "C" => b"?".to_vec(),
        _ => {
            let mut out = b"function <".to_vec();
            out.extend_from_slice(&info.short_src);
            out.extend_from_slice(format!(":{}>", info.linedefined).as_bytes());
            out
        }
    }
}

/// `debug.traceback([thread,] [message [, level]])`.
#[allow(clippy::arithmetic_side_effects)] // `arg` is 0 or 1; levels are bounded by the frames there are
fn traceback<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    stack: &mut Stack<'gc, '_>,
    loaded: Table<'gc>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let (thread, arg) = thread_arg(stack);
    let msg = stack.get(arg);
    // A message that is neither a string nor nil is returned untouched.
    let msg = match msg {
        Value::Nil => None,
        Value::String(s) => Some(s.as_bytes().to_vec()),
        Value::Integer(_) | Value::Number(_) => Some(
            msg.into_string(ctx)
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        other => {
            stack.replace(ctx, other);
            return Ok(CallbackReturn::Return);
        }
    };
    let level = {
        let args = LuaArgs { ctx, stack };
        match args.get(arg + 2) {
            None | Some(Value::Nil) => i64::from(thread.is_none()),
            Some(_) => args
                .check_integer(arg + 2)
                .map_err(|e| raise(ctx, "traceback", e))?,
        }
    };
    let frames = levels(&exec, thread);
    let mut out = Vec::new();
    if let Some(m) = msg {
        out.extend_from_slice(&m);
        out.push(b'\n');
    }
    out.extend_from_slice(b"stack traceback:");
    let last = frames.len().saturating_sub(1);
    let mut level = usize::try_from(level.max(0)).unwrap_or(usize::MAX);
    let mut limit = if last.saturating_sub(level) > LEVELS1 + LEVELS2 {
        Some(LEVELS1)
    } else {
        None
    };
    while let Some(frame) = frames.get(level) {
        level += 1;
        if limit == Some(0) {
            let n = last.saturating_sub(level).saturating_sub(LEVELS2) + 1;
            out.extend_from_slice(format!("\n\t...\t(skipping {n} levels)").as_bytes());
            level += n;
            limit = None;
            continue;
        }
        limit = limit.map(|l| l - 1);
        let info = Info::of(frame.function, frame.lua.map(|(_, l)| l));
        out.extend_from_slice(b"\n\t");
        out.extend_from_slice(&info.short_src);
        if info.currentline > 0 {
            out.extend_from_slice(format!(":{}", info.currentline).as_bytes());
        }
        out.extend_from_slice(b": in ");
        out.extend_from_slice(&func_name(ctx, loaded, frame.function, &info));
    }
    let s = ctx.intern(&out);
    stack.replace(ctx, s);
    Ok(CallbackReturn::Return)
}
