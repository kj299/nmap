//! The tail of the standard library NSE needs: `_G`, `rawequal`, `xpcall`,
//! `load`, `coroutine.wrap` and `string.rep`.
//!
//! These are bindings, not parsers. Each is a few lines of PUC-Lua
//! (`lbaselib.c`, `lcorolib.c`, `lstrlib.c`) whose behaviour is about the
//! interpreter — calling, resuming, compiling — so they are written against
//! the VM's public API here, and the one piece with byte-level work,
//! `string.rep`, is in [`super::strrep`].
//!
//! Two deliberate departures, both ledgered in DIVERGENCES.md with the
//! smaller differences at the edges (the `xpcall` handler's run count and
//! timing, messages):
//!
//! * `load` never loads precompiled bytecode. PUC-Lua has no bytecode
//!   verifier, so a crafted binary chunk is a memory-safety hole in the C,
//!   and this VM cannot load bytecode anyway; a binary chunk is refused as a
//!   load failure (`nil` and a message), even where the mode would allow it.
//! * `load`'s syntax-error messages are the VM compiler's, not `luac`'s.

use std::pin::Pin;

use gc_arena::{Collect, Gc};
use piccolo::closure::{CompilerError, UpValueState};
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Closure, Context, Error, Execution, Function, Sequence,
    SequencePoll, Stack, Thread, ThreadMode, Value,
};

use super::strpack::PackError;
use super::strrep::rep;
use super::{lua_error, string_table, type_error, LoadError, LuaArgs};

/// Installs `_G`, `rawequal`, `xpcall`, `load`, `coroutine.wrap` and
/// `string.rep` into `ctx`'s globals, replacing anything already there.
pub fn load_tail<'gc>(ctx: Context<'gc>) -> Result<(), LoadError> {
    let globals = ctx.globals();
    let string = string_table(ctx)?;
    let Value::Table(coroutine) = globals.get_value(ctx, "coroutine") else {
        return Err(LoadError::NoCoroutineTable);
    };

    // `luaopen_base` sets `_G._G = _G`.
    globals.set_field(ctx, "_G", globals);

    globals.set_field(ctx, "rawequal", Callback::from_fn(&ctx, rawequal));
    globals.set_field(ctx, "xpcall", Callback::from_fn(&ctx, xpcall));
    globals.set_field(ctx, "load", Callback::from_fn(&ctx, load));
    coroutine.set_field(ctx, "wrap", Callback::from_fn(&ctx, wrap));
    string.set_field(ctx, "rep", Callback::from_fn(&ctx, string_rep));
    Ok(())
}

/// Raise `e` as `luaL_argerror`/`luaL_error` would from function `name`.
fn raise<'gc>(ctx: Context<'gc>, name: &str, e: PackError) -> Error<'gc> {
    lua_error(ctx, &e.lua_message(name))
}

/// The address of a value the collector owns, for identity comparison.
fn address(v: Value<'_>) -> Option<usize> {
    use piccolo::Function as F;
    Some(match v {
        Value::String(s) => Gc::as_ptr(s.into_inner()) as *const () as usize,
        Value::Table(t) => Gc::as_ptr(t.into_inner()) as *const () as usize,
        Value::Function(F::Closure(c)) => Gc::as_ptr(c.into_inner()) as *const () as usize,
        Value::Function(F::Callback(c)) => Gc::as_ptr(c.into_inner()) as *const () as usize,
        Value::Thread(t) => Gc::as_ptr(t.into_inner()) as *const () as usize,
        Value::UserData(u) => Gc::as_ptr(u.into_inner()) as *const () as usize,
        _ => return None,
    })
}

/// `lua_rawequal` (`luaV_rawequalobj`): equality without metamethods. An
/// integer and a float are equal when the float converts to that integer
/// exactly; strings by content; everything else by identity.
fn raw_equal(a: Value<'_>, b: Value<'_>) -> bool {
    match (a, b) {
        (Value::Nil, Value::Nil) => true,
        (Value::Boolean(x), Value::Boolean(y)) => x == y,
        (Value::Integer(x), Value::Integer(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => x == y,
        (Value::Integer(i), Value::Number(f)) | (Value::Number(f), Value::Integer(i)) => {
            float_is_integer(f, i)
        }
        (Value::String(x), Value::String(y)) => x.as_bytes() == y.as_bytes(),
        (x, y) => match (address(x), address(y)) {
            (Some(p), Some(q)) => p == q && x.type_name() == y.type_name(),
            _ => false,
        },
    }
}

/// `luaV_flttointeger(f, &j, F2Ieq) && j == i`: `f` is exactly the integer `i`.
fn float_is_integer(f: f64, i: i64) -> bool {
    // -2^63 <= f < 2^63, and integral.
    (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f) && f == f.floor() && {
        #[allow(clippy::cast_possible_truncation)] // in range and integral, just checked
        let j = f as i64;
        j == i
    }
}

/// `rawequal(v1, v2)` (`lbaselib.c:149`).
fn rawequal<'gc>(
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    for arg in [1, 2] {
        if stack.len() < arg {
            return Err(raise(
                ctx,
                "rawequal",
                PackError::bad_argument(arg, "value expected"),
            ));
        }
    }
    let eq = raw_equal(stack.get(0), stack.get(1));
    stack.replace(ctx, eq);
    Ok(CallbackReturn::Return)
}

/// `xpcall(f, msgh, ...)` (`lbaselib.c:487`).
fn xpcall<'gc>(
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let handler = match stack.get(1) {
        Value::Function(h) if stack.len() >= 2 => h,
        _ => {
            let got = (stack.len() >= 2).then(|| stack.get(1));
            return Err(raise(ctx, "xpcall", type_error(got, 2, "function")));
        }
    };
    let f = stack.get(0);
    stack.remove(1);
    stack.pop_front();
    Ok(CallbackReturn::Sequence(BoxSequence::new(
        &ctx,
        XPcall {
            f,
            handler,
            stage: XStage::Start,
            runs: 0,
        },
    )))
}

#[derive(Collect, Clone, Copy, PartialEq, Eq)]
#[collect(require_static)]
enum XStage {
    /// The protected function has not been called yet.
    Start,
    /// It is running.
    Calling,
    /// It raised, and the handler is running on its error.
    Handling,
}

/// How many times the handler may run on one error before `xpcall` gives up
/// with "error in error handling". PUC-Lua passes an error raised *inside*
/// the handler back through the handler, recursively, until the C stack
/// overflows: `LUAI_MAXCCALLS / 10 * 11` nested C calls, less however many
/// the caller already holds (214 handler runs from a chunk called by `pcall`,
/// fewer deeper down). This port counts the runs instead, up to the C's ceiling.
const HANDLER_RUNS: u16 = 200 / 10 * 11;

/// The protected call of `xpcall`. The handler is called with the error and
/// its first result becomes the message. An error inside the handler is
/// handed to the handler again, and the first value a run of it returns is
/// the message; a handler that never returns ends in "error in error
/// handling".
#[derive(Collect)]
#[collect(no_drop)]
struct XPcall<'gc> {
    f: Value<'gc>,
    handler: Function<'gc>,
    stage: XStage,
    /// Handler runs started so far.
    #[collect(require_static)]
    runs: u16,
}

impl<'gc> Sequence<'gc> for XPcall<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        match this.stage {
            XStage::Start => match this.f {
                Value::Function(f) => {
                    this.stage = XStage::Calling;
                    Ok(SequencePoll::Call {
                        bottom: 0,
                        function: f,
                    })
                }
                other => {
                    // Calling a value that is not callable raises inside the
                    // protected call, so the handler sees it.
                    let callable = piccolo::meta_ops::call(ctx, other);
                    match callable {
                        Ok(f) => {
                            this.stage = XStage::Calling;
                            Ok(SequencePoll::Call {
                                bottom: 0,
                                function: f,
                            })
                        }
                        Err(_) => {
                            let msg = format!("attempt to call a {} value", other.type_name());
                            stack.replace(ctx, ctx.intern(msg.as_bytes()));
                            this.stage = XStage::Handling;
                            this.runs = 1;
                            Ok(SequencePoll::Call {
                                bottom: 0,
                                function: this.handler,
                            })
                        }
                    }
                }
            },
            XStage::Calling => {
                stack.push_front(Value::Boolean(true));
                Ok(SequencePoll::Return)
            }
            XStage::Handling => {
                let msg = stack.get(0);
                stack.replace(ctx, (false, msg));
                Ok(SequencePoll::Return)
            }
        }
    }

    fn error(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        error: Error<'gc>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        // From the protected function or from a run of the handler alike, the
        // error goes to the handler — until the C would have run out of stack.
        if this.runs >= HANDLER_RUNS {
            stack.replace(ctx, (false, "error in error handling"));
            return Ok(SequencePoll::Return);
        }
        this.runs = this.runs.saturating_add(1);
        stack.replace(ctx, error.to_value(ctx));
        this.stage = XStage::Handling;
        Ok(SequencePoll::Call {
            bottom: 0,
            function: this.handler,
        })
    }
}

/// `load(chunk [, chunkname [, mode [, env]]])` (`lbaselib.c:387`).
fn load<'gc>(
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let args = LuaArgs { ctx, stack: &stack };
    let opt_string = |arg: usize| -> Result<Option<Vec<u8>>, PackError> {
        match args.get(arg) {
            None | Some(Value::Nil) => Ok(None),
            Some(_) => args.string(arg).map(|s| Some(s.into_owned())),
        }
    };
    let mode = opt_string(3)
        .map_err(|e| raise(ctx, "load", e))?
        .unwrap_or_else(|| b"bt".to_vec());
    let env = args.get(4); // an explicit nil counts: `!lua_isnone(L, 4)`
    match args.get(1) {
        Some(Value::String(_) | Value::Integer(_) | Value::Number(_)) => {
            let chunk = args
                .string(1)
                .map_err(|e| raise(ctx, "load", e))?
                .into_owned();
            let name = opt_string(2)
                .map_err(|e| raise(ctx, "load", e))?
                .unwrap_or_else(|| chunk.clone());
            compile(ctx, &chunk, &name, &mode, env).push(ctx, &mut stack);
            Ok(CallbackReturn::Return)
        }
        Some(Value::Function(reader)) => {
            let name = opt_string(2)
                .map_err(|e| raise(ctx, "load", e))?
                .unwrap_or_else(|| b"=(load)".to_vec());
            stack.clear();
            Ok(CallbackReturn::Sequence(BoxSequence::new(
                &ctx,
                Reader {
                    reader,
                    env,
                    name,
                    mode,
                    chunk: Vec::new(),
                },
            )))
        }
        other => Err(raise(ctx, "load", type_error(other, 1, "function"))),
    }
}

/// `luaL_loadbufferx` and `load_aux`: the compiled chunk, or `nil` and a
/// message.
fn compile<'gc>(
    ctx: Context<'gc>,
    chunk: &[u8],
    name: &[u8],
    mode: &[u8],
    env: Option<Value<'gc>>,
) -> Loaded<'gc> {
    let fail = |msg: &[u8]| Loaded::Failed(Value::String(ctx.intern(msg)));
    // `f_parser`: a chunk is binary if its first byte is LUA_SIGNATURE[0].
    let binary = chunk.first() == Some(&0x1b);
    let (kind, letter) = if binary {
        ("binary", b'b')
    } else {
        ("text", b't')
    };
    // `checkmode` reads the mode as a C string.
    let mode = until_nul(mode);
    if !mode.contains(&letter) {
        let mut msg = format!("attempt to load a {kind} chunk (mode is '").into_bytes();
        msg.extend_from_slice(mode);
        msg.extend_from_slice(b"')");
        return fail(&msg);
    }
    if binary {
        return fail(b"attempt to load a binary chunk (this VM loads only text)");
    }
    let id = chunk_id(name);
    match Closure::load_with_env(
        ctx,
        Some(&String::from_utf8_lossy(c_name(name))),
        chunk,
        ctx.globals(),
    ) {
        Ok(closure) => {
            // `lua_setupvalue(L, -2, 1)`: any value, `nil` included.
            if let (Some(env), Some(up)) = (env, closure.upvalues().first()) {
                up.set(&ctx, UpValueState::Closed(env));
            }
            Loaded::Ok(Function::Closure(closure))
        }
        Err(e) => {
            // `luaG_addinfo`'s shape, `chunkid:line: message`; the message
            // itself is the VM compiler's wording, not `llex.c`'s.
            let (line, what) = match &e {
                CompilerError::Parsing(p) => (p.line_number, p.kind.to_string()),
                CompilerError::Compilation(c) => (c.line_number, c.kind.to_string()),
            };
            let mut msg = id;
            msg.extend_from_slice(format!(":{line}: {what}").as_bytes());
            fail(&msg)
        }
    }
}

/// What [`compile`] produced: `load` returns the function alone, or `nil` and
/// the message.
enum Loaded<'gc> {
    Ok(Function<'gc>),
    Failed(Value<'gc>),
}

impl<'gc> Loaded<'gc> {
    fn push(self, ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) {
        match self {
            Loaded::Ok(f) => stack.replace(ctx, f),
            Loaded::Failed(msg) => stack.replace(ctx, (Value::Nil, msg)),
        }
    }
}

/// The chunk name as `lua_load` stores it: the C string, raw. Errors name the
/// chunk through `luaO_chunkid` when they are raised.
fn c_name(name: &[u8]) -> &[u8] {
    until_nul(name)
}

/// The bytes of `s` before its first NUL: what C sees of a Lua string passed
/// as `const char *`.
fn until_nul(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// `luaO_chunkid`, which lives in the VM because its runtime errors need it too.
pub use piccolo::chunk_id::chunk_id;

/// `load` from a reader function (`generic_reader`): called until it returns
/// `nil` or an empty string, each piece appended.
#[derive(Collect)]
#[collect(no_drop)]
struct Reader<'gc> {
    reader: Function<'gc>,
    env: Option<Value<'gc>>,
    #[collect(require_static)]
    name: Vec<u8>,
    #[collect(require_static)]
    mode: Vec<u8>,
    #[collect(require_static)]
    chunk: Vec<u8>,
}

impl<'gc> Sequence<'gc> for Reader<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        // The first poll has an empty stack; later ones hold a piece.
        if !stack.is_empty() {
            // `lua_isstring`: a number is a piece too, converted.
            let piece = match stack.get(0) {
                v @ (Value::Integer(_) | Value::Number(_)) => {
                    v.into_string(ctx).map_or(v, Value::String)
                }
                v => v,
            };
            stack.clear();
            match piece {
                Value::Nil => {}
                Value::String(s) if !s.as_bytes().is_empty() => {
                    if this.chunk.try_reserve(s.as_bytes().len()).is_err() {
                        return Err(lua_error(ctx, "not enough memory"));
                    }
                    this.chunk.extend_from_slice(s.as_bytes());
                    return Ok(SequencePoll::Call {
                        bottom: 0,
                        function: this.reader,
                    });
                }
                Value::String(_) => {}
                _ => {
                    // `generic_reader` raises; `load` returns it as a failure.
                    stack.replace(ctx, (Value::Nil, "reader function must return a string"));
                    return Ok(SequencePoll::Return);
                }
            }
            compile(ctx, &this.chunk, &this.name, &this.mode, this.env).push(ctx, &mut stack);
            return Ok(SequencePoll::Return);
        }
        Ok(SequencePoll::Call {
            bottom: 0,
            function: this.reader,
        })
    }

    /// An error raised by the reader is caught by `lua_load`, and `load`
    /// returns it, whatever its type, after a `nil`.
    fn error(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        error: Error<'gc>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.replace(ctx, (Value::Nil, error.to_value(ctx)));
        Ok(SequencePoll::Return)
    }
}

/// `coroutine.wrap(f)` (`lcorolib.c`): a function that resumes a coroutine
/// running `f`, returns what it yields or returns, and propagates its errors.
fn wrap<'gc>(
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let f = match stack.get(0) {
        Value::Function(f) if !stack.is_empty() => f,
        _ => {
            let got = (!stack.is_empty()).then(|| stack.get(0));
            return Err(raise(ctx, "wrap", type_error(got, 1, "function")));
        }
    };
    let thread = Thread::new(ctx);
    thread
        .start_suspended(&ctx, f)
        .map_err(|e| lua_error(ctx, &e.to_string()))?;
    let resume = Callback::from_fn_with(&ctx, thread, |thread, ctx, _, _| {
        // `auxresume`'s checks, in the C's words.
        match thread.mode() {
            ThreadMode::Suspended => {}
            ThreadMode::Stopped => return Err(lua_error(ctx, "cannot resume dead coroutine")),
            _ => return Err(lua_error(ctx, "cannot resume non-suspended coroutine")),
        }
        // Never `then: None`. With nothing left to run in the caller, the
        // executor tail-calls a bare resume by *dropping the caller's thread*,
        // and the coroutine becomes the bottom of the thread stack: inside it,
        // `coroutine.running()` reports the main thread, and a `yield`
        // suspends the whole executor — which the NSE runtime would take for a
        // script waiting on I/O. A pass-through sequence keeps the caller's
        // frame, so the yield comes back here as the C's does.
        Ok(CallbackReturn::Resume {
            thread: *thread,
            then: Some(BoxSequence::new(&ctx, PassThrough)),
        })
    });
    stack.replace(ctx, resume);
    Ok(CallbackReturn::Return)
}

/// Returns what the resumed coroutine returned or yielded, and lets its
/// errors propagate: the default [`Sequence::error`].
#[derive(Collect)]
#[collect(require_static)]
struct PassThrough;

impl<'gc> Sequence<'gc> for PassThrough {
    fn poll(
        self: Pin<&mut Self>,
        _ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        _stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        Ok(SequencePoll::Return)
    }
}

/// `string.rep(s, n [, sep])` (`lstrlib.c:150`).
fn string_rep<'gc>(
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let out = {
        let args = LuaArgs { ctx, stack: &stack };
        let s = args.string(1).map_err(|e| raise(ctx, "rep", e))?;
        let n = args.check_integer(2).map_err(|e| raise(ctx, "rep", e))?;
        let sep = match args.get(3) {
            None | Some(Value::Nil) => Default::default(),
            Some(_) => args.string(3).map_err(|e| raise(ctx, "rep", e))?,
        };
        rep(&s, n, &sep).map_err(|e| lua_error(ctx, e.0))?
    };
    stack.replace(ctx, Value::String(ctx.intern(&out)));
    Ok(CallbackReturn::Return)
}

#[cfg(test)]
mod tests {
    //! The pure helpers directly, and each binding end to end through the VM —
    //! in-module, so that Miri runs them; the differential corpus reads from
    //! disk and cannot. One chunk per binding keeps the VM start-ups, which
    //! dominate under Miri, few.
    use super::{chunk_id, float_is_integer, raw_equal};
    use crate::nse::stdlib::tests::run;
    use piccolo::Value;

    fn s(v: &str) -> String {
        format!("{:?}", v.as_bytes())
    }

    #[test]
    fn chunk_ids_are_the_cs() {
        assert_eq!(chunk_id(b"=abc"), b"abc");
        assert_eq!(chunk_id(b"="), b"");
        assert_eq!(
            chunk_id(&[b"=".as_slice(), &[b'y'; 80]].concat()),
            [b'y'; 59]
        );
        assert_eq!(chunk_id(b"@file.lua"), b"file.lua");
        // "@" plus 59 bytes fits; one more and the tail is kept behind "...".
        let at60 = [b"@".as_slice(), &[b'a'; 58], b"Z"].concat();
        assert_eq!(chunk_id(&at60), &at60[1..]);
        let at61 = [b"@".as_slice(), &[b'a'; 59], b"Z"].concat();
        assert_eq!(
            chunk_id(&at61),
            [b"...".as_slice(), &[b'a'; 55], b"Z"].concat()
        );
        assert_eq!(chunk_id(b"return 1"), b"[string \"return 1\"]");
        // 44 bytes of text fit; 45 are cut to 45 and marked.
        assert_eq!(
            chunk_id(&[b's'; 44]),
            [b"[string \"".as_slice(), &[b's'; 44], b"\"]"].concat()
        );
        assert_eq!(
            chunk_id(&[b's'; 45]),
            [b"[string \"".as_slice(), &[b's'; 45], b"...\"]"].concat()
        );
        assert_eq!(chunk_id(b"ab\ncd"), b"[string \"ab...\"]");
        // The name is a C string: nothing after a NUL is seen.
        assert_eq!(chunk_id(b"ab\0c\nd"), b"[string \"ab\"]");
        assert_eq!(chunk_id(b"=ab\0cd"), b"ab");
    }

    #[test]
    fn raw_equality_of_numbers_is_exact() {
        assert!(raw_equal(Value::Integer(1), Value::Number(1.0)));
        assert!(raw_equal(Value::Number(-0.0), Value::Integer(0)));
        assert!(!raw_equal(Value::Number(0.5), Value::Integer(0)));
        assert!(!raw_equal(Value::Number(f64::NAN), Value::Number(f64::NAN)));
        // 2^63 is past every integer; maxinteger as a float rounds up to it.
        assert!(!raw_equal(
            Value::Integer(i64::MAX),
            Value::Number(9_223_372_036_854_775_808.0)
        ));
        assert!(raw_equal(
            Value::Integer(i64::MIN),
            Value::Number(-9_223_372_036_854_775_808.0)
        ));
        assert!(!float_is_integer(f64::INFINITY, i64::MAX));
        assert!(!raw_equal(Value::Nil, Value::Boolean(false)));
        assert!(raw_equal(Value::Nil, Value::Nil));
    }

    #[test]
    fn rawequal_and_g_through_the_vm() {
        let got = run(r#"
            local t = setmetatable({}, {__eq = function() return true end})
            local u = setmetatable({}, getmetatable(t))
            return rawequal(t, t), rawequal(t, u), t == u, rawequal("a" .. "b", "ab"),
                   _G._G == _G, select(2, pcall(rawequal, 1))
        "#);
        assert_eq!(
            got,
            Ok(vec![
                "boolean:true".into(),
                "boolean:false".into(),
                "boolean:true".into(),
                "boolean:true".into(),
                "boolean:true".into(),
                s("bad argument #2 to 'rawequal' (value expected)"),
            ])
        );
    }

    #[test]
    fn xpcall_through_the_vm() {
        let got = run(r#"
            local h = function(e) return "H:" .. tostring(e) end
            local a, b = xpcall(error, h, "boom", 0)
            local c, d = xpcall(error, function() error("again") end, "x")
            local e, f, g = xpcall(function(...) return ... end, h, 1, 2)
            local i, j = xpcall(nil, h)
            return a, b, c, d, e, f, g, i, j, select(2, pcall(xpcall, h))
        "#);
        assert_eq!(
            got,
            Ok(vec![
                "boolean:false".into(),
                s("H:boom"),
                "boolean:false".into(),
                s("error in error handling"),
                "boolean:true".into(),
                "number:1".into(),
                "number:2".into(),
                "boolean:false".into(),
                s("H:attempt to call a nil value"),
                s("bad argument #2 to 'xpcall' (function expected, got no value)"),
            ])
        );
    }

    #[test]
    fn wrap_through_the_vm() {
        let got = run(r#"
            local w = coroutine.wrap(function(a)
                local b = coroutine.yield(a + 1)
                local _, main = coroutine.running()
                return b * 2, main
            end)
            local x = w(1)
            local y, main = w(10)
            local ok, e = pcall(w)
            local t = coroutine.wrap(function() coroutine.yield("y") return "r" end)
            local function tail() return t() end
            return x, y, main, ok, e, tail(), tail()
        "#);
        assert_eq!(
            got,
            Ok(vec![
                "number:2".into(),
                "number:20".into(),
                "boolean:false".into(),
                "boolean:false".into(),
                s("cannot resume dead coroutine"),
                s("y"),
                s("r"),
            ])
        );
    }

    #[test]
    fn load_through_the_vm() {
        let got = run(r##"
            local parts, i = {"return ", 4, "0 + x"}, 0
            local f = load(function() i = i + 1 return parts[i] end, "=rdr", "t", {x = 2})
            local _, syn = load("(", "=name")
            local _, bin = load("\27Lua", "c", "t")
            local _, bc = load("\27Lua")
            local _, re = load(function() error("r", 0) end)
            return f(), select("#", load("return 1")), (syn:match("^name:1:")),
                   bin, bc, re, string.rep("ab", 3, "-"), select(2, pcall(string.rep, "x", 1 << 31))
        "##);
        assert_eq!(
            got,
            Ok(vec![
                "number:42".into(),
                "number:1".into(),
                s("name:1:"),
                s("attempt to load a binary chunk (mode is 't')"),
                s("attempt to load a binary chunk (this VM loads only text)"),
                s("r"),
                s("ab-ab-ab"),
                s("resulting string too large"),
            ])
        );
    }
}
