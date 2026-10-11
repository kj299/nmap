//! The base library NSE runs on (`lbaselib.c`), the coroutine library
//! (`lcorolib.c`), and the parts of the string and table libraries whose
//! behaviour is about the interpreter rather than about bytes: `string.rep`,
//! `string.char`, the string metatable's arithmetic metamethods, and the
//! argument checks of `table.insert`, `table.remove` and `table.concat`.
//!
//! These are bindings, not parsers. Each is a few lines of PUC-Lua
//! (`lbaselib.c`, `lcorolib.c`, `lstrlib.c`, `ltablib.c`) whose behaviour is
//! about the interpreter — calling, resuming, compiling, metatables — so they
//! are written against the VM's public API here, and the one piece with
//! byte-level work, `string.rep`, is in [`super::strrep`].
//!
//! They replace the vendored VM's own base and coroutine functions, which
//! answered in their own words ("type error, expected Table, found number"),
//! raised where the C returns (`pcall(nil)`), returned two values where the C
//! returns three (`pairs`, `ipairs`), and had no `warn`,
//! `coroutine.isyieldable` or `coroutine.close`. Every message is the C's,
//! and an error the C raises with `luaL_error` or `luaL_argerror` carries the
//! position `luaL_where(L, 1)` gives it: that of the Lua function that made the
//! call, which a call made by `pcall` directly does not have.
//!
//! What is left to the VM or to another module, and why, is in
//! DIVERGENCES.md under "the base and coroutine libraries": `print` (the `io`
//! binding),
//! `dofile` and `loadfile` (`require-searches-only-nselib`), `table.sort`
//! (`vm-sort-is-not-luas-quicksort`), the work of `table.insert`,
//! `table.remove` and `table.concat` after their checks.
//!
//! Deliberate departures, ledgered in DIVERGENCES.md with the smaller
//! differences at the edges (the `xpcall` handler's run count and timing,
//! messages):
//!
//! * `load` never loads precompiled bytecode. PUC-Lua has no bytecode
//!   verifier, so a crafted binary chunk is a memory-safety hole in the C,
//!   and this VM cannot load bytecode anyway; a binary chunk is refused as a
//!   load failure (`nil` and a message), even where the mode would allow it.
//! * `load`'s syntax-error messages are the VM compiler's, not `luac`'s.
//! * `collectgarbage` reports what the C would but drives no collector: the
//!   VM collects on its own schedule (`vm-collectgarbage-drives-no-collector`).

use std::cell::{Cell, RefCell};
use std::io::Write as _;
use std::pin::Pin;

use gc_arena::lock::RefLock;
use gc_arena::{Collect, Gc, GcWeak, Rootable};
use piccolo::closure::{CompilerError, UpValueState};
use piccolo::meta_ops::{self, MetaOperatorError, MetaResult};
use piccolo::table::NextValue;
use piccolo::thread::ThreadInner;
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Closure, Context, Error, Execution, Function, Sequence,
    SequencePoll, Singleton, Stack, Table, Thread, ThreadMode, Value,
};

use super::strpack::PackError;
use super::strrep::rep;
use super::{
    check_integer, lua_error, lua_error_bytes, string_table, type_error, LoadError, LuaArgs,
};

/// What a Rust function returns to the VM.
type Ret<'gc> = Result<CallbackReturn<'gc>, Error<'gc>>;

/// Installs the base library, the coroutine library, `string.rep`,
/// `string.char`, the string metatable's arithmetic metamethods and the
/// checks of `table.insert`, `table.remove` and `table.concat` into `ctx`'s
/// globals, replacing what the VM put there.
pub fn load_tail<'gc>(ctx: Context<'gc>) -> Result<(), LoadError> {
    let globals = ctx.globals();
    let string = string_table(ctx)?;
    let Value::Table(coroutine) = globals.get_value(ctx, "coroutine") else {
        return Err(LoadError::NoCoroutineTable);
    };

    // `luaopen_base` sets `_G._G = _G` and `_VERSION`.
    globals.set_field(ctx, "_G", globals);
    globals.set_field(ctx, "_VERSION", "Lua 5.4");

    globals.set_field(ctx, "assert", Callback::from_fn(&ctx, assert));
    globals.set_field(
        ctx,
        "collectgarbage",
        Callback::from_fn(&ctx, collectgarbage),
    );
    globals.set_field(ctx, "error", Callback::from_fn(&ctx, error));
    globals.set_field(ctx, "getmetatable", Callback::from_fn(&ctx, getmetatable));
    let aux = Callback::from_fn(&ctx, ipairsaux);
    globals.set_field(ctx, "ipairs", Callback::from_fn_with(&ctx, aux, ipairs));
    globals.set_field(ctx, "load", Callback::from_fn(&ctx, load));
    // `pairs` returns `luaB_next` itself: the very function `next` is.
    let next = Callback::from_fn(&ctx, next);
    globals.set_field(ctx, "next", next);
    globals.set_field(ctx, "pairs", Callback::from_fn_with(&ctx, next, pairs));
    globals.set_field(ctx, "pcall", Callback::from_fn(&ctx, pcall));
    globals.set_field(ctx, "rawequal", Callback::from_fn(&ctx, rawequal));
    globals.set_field(ctx, "rawget", Callback::from_fn(&ctx, rawget));
    globals.set_field(ctx, "rawlen", Callback::from_fn(&ctx, rawlen));
    globals.set_field(ctx, "rawset", Callback::from_fn(&ctx, rawset));
    globals.set_field(ctx, "select", Callback::from_fn(&ctx, select));
    globals.set_field(ctx, "setmetatable", Callback::from_fn(&ctx, setmetatable));
    globals.set_field(ctx, "tonumber", Callback::from_fn(&ctx, tonumber));
    globals.set_field(ctx, "tostring", Callback::from_fn(&ctx, tostring));
    globals.set_field(ctx, "type", Callback::from_fn(&ctx, type_of));
    globals.set_field(ctx, "warn", Callback::from_fn(&ctx, warn));
    globals.set_field(ctx, "xpcall", Callback::from_fn(&ctx, xpcall));

    coroutine.set_field(ctx, "close", Callback::from_fn(&ctx, co_close));
    coroutine.set_field(ctx, "create", Callback::from_fn(&ctx, co_create));
    coroutine.set_field(ctx, "isyieldable", Callback::from_fn(&ctx, co_isyieldable));
    coroutine.set_field(ctx, "resume", Callback::from_fn(&ctx, co_resume));
    coroutine.set_field(ctx, "running", Callback::from_fn(&ctx, co_running));
    coroutine.set_field(ctx, "status", Callback::from_fn(&ctx, co_status));
    coroutine.set_field(ctx, "wrap", Callback::from_fn(&ctx, wrap));

    string.set_field(ctx, "char", Callback::from_fn(&ctx, string_char));
    string.set_field(ctx, "rep", Callback::from_fn(&ctx, string_rep));
    // `lstrlib.c`'s `stringmetamethods`: the arithmetic the string metatable
    // offers, beside the `__index` the VM put there.
    let meta = meta_ops::string_metatable(ctx);
    for (event, op) in STRING_ARITH {
        meta.set_field(
            ctx,
            event,
            Callback::from_fn(&ctx, move |ctx, exec, stack| {
                string_arith(ctx, exec, stack, event, op)
            }),
        );
    }

    // The table functions keep the VM's work; their argument checks are the
    // C's, made before it starts.
    if let Value::Table(table) = globals.get_value(ctx, "table") {
        if let Value::Function(f) = table.get_value(ctx, "insert") {
            table.set_field(ctx, "insert", Callback::from_fn_with(&ctx, f, table_insert));
        }
        if let Value::Function(f) = table.get_value(ctx, "remove") {
            table.set_field(ctx, "remove", Callback::from_fn_with(&ctx, f, table_remove));
        }
        if let Value::Function(f) = table.get_value(ctx, "concat") {
            table.set_field(ctx, "concat", Callback::from_fn_with(&ctx, f, table_concat));
        }
    }
    Ok(())
}

/// Raise `e` as `luaL_argerror` (or `luaL_error`, for an error that names no
/// argument) raises it from function `name`: after `luaL_where(L, 1)`, the
/// position of the Lua function that called it, if a Lua function did.
fn arg_error<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    name: &str,
    e: PackError,
) -> Error<'gc> {
    positioned(ctx, exec, &e.lua_message(name))
}

/// `luaL_error(L, "%s", msg)`: `msg` after `luaL_where(L, 1)`.
fn positioned<'gc>(ctx: Context<'gc>, exec: &Execution<'gc, '_>, msg: &[u8]) -> Error<'gc> {
    let mut out = exec.where_at(1);
    out.extend_from_slice(msg);
    lua_error_bytes(ctx, &out)
}

/// An operator's error, raised from a Rust function as `luaG_runerror`
/// raises it from a C function: in its words, without a position.
fn operator_error<'gc>(ctx: Context<'gc>, e: &MetaOperatorError) -> Error<'gc> {
    lua_error(ctx, &e.to_string())
}

/// `luaL_checkany(L, arg)`: the argument, which must be there.
fn check_any<'gc>(stack: &Stack<'gc, '_>, arg: usize) -> Result<Value<'gc>, PackError> {
    arg.checked_sub(1)
        .filter(|&i| i < stack.len())
        .map(|i| stack.get(i))
        .ok_or_else(|| PackError::bad_argument(arg, "value expected"))
}

/// `luaL_checktype(L, arg, LUA_TTABLE)`.
fn check_table<'gc>(
    ctx: Context<'gc>,
    stack: &Stack<'gc, '_>,
    arg: usize,
) -> Result<Table<'gc>, PackError> {
    match (LuaArgs { ctx, stack }).get(arg) {
        Some(Value::Table(t)) => Ok(t),
        other => Err(type_error(ctx, other, arg, "table")),
    }
}

/// The metatable `lua_getmetatable` finds for `v`: a table's or a userdata's
/// own, and the one every string shares.
fn metatable_of<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<Table<'gc>> {
    match v {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        Value::String(_) => Some(meta_ops::string_metatable(ctx)),
        _ => None,
    }
}

/// `luaL_getmetafield(L, obj, event)`: the field of `v`'s metatable, read
/// raw, if it is not nil.
fn metafield<'gc>(ctx: Context<'gc>, v: Value<'gc>, event: &'static str) -> Option<Value<'gc>> {
    metatable_of(ctx, v)
        .map(|mt| mt.get_value(ctx, event))
        .filter(|f| !f.is_nil())
}

/// What a call of `v` calls. For a value that cannot be called, a function
/// that raises the VM's error for calling it: `luaD_call` raises that inside
/// the call, after the C level the call takes, so it is raised there here
/// too, and "C stack overflow" falls where it falls in C.
fn callable<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Function<'gc> {
    match meta_ops::call(ctx, v) {
        Ok(f) => f,
        Err(e) => {
            let msg = Value::String(ctx.intern(e.to_string().as_bytes()));
            Callback::from_fn_with(&ctx, msg, |msg, _, _, _| Err((*msg).into())).into()
        }
    }
}

/// The low 32 bits of `v`, as C's `(int)` cast keeps them.
fn c_int(v: i64) -> i32 {
    let b = v.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Returns the first `self.0` values of the call it follows, padded with
/// `nil`: `lua_call(L, n, self.0)`.
#[derive(Collect)]
#[collect(require_static)]
struct Results(usize);

impl<'gc> Sequence<'gc> for Results {
    fn poll(
        self: Pin<&mut Self>,
        _ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.resize(self.0);
        Ok(SequencePoll::Return)
    }
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
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    for arg in [1, 2] {
        check_any(&stack, arg).map_err(|e| arg_error(ctx, &exec, "rawequal", e))?;
    }
    let eq = raw_equal(stack.get(0), stack.get(1));
    stack.replace(ctx, eq);
    Ok(CallbackReturn::Return)
}

/// `rawlen(v)` (`lbaselib.c:157`): a table's raw border or a string's length.
fn rawlen<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let n = match (LuaArgs { ctx, stack: &stack }).get(1) {
        Some(Value::Table(t)) => t.length(),
        Some(Value::String(s)) => i64::try_from(s.as_bytes().len()).unwrap_or(i64::MAX),
        other => {
            let e = type_error(ctx, other, 1, "table or string");
            return Err(arg_error(ctx, &exec, "rawlen", e));
        }
    };
    stack.replace(ctx, n);
    Ok(CallbackReturn::Return)
}

/// `rawget(t, k)` (`lbaselib.c:166`).
fn rawget<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let fail = |e| arg_error(ctx, &exec, "rawget", e);
    let t = check_table(ctx, &stack, 1).map_err(fail)?;
    let k = check_any(&stack, 2).map_err(fail)?;
    stack.replace(ctx, t.get_raw(k));
    Ok(CallbackReturn::Return)
}

/// `rawset(t, k, v)` (`lbaselib.c:174`). A nil or NaN key is `luaH_newkey`'s
/// error, raised in the C function, so unpositioned.
fn rawset<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let fail = |e| arg_error(ctx, &exec, "rawset", e);
    let t = check_table(ctx, &stack, 1).map_err(fail)?;
    let k = check_any(&stack, 2).map_err(fail)?;
    let v = check_any(&stack, 3).map_err(fail)?;
    t.set_raw(&ctx, k, v)
        .map_err(|e| lua_error(ctx, &e.to_string()))?;
    stack.replace(ctx, t);
    Ok(CallbackReturn::Return)
}

/// `pcall(f, ...)` (`lbaselib.c:463`). A value that cannot be called fails
/// inside the protected call, so `pcall` returns `false` and the message.
fn pcall<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let f = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "pcall", e))?;
    stack.pop_front();
    // `lua_pcallk` takes a C level, as a call with a `then` does.
    Ok(CallbackReturn::Call {
        function: callable(ctx, f),
        then: Some(BoxSequence::new(&ctx, Protected)),
    })
}

/// `finishpcall`: `true` and the results, or `false` and the error.
#[derive(Collect)]
#[collect(require_static)]
struct Protected;

impl<'gc> Sequence<'gc> for Protected {
    fn poll(
        self: Pin<&mut Self>,
        _ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.push_front(Value::Boolean(true));
        Ok(SequencePoll::Return)
    }

    fn error(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        error: Error<'gc>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.replace(ctx, (false, error.to_value(ctx)));
        Ok(SequencePoll::Return)
    }
}

/// `xpcall(f, msgh, ...)` (`lbaselib.c:487`).
fn xpcall<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let handler = match stack.get(1) {
        Value::Function(h) if stack.len() >= 2 => h,
        _ => {
            let got = (stack.len() >= 2).then(|| stack.get(1));
            let e = type_error(ctx, got, 2, "function");
            return Err(arg_error(ctx, &exec, "xpcall", e));
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

/// A backstop on how many times the handler may run on one error. PUC-Lua
/// passes an error raised *inside* the handler back through the handler,
/// each run one C level above the error it handles, until the levels reach
/// `LUAI_MAXCCALLS / 10 * 11` and the call fails with "error in error
/// handling", which no handler sees: 214 runs from a chunk called by `pcall`,
/// fewer deeper down. The VM counts those levels the same way, so this bound,
/// the most runs any depth allows, is never what stops a handler.
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
        exec: Execution<'gc, '_>,
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
                    match piccolo::meta_ops::call(ctx, other) {
                        Ok(f) => {
                            this.stage = XStage::Calling;
                            Ok(SequencePoll::Call {
                                bottom: 0,
                                function: f,
                            })
                        }
                        Err(e) => {
                            // `luaG_callerror`, which names the value as
                            // `luaT_objtypename` does: by its `__name`.
                            stack.replace(ctx, ctx.intern(e.to_string().as_bytes()));
                            this.stage = XStage::Handling;
                            this.runs = 1;
                            // Raised by the call `lua_pcall` makes, one level
                            // up; the handler runs one above that.
                            Ok(SequencePoll::CallAt {
                                bottom: 0,
                                function: this.handler,
                                ccalls: exec.ccalls().saturating_add(2),
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
        exec: Execution<'gc, '_>,
        error: Error<'gc>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        // "not enough memory" and "error in error handling" are thrown past
        // the handler (`LUA_ERRMEM`, `LUA_ERRERR`).
        if ctx.bypasses_handler(&error) {
            stack.replace(ctx, (false, error.to_value(ctx)));
            return Ok(SequencePoll::Return);
        }
        // From the protected function or from a run of the handler alike, the
        // error goes to the handler — until the C would have run out of stack.
        if this.runs >= HANDLER_RUNS {
            stack.replace(ctx, (false, "error in error handling"));
            return Ok(SequencePoll::Return);
        }
        this.runs = this.runs.saturating_add(1);
        stack.replace(ctx, error.to_value(ctx));
        this.stage = XStage::Handling;
        // `luaG_errormsg` calls the handler one level above the error.
        Ok(SequencePoll::CallAt {
            bottom: 0,
            function: this.handler,
            ccalls: exec.error_ccalls().saturating_add(1),
        })
    }
}

/// `next(t [, k])` (`lbaselib.c:262`): the next key and its value, or one
/// `nil` past the last.
fn next<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let t = check_table(ctx, &stack, 1).map_err(|e| arg_error(ctx, &exec, "next", e))?;
    let key = stack.get(1);
    // `findindex` looks a float key up as a float, and no table holds one
    // with an integral value (`luaH_set` stores those as integers): so
    // `next(t, 1.0)` is an invalid key even where `t[1]` is there.
    if let Value::Number(f) = key {
        if f == f.floor()
            && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f)
        {
            return Err(lua_error(ctx, "invalid key to 'next'"));
        }
    }
    match t.next(key) {
        NextValue::Found { key, value } => stack.replace(ctx, (key, value)),
        NextValue::Last => stack.replace(ctx, Value::Nil),
        // `luaH_next`'s `luaG_runerror`, raised in the C function.
        NextValue::NotFound => return Err(lua_error(ctx, "invalid key to 'next'")),
    }
    Ok(CallbackReturn::Return)
}

/// `pairs(v)` (`lbaselib.c:284`): `next, v, nil`, or the first three values
/// `__pairs` returns, padded with `nil`.
fn pairs<'gc>(
    next: &Callback<'gc>,
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let v = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "pairs", e))?;
    match metafield(ctx, v, "__pairs") {
        None => {
            stack.replace(ctx, (*next, v, Value::Nil));
            Ok(CallbackReturn::Return)
        }
        Some(mm) => {
            stack.replace(ctx, v);
            Ok(CallbackReturn::Call {
                function: callable(ctx, mm),
                then: Some(BoxSequence::new(&ctx, Results(3))),
            })
        }
    }
}

/// `ipairs(v)` (`lbaselib.c:313`): `ipairsaux, v, 0`, for any value.
fn ipairs<'gc>(
    aux: &Callback<'gc>,
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let v = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "ipairs", e))?;
    stack.replace(ctx, (*aux, v, 0_i64));
    Ok(CallbackReturn::Return)
}

/// `ipairsaux(v, i)` (`lbaselib.c:302`): `i + 1` and `v[i + 1]`, read with
/// metamethods (`lua_geti`), or one `nil` when that is nil. The C function
/// has no name of its own; `luaL_argerror` finds none for it.
fn ipairsaux<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let i = (LuaArgs { ctx, stack: &stack })
        .check_integer(2)
        .map_err(|e| arg_error(ctx, &exec, "?", e))?
        .wrapping_add(1);
    match meta_ops::index(ctx, stack.get(0), Value::Integer(i))
        .map_err(|e| operator_error(ctx, &e))?
    {
        MetaResult::Value(v) => {
            if v.is_nil() {
                stack.replace(ctx, Value::Nil);
            } else {
                stack.replace(ctx, (i, v));
            }
            Ok(CallbackReturn::Return)
        }
        MetaResult::Call(call) => {
            stack.clear();
            stack.extend(call.args);
            Ok(CallbackReturn::Call {
                function: call.function,
                then: Some(BoxSequence::new(&ctx, IpairsValue(i))),
            })
        }
    }
}

/// The end of `ipairsaux` once `__index` has answered for `self.0`.
#[derive(Collect)]
#[collect(require_static)]
struct IpairsValue(i64);

impl<'gc> Sequence<'gc> for IpairsValue {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let v = stack.get(0);
        if v.is_nil() {
            stack.replace(ctx, Value::Nil);
        } else {
            stack.replace(ctx, (self.0, v));
        }
        Ok(SequencePoll::Return)
    }
}

/// `select(n, ...)` (`lbaselib.c:446`).
fn select<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let n = stack.len();
    // `*lua_tostring(L, 1) == '#'`: only the first byte counts.
    if let Value::String(s) = stack.get(0) {
        if s.as_bytes().first() == Some(&b'#') {
            stack.replace(ctx, i64::try_from(n.saturating_sub(1)).unwrap_or(i64::MAX));
            return Ok(CallbackReturn::Return);
        }
    }
    let fail = |e| arg_error(ctx, &exec, "select", e);
    let i = (LuaArgs { ctx, stack: &stack })
        .check_integer(1)
        .map_err(fail)?;
    let top = i64::try_from(n).unwrap_or(i64::MAX);
    let i = if i < 0 {
        top.saturating_add(i)
    } else {
        i.min(top)
    };
    if i < 1 {
        return Err(fail(PackError::bad_argument(1, "index out of range")));
    }
    stack.drain(..usize::try_from(i).unwrap_or(n));
    Ok(CallbackReturn::Return)
}

/// `type(v)` (`lbaselib.c:254`).
fn type_of<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let v = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "type", e))?;
    stack.replace(ctx, v.type_name());
    Ok(CallbackReturn::Return)
}

/// `tostring(v)` (`lbaselib.c:507`), which is `luaL_tolstring`: a
/// `__tostring` metafield is called, and must give a string or a number;
/// otherwise the VM's own text.
fn tostring<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let v = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "tostring", e))?;
    if let Some(mm) = metafield(ctx, v, "__tostring") {
        stack.replace(ctx, v);
        return Ok(CallbackReturn::Call {
            function: callable(ctx, mm),
            then: Some(BoxSequence::new(&ctx, ToStringResult)),
        });
    }
    match meta_ops::tostring(ctx, v).map_err(|e| operator_error(ctx, &e))? {
        MetaResult::Value(s) => {
            stack.replace(ctx, s);
            Ok(CallbackReturn::Return)
        }
        // Only a `__tostring` asks for a call, and there is none.
        MetaResult::Call(call) => {
            stack.clear();
            stack.extend(call.args);
            Ok(CallbackReturn::Call {
                function: call.function,
                then: Some(BoxSequence::new(&ctx, ToStringResult)),
            })
        }
    }
}

/// The end of `luaL_tolstring` after `__tostring`: its first result, which
/// must be a string, or a number, which `lua_tolstring` converts.
#[derive(Collect)]
#[collect(require_static)]
struct ToStringResult;

impl<'gc> Sequence<'gc> for ToStringResult {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let r = stack.get(0);
        let s = match r {
            Value::String(_) => r,
            Value::Integer(_) | Value::Number(_) => r.into_string(ctx).map_or(r, Value::String),
            _ => return Err(positioned(ctx, &exec, b"'__tostring' must return a string")),
        };
        stack.replace(ctx, s);
        Ok(SequencePoll::Return)
    }
}

/// `tonumber(v [, base])` (`lbaselib.c:76`).
fn tonumber<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let args = LuaArgs { ctx, stack: &stack };
    let fail = |e| arg_error(ctx, &exec, "tonumber", e);
    let result = match args.get(2) {
        None | Some(Value::Nil) => match args.get(1) {
            Some(v @ (Value::Integer(_) | Value::Number(_))) => v,
            // `lua_stringtonumber`: the whole string, as the VM converts it.
            Some(v @ Value::String(_)) => v.to_numeric().unwrap_or(Value::Nil),
            Some(_) => Value::Nil,
            None => return Err(fail(PackError::bad_argument(1, "value expected"))),
        },
        Some(_) => {
            let base = args.check_integer(2).map_err(fail)?;
            let s = match args.get(1) {
                Some(Value::String(s)) => s,
                other => return Err(fail(type_error(ctx, other, 1, "string"))),
            };
            if !(2..=36).contains(&base) {
                return Err(fail(PackError::bad_argument(2, "base out of range")));
            }
            str2int(s.as_bytes(), base).map_or(Value::Nil, Value::Integer)
        }
    };
    stack.replace(ctx, result);
    Ok(CallbackReturn::Return)
}

/// `b_str2int` (`lbaselib.c:49`): `s`, all of it, as an integer numeral in
/// `base` with optional spaces and sign around it, wrapping as `lua_Unsigned`
/// arithmetic wraps. `None` where the C answers `fail`.
fn str2int(s: &[u8], base: i64) -> Option<i64> {
    fn spaces(mut s: &[u8]) -> &[u8] {
        // `SPACECHARS`.
        while let [b' ' | b'\x0c' | b'\n' | b'\r' | b'\t' | b'\x0b', rest @ ..] = s {
            s = rest;
        }
        s
    }
    let base = u64::try_from(base).ok()?;
    let mut s = spaces(s);
    let neg = match s {
        [b'-', rest @ ..] => {
            s = rest;
            true
        }
        [b'+', rest @ ..] => {
            s = rest;
            false
        }
        _ => false,
    };
    if !s.first().is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    let mut n: u64 = 0;
    while let [c, rest @ ..] = s {
        if !c.is_ascii_alphanumeric() {
            break;
        }
        let digit = if c.is_ascii_digit() {
            u64::from(c.wrapping_sub(b'0'))
        } else {
            u64::from(c.to_ascii_uppercase().wrapping_sub(b'A')).wrapping_add(10)
        };
        if digit >= base {
            return None;
        }
        n = n.wrapping_mul(base).wrapping_add(digit);
        s = rest;
    }
    if !spaces(s).is_empty() {
        return None;
    }
    let n = if neg { 0_u64.wrapping_sub(n) } else { n };
    Some(i64::from_le_bytes(n.to_le_bytes()))
}

/// `getmetatable(v)` (`lbaselib.c:125`): a `__metatable` field stands in for
/// the metatable.
fn getmetatable<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let v = check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "getmetatable", e))?;
    let mt = match metatable_of(ctx, v) {
        None => Value::Nil,
        Some(mt) => match mt.get_value(ctx, "__metatable") {
            Value::Nil => Value::Table(mt),
            protected => protected,
        },
    };
    stack.replace(ctx, mt);
    Ok(CallbackReturn::Return)
}

/// `setmetatable(t, mt)` (`lbaselib.c:136`): refused for a table whose
/// metatable has a `__metatable` field.
fn setmetatable<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let args = LuaArgs { ctx, stack: &stack };
    let fail = |e| arg_error(ctx, &exec, "setmetatable", e);
    let t = match args.get(1) {
        Some(Value::Table(t)) => t,
        other => return Err(fail(type_error(ctx, other, 1, "table"))),
    };
    let mt = match args.get(2) {
        Some(Value::Nil) => None,
        Some(Value::Table(mt)) => Some(mt),
        other => return Err(fail(type_error(ctx, other, 2, "nil or table"))),
    };
    if metafield(ctx, Value::Table(t), "__metatable").is_some() {
        return Err(positioned(
            ctx,
            &exec,
            b"cannot change a protected metatable",
        ));
    }
    t.set_metatable(&ctx, mt);
    stack.replace(ctx, t);
    Ok(CallbackReturn::Return)
}

/// The collector settings `collectgarbage` reports, kept as `lua_gc` keeps
/// them: stopped or not, the mode, and the pause and step multiplier, each
/// stored as `setgcparam` stores it — a quarter of the value, in a byte.
#[derive(Collect)]
#[collect(require_static)]
struct GcSettings {
    stopped: Cell<bool>,
    generational: Cell<bool>,
    pause: Cell<u8>,
    stepmul: Cell<u8>,
}

/// `LUAI_GCPAUSE` and `LUAI_GCMUL` (`lgc.h`).
const GC_PAUSE: i32 = 200;
const GC_STEPMUL: i32 = 100;

/// `setgcparam(p, v)`: `v / 4`, in a `lu_byte`.
fn gc_param(v: i32) -> u8 {
    v.wrapping_div(4).to_le_bytes()[0]
}

/// `getgcparam(p)`: `p * 4`.
fn gc_param_value(p: u8) -> i64 {
    i64::from(p).wrapping_mul(4)
}

impl Default for GcSettings {
    fn default() -> Self {
        GcSettings {
            stopped: Cell::new(false),
            generational: Cell::new(false),
            pause: Cell::new(gc_param(GC_PAUSE)),
            stepmul: Cell::new(gc_param(GC_STEPMUL)),
        }
    }
}

/// `collectgarbage([opt [, ...]])` (`lbaselib.c:203`). Each option answers
/// what `lua_gc` would; `"count"` is the VM's heap. The collector itself is
/// the VM's, which runs on its own schedule: `"collect"` and `"step"` do no
/// collecting, and `"stop"` stops none (`vm-collectgarbage-drives-no-collector`).
fn collectgarbage<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    const OPTIONS: [&str; 10] = [
        "stop",
        "restart",
        "collect",
        "count",
        "step",
        "setpause",
        "setstepmul",
        "isrunning",
        "generational",
        "incremental",
    ];
    let args = LuaArgs { ctx, stack: &stack };
    let fail = |e| arg_error(ctx, &exec, "collectgarbage", e);
    // `luaL_checkoption(L, 1, "collect", opts)`, which compares C strings.
    let given = match args.get(1) {
        None | Some(Value::Nil) => b"collect".to_vec(),
        Some(_) => args.string(1).map_err(fail)?.into_owned(),
    };
    let name = until_nul(&given);
    let Some(&option) = OPTIONS.iter().find(|o| o.as_bytes() == name) else {
        let mut msg = b"invalid option '".to_vec();
        msg.extend_from_slice(name);
        msg.push(b'\'');
        return Err(fail(PackError::bad_argument(1, msg)));
    };
    // `(int)luaL_optinteger(L, arg, 0)`.
    let opt_int = |arg| args.opt_integer(arg, 0).map(c_int).map_err(fail);
    let gc = ctx.singleton::<Rootable![GcSettings]>();
    let mode = |gc: &GcSettings| {
        if gc.generational.get() {
            "generational"
        } else {
            "incremental"
        }
    };
    let result: Value<'gc> = match option {
        "stop" => {
            gc.stopped.set(true);
            Value::Integer(0)
        }
        "restart" => {
            gc.stopped.set(false);
            Value::Integer(0)
        }
        "count" => {
            #[allow(clippy::cast_precision_loss)] // as `(lua_Number)k + b/1024`
            let kb = ctx.metrics().total_allocation() as f64 / 1024.0;
            Value::Number(kb)
        }
        "step" => {
            opt_int(2)?;
            // `lua_gc(L, LUA_GCSTEP)` says whether the step finished a cycle;
            // there is no cycle here to finish.
            Value::Boolean(false)
        }
        "setpause" => {
            let v = opt_int(2)?;
            let previous = gc_param_value(gc.pause.replace(gc_param(v)));
            Value::Integer(previous)
        }
        "setstepmul" => {
            let v = opt_int(2)?;
            let previous = gc_param_value(gc.stepmul.replace(gc_param(v)));
            Value::Integer(previous)
        }
        "isrunning" => Value::Boolean(!gc.stopped.get()),
        "generational" => {
            opt_int(2)?;
            opt_int(3)?;
            let previous = mode(gc);
            gc.generational.set(true);
            Value::String(ctx.intern_static(previous.as_bytes()))
        }
        "incremental" => {
            let pause = opt_int(2)?;
            let stepmul = opt_int(3)?;
            opt_int(4)?;
            let previous = mode(gc);
            if pause != 0 {
                gc.pause.set(gc_param(pause));
            }
            if stepmul != 0 {
                gc.stepmul.set(gc_param(stepmul));
            }
            gc.generational.set(false);
            Value::String(ctx.intern_static(previous.as_bytes()))
        }
        // "collect": `lua_gc` returns 0.
        _ => Value::Integer(0),
    };
    stack.replace(ctx, result);
    Ok(CallbackReturn::Return)
}

/// `assert(v [, message, ...])` (`lbaselib.c:431`): all its arguments when
/// `v` is true; otherwise `error(message)`, `message` defaulting to
/// "assertion failed!" only when there is no second argument at all.
fn assert<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, stack: Stack<'gc, '_>) -> Ret<'gc> {
    if stack.get(0).to_bool() {
        return Ok(CallbackReturn::Return);
    }
    check_any(&stack, 1).map_err(|e| arg_error(ctx, &exec, "assert", e))?;
    let msg = if stack.len() >= 2 {
        stack.get(1)
    } else {
        Value::String(ctx.intern_static(b"assertion failed!"))
    };
    Err(raise_value(ctx, &exec, msg, 1))
}

/// `error(message [, level])` (`lbaselib.c:113`).
fn error<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, stack: Stack<'gc, '_>) -> Ret<'gc> {
    let level = (LuaArgs { ctx, stack: &stack })
        .opt_integer(2, 1)
        .map_err(|e| arg_error(ctx, &exec, "error", e))?;
    Err(raise_value(ctx, &exec, stack.get(0), c_int(level)))
}

/// `luaB_error`'s raise: a string message after the position of the function
/// `level` calls up (`luaL_where(L, level)`); any other value as it is.
fn raise_value<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    msg: Value<'gc>,
    level: i32,
) -> Error<'gc> {
    if let Value::String(s) = msg {
        if let Some(level) = usize::try_from(level).ok().filter(|&l| l > 0) {
            let mut out = exec.where_at(level);
            if !out.is_empty() {
                out.extend_from_slice(s.as_bytes());
                return lua_error_bytes(ctx, &out);
            }
        }
    }
    Error::from(msg)
}

/// The warning system of a state made by `luaL_newstate`, as nmap 7.94 makes
/// its own: off until a `"@on"` control message, then each warning written
/// as `"Lua warning: "`, its pieces and a newline (`lauxlib.c`'s `warnfon`).
#[derive(Collect, Default)]
#[collect(require_static)]
struct Warnings {
    on: Cell<bool>,
    /// Where warnings go; the process's standard error when unset.
    #[allow(clippy::type_complexity)]
    sink: RefCell<Option<Box<dyn FnMut(&[u8])>>>,
}

/// Send `warn`'s output for `ctx`'s state to `sink` instead of the process's
/// standard error, where `lua_writestringerror` writes it.
pub fn set_warning_sink(ctx: Context<'_>, sink: impl FnMut(&[u8]) + 'static) {
    *ctx.singleton::<Rootable![Warnings]>().sink.borrow_mut() = Some(Box::new(sink));
}

/// `warn(msg1, ...)` (`lbaselib.c:45`): every argument is checked before any
/// is written, and the pieces make one message.
fn warn<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let pieces = {
        let args = LuaArgs { ctx, stack: &stack };
        (1..=stack.len().max(1))
            .map(|i| args.string(i).map_err(|e| arg_error(ctx, &exec, "warn", e)))
            .collect::<Result<Vec<_>, _>>()?
    };
    let w = ctx.singleton::<Rootable![Warnings]>();
    let mut out = Vec::new();
    // `warnfcont`: inside a message, a piece is written as it is.
    let mut continuing = false;
    let last = pieces.len().saturating_sub(1);
    for (i, piece) in pieces.iter().enumerate() {
        let tocont = i < last;
        // Each piece is handed on as a C string.
        let piece = until_nul(piece);
        if continuing {
            out.extend_from_slice(piece);
        } else if let (false, [b'@', control @ ..]) = (tocont, piece) {
            // `checkcontrol`: a message of one piece starting with '@'.
            match control {
                b"on" => w.on.set(true),
                b"off" => w.on.set(false),
                _ => {}
            }
            continue;
        } else if w.on.get() {
            out.extend_from_slice(b"Lua warning: ");
            out.extend_from_slice(piece);
            continuing = true;
        } else {
            continue;
        }
        if !tocont {
            out.push(b'\n');
            continuing = false;
        }
    }
    if !out.is_empty() {
        match w.sink.borrow_mut().as_mut() {
            Some(sink) => sink(&out),
            None => {
                // `lua_writestringerror`: `fprintf` and `fflush`, unchecked.
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(&out);
                let _ = err.flush();
            }
        }
    }
    stack.clear();
    Ok(CallbackReturn::Return)
}

/// `load(chunk [, chunkname [, mode [, env]]])` (`lbaselib.c:387`).
fn load<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let args = LuaArgs { ctx, stack: &stack };
    let fail = |e| arg_error(ctx, &exec, "load", e);
    let opt_string = |arg: usize| -> Result<Option<Vec<u8>>, PackError> {
        match args.get(arg) {
            None | Some(Value::Nil) => Ok(None),
            Some(_) => args.string(arg).map(|s| Some(s.into_owned())),
        }
    };
    let mode = opt_string(3)
        .map_err(fail)?
        .unwrap_or_else(|| b"bt".to_vec());
    let env = args.get(4); // an explicit nil counts: `!lua_isnone(L, 4)`
    match args.get(1) {
        Some(Value::String(_) | Value::Integer(_) | Value::Number(_)) => {
            let chunk = args.string(1).map_err(fail)?.into_owned();
            let name = opt_string(2)
                .map_err(fail)?
                .unwrap_or_else(|| chunk.clone());
            compile(ctx, &chunk, &name, &mode, env).push(ctx, &mut stack);
            Ok(CallbackReturn::Return)
        }
        Some(Value::Function(reader)) => {
            let name = opt_string(2)
                .map_err(fail)?
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
        other => Err(fail(type_error(ctx, other, 1, "function"))),
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
        exec: Execution<'gc, '_>,
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
                    if !super::reserve(&mut this.chunk, s.as_bytes().len()) {
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
                    // `generic_reader` raises with `luaL_error`, positioned at
                    // `load`'s caller; `load` returns it as a failure.
                    let mut msg = exec.where_at(1);
                    msg.extend_from_slice(b"reader function must return a string");
                    stack.replace(ctx, (Value::Nil, Value::String(ctx.intern(&msg))));
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

/// What the coroutine library keeps about threads it cannot ask the VM: the
/// threads `coroutine.running` has found to be a state's main thread, and
/// the error each coroutine that died of one died with, until it is closed.
/// Both hold their threads weakly, so that neither keeps a thread alive.
#[derive(Collect, Clone, Copy)]
#[collect(no_drop)]
struct Coroutines<'gc> {
    mains: Gc<'gc, RefLock<Vec<WeakThread<'gc>>>>,
    errors: Gc<'gc, RefLock<Vec<(WeakThread<'gc>, Value<'gc>)>>>,
}

/// A thread, held weakly.
type WeakThread<'gc> = GcWeak<'gc, ThreadInner<'gc>>;

impl<'gc> Singleton<'gc> for Coroutines<'gc> {
    fn create(ctx: Context<'gc>) -> Self {
        Coroutines {
            mains: Gc::new(&ctx, RefLock::new(Vec::new())),
            errors: Gc::new(&ctx, RefLock::new(Vec::new())),
        }
    }
}

fn coroutines<'gc>(ctx: Context<'gc>) -> Coroutines<'gc> {
    *ctx.singleton::<Rootable![Coroutines<'_>]>()
}

/// Whether `w` is `t`. A weak pointer keeps its allocation, so no other
/// thread can have the address while `w` exists.
fn is_thread<'gc>(w: WeakThread<'gc>, t: Thread<'gc>) -> bool {
    std::ptr::eq(w.as_ptr(), Gc::as_ptr(t.into_inner()))
}

/// `true` and the `then` of a resume: `lua_resume`'s results, or `false` and
/// the error. A coroutine that died of the error keeps it for `close`
/// (`luaD_seterrorobj` leaves it on the coroutine's stack).
#[derive(Collect)]
#[collect(no_drop)]
struct Resumed<'gc> {
    co: Thread<'gc>,
}

impl<'gc> Sequence<'gc> for Resumed<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        _ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.push_front(Value::Boolean(true));
        Ok(SequencePoll::Return)
    }

    fn error(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        error: Error<'gc>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let error = error.to_value(ctx);
        // An error raised before the coroutine ran ("C stack overflow")
        // leaves it suspended.
        if self.co.mode() == ThreadMode::Stopped {
            let mut errors = coroutines(ctx).errors.borrow_mut(&ctx);
            errors.retain(|(w, _)| w.upgrade(&ctx).is_some());
            errors.push((Gc::downgrade(self.co.into_inner()), error));
        }
        stack.replace(ctx, (false, error));
        Ok(SequencePoll::Return)
    }
}

/// `getco`: argument 1, which must be a thread.
fn get_co<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    stack: &Stack<'gc, '_>,
    name: &str,
) -> Result<Thread<'gc>, Error<'gc>> {
    match (LuaArgs { ctx, stack }).get(1) {
        Some(Value::Thread(t)) => Ok(t),
        other => Err(arg_error(
            ctx,
            exec,
            name,
            type_error(ctx, other, 1, "thread"),
        )),
    }
}

/// `auxstatus`'s answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CoStatus {
    Running,
    Dead,
    Suspended,
    Normal,
}

impl CoStatus {
    fn name(self) -> &'static str {
        match self {
            CoStatus::Running => "running",
            CoStatus::Dead => "dead",
            CoStatus::Suspended => "suspended",
            CoStatus::Normal => "normal",
        }
    }
}

/// `auxstatus(L, co)` (`lcorolib.c:118`): running if it is the caller;
/// otherwise suspended, dead, or normal — active but waiting on a coroutine
/// it resumed.
fn co_status_of<'gc>(exec: &Execution<'gc, '_>, co: Thread<'gc>) -> CoStatus {
    if co == exec.current_thread().thread {
        return CoStatus::Running;
    }
    match co.mode() {
        ThreadMode::Stopped => CoStatus::Dead,
        ThreadMode::Suspended | ThreadMode::Result => CoStatus::Suspended,
        ThreadMode::Normal | ThreadMode::Waiting => CoStatus::Normal,
        ThreadMode::Running => CoStatus::Running,
    }
}

/// `coroutine.create(f)` (`lcorolib.c:90`): `f` must be a function.
fn co_create<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let f = match (LuaArgs { ctx, stack: &stack }).get(1) {
        Some(Value::Function(f)) => f,
        other => {
            let e = type_error(ctx, other, 1, "function");
            return Err(arg_error(ctx, &exec, "create", e));
        }
    };
    let thread = Thread::new(ctx);
    thread
        .start_suspended(&ctx, f)
        .map_err(|e| lua_error(ctx, &e.to_string()))?;
    stack.replace(ctx, thread);
    Ok(CallbackReturn::Return)
}

/// `coroutine.resume(co, ...)` (`lcorolib.c:56`): `true` and what it yields or
/// returns, or `false` and why not.
fn co_resume<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let co = get_co(ctx, &exec, &stack, "resume")?;
    stack.pop_front();
    // `lua_resume`'s checks.
    match co.mode() {
        ThreadMode::Suspended => Ok(CallbackReturn::Resume {
            thread: co,
            then: Some(BoxSequence::new(&ctx, Resumed { co })),
        }),
        ThreadMode::Stopped => {
            stack.replace(ctx, (false, "cannot resume dead coroutine"));
            Ok(CallbackReturn::Return)
        }
        _ => {
            stack.replace(ctx, (false, "cannot resume non-suspended coroutine"));
            Ok(CallbackReturn::Return)
        }
    }
}

/// `coroutine.status(co)` (`lcorolib.c:139`).
fn co_status<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let co = get_co(ctx, &exec, &stack, "status")?;
    stack.replace(ctx, co_status_of(&exec, co).name());
    Ok(CallbackReturn::Return)
}

/// `coroutine.running()` (`lcorolib.c:153`). A main thread it reports is
/// remembered, for `isyieldable`: no Lua code can hold one any other way.
fn co_running<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let current = exec.current_thread();
    if current.is_main {
        let mut mains = coroutines(ctx).mains.borrow_mut(&ctx);
        mains.retain(|w| w.upgrade(&ctx).is_some());
        if !mains.iter().any(|&w| is_thread(w, current.thread)) {
            mains.push(Gc::downgrade(current.thread.into_inner()));
        }
    }
    stack.replace(ctx, (current.thread, current.is_main));
    Ok(CallbackReturn::Return)
}

/// `coroutine.isyieldable([co])` (`lcorolib.c:146`): whether `co`, the
/// running coroutine by default, may yield. Every call into Lua may yield in
/// this VM, so that is whether it is not a main thread.
fn co_isyieldable<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let current = exec.current_thread();
    let yieldable = if stack.is_empty() {
        !current.is_main
    } else {
        let co = get_co(ctx, &exec, &stack, "isyieldable")?;
        if co == current.thread {
            !current.is_main
        } else {
            !coroutines(ctx)
                .mains
                .borrow()
                .iter()
                .any(|&w| is_thread(w, co))
        }
    };
    stack.replace(ctx, yieldable);
    Ok(CallbackReturn::Return)
}

/// `coroutine.close(co)` (`lcorolib.c:160`): a suspended or dead coroutine is
/// closed, returning `true`, or `false` and the error it died of; a running
/// or normal one cannot be.
fn co_close<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let co = get_co(ctx, &exec, &stack, "close")?;
    let status = co_status_of(&exec, co);
    match status {
        CoStatus::Dead | CoStatus::Suspended => {
            // `lua_closethread`: the thread is reset, and the error a dead
            // one kept is returned, once.
            co.reset(&ctx).map_err(|e| lua_error(ctx, &e.to_string()))?;
            let error = {
                let mut errors = coroutines(ctx).errors.borrow_mut(&ctx);
                errors
                    .iter()
                    .position(|&(w, _)| is_thread(w, co))
                    .map(|i| errors.swap_remove(i).1)
            };
            match error {
                Some(e) => stack.replace(ctx, (false, e)),
                None => stack.replace(ctx, true),
            }
            Ok(CallbackReturn::Return)
        }
        CoStatus::Running | CoStatus::Normal => {
            let msg = format!("cannot close a {} coroutine", status.name());
            Err(positioned(ctx, &exec, msg.as_bytes()))
        }
    }
}

/// `coroutine.wrap(f)` (`lcorolib.c`): a function that resumes a coroutine
/// running `f`, returns what it yields or returns, and propagates its errors.
fn wrap<'gc>(ctx: Context<'gc>, exec: Execution<'gc, '_>, mut stack: Stack<'gc, '_>) -> Ret<'gc> {
    let f = match stack.get(0) {
        Value::Function(f) if !stack.is_empty() => f,
        _ => {
            let got = (!stack.is_empty()).then(|| stack.get(0));
            let e = type_error(ctx, got, 1, "function");
            return Err(arg_error(ctx, &exec, "wrap", e));
        }
    };
    let thread = Thread::new(ctx);
    thread
        .start_suspended(&ctx, f)
        .map_err(|e| lua_error(ctx, &e.to_string()))?;
    let resume = Callback::from_fn_with(&ctx, thread, |thread, ctx, exec, _| {
        // `auxresume`'s checks, in the C's words, positioned by `auxwrap`.
        match thread.mode() {
            ThreadMode::Suspended => {}
            ThreadMode::Stopped => {
                return Err(positioned(ctx, &exec, b"cannot resume dead coroutine"))
            }
            _ => {
                return Err(positioned(
                    ctx,
                    &exec,
                    b"cannot resume non-suspended coroutine",
                ))
            }
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

/// Returns what the resumed coroutine returned or yielded, and propagates its
/// errors as `auxwrap` does: a string, unless it is the memory error, after
/// the position of the Lua function that called the wrapper.
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

    fn error(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        exec: Execution<'gc, '_>,
        error: Error<'gc>,
        _stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        if let Error::Lua(e) = &error {
            if let Value::String(s) = e.0 {
                if s.as_bytes() != piccolo::limits::NOT_ENOUGH_MEMORY.as_bytes() {
                    return Err(positioned(ctx, &exec, s.as_bytes()));
                }
            }
        }
        Err(error)
    }
}

/// `string.rep(s, n [, sep])` (`lstrlib.c:150`).
fn string_rep<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let out = {
        let args = LuaArgs { ctx, stack: &stack };
        let fail = |e| arg_error(ctx, &exec, "rep", e);
        let s = args.string(1).map_err(fail)?;
        let n = args.check_integer(2).map_err(fail)?;
        let sep = match args.get(3) {
            None | Some(Value::Nil) => Default::default(),
            Some(_) => args.string(3).map_err(fail)?,
        };
        rep(&s, n, &sep).map_err(|e| positioned(ctx, &exec, e.0.as_bytes()))?
    };
    stack.replace(ctx, Value::String(ctx.intern(&out)));
    Ok(CallbackReturn::Return)
}

/// `string.char(...)` (`lstrlib.c:214`): each argument an integer from 0 to
/// 255.
fn string_char<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let mut out = Vec::new();
    if !super::reserve(&mut out, stack.len()) {
        return Err(lua_error(ctx, "not enough memory"));
    }
    for i in 0..stack.len() {
        let arg = i.saturating_add(1);
        let fail = |e| arg_error(ctx, &exec, "char", e);
        let c = check_integer(ctx, Some(stack.get(i)), arg).map_err(fail)?;
        let byte = u8::try_from(c)
            .map_err(|_| fail(PackError::bad_argument(arg, "value out of range")))?;
        out.push(byte);
    }
    stack.replace(ctx, Value::String(ctx.intern(&out)));
    Ok(CallbackReturn::Return)
}

/// The arithmetic `lstrlib.c` gives strings (`stringmetamethods`).
#[derive(Clone, Copy)]
enum Arith {
    Add,
    Sub,
    Mul,
    Mod,
    Pow,
    Div,
    IDiv,
    Unm,
}

const STRING_ARITH: [(&str, Arith); 8] = [
    ("__add", Arith::Add),
    ("__sub", Arith::Sub),
    ("__mul", Arith::Mul),
    ("__mod", Arith::Mod),
    ("__pow", Arith::Pow),
    ("__div", Arith::Div),
    ("__idiv", Arith::IDiv),
    ("__unm", Arith::Unm),
];

/// `tonum(L, arg)` (`lstrlib.c:262`) on `stack`, the C function's stack:
/// whether its value at `arg` (0-based) is a number or a string that is one
/// whole. Like the C it pushes what it converts — a number, or the number a
/// string's text up to its first NUL makes (`lua_stringtonumber` pushes on
/// success even when the length check then fails) — so with one argument
/// the second `tonum` finds the first's number at index 2.
fn to_num<'gc>(stack: &mut Vec<Value<'gc>>, arg: usize) -> bool {
    match stack.get(arg).copied() {
        Some(v @ (Value::Integer(_) | Value::Number(_))) => {
            stack.push(v);
            true
        }
        Some(Value::String(s)) => {
            let text = until_nul(s.as_bytes());
            let n = match piccolo::Constant::String(text).to_numeric() {
                Some(piccolo::Constant::Integer(i)) => Value::Integer(i),
                Some(piccolo::Constant::Number(f)) => Value::Number(f),
                _ => return false,
            };
            stack.push(n);
            text.len() == s.as_bytes().len()
        }
        _ => false,
    }
}

/// The value of an operator on two numbers, which never calls a metamethod.
fn operator_value<'gc, const N: usize>(
    ctx: Context<'gc>,
    r: Result<MetaResult<'gc, N>, MetaOperatorError>,
) -> Result<Value<'gc>, Error<'gc>> {
    match r {
        Ok(MetaResult::Value(v)) => Ok(v),
        Ok(MetaResult::Call(_)) => Err(lua_error(
            ctx,
            "attempt to perform arithmetic on a number value",
        )),
        Err(e) => Err(operator_error(ctx, &e)),
    }
}

/// `arith` (`lstrlib.c:288`), the string metatable's `event`: the operator on
/// the two arguments converted to numbers, or else the second argument's own
/// metamethod (`trymt`). The VM does its string arithmetic itself and never
/// calls these (`vm-string-arith-hooks-ignored`); they are what a script that
/// looks one up and calls it gets. `__unm` takes its operand from the second
/// argument, as `lua_arith` takes the top of the stack: the VM passes the
/// operand twice. Called with one argument, the operation is on that
/// argument twice, as [`to_num`] leaves the C's stack.
fn string_arith<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
    event: &'static str,
    op: Arith,
) -> Ret<'gc> {
    let mut c: Vec<Value<'gc>> = (0..stack.len()).map(|i| stack.get(i)).collect();
    if to_num(&mut c, 0) && to_num(&mut c, 1) {
        // `lua_arith` on the two values on top, or the one on top for
        // `__unm`; its errors (`n%0`, division by zero) come from the C
        // function, unpositioned.
        let (x, y) = match c.as_slice() {
            [.., x, y] => (*x, *y),
            _ => (Value::Nil, Value::Nil),
        };
        let v = match op {
            Arith::Add => operator_value(ctx, meta_ops::add(ctx, x, y)),
            Arith::Sub => operator_value(ctx, meta_ops::subtract(ctx, x, y)),
            Arith::Mul => operator_value(ctx, meta_ops::multiply(ctx, x, y)),
            Arith::Mod => operator_value(ctx, meta_ops::modulo(ctx, x, y)),
            Arith::Pow => operator_value(ctx, meta_ops::exponentiate(ctx, x, y)),
            Arith::Div => operator_value(ctx, meta_ops::float_divide(ctx, x, y)),
            Arith::IDiv => operator_value(ctx, meta_ops::floor_divide(ctx, x, y)),
            Arith::Unm => operator_value(ctx, meta_ops::negate(ctx, y)),
        }?;
        stack.replace(ctx, v);
        return Ok(CallbackReturn::Return);
    }
    // `trymt`, after `lua_settop(L, 2)`, which keeps what `tonum` pushed
    // when there was one argument.
    c.resize(2, Value::Nil);
    let (a, b) = (c[0], c[1]);
    if !matches!(b, Value::String(_)) {
        if let Some(mm) = metafield(ctx, b, event) {
            stack.replace(ctx, (a, b));
            return Ok(CallbackReturn::Call {
                function: callable(ctx, mm),
                then: Some(BoxSequence::new(&ctx, Results(1))),
            });
        }
    }
    let msg = format!(
        "attempt to {} a '{}' with a '{}'",
        event.trim_start_matches("__"),
        a.type_name(),
        b.type_name()
    );
    Err(positioned(ctx, &exec, msg.as_bytes()))
}

/// What `checktab` (`ltablib.c:44`) asks of a table-like argument.
const TAB_R: u8 = 1;
const TAB_W: u8 = 2;
const TAB_L: u8 = 4;

/// `checktab(L, 1, what)` for table function `name`, and the table whose raw
/// border is the length `aux_getn` reads: `None` when a `__len` answers for
/// it, or the argument only behaves as a table. The border is read only by
/// the checks that need it, so that appending and popping pay nothing for it.
fn check_tab<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    stack: &Stack<'gc, '_>,
    name: &str,
    what: u8,
) -> Result<Option<Table<'gc>>, Error<'gc>> {
    let v = (LuaArgs { ctx, stack }).get(1);
    if let Some(Value::Table(t)) = v {
        let has_len = t
            .metatable()
            .is_some_and(|mt| !mt.get_value(ctx, "__len").is_nil());
        return Ok((!has_len).then_some(t));
    }
    let has = |mt: Table<'gc>, flag: u8, field: &'static str| {
        what & flag == 0 || !mt.get_value(ctx, field).is_nil()
    };
    let like_a_table = v.and_then(|v| metatable_of(ctx, v)).is_some_and(|mt| {
        has(mt, TAB_R, "__index") && has(mt, TAB_W, "__newindex") && has(mt, TAB_L, "__len")
    });
    if like_a_table {
        Ok(None)
    } else {
        Err(arg_error(ctx, exec, name, type_error(ctx, v, 1, "table")))
    }
}

/// `table.insert(t, [pos,] v)` (`ltablib.c:61`): the C's checks, then the VM's
/// insertion (`insert`), tail-called so that it takes no C level of its own.
fn table_insert<'gc>(
    insert: &Function<'gc>,
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let raw = check_tab(ctx, &exec, &stack, "insert", TAB_R | TAB_W | TAB_L)?;
    match stack.len() {
        2 => {}
        3 => {
            let fail = |e| arg_error(ctx, &exec, "insert", e);
            let pos = (LuaArgs { ctx, stack: &stack })
                .check_integer(2)
                .map_err(fail)?;
            // `(lua_Unsigned)pos - 1u < (lua_Unsigned)e`: `pos` in `[1, e]`.
            if let Some(t) = raw {
                let e = t.length().wrapping_add(1);
                if (pos as u64).wrapping_sub(1) >= e as u64 {
                    return Err(fail(PackError::bad_argument(2, "position out of bounds")));
                }
            }
        }
        _ => {
            return Err(positioned(
                ctx,
                &exec,
                b"wrong number of arguments to 'insert'",
            ))
        }
    }
    Ok(CallbackReturn::Call {
        function: *insert,
        then: None,
    })
}

/// `table.remove(t [, pos])` (`ltablib.c:90`): the C's checks, then the VM's
/// removal (`remove`), tail-called.
fn table_remove<'gc>(
    remove: &Function<'gc>,
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let raw = check_tab(ctx, &exec, &stack, "remove", TAB_R | TAB_W | TAB_L)?;
    let fail = |e| arg_error(ctx, &exec, "remove", e);
    // `luaL_optinteger(L, 2, size)`: without a position, the last element,
    // which needs no check.
    let args = LuaArgs { ctx, stack: &stack };
    if !matches!(args.get(2), None | Some(Value::Nil)) {
        let pos = args.check_integer(2).map_err(fail)?;
        // `(lua_Unsigned)pos - 1u <= (lua_Unsigned)size`: `pos` in
        // `[1, size + 1]`, when it is not `size` itself.
        if let Some(t) = raw {
            let size = t.length();
            if pos != size && (pos as u64).wrapping_sub(1) > size as u64 {
                return Err(fail(PackError::bad_argument(2, "position out of bounds")));
            }
        }
    }
    Ok(CallbackReturn::Call {
        function: *remove,
        then: None,
    })
}

/// `table.concat(t [, sep [, i [, j]]])` (`ltablib.c:160`): the C's checks of
/// its arguments, and of each value (`addfield`) where the table answers for
/// itself, then the VM's concatenation (`concat`), tail-called.
fn table_concat<'gc>(
    concat: &Function<'gc>,
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    stack: Stack<'gc, '_>,
) -> Ret<'gc> {
    let raw = check_tab(ctx, &exec, &stack, "concat", TAB_R | TAB_L)?;
    let args = LuaArgs { ctx, stack: &stack };
    let fail = |e| arg_error(ctx, &exec, "concat", e);
    if !matches!(args.get(2), None | Some(Value::Nil)) {
        args.string(2).map_err(fail)?;
    }
    let first = args.opt_integer(3, 1).map_err(fail)?;
    let given_last = !matches!(args.get(4), None | Some(Value::Nil));
    let last = if given_last {
        args.check_integer(4).map_err(fail)?
    } else {
        raw.map_or(0, |t| t.length())
    };
    if let Some(Value::Table(t)) = args.get(1) {
        let unindexed = t
            .metatable()
            .is_none_or(|mt| mt.get_value(ctx, "__index").is_nil());
        if unindexed && (raw.is_some() || given_last) {
            // An absent index is nil and ends the walk, so it takes at most
            // one step more than the table has entries.
            let mut i = first;
            while i <= last {
                let v = t.get_raw(Value::Integer(i));
                if !matches!(v, Value::String(_) | Value::Integer(_) | Value::Number(_)) {
                    let msg = format!(
                        "invalid value ({}) at index {i} in table for 'concat'",
                        v.type_name()
                    );
                    return Err(positioned(ctx, &exec, msg.as_bytes()));
                }
                match i.checked_add(1) {
                    Some(n) => i = n,
                    None => break,
                }
            }
        }
    }
    Ok(CallbackReturn::Call {
        function: *concat,
        then: None,
    })
}

#[cfg(test)]
mod tests {
    //! The pure helpers directly, and each binding end to end through the VM —
    //! in-module, so that Miri runs them; the differential corpus reads from
    //! disk and cannot. Few chunks, each asking much of one VM, keep the VM
    //! start-ups, which dominate under Miri, few.
    use super::{chunk_id, float_is_integer, gc_param, gc_param_value, raw_equal, str2int};
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
    fn str2int_is_b_str2int() {
        assert_eq!(str2int(b"ff", 16), Some(255));
        assert_eq!(str2int(b"  -zz \t", 36), Some(-1295));
        assert_eq!(str2int(b"+10", 2), Some(2));
        assert_eq!(str2int(b"8", 8), None);
        assert_eq!(str2int(b"", 10), None);
        assert_eq!(str2int(b" - 1", 10), None);
        assert_eq!(str2int(b"1 2", 10), None);
        assert_eq!(str2int(b"1\x002", 10), None);
        // `lua_Unsigned` arithmetic wraps.
        assert_eq!(str2int(b"ffffffffffffffff", 16), Some(-1));
        assert_eq!(str2int(b"10000000000000000", 16), Some(0));
        assert_eq!(str2int(b"\xc3\xa9", 36), None);
    }

    #[test]
    fn gc_parameters_are_kept_as_lua_keeps_them() {
        assert_eq!(gc_param_value(gc_param(200)), 200);
        assert_eq!(gc_param_value(gc_param(101)), 100);
        // A quarter of the value, in a byte.
        assert_eq!(gc_param_value(gc_param(2000)), 976);
        assert_eq!(gc_param_value(gc_param(-8)), 1016);
        assert_eq!(gc_param_value(gc_param(3)), 0);
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
            local _, k = xpcall(setmetatable({}, {__name = "Foo"}), h)
            return a, b, c, d, e, f, g, i, j, k, select(2, pcall(xpcall, h))
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
                // `luaT_objtypename`: the `__name`.
                s("H:attempt to call a Foo value"),
                s("bad argument #2 to 'xpcall' (function expected, got no value)"),
            ])
        );
    }

    #[test]
    fn pcall_and_raw_access_through_the_vm() {
        let got = run(r#"
            local named = setmetatable({}, {__name = "Foo"})
            local t = {}
            local a = table.pack(pcall(nil))
            local b = table.pack(pcall(pcall, nil))
            local _, c = pcall(pcall)
            local _, d = pcall(named)
            local _, e = pcall(rawset, t, "k")
            local _, f = pcall(rawget, {})
            local _, g = pcall(rawlen, 5)
            local _, h = pcall(rawset, t, nil, 1)
            local _, i = pcall(function() return rawlen(true) end)
            return a.n, a[1], a[2], b.n, b[1], b[2], c, d, e, f, g, h, i,
                   rawlen("abc"), rawequal(rawset(t, 1, 2), t), rawget(t, 1.0)
        "#);
        assert_eq!(
            got,
            Ok(vec![
                "number:2".into(),
                "boolean:false".into(),
                s("attempt to call a nil value"),
                "number:3".into(),
                "boolean:true".into(),
                "boolean:false".into(),
                s("bad argument #1 to 'pcall' (value expected)"),
                s("attempt to call a Foo value"),
                s("bad argument #3 to 'rawset' (value expected)"),
                s("bad argument #2 to 'rawget' (value expected)"),
                s("bad argument #1 to 'rawlen' (table or string expected, got number)"),
                s("table index is nil"),
                // Called from a Lua function: positioned.
                s("[string \"<anonymous>\"]:12: bad argument #1 to 'rawlen' (table or string expected, got boolean)"),
                "number:3".into(),
                "boolean:true".into(),
                "number:2".into(),
            ])
        );
    }

    #[test]
    fn iteration_through_the_vm() {
        let got = run(r##"
            local mt = {__index = function(t, i) if i <= 3 then return i * 10 end end}
            local sum = 0
            for _, v in ipairs(setmetatable({}, mt)) do sum = sum + v end
            local one = setmetatable({}, {__pairs = function(t) return next end})
            local many = setmetatable({}, {__pairs = function(t) return next, t, nil, 4 end})
            local _, e1 = pcall(pairs)
            local _, e2 = pcall(next, {}, "absent")
            local _, e3 = pcall(select, 0)
            local _, e4 = pcall(select, "x")
            return select("#", pairs({})), select("#", ipairs({})), select(3, ipairs({})),
                   select("#", pairs(one)), select("#", pairs(many)), pairs({}) == next,
                   sum, select("#", next({})), e1, e2, e3, e4, select(-1, "a", "b"),
                   select("#abc", 1, 2)
        "##);
        assert_eq!(
            got,
            Ok(vec![
                "number:3".into(),
                "number:3".into(),
                "number:0".into(),
                "number:3".into(),
                "number:3".into(),
                "boolean:true".into(),
                "number:60".into(),
                "number:1".into(),
                s("bad argument #1 to 'pairs' (value expected)"),
                s("invalid key to 'next'"),
                s("bad argument #1 to 'select' (index out of range)"),
                s("bad argument #1 to 'select' (number expected, got string)"),
                s("b"),
                "number:2".into(),
            ])
        );
    }

    #[test]
    fn conversions_and_metatables_through_the_vm() {
        let got = run(r#"
            local locked = setmetatable({}, {__metatable = "locked"})
            local _, e1 = pcall(setmetatable, locked, {})
            local _, e2 = pcall(setmetatable, {})
            local _, e3 = pcall(tostring, setmetatable({}, {__tostring = function() return {} end}))
            local _, e4 = pcall(tonumber, 10, 16)
            local _, e5 = pcall(tonumber, "10", 99)
            local _, e6 = pcall(type)
            local _, e7 = pcall(function() return tostring(setmetatable({}, {__tostring = function() end})) end)
            return getmetatable(locked), e1, e2, e3, e4, e5, e6, e7,
                   tostring(setmetatable({}, {__tostring = function() return 42 end})),
                   tonumber("  0x10  "), tonumber("z", 36), tonumber("1e1"), tonumber({}),
                   tonumber("1\0")
        "#);
        assert_eq!(
            got,
            Ok(vec![
                s("locked"),
                s("cannot change a protected metatable"),
                s("bad argument #2 to 'setmetatable' (nil or table expected, got no value)"),
                s("'__tostring' must return a string"),
                s("bad argument #1 to 'tonumber' (string expected, got number)"),
                s("bad argument #2 to 'tonumber' (base out of range)"),
                s("bad argument #1 to 'type' (value expected)"),
                s("[string \"<anonymous>\"]:9: '__tostring' must return a string"),
                s("42"),
                "number:16".into(),
                "number:35".into(),
                "number:10.0".into(),
                "nil:nil".into(),
                "nil:nil".into(),
            ])
        );
    }

    #[test]
    fn assert_error_and_collectgarbage_through_the_vm() {
        let got = run(r#"
            local _, e1 = pcall(assert)
            local _, e2 = pcall(assert, false, nil)
            local _, e3 = pcall(error, "x", "y")
            local _, e4 = pcall(function() assert(false) end)
            local _, e5 = pcall(collectgarbage, "bogus")
            local a = collectgarbage("setpause", 100)
            local b = collectgarbage("setpause", a)
            local stopped = (collectgarbage("stop") == 0) and not collectgarbage("isrunning")
            collectgarbage("restart")
            return e1, e2, e3, e4, e5, a, b, stopped, collectgarbage("isrunning"),
                   collectgarbage(), math.type(collectgarbage("count")),
                   collectgarbage("generational"), collectgarbage("incremental"),
                   collectgarbage("step"), assert(1, 2)
        "#);
        assert_eq!(
            got,
            Ok(vec![
                s("bad argument #1 to 'assert' (value expected)"),
                "nil:nil".into(),
                s("bad argument #2 to 'error' (number expected, got string)"),
                s("[string \"<anonymous>\"]:5: assertion failed!"),
                s("bad argument #1 to 'collectgarbage' (invalid option 'bogus')"),
                "number:200".into(),
                "number:100".into(),
                "boolean:true".into(),
                "boolean:true".into(),
                "number:0".into(),
                s("float"),
                s("incremental"),
                s("generational"),
                "boolean:false".into(),
                "number:1".into(),
                "number:2".into(),
            ])
        );
    }

    #[test]
    fn coroutines_through_the_vm() {
        let got = run(r#"
            local co1, co2
            co2 = coroutine.create(function() return coroutine.status(co1) end)
            co1 = coroutine.create(function() return select(2, coroutine.resume(co2)) end)
            local normal = select(2, coroutine.resume(co1))
            local dead = coroutine.create(function() error("boom", 0) end)
            coroutine.resume(dead)
            local first = table.pack(coroutine.close(dead))
            local sus = coroutine.create(function() coroutine.yield() end)
            coroutine.resume(sus)
            local closed = coroutine.close(sus)
            local main = coroutine.running()
            local inner = coroutine.wrap(function()
                return coroutine.isyieldable(), coroutine.isyieldable(main), coroutine.status(main)
            end)
            local y1, y2, st = inner()
            local _, e1 = pcall(coroutine.close, main)
            local _, e2 = pcall(coroutine.create, setmetatable({}, {__call = function() end, __name = "Callable"}))
            return normal, first.n, first[1], first[2], coroutine.close(dead), closed,
                   coroutine.status(sus), select(2, coroutine.resume(sus)),
                   coroutine.isyieldable(), y1, y2, st, e1, e2,
                   select(2, coroutine.resume(main))
        "#);
        assert_eq!(
            got,
            Ok(vec![
                s("normal"),
                "number:2".into(),
                "boolean:false".into(),
                s("boom"),
                // Closed once, the error is gone.
                "boolean:true".into(),
                "boolean:true".into(),
                s("dead"),
                s("cannot resume dead coroutine"),
                "boolean:false".into(),
                "boolean:true".into(),
                "boolean:false".into(),
                s("normal"),
                s("cannot close a running coroutine"),
                s("bad argument #1 to 'create' (function expected, got Callable)"),
                s("cannot resume non-suspended coroutine"),
            ])
        );
    }

    #[test]
    fn warnings_are_off_until_turned_on() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let out = Rc::new(RefCell::new(Vec::<u8>::new()));
        let sink = out.clone();
        let mut lua = piccolo::Lua::core();
        let ex = lua.enter(|ctx| {
            crate::nse::stdlib::load_tail(ctx).expect("tables");
            super::set_warning_sink(ctx, move |b| sink.borrow_mut().extend_from_slice(b));
            let src = r#"
                warn("hidden") warn("@on") warn("shown") warn("a", "b", 3)
                warn("@off") warn("hidden") warn("x", "@on") warn("on again")
                warn("@on", "y") warn("z\0cut") warn("@off")
                return select(2, pcall(warn)), select(2, pcall(warn, "a", {}))
            "#;
            let c = piccolo::Closure::load(ctx, None, src.as_bytes()).expect("compiles");
            ctx.stash(piccolo::Executor::start(ctx, c.into(), ()))
        });
        lua.finish(&ex).expect("runs");
        let errors = lua.enter(|ctx| {
            let (a, b) = ctx
                .fetch(&ex)
                .take_result::<(piccolo::String, piccolo::String)>(ctx)
                .expect("finished")
                .expect("no error");
            (a.as_bytes().to_vec(), b.as_bytes().to_vec())
        });
        assert_eq!(
            String::from_utf8_lossy(&out.borrow()),
            "Lua warning: shown\nLua warning: ab3\nLua warning: on again\n\
             Lua warning: @ony\nLua warning: z\n"
        );
        assert_eq!(
            errors,
            (
                b"bad argument #1 to 'warn' (string expected, got no value)".to_vec(),
                b"bad argument #2 to 'warn' (string expected, got table)".to_vec()
            )
        );
    }

    #[test]
    fn string_and_table_checks_through_the_vm() {
        let got = run(r#"
            local mt = getmetatable("")
            local _, e1 = pcall(mt.__add, "a", 4)
            local _, e2 = pcall(mt.__mod, "1", "0")
            local _, e3 = pcall(string.char, 256)
            local _, e4 = pcall(table.insert, {}, 1, 2, 3)
            local _, e5 = pcall(table.insert, {}, 5, 1)
            local _, e6 = pcall(table.remove, {1, 2}, 5)
            local _, e7 = pcall(table.concat, {1, {}, 3})
            local _, e8 = pcall(table.insert, "x", 1)
            local t = {1, 2, 3}
            table.insert(t, 2, "x")
            return mt.__add("3", 4), mt.__unm("2", "3"), mt.__pow("2", 3),
                   mt.__add("1", setmetatable({}, {__add = function(a, b) return "mm" end})),
                   e1, e2, e3, e4, e5, e6, e7, e8, string.char(104, 105),
                   table.concat(t, ","), table.remove(t), table.concat({1, 2.5, "x"}, "-")
        "#);
        assert_eq!(
            got,
            Ok(vec![
                "number:7".into(),
                "number:-3".into(),
                "number:8.0".into(),
                s("mm"),
                s("attempt to add a 'string' with a 'number'"),
                s("attempt to perform 'n%0'"),
                s("bad argument #1 to 'char' (value out of range)"),
                s("wrong number of arguments to 'insert'"),
                s("bad argument #2 to 'insert' (position out of bounds)"),
                s("bad argument #2 to 'remove' (position out of bounds)"),
                s("invalid value (table) at index 2 in table for 'concat'"),
                s("bad argument #1 to 'insert' (table expected, got string)"),
                s("hi"),
                s("1,x,2,3"),
                "number:3".into(),
                s("1-2.5-x"),
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
            local _, positioned = pcall(function() return w() end)
            return x, y, main, ok, e, tail(), tail(), positioned
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
                s("[string \"<anonymous>\"]:12: cannot resume dead coroutine"),
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
