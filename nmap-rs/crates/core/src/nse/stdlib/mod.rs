//! The first-party half of NSE's Lua standard library.
//!
//! The vendored VM ships seven string functions. The rest of what the shipped
//! scripts call — Lua patterns, `string.format`, `string.pack`/`unpack`, the tail — is
//! written here, against the VM's public API, rather than patched into
//! `crates/vendor/piccolo`. The reason is the gates: a function in this crate is
//! reachable by the differential corpus, the fuzz targets and Miri, and a
//! function inside a vendored dependency is reachable by none of them
//! (`docs/M6-ANALYSIS.md`, "What the fork is *for*").
//!
//! Each function is split in two. The byte-level work is a pure module that
//! knows nothing about the interpreter — [`strpack`], [`pattern`],
//! [`strformat`], [`strrep`] — so that it
//! can be fuzzed and run under Miri directly. What is left here is the binding:
//! turning Lua values into the arguments those functions take, with the
//! **VM's own** conversions, and turning the results back. Nothing in this file
//! parses a byte of script-supplied data.
//!
//! [`base`] is the exception that proves the rule: `_G`, `rawequal`, `xpcall`,
//! `load` and `coroutine.wrap` are about calling, resuming and compiling, which
//! only the VM can do, so they are bindings with no pure half — save
//! [`base::chunk_id`], which names a chunk in an error message.

pub mod base;
pub mod pattern;
pub mod strformat;
pub mod strpack;
pub mod strrep;

pub use self::base::load_tail;

use std::borrow::Cow;
use std::cell::Cell;
use std::pin::Pin;

use gc_arena::Collect;
use piccolo::meta_ops::{self, MetaResult};
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Context, Error, Execution, Function, Sequence,
    SequencePoll, Stack, String as LuaString, Table, Value,
};

use self::pattern::{Capture, Gmatch, Gsub, Match, PatternError};
use self::strformat::{format_step, FormatArgs, Formatter, Literal, Step};
use self::strpack::{PackArgs, PackError, Unpacked};

/// The `string` table of `ctx`'s globals: the one the string metatable's
/// `__index` points at, so that what is installed into it also resolves as a
/// method, `s:find(...)`.
fn string_table<'gc>(ctx: Context<'gc>) -> Result<Table<'gc>, LoadError> {
    match ctx.globals().get_value(ctx, "string") {
        Value::Table(t) => Ok(t),
        _ => Err(LoadError::NoStringTable),
    }
}

/// Installs `string.pack`, `string.unpack` and `string.packsize` into the
/// `string` table of `ctx`'s globals, replacing anything already there.
///
/// The `string` table is the one the string metatable's `__index` points at,
/// so this also makes `fmt:pack(...)`-style method calls resolve.
pub fn load_strpack<'gc>(ctx: Context<'gc>) -> Result<(), LoadError> {
    let string = string_table(ctx)?;
    install(ctx, string, "pack", str_pack);
    install(ctx, string, "unpack", str_unpack);
    install(ctx, string, "packsize", str_packsize);
    Ok(())
}

/// Installs `string.format` into the `string` table of `ctx`'s globals,
/// replacing anything already there.
pub fn load_format<'gc>(ctx: Context<'gc>) -> Result<(), LoadError> {
    let string = string_table(ctx)?;
    string.set_field(
        ctx,
        "format",
        Callback::from_fn(&ctx, |ctx, _, mut stack| {
            let mut seq = FormatSeq {
                args: stack.drain(..).collect(),
                resolved: Vec::new(),
                need: None,
                awaiting: None,
                f: Formatter::default(),
            };
            // Most formats need no `__tostring` call and finish here; one that
            // does continues as a sequence from where it stopped.
            match seq.run(ctx)? {
                Some(result) => {
                    stack.push_back(Value::String(result));
                    Ok(CallbackReturn::Return)
                }
                None => Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, seq))),
            }
        }),
    );
    Ok(())
}

/// Installs `string.find`, `string.match`, `string.gmatch` and `string.gsub`
/// into the `string` table of `ctx`'s globals, replacing anything already
/// there.
pub fn load_patterns<'gc>(ctx: Context<'gc>) -> Result<(), LoadError> {
    let string = string_table(ctx)?;
    install(ctx, string, "find", str_find);
    install(ctx, string, "match", str_match);
    install(ctx, string, "gmatch", str_gmatch);
    string.set_field(
        ctx,
        "gsub",
        Callback::from_fn(&ctx, |ctx, _, mut stack| {
            let seq =
                gsub_start(ctx, &stack).map_err(|e| lua_error(ctx, &e.lua_message("gsub")))?;
            stack.clear();
            Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, seq)))
        }),
    );
    Ok(())
}

/// Why a `load_*` function could not install its functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The globals hold no `string` table — the VM was built without
    /// `load_string`. There is nothing sensible to install into.
    NoStringTable,
    /// The globals hold no `coroutine` table — the VM was built without
    /// `load_coroutine`, so there is nowhere to put `coroutine.wrap`.
    NoCoroutineTable,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NoStringTable => f.write_str("the Lua state has no `string` table"),
            LoadError::NoCoroutineTable => f.write_str("the Lua state has no `coroutine` table"),
        }
    }
}

impl std::error::Error for LoadError {}

type Body = for<'gc, 'a> fn(Context<'gc>, &mut Stack<'gc, 'a>) -> Result<(), PackError>;

fn install<'gc>(ctx: Context<'gc>, table: Table<'gc>, name: &'static str, body: Body) {
    table.set_field(
        ctx,
        name,
        Callback::from_fn(&ctx, move |ctx, _, mut stack| match body(ctx, &mut stack) {
            Ok(()) => Ok(CallbackReturn::Return),
            Err(e) => Err(lua_error(ctx, &e.lua_message(name))),
        }),
    );
}

/// Make room for `additional` more bytes in a buffer whose size a script
/// chooses, or say why not: `luaL_Buffer` raises "not enough memory" when
/// its allocator refuses. The buffer is not on the VM's heap, so the memory
/// budget is asked for the whole capacity it grows to, before the allocator
/// is — which, overcommitting, would grant gigabytes it cannot back.
pub(crate) fn reserve(out: &mut Vec<u8>, additional: usize) -> bool {
    if out.capacity().saturating_sub(out.len()) >= additional {
        return true;
    }
    let grown = out
        .len()
        .saturating_add(additional)
        .max(out.capacity().saturating_mul(2));
    piccolo::budget::allows(grown) && out.try_reserve(additional).is_ok()
}

/// A Lua error carrying a string, which is what `luaL_error` and
/// `luaL_argerror` raise: `pcall` returns it as the message.
pub(crate) fn lua_error<'gc>(ctx: Context<'gc>, msg: &str) -> Error<'gc> {
    lua_error_bytes(ctx, msg.as_bytes())
}

/// [`lua_error`] for a message that is not UTF-8: Lua strings are bytes, and
/// a message quoting part of a script's input carries its bytes unchanged.
pub(crate) fn lua_error_bytes<'gc>(ctx: Context<'gc>, msg: &[u8]) -> Error<'gc> {
    Error::from(Value::String(ctx.intern(msg)))
}

/// A matcher error is a `luaL_error`: it names no argument.
fn pattern_error(e: PatternError) -> PackError {
    PackError {
        arg: None,
        msg: e.msg,
    }
}

/// The Lua arguments of one call, read by 1-based argument number.
pub(crate) struct LuaArgs<'s, 'gc, 'a> {
    pub(crate) ctx: Context<'gc>,
    pub(crate) stack: &'s Stack<'gc, 'a>,
}

impl<'gc> LuaArgs<'_, 'gc, '_> {
    /// The argument, or `None` if the call passed fewer — which the C words
    /// differently from an explicit `nil` ("got no value").
    pub(crate) fn get(&self, arg: usize) -> Option<Value<'gc>> {
        arg.checked_sub(1)
            .filter(|&i| i < self.stack.len())
            .map(|i| self.stack.get(i))
    }

    fn type_error(&self, arg: usize, expected: &str) -> PackError {
        type_error(self.get(arg), arg, expected)
    }

    /// `luaL_checklstring` for an argument that must be present.
    pub(crate) fn string(&self, arg: usize) -> Result<Cow<'gc, [u8]>, PackError> {
        match self.get(arg) {
            Some(Value::String(s)) => Ok(Cow::Borrowed(s.as_bytes())),
            // `lua_tolstring` converts a number in place. `into_string` is the
            // VM's own conversion — the one `tostring` and `..` use — so the
            // text is exactly Lua's, `.0` and all.
            Some(v @ (Value::Integer(_) | Value::Number(_))) => v
                .into_string(self.ctx)
                .map(|s| Cow::Borrowed(s.as_bytes()))
                .ok_or_else(|| self.type_error(arg, "string")),
            _ => Err(self.type_error(arg, "string")),
        }
    }

    /// `luaL_checklstring`, keeping the Lua string itself rather than its
    /// bytes, for a caller that must hold it past this call.
    fn string_value(&self, arg: usize) -> Result<LuaString<'gc>, PackError> {
        match self.get(arg) {
            Some(Value::String(s)) => Ok(s),
            Some(v @ (Value::Integer(_) | Value::Number(_))) => v
                .into_string(self.ctx)
                .ok_or_else(|| self.type_error(arg, "string")),
            _ => Err(self.type_error(arg, "string")),
        }
    }

    /// `luaL_optinteger(L, arg, def)`.
    fn opt_integer(&self, arg: usize, def: i64) -> Result<i64, PackError> {
        match self.get(arg) {
            None | Some(Value::Nil) => Ok(def),
            Some(_) => self.check_integer(arg),
        }
    }

    /// `luaL_checkinteger`. The two failure messages are the C's: a value
    /// that *is* a number but not an integral one says so, and anything else is
    /// a type error.
    pub(crate) fn check_integer(&self, arg: usize) -> Result<i64, PackError> {
        check_integer(self.get(arg), arg)
    }
}

/// `luaL_typeerror`'s message for argument `arg`, which is `v` (`None` if the
/// call passed fewer arguments).
pub(crate) fn type_error(v: Option<Value<'_>>, arg: usize, expected: &str) -> PackError {
    let got = v.map_or("no value", |v| v.type_name());
    PackError::bad_argument(arg, format!("{expected} expected, got {got}"))
}

/// `luaL_checkinteger`. The two failure messages are the C's: a value that
/// *is* a number but not an integral one says so, and anything else is a type
/// error.
fn check_integer(v: Option<Value<'_>>, arg: usize) -> Result<i64, PackError> {
    let val = v.unwrap_or(Value::Nil);
    match val.to_integer() {
        Some(i) => Ok(i),
        None if val.to_number().is_some() => Err(PackError::bad_argument(
            arg,
            "number has no integer representation",
        )),
        None => Err(type_error(v, arg, "number")),
    }
}

/// `luaL_checknumber`.
fn check_number(v: Option<Value<'_>>, arg: usize) -> Result<f64, PackError> {
    v.and_then(Value::to_number)
        .ok_or_else(|| type_error(v, arg, "number"))
}

impl PackArgs for LuaArgs<'_, '_, '_> {
    fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
        self.check_integer(arg)
    }

    fn number(&mut self, arg: usize) -> Result<f64, PackError> {
        check_number(self.get(arg), arg)
    }

    fn bytes(&mut self, arg: usize) -> Result<Cow<'_, [u8]>, PackError> {
        self.string(arg)
    }
}

/// `string.pack(fmt, v1, v2, ...)`.
fn str_pack<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    let packed = {
        let mut args = LuaArgs { ctx, stack };
        let fmt = args.string(1)?;
        strpack::pack(&fmt, &mut args)?
    };
    stack.replace(ctx, Value::String(ctx.intern(&packed)));
    Ok(())
}

/// `string.packsize(fmt)`.
fn str_packsize<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    let size = {
        let args = LuaArgs { ctx, stack };
        let fmt = args.string(1)?;
        strpack::packsize(&fmt)?
    };
    stack.replace(ctx, Value::Integer(size));
    Ok(())
}

/// `string.unpack(fmt, s [, init])`.
fn str_unpack<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    // The results borrow from the data argument, so they are turned into Lua
    // values before the stack they came from is overwritten.
    let values: Vec<Value<'gc>> = {
        let args = LuaArgs { ctx, stack };
        let fmt = args.string(1)?;
        let data = args.string(2)?;
        let init = args.opt_integer(3, 1)?;
        let (items, next) = strpack::unpack(&fmt, &data, init)?;
        items
            .into_iter()
            .map(|item| match item {
                Unpacked::Integer(i) => Value::Integer(i),
                Unpacked::Float(f) => Value::Number(f),
                Unpacked::Bytes(b) => Value::String(ctx.intern(b)),
            })
            .chain(std::iter::once(Value::Integer(next)))
            .collect()
    };
    stack.clear();
    for v in values {
        stack.push_back(v);
    }
    Ok(())
}

/// A capture as the Lua value `push_onecapture` pushes.
fn capture_value<'gc>(ctx: Context<'gc>, c: Capture<'_>) -> Value<'gc> {
    match c {
        Capture::Bytes(b) => Value::String(ctx.intern(b)),
        Capture::Position(n) => Value::Integer(n),
    }
}

/// Replace the call's arguments with `values`.
fn set_results<'gc>(stack: &mut Stack<'gc, '_>, values: Vec<Value<'gc>>) {
    stack.clear();
    for v in values {
        stack.push_back(v);
    }
}

/// `string.find(s, pattern [, init [, plain]])`.
fn str_find<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    // The captures borrow from the subject, so they become Lua values before
    // the stack holding it is overwritten.
    let values: Vec<Value<'gc>> = {
        let args = LuaArgs { ctx, stack };
        let s = args.string(1)?;
        let p = args.string(2)?;
        let init = args.opt_integer(3, 1)?;
        let plain = args.get(4).is_some_and(Value::to_bool);
        match pattern::find(&s, &p, init, plain).map_err(pattern_error)? {
            Some(found) => [Value::Integer(found.start), Value::Integer(found.end)]
                .into_iter()
                .chain(found.captures.into_iter().map(|c| capture_value(ctx, c)))
                .collect(),
            None => vec![Value::Nil],
        }
    };
    set_results(stack, values);
    Ok(())
}

/// `string.match(s, pattern [, init])`.
fn str_match<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    let values: Vec<Value<'gc>> = {
        let args = LuaArgs { ctx, stack };
        let s = args.string(1)?;
        let p = args.string(2)?;
        let init = args.opt_integer(3, 1)?;
        match pattern::str_match(&s, &p, init).map_err(pattern_error)? {
            Some(caps) => caps.into_iter().map(|c| capture_value(ctx, c)).collect(),
            None => vec![Value::Nil],
        }
    };
    set_results(stack, values);
    Ok(())
}

/// What a `gmatch` iterator closes over: the two strings (`lua_settop(L, 2)`
/// keeps them alive in the C) and the iteration state.
#[derive(Collect)]
#[collect(no_drop)]
struct GmatchRoot<'gc> {
    s: LuaString<'gc>,
    p: LuaString<'gc>,
    state: Cell<Gmatch>,
}

/// `string.gmatch(s, pattern [, init])`: returns the iterator.
fn str_gmatch<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>) -> Result<(), PackError> {
    let root = {
        let args = LuaArgs { ctx, stack };
        let s = args.string_value(1)?;
        let p = args.string_value(2)?;
        let init = args.opt_integer(3, 1)?;
        GmatchRoot {
            s,
            p,
            state: Cell::new(Gmatch::new(s.as_bytes().len(), init)),
        }
    };
    let iter = Callback::from_fn_with(&ctx, root, |root, ctx, _, mut stack| {
        let mut state = root.state.get();
        let found = state.next(root.s.as_bytes(), root.p.as_bytes());
        // Whatever `next` advanced is kept even if reading the captures then
        // failed, as the C keeps it.
        root.state.set(state);
        let values = match found.map_err(|e| lua_error(ctx, &e.msg))? {
            Some(caps) => caps.into_iter().map(|c| capture_value(ctx, c)).collect(),
            None => Vec::new(),
        };
        set_results(&mut stack, values);
        Ok(CallbackReturn::Return)
    });
    stack.replace(ctx, iter);
    Ok(())
}

/// `gsub`'s third argument, by `lua_type`.
#[derive(Collect, Clone, Copy)]
#[collect(no_drop)]
enum Replacement<'gc> {
    /// A string, or a number already converted to one, as `add_s`'s
    /// `lua_tolstring` converts it.
    Template(LuaString<'gc>),
    Function(Function<'gc>),
    Table(Table<'gc>),
}

/// `string.gsub(s, pattern, repl [, n])`, as a [`Sequence`]: a function or
/// table replacement is a call back into the VM between one match and the
/// next.
#[derive(Collect)]
#[collect(no_drop)]
struct GsubSeq<'gc> {
    s: LuaString<'gc>,
    p: LuaString<'gc>,
    repl: Replacement<'gc>,
    #[collect(require_static)]
    driver: Gsub,
    /// The match whose replacement the VM is computing.
    #[collect(require_static)]
    pending: Option<Match>,
}

/// The argument checks of `str_gsub` (`lstrlib.c:928`), in the C's order: the
/// count (argument 4) is read before the replacement's type (argument 3) is
/// checked, so a bad count is the error reported when both are wrong.
fn gsub_start<'gc>(ctx: Context<'gc>, stack: &Stack<'gc, '_>) -> Result<GsubSeq<'gc>, PackError> {
    let args = LuaArgs { ctx, stack };
    let s = args.string_value(1)?;
    let p = args.string_value(2)?;
    let tr = args.get(3);
    let srcl = i64::try_from(s.as_bytes().len()).unwrap_or(i64::MAX);
    let max_s = args.opt_integer(4, srcl.saturating_add(1))?;
    let repl = match tr {
        Some(Value::String(r)) => Replacement::Template(r),
        Some(v @ (Value::Integer(_) | Value::Number(_))) => Replacement::Template(
            v.into_string(ctx)
                .ok_or_else(|| args.type_error(3, "string/function/table"))?,
        ),
        Some(Value::Function(f)) => Replacement::Function(f),
        Some(Value::Table(t)) => Replacement::Table(t),
        _ => return Err(args.type_error(3, "string/function/table")),
    };
    Ok(GsubSeq {
        s,
        p,
        repl,
        driver: Gsub::new(p.as_bytes(), max_s),
        pending: None,
    })
}

impl<'gc> GsubSeq<'gc> {
    /// The tail of `add_value` (`lstrlib.c:899`): what a function returned or
    /// a table held for this match.
    fn apply(&mut self, ctx: Context<'gc>, m: &Match, v: Value<'gc>) -> Result<(), Error<'gc>> {
        let s = self.s.as_bytes();
        let res = if !v.to_bool() {
            self.driver.keep(s, m) // nil or false: keep the original text
        } else {
            match v {
                Value::String(r) => self.driver.add_value(m, r.as_bytes()),
                Value::Integer(_) | Value::Number(_) => {
                    let text = v.into_string(ctx).map_or(&[][..], |r| r.as_bytes());
                    self.driver.add_value(m, text)
                }
                other => {
                    return Err(lua_error(
                        ctx,
                        &format!("invalid replacement value (a {})", other.type_name()),
                    ))
                }
            }
        };
        res.map_err(|e| lua_error(ctx, &e.msg))
    }
}

impl<'gc> Sequence<'gc> for GsubSeq<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        mut exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        let (s, p) = (this.s.as_bytes(), this.p.as_bytes());
        let err = |e: PatternError| lua_error(ctx, &e.msg);

        // A call made on the previous poll has returned: its first result is
        // the replacement (`lua_call(L, n, 1)`, `lua_gettable`).
        if let Some(m) = this.pending.take() {
            let v = stack.get(0);
            stack.clear();
            this.apply(ctx, &m, v)?;
        }

        loop {
            let Some(m) = this.driver.next(s, p).map_err(err)? else {
                let (out, n) = this.driver.finish(s).map_err(err)?;
                let result = out.map_or(this.s, |b| ctx.intern(&b));
                stack.replace(ctx, (Value::String(result), Value::Integer(n)));
                return Ok(SequencePoll::Return);
            };
            match this.repl {
                Replacement::Template(r) => {
                    this.driver.add_template(s, &m, r.as_bytes()).map_err(err)?;
                }
                Replacement::Function(f) => {
                    let caps = m.captures(s, true).map_err(err)?;
                    stack.clear();
                    for c in caps {
                        stack.push_back(capture_value(ctx, c));
                    }
                    this.pending = Some(m);
                    return Ok(SequencePoll::Call {
                        bottom: 0,
                        function: f,
                    });
                }
                Replacement::Table(t) => {
                    let key = capture_value(ctx, m.capture(s, 0).map_err(err)?);
                    match meta_ops::index(ctx, Value::Table(t), key)? {
                        MetaResult::Value(v) => this.apply(ctx, &m, v)?,
                        MetaResult::Call(call) => {
                            stack.clear();
                            stack.extend(call.args);
                            this.pending = Some(m);
                            return Ok(SequencePoll::Call {
                                bottom: 0,
                                function: call.function,
                            });
                        }
                    }
                }
            }
            // One unit of fuel per replacement, so that a long substitution
            // yields to the host between matches rather than holding the VM.
            let fuel = exec.fuel();
            fuel.consume(1);
            if !fuel.should_continue() {
                return Ok(SequencePoll::Pending);
            }
        }
    }
}

/// `string.format`, as a [`Sequence`] for the one case that needs it: a `%s`
/// whose argument has a `__tostring` metamethod, which is a call into the VM.
#[derive(Collect)]
#[collect(no_drop)]
struct FormatSeq<'gc> {
    /// The call's arguments; the format is the first.
    args: Vec<Value<'gc>>,
    /// `__tostring` results already obtained, by argument index (0-based).
    resolved: Vec<Option<LuaString<'gc>>>,
    /// An argument whose `__tostring` must be called before formatting can
    /// continue.
    #[collect(require_static)]
    need: Option<usize>,
    /// The argument whose `__tostring` the VM is running now.
    #[collect(require_static)]
    awaiting: Option<usize>,
    #[collect(require_static)]
    f: Formatter,
}

/// The arguments of a `string.format` call as [`FormatArgs`].
struct VmArgs<'s, 'gc> {
    ctx: Context<'gc>,
    args: &'s [Value<'gc>],
    resolved: &'s [Option<LuaString<'gc>>],
}

impl<'gc> VmArgs<'_, 'gc> {
    fn get(&self, arg: usize) -> Option<Value<'gc>> {
        arg.checked_sub(1).and_then(|i| self.args.get(i)).copied()
    }
}

impl FormatArgs for VmArgs<'_, '_> {
    fn count(&self) -> usize {
        self.args.len()
    }

    fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
        check_integer(self.get(arg), arg)
    }

    fn number(&mut self, arg: usize) -> Result<f64, PackError> {
        check_number(self.get(arg), arg)
    }

    /// `luaL_tolstring`: the VM's own `tostring`, so that `%s` and `tostring`
    /// agree on every value. A `__tostring` metamethod is a call the binding
    /// must make, so that answers "not yet" until it has.
    fn tostring(&mut self, arg: usize) -> Result<Option<Cow<'_, [u8]>>, PackError> {
        let i = arg.saturating_sub(1);
        if let Some(Some(s)) = self.resolved.get(i) {
            return Ok(Some(Cow::Borrowed(s.as_bytes())));
        }
        let v = self.get(arg).unwrap_or(Value::Nil);
        match meta_ops::tostring(self.ctx, v) {
            Ok(MetaResult::Value(Value::String(s))) => Ok(Some(Cow::Borrowed(s.as_bytes()))),
            Ok(MetaResult::Value(other)) => {
                Ok(Some(Cow::Owned(other.display().to_string().into_bytes())))
            }
            Ok(MetaResult::Call(_)) => Ok(None),
            // `luaL_callmeta` calls whatever `__tostring` holds, and calling a
            // value that is not callable raises the VM's call error.
            Err(_) => {
                let mm = match v {
                    Value::Table(t) => t.metatable(),
                    Value::UserData(u) => u.metatable(),
                    _ => None,
                }
                .map_or(Value::Nil, |mt| mt.get_value(self.ctx, "__tostring"));
                Err(PackError {
                    arg: None,
                    msg: format!("attempt to call a {} value", mm.type_name()),
                })
            }
        }
    }

    fn literal(&mut self, arg: usize) -> Result<Literal<'_>, PackError> {
        match self.get(arg) {
            Some(Value::String(s)) => Ok(Literal::Str(Cow::Borrowed(s.as_bytes()))),
            Some(Value::Integer(n)) => Ok(Literal::Integer(n)),
            Some(Value::Number(x)) => Ok(Literal::Float(x)),
            Some(Value::Nil) => Ok(Literal::Text("nil")),
            Some(Value::Boolean(true)) => Ok(Literal::Text("true")),
            Some(Value::Boolean(false)) => Ok(Literal::Text("false")),
            _ => Err(PackError::bad_argument(arg, "value has no literal form")),
        }
    }

    /// `lua_topointer`: the object's address for anything the collector owns,
    /// `None` for numbers, booleans and `nil`.
    fn pointer(&mut self, arg: usize) -> Option<usize> {
        use gc_arena::Gc;
        use piccolo::Function as F;
        Some(match self.get(arg)? {
            Value::String(s) => Gc::as_ptr(s.into_inner()) as *const () as usize,
            Value::Table(t) => Gc::as_ptr(t.into_inner()) as *const () as usize,
            Value::Function(F::Closure(c)) => Gc::as_ptr(c.into_inner()) as *const () as usize,
            Value::Function(F::Callback(c)) => Gc::as_ptr(c.into_inner()) as *const () as usize,
            Value::Thread(t) => Gc::as_ptr(t.into_inner()) as *const () as usize,
            Value::UserData(u) => Gc::as_ptr(u.into_inner()) as *const () as usize,
            _ => return None,
        })
    }
}

impl<'gc> FormatSeq<'gc> {
    /// Format until done (the result) or until a `__tostring` call is needed
    /// (`None`, with the call recorded in `pending`).
    fn run(&mut self, ctx: Context<'gc>) -> Result<Option<LuaString<'gc>>, Error<'gc>> {
        let fmt = match self.args.first() {
            Some(Value::String(s)) => s.as_bytes(),
            v => {
                let s = v
                    .copied()
                    .filter(|v| matches!(v, Value::Integer(_) | Value::Number(_)))
                    .and_then(|v| v.into_string(ctx))
                    .ok_or_else(|| {
                        lua_error(
                            ctx,
                            &type_error(v.copied(), 1, "string").lua_message("format"),
                        )
                    })?;
                self.args[0] = Value::String(s);
                s.as_bytes()
            }
        };
        let mut args = VmArgs {
            ctx,
            args: &self.args,
            resolved: &self.resolved,
        };
        match format_step(fmt, &mut self.f, &mut args) {
            Ok(Step::Done(out)) => Ok(Some(ctx.intern(&out))),
            Ok(Step::NeedsToString(arg)) => {
                self.need = Some(arg);
                Ok(None)
            }
            Err(e) => Err(lua_error_bytes(ctx, &e.lua_message("format"))),
        }
    }
}

impl<'gc> Sequence<'gc> for FormatSeq<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        if let Some(arg) = this.awaiting.take() {
            // `luaL_tolstring`: the metamethod's first result, which must be a
            // string or a number (converted as `lua_tolstring` converts it).
            let v = stack.get(0);
            stack.clear();
            let s = match v {
                Value::String(s) => s,
                Value::Integer(_) | Value::Number(_) => v
                    .into_string(ctx)
                    .ok_or_else(|| lua_error(ctx, "'__tostring' must return a string"))?,
                _ => return Err(lua_error(ctx, "'__tostring' must return a string")),
            };
            let i = arg.saturating_sub(1);
            if this.resolved.len() <= i {
                this.resolved.resize(i.saturating_add(1), None);
            }
            this.resolved[i] = Some(s);
        }
        loop {
            if let Some(arg) = this.need.take() {
                let v = this
                    .args
                    .get(arg.saturating_sub(1))
                    .copied()
                    .unwrap_or(Value::Nil);
                match meta_ops::tostring(ctx, v)? {
                    MetaResult::Call(call) => {
                        stack.clear();
                        stack.extend(call.args);
                        this.awaiting = Some(arg);
                        return Ok(SequencePoll::Call {
                            bottom: 0,
                            function: call.function,
                        });
                    }
                    // Not reachable — `need` is only set for a metamethod —
                    // but harmless: record the value and carry on.
                    MetaResult::Value(v) => {
                        let i = arg.saturating_sub(1);
                        if this.resolved.len() <= i {
                            this.resolved.resize(i.saturating_add(1), None);
                        }
                        this.resolved[i] = v.into_string(ctx);
                    }
                }
            }
            if let Some(result) = this.run(ctx)? {
                stack.replace(ctx, Value::String(result));
                return Ok(SequencePoll::Return);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end through the VM, in-module so that Miri runs them: the
    //! differential corpora read from disk and so cannot. These cover the
    //! binding's own decisions — argument conversion, the "no value" versus
    //! `nil` distinction, results outliving the stack they came from, and the
    //! `gsub` sequence's calls back into the VM across garbage collections.
    use super::{load_format, load_patterns, load_strpack, load_tail};
    use piccolo::{Closure, Executor, Fuel, Lua, Value, Variadic};

    /// Run `src` and render its results, or `Err` with the Lua error message.
    /// Shared with the submodules' tests.
    pub(super) fn run(src: &str) -> Result<Vec<String>, String> {
        let mut lua = Lua::core();
        let ex = lua
            .try_enter(|ctx| {
                load_strpack(ctx).expect("Lua::core() has a string table");
                load_patterns(ctx).expect("Lua::core() has a string table");
                load_format(ctx).expect("Lua::core() has a string table");
                load_tail(ctx).expect("Lua::core() has string and coroutine tables");
                let c = Closure::load(ctx, None, src.as_bytes())?;
                Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
            })
            .map_err(|e| e.to_string())?;
        lua.finish(&ex).map_err(|e| e.to_string())?;
        lua.enter(
            |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => Ok(vs
                    .0
                    .into_iter()
                    .map(|v| match v {
                        Value::String(s) => format!("{:?}", s.as_bytes()),
                        v => format!("{}:{}", v.type_name(), v.display()),
                    })
                    .collect()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(e) => Err(e.to_string()),
            },
        )
    }

    #[test]
    fn pack_unpack_and_packsize_are_installed() {
        assert_eq!(
            run("return string.pack('<i2', -2)").unwrap(),
            ["[254, 255]"]
        );
        assert_eq!(
            run("return string.unpack('<i2 B', '\\254\\255\\7')").unwrap(),
            ["number:-2", "number:7", "number:4"]
        );
        assert_eq!(
            run("return string.packsize('i4 i8')").unwrap(),
            ["number:12"]
        );
    }

    #[test]
    fn method_calls_resolve_through_the_string_metatable() {
        assert_eq!(run("return ('<I2'):pack(258)").unwrap(), ["[2, 1]"]);
    }

    #[test]
    fn arguments_convert_as_lua_converts_them() {
        // `luaL_checkinteger` coerces a numeric string and an integral float.
        assert_eq!(run("return string.pack('b', '7')").unwrap(), ["[7]"]);
        assert_eq!(run("return string.pack('b', 7.0)").unwrap(), ["[7]"]);
        // `luaL_checklstring` renders a number the way `tostring` does.
        assert_eq!(
            run("return string.pack('z', 1.5)").unwrap(),
            ["[49, 46, 53, 0]"]
        );
        assert_eq!(
            run("return string.pack('z', 2.0)").unwrap(),
            ["[50, 46, 48, 0]"]
        );
        let e = run("return string.pack('b', 1.5)").unwrap_err();
        assert!(e.contains("number has no integer representation"), "{e}");
        let e = run("return string.pack('b', {})").unwrap_err();
        assert!(e.contains("number expected, got table"), "{e}");
    }

    #[test]
    fn errors_are_catchable_lua_errors() {
        assert_eq!(
            run("return pcall(string.unpack, 'i4', 'ab')").unwrap()[0],
            "boolean:false"
        );
        let e = run("return string.pack('i1', 300)").unwrap_err();
        assert!(
            e.contains("bad argument #2 to 'pack' (integer overflow)"),
            "{e}"
        );
    }

    #[test]
    fn a_missing_argument_is_no_value_not_nil() {
        let e = run("return string.unpack('b')").unwrap_err();
        assert!(e.contains("string expected, got no value"), "{e}");
        let e = run("return string.unpack('b', nil)").unwrap_err();
        assert!(e.contains("string expected, got nil"), "{e}");
    }

    /// How `run` renders a string result.
    fn bytes(s: &str) -> String {
        format!("{:?}", s.as_bytes())
    }

    // Each VM costs seconds under Miri, so each of the next two tests asks
    // everything of one VM, catching errors with `pcall` inside the chunk
    // rather than starting a VM per error.

    #[test]
    fn find_match_gmatch_and_gsub_are_installed() {
        let got = run("local f1, f2 = string.find('hello', 'l+') \
             local k, v = ('key=val'):match('(%w+)=(%w+)') \
             local t = {} for w in ('a b c'):gmatch('%a') do t[#t + 1] = w end \
             local g, n = ('hello'):gsub('l', 'L') \
             local miss = string.find('abc', 'x') \
             local _, e1 = pcall(string.find, 'b', 'b[') \
             local _, e2 = pcall(('ab'):gmatch('(a')) \
             return f1, f2, k, v, #t, g, n, miss, e1, e2")
        .unwrap();
        assert_eq!(
            got,
            [
                "number:3".to_string(),
                "number:4".to_string(),
                bytes("key"),
                bytes("val"),
                "number:3".to_string(),
                bytes("heLLo"),
                "number:2".to_string(),
                "nil:nil".to_string(),
                // Matcher errors are ordinary Lua errors, with the C's text.
                bytes("malformed pattern (missing ']')"),
                bytes("unfinished capture"),
            ]
        );
    }

    #[test]
    fn gsub_calls_functions_and_tables_back_in_the_vm() {
        let got = run(
            "local a, an = ('abc'):gsub('%w', function(c) return c .. c end) \
             local b = ('abc'):gsub('%w', function(c) if c == 'b' then return 1.5 end end) \
             local t = setmetatable({}, {__index = function(_, k) return k:upper() end}) \
             local c = ('ab'):gsub('%w', t) \
             local _, e1 = pcall(string.gsub, 'ab', '%w', function() return {} end) \
             local _, e2 = pcall(string.gsub, 'ab', '%w', function() error('boom', 0) end) \
             local _, e3 = pcall(string.gsub, 'ab', '%w', true) \
             return a, an, b, c, e1, e2, e3",
        )
        .unwrap();
        assert_eq!(
            got,
            [
                bytes("aabbcc"),
                "number:3".to_string(),
                // `nil` keeps the match; a number is rendered as `tostring` does.
                bytes("a1.5c"),
                // A table is indexed with metamethods, as `lua_gettable` does.
                bytes("AB"),
                bytes("invalid replacement value (a table)"),
                // An error inside the callback propagates unchanged.
                bytes("boom"),
                bytes("bad argument #3 to 'gsub' (string/function/table expected, got boolean)"),
            ]
        );
    }

    #[test]
    fn a_gsub_interrupted_by_fuel_resumes_where_it_stopped() {
        // One unit of fuel per step: the sequence returns `Pending` between
        // replacements, the arena is left — and fully collected — between
        // steps, and the subject, built at run time so the sequence holds the
        // only reference to it, must still be there when the sequence resumes.
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            load_patterns(ctx).expect("Lua::core() has a string table");
            let src = "local s = '' for i = 1, 12 do s = s .. 'ab' end \
                       return s:gsub('a', function(c) return c:upper() end)";
            let c = Closure::load(ctx, None, src.as_bytes()).expect("compiles");
            ctx.stash(Executor::start(ctx, c.into(), ()))
        });
        let mut steps = 0;
        loop {
            let mut fuel = Fuel::with(1);
            if lua
                .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
                .expect("steps")
            {
                break;
            }
            lua.gc_collect();
            steps += 1;
            assert!(steps < 100_000, "the substitution never finished");
        }
        let (out, n) = lua.enter(|ctx| {
            let (s, n) = ctx
                .fetch(&ex)
                .take_result::<(piccolo::String, i64)>(ctx)
                .expect("finished")
                .expect("no error");
            (s.as_bytes().to_vec(), n)
        });
        assert_eq!(out, b"Ab".repeat(12));
        assert_eq!(n, 12);
        assert!(steps > 12, "only {steps} steps: the sequence never yielded");
    }

    #[test]
    fn format_is_installed_and_calls_tostring_back_in_the_vm() {
        let got = run("local t = setmetatable({}, {__tostring = function() return 'obj' end}) \
             local n = setmetatable({}, {__tostring = function() return 7 end}) \
             local _, e1 = pcall(string.format, '%s', setmetatable({}, {__tostring = function() return {} end})) \
             local _, e2 = pcall(string.format, '%d %s', 'x', t) \
             local _, e3 = pcall(string.format, '%y', 1) \
             return string.format('%5.1f|%-4d|%x|%q', 3.14159, 42, 255, 'a\\n'), \
                    ('%s and %s'):format(t, n), string.format('[%5s]', t), e1, e2, e3")
        .unwrap();
        assert_eq!(
            got,
            [
                bytes("  3.1|42  |ff|\"a\\\n\""),
                bytes("obj and 7"),
                bytes("[  obj]"),
                bytes("'__tostring' must return a string"),
                // The integer is checked before `__tostring` is ever called.
                bytes("bad argument #2 to 'format' (number expected, got string)"),
                bytes("invalid conversion '%y' to 'format'"),
            ]
        );
    }
}
