//! The first-party half of NSE's Lua standard library.
//!
//! The vendored VM ships seven string functions. The rest of what the shipped
//! scripts call — Lua patterns, `string.format`, `string.pack`/`unpack` — is
//! written here, against the VM's public API, rather than patched into
//! `crates/vendor/piccolo`. The reason is the gates: a function in this crate is
//! reachable by the differential corpus, the fuzz targets and Miri, and a
//! function inside a vendored dependency is reachable by none of them
//! (`docs/M6-ANALYSIS.md`, "What the fork is *for*").
//!
//! Each function is split in two. The byte-level work is a pure module that
//! knows nothing about the interpreter — [`strpack`], [`pattern`] — so that it
//! can be fuzzed and run under Miri directly. What is left here is the binding:
//! turning Lua values into the arguments those functions take, with the
//! **VM's own** conversions, and turning the results back. Nothing in this file
//! parses a byte of script-supplied data.

pub mod pattern;
pub mod strpack;

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
            let seq = gsub_start(ctx, &stack)
                .map_err(|e| lua_error(ctx, &e.lua_message("gsub")))?;
            stack.clear();
            Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, seq)))
        }),
    );
    Ok(())
}

/// Why [`load_strpack`] could not install the functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The globals hold no `string` table — the VM was built without
    /// `load_string`. There is nothing sensible to install into.
    NoStringTable,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NoStringTable => f.write_str("the Lua state has no `string` table"),
        }
    }
}

impl std::error::Error for LoadError {}

type Body = for<'gc, 'a> fn(Context<'gc>, &mut Stack<'gc, 'a>) -> Result<(), PackError>;

fn install<'gc>(ctx: Context<'gc>, table: Table<'gc>, name: &'static str, body: Body) {
    table.set_field(
        ctx,
        name,
        Callback::from_fn(&ctx, move |ctx, _, mut stack| {
            match body(ctx, &mut stack) {
                Ok(()) => Ok(CallbackReturn::Return),
                Err(e) => Err(lua_error(ctx, &e.lua_message(name))),
            }
        }),
    );
}

/// A Lua error carrying a string, which is what `luaL_error` and
/// `luaL_argerror` raise: `pcall` returns it as the message.
fn lua_error<'gc>(ctx: Context<'gc>, msg: &str) -> Error<'gc> {
    Error::from(Value::String(ctx.intern(msg.as_bytes())))
}

/// A matcher error is a `luaL_error`: it names no argument.
fn pattern_error(e: PatternError) -> PackError {
    PackError {
        arg: None,
        msg: e.msg,
    }
}

/// The Lua arguments of one call, read by 1-based argument number.
struct LuaArgs<'s, 'gc, 'a> {
    ctx: Context<'gc>,
    stack: &'s Stack<'gc, 'a>,
}

impl<'gc> LuaArgs<'_, 'gc, '_> {
    /// The argument, or `None` if the call passed fewer — which the C words
    /// differently from an explicit `nil` ("got no value").
    fn get(&self, arg: usize) -> Option<Value<'gc>> {
        arg.checked_sub(1)
            .filter(|&i| i < self.stack.len())
            .map(|i| self.stack.get(i))
    }

    fn type_error(&self, arg: usize, expected: &str) -> PackError {
        let got = self.get(arg).map_or("no value", |v| v.type_name());
        PackError::bad_argument(arg, format!("{expected} expected, got {got}"))
    }

    /// `luaL_checklstring` for an argument that must be present.
    fn string(&self, arg: usize) -> Result<Cow<'gc, [u8]>, PackError> {
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
    fn check_integer(&self, arg: usize) -> Result<i64, PackError> {
        let v = self.get(arg).unwrap_or(Value::Nil);
        match v.to_integer() {
            Some(i) => Ok(i),
            None if v.to_number().is_some() => Err(PackError::bad_argument(
                arg,
                "number has no integer representation",
            )),
            None => Err(self.type_error(arg, "number")),
        }
    }
}

impl PackArgs for LuaArgs<'_, '_, '_> {
    fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
        self.check_integer(arg)
    }

    fn number(&mut self, arg: usize) -> Result<f64, PackError> {
        self.get(arg)
            .and_then(Value::to_number)
            .ok_or_else(|| self.type_error(arg, "number"))
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

#[cfg(test)]
mod tests {
    //! End-to-end through the VM, in-module so that Miri runs them: the
    //! 4,804-case differential reads its corpus from disk and so cannot. These
    //! cover the binding's own decisions — argument conversion, the "no value"
    //! versus `nil` distinction, results outliving the stack they came from.
    use super::load_strpack;
    use piccolo::{Closure, Executor, Lua, Value, Variadic};

    /// Run `src` and render its results, or `Err` with the Lua error message.
    fn run(src: &str) -> Result<Vec<String>, String> {
        let mut lua = Lua::core();
        let ex = lua
            .try_enter(|ctx| {
                load_strpack(ctx).expect("Lua::core() has a string table");
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
}
