use std::io::Write;

use gc_arena::{Collect, Rootable};
use thiserror::Error;

use crate::async_callback::{AsyncSequence, Locals};
use crate::number_format;
use crate::{async_sequence, SequenceReturn, Stack};
use crate::{
    table::InvalidTableKey, Callback, CallbackReturn, Constant, Context, Function, IntoValue,
    Singleton, Table, Value,
};

/// An enum of every possible Lua metamethod.
///
/// The [`MetaMethod::name`] method will return the name that Lua expects to be the key
/// for the metamethod in a metatable. For example, `MetaMethod::Add.name()` is `"__add"`,
/// `MetaMethod::Sub.name()` is `"__sub"`, etc.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Collect)]
#[collect(require_static)]
pub enum MetaMethod {
    Len,
    Index,
    NewIndex,
    Call,
    Pairs,
    ToString,
    Eq,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Unm,
    IDiv,
    BAnd,
    BOr,
    BXor,
    BNot,
    Shl,
    Shr,
    Concat,
    Lt,
    Le,
}

impl MetaMethod {
    pub const fn name(self) -> &'static str {
        match self {
            MetaMethod::Len => "__len",
            MetaMethod::Index => "__index",
            MetaMethod::NewIndex => "__newindex",
            MetaMethod::Call => "__call",
            MetaMethod::Pairs => "__pairs",
            MetaMethod::ToString => "__tostring",
            MetaMethod::Eq => "__eq",
            MetaMethod::Add => "__add",
            MetaMethod::Sub => "__sub",
            MetaMethod::Mul => "__mul",
            MetaMethod::Div => "__div",
            MetaMethod::Mod => "__mod",
            MetaMethod::Pow => "__pow",
            MetaMethod::Unm => "__unm",
            MetaMethod::IDiv => "__idiv",
            MetaMethod::BAnd => "__band",
            MetaMethod::BOr => "__bor",
            MetaMethod::BXor => "__bxor",
            MetaMethod::BNot => "__bnot",
            MetaMethod::Shl => "__shl",
            MetaMethod::Shr => "__shr",
            MetaMethod::Concat => "__concat",
            MetaMethod::Lt => "__lt",
            MetaMethod::Le => "__le",
        }
    }

    /// Sentence-form verb of this metamethod's action
    ///
    /// - unary: "Could not {verb} a {type} value"
    /// - index: "Could not {verb} a {type} value"
    /// - binary: "Could not {verb} values of type {lhs_type} and {rhs_type}"
    pub const fn verb(self) -> &'static str {
        match self {
            MetaMethod::Len => "determine length of",
            MetaMethod::Call => "call",
            MetaMethod::Pairs => "get pairs of",
            MetaMethod::ToString => "convert to string", // a bit awkward, but works
            MetaMethod::Index => "index into",
            MetaMethod::NewIndex => "index-assign into",
            MetaMethod::Eq => "compare equality of",
            MetaMethod::Add => "add",
            MetaMethod::Sub => "subtract",
            MetaMethod::Mul => "multiply",
            MetaMethod::Div => "divide",
            MetaMethod::Mod => "take modulus of",
            MetaMethod::Pow => "exponentiate",
            MetaMethod::Unm => "negate",
            MetaMethod::IDiv => "flooring divide",
            MetaMethod::BAnd => "binary and",
            MetaMethod::BOr => "binary or",
            MetaMethod::BXor => "binary xor",
            MetaMethod::BNot => "binary negate",
            MetaMethod::Shl => "left shift",
            MetaMethod::Shr => "right shift",
            MetaMethod::Concat => "concatenate",
            MetaMethod::Lt => "compare",
            MetaMethod::Le => "compare",
        }
    }
}

impl<'gc> IntoValue<'gc> for MetaMethod {
    fn into_value(self, ctx: Context<'gc>) -> Value<'gc> {
        self.name().into_value(ctx)
    }
}

/// If invoking a metamethod must call Lua code, this will contain a function and arguments to call
/// to trigger it.
#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub struct MetaCall<'gc, const N: usize> {
    pub function: Function<'gc>,
    pub args: [Value<'gc>; N],
}

/// Return value for metamethods that return a value *or* require calling into Lua.
#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub enum MetaResult<'gc, const N: usize> {
    Value(Value<'gc>),
    Call(MetaCall<'gc, N>),
}

impl<'gc, const N: usize> From<Value<'gc>> for MetaResult<'gc, N> {
    fn from(value: Value<'gc>) -> Self {
        Self::Value(value)
    }
}

impl<'gc, const N: usize> From<MetaCall<'gc, N>> for MetaResult<'gc, N> {
    fn from(call: MetaCall<'gc, N>) -> Self {
        MetaResult::Call(call)
    }
}

/// An operator that could not be applied. Every message is PUC-Lua 5.4's,
/// word for word, without the `chunk:line:` position the executor adds when
/// the operator ran in a Lua function.
#[derive(Debug, Clone, Error)]
pub enum MetaOperatorError {
    /// The metamethod found is not callable: its call's error.
    #[error("{1}")]
    Call(MetaMethod, #[source] MetaCallError),
    /// The operands are wrong, in PUC-Lua's words (`ldebug.c`, `lstrlib.c`).
    #[error("{0}")]
    Message(std::string::String),
    /// As `Message`, but raised by `luaG_runerror` inside a C function (the
    /// string metatable's arithmetic), which gives no position.
    #[error("{0}")]
    MessageFromC(std::string::String),
    #[error("{0}")]
    IndexKeyError(#[from] InvalidTableKey),
    /// `luaV_concat`'s "string length overflow".
    #[error("string length overflow")]
    ConcatOverflow,
}

/// A value that cannot be called: "attempt to call a X value".
#[derive(Debug, Clone, Error)]
#[error("attempt to call a {0} value")]
pub struct MetaCallError(std::string::String);

impl MetaCallError {
    /// The error for calling `v`, named as `luaT_objtypename` names it.
    pub fn for_value<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Self {
        Self(objtypename(ctx, v))
    }
}

/// `luaT_objtypename`: a table's or userdata's `__name`, when its metatable
/// has a string there, else the basic type name.
pub fn objtypename<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> std::string::String {
    let mt = match v {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        _ => None,
    };
    if let Some(mt) = mt {
        if let Value::String(name) = mt.get_value(ctx, "__name") {
            return std::string::String::from_utf8_lossy(name.as_bytes()).into_owned();
        }
    }
    v.type_name().to_owned()
}

/// `ttisnumber`: an integer or a float, not a numeric string.
fn is_number(v: Value<'_>) -> bool {
    matches!(v, Value::Integer(_) | Value::Number(_))
}

/// The `__add`-style name `lstrlib.c`'s `trymt` prints, less its `__`.
fn arith_name(method: MetaMethod) -> &'static str {
    match method {
        MetaMethod::Add => "add",
        MetaMethod::Sub => "sub",
        MetaMethod::Mul => "mul",
        MetaMethod::Mod => "mod",
        MetaMethod::Pow => "pow",
        MetaMethod::Div => "div",
        MetaMethod::IDiv => "idiv",
        _ => "unm",
    }
}

/// The error for a binary operator `method` on `lhs` and `rhs`, which no
/// metamethod and no primitive operation could handle.
fn binary_error<'gc>(
    ctx: Context<'gc>,
    method: MetaMethod,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> MetaOperatorError {
    let msg = match method {
        // `luaG_concaterror`: the first operand that is not a string or number.
        MetaMethod::Concat => {
            let culprit = if lhs.is_implicit_string() { rhs } else { lhs };
            format!(
                "attempt to concatenate a {} value",
                objtypename(ctx, culprit)
            )
        }
        // `luaG_ordererror`.
        MetaMethod::Lt | MetaMethod::Le => {
            let (t1, t2) = (objtypename(ctx, lhs), objtypename(ctx, rhs));
            if t1 == t2 {
                format!("attempt to compare two {t1} values")
            } else {
                format!("attempt to compare {t1} with {t2}")
            }
        }
        // `luaT_trybinTM` for the bitwise events: two numbers that are not
        // integers, else the first operand that is not a number.
        MetaMethod::BAnd
        | MetaMethod::BOr
        | MetaMethod::BXor
        | MetaMethod::Shl
        | MetaMethod::Shr => {
            if is_number(lhs) && is_number(rhs) {
                "number has no integer representation".to_owned()
            } else {
                let culprit = if is_number(lhs) { rhs } else { lhs };
                format!(
                    "attempt to perform bitwise operation on a {} value",
                    objtypename(ctx, culprit)
                )
            }
        }
        _ => {
            // A string operand: the string metatable's arithmetic metamethod
            // ran and gave up (`lstrlib.c`'s `trymt`).
            let numeric = |v: Value<'gc>| v.to_constant().and_then(|c| c.to_numeric());
            if let (
                Value::String(_) | Value::Integer(_),
                Value::String(_) | Value::Integer(_),
                Some(Constant::Integer(_)),
                Some(Constant::Integer(0)),
            ) = (lhs, rhs, numeric(lhs), numeric(rhs))
            {
                // Numeric strings: `lstrlib.c`'s `arith` converted them and
                // `lua_arith` divided by zero, inside that C function.
                if matches!(method, MetaMethod::Mod | MetaMethod::IDiv)
                    && (matches!(lhs, Value::String(_)) || matches!(rhs, Value::String(_)))
                {
                    return MetaOperatorError::MessageFromC(if method == MetaMethod::Mod {
                        "attempt to perform 'n%0'".to_owned()
                    } else {
                        "attempt to divide by zero".to_owned()
                    });
                }
            }
            if matches!(lhs, Value::String(_)) || matches!(rhs, Value::String(_)) {
                format!(
                    "attempt to {} a '{}' with a '{}'",
                    arith_name(method),
                    lhs.type_name(),
                    rhs.type_name()
                )
            } else if let (Value::Integer(_), Value::Integer(0)) = (lhs, rhs) {
                // `luaV_idiv` and `luaV_mod`.
                if method == MetaMethod::Mod {
                    "attempt to perform 'n%0'".to_owned()
                } else {
                    "attempt to divide by zero".to_owned()
                }
            } else {
                // `luaG_opinterror`: the first operand that is not a number.
                let culprit = if is_number(lhs) { rhs } else { lhs };
                format!(
                    "attempt to perform arithmetic on a {} value",
                    objtypename(ctx, culprit)
                )
            }
        }
    };
    MetaOperatorError::Message(msg)
}

/// The error for a unary operator `method` on `v`.
fn unary_error<'gc>(ctx: Context<'gc>, method: MetaMethod, v: Value<'gc>) -> MetaOperatorError {
    let msg = match method {
        MetaMethod::Index | MetaMethod::NewIndex => {
            format!("attempt to index a {} value", objtypename(ctx, v))
        }
        MetaMethod::Len => format!("attempt to get length of a {} value", objtypename(ctx, v)),
        MetaMethod::Call => format!("attempt to call a {} value", objtypename(ctx, v)),
        // Unary operators are binary in PUC-Lua, with the operand twice.
        MetaMethod::Unm | MetaMethod::BNot => {
            let MetaOperatorError::Message(m) = binary_error(
                ctx,
                if method == MetaMethod::Unm {
                    MetaMethod::Unm
                } else {
                    MetaMethod::BAnd
                },
                v,
                v,
            ) else {
                unreachable!("binary_error builds a message")
            };
            m
        }
        _ => format!(
            "attempt to {} a {} value",
            method.verb(),
            objtypename(ctx, v)
        ),
    };
    MetaOperatorError::Message(msg)
}

/// The metatable shared by every Lua string value.
///
/// Lua gives strings a metatable, and it is what makes method-call syntax work: `s:sub(1, 2)` is
/// an `__index` lookup on a *string*, not a call to `string.sub`. PUC-Lua builds this in
/// `luaopen_string` -- `createmetatable` (`lstrlib.c`) sets a metatable on a dummy string and
/// points its `__index` at the `string` library -- and there is exactly one of them per state, so
/// `rawequal(getmetatable("a"), getmetatable("b"))` is true.
///
/// It is a [`Singleton`] for that reason: one table per [`Lua`](crate::Lua) instance, created on
/// first use. It starts EMPTY; [`load_string`](crate::stdlib::load_string) is what installs
/// `__index`. That split is deliberate rather than incidental -- an embedder that builds its
/// stdlib from `Lua::empty()` can install its own `__index` here and get method dispatch over its
/// own string library, without this module needing to know anything about it.
pub fn string_metatable<'gc>(ctx: Context<'gc>) -> Table<'gc> {
    #[derive(Copy, Clone, Collect)]
    #[collect(no_drop)]
    struct StringMeta<'gc>(Table<'gc>);

    impl<'gc> Singleton<'gc> for StringMeta<'gc> {
        fn create(ctx: Context<'gc>) -> Self {
            Self(Table::new(&ctx))
        }
    }

    ctx.singleton::<Rootable![StringMeta<'_>]>().0
}

fn get_metatable<'gc>(ctx: Context<'gc>, val: Value<'gc>) -> Option<Table<'gc>> {
    match val {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        // Every string shares one metatable. Returning it here is what lets the metamethod
        // lookups below see it; since it holds only `__index`, every other metamethod resolves to
        // nil exactly as it did before, so no arithmetic or comparison behaviour changes.
        Value::String(_) => Some(string_metatable(ctx)),
        _ => None,
    }
}

fn get_metamethod<'gc>(
    ctx: Context<'gc>,
    val: Value<'gc>,
    method: MetaMethod,
) -> Option<Value<'gc>> {
    get_metatable(ctx, val)
        .map(|mt| mt.get_value(ctx, method))
        .filter(|v| !v.is_nil())
}

/// `MAXTAGLOOP` (`lvm.c`): how many `__index` / `__newindex` values a lookup
/// follows before it gives up.
pub const MAXTAGLOOP: usize = 2000;

/// The metatable PUC-Lua consults for `v` (`luaT_gettmbyobj`), if any.
fn metatable_of<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<Table<'gc>> {
    match v {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        // What makes `s:sub(1, 2)` and `("x"):rep(3)` work: a method call
        // and a plain index both route here.
        Value::String(_) => Some(string_metatable(ctx)),
        _ => None,
    }
}

/// `luaV_finishget`: follow `__index` values from `table` until one gives
/// the value. A table is read raw; a function is called (the one call this
/// returns); anything else is indexed in turn, through its own metatable. A
/// lookup runs in one go, at most `MAXTAGLOOP` hops, so that no chain costs
/// more than one call level, as no chain does in PUC-Lua.
pub fn index<'gc>(
    ctx: Context<'gc>,
    table: Value<'gc>,
    key: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    let mut t = table;
    let mut hops = 0;
    loop {
        if let Value::Table(table) = t {
            let v = table.get_value(ctx, key);
            if !v.is_nil() {
                return Ok(MetaResult::Value(v));
            }
        }
        if hops == MAXTAGLOOP {
            return Err(MetaOperatorError::Message(
                "'__index' chain too long; possible loop".into(),
            ));
        }
        hops += 1;
        let tm = metatable_of(ctx, t)
            .map(|mt| mt.get_value(ctx, MetaMethod::Index))
            .unwrap_or_default();
        if tm.is_nil() {
            // A table without one reads as nil; anything else cannot be
            // indexed.
            return match t {
                Value::Table(_) => Ok(MetaResult::Value(Value::Nil)),
                _ => Err(unary_error(ctx, MetaMethod::Index, t)),
            };
        }
        if let Value::Function(function) = tm {
            return Ok(MetaResult::Call(MetaCall {
                function,
                args: [t, key],
            }));
        }
        t = tm;
    }
}

/// `luaV_finishset`: follow `__newindex` values from `table` until one
/// takes the value. A table that holds the key, or has no `__newindex`, is
/// written raw; a function is called; anything else is assigned to in turn.
/// At most `MAXTAGLOOP` hops, all in one go.
pub fn new_index<'gc>(
    ctx: Context<'gc>,
    table: Value<'gc>,
    key: Value<'gc>,
    value: Value<'gc>,
) -> Result<Option<MetaCall<'gc, 3>>, MetaOperatorError> {
    let mut t = table;
    let mut hops = 0;
    loop {
        if let Value::Table(table) = t {
            if !table.get_value(ctx, key).is_nil() {
                table.set_raw(&ctx, key, value)?;
                return Ok(None);
            }
        }
        if hops == MAXTAGLOOP {
            return Err(MetaOperatorError::Message(
                "'__newindex' chain too long; possible loop".into(),
            ));
        }
        hops += 1;
        let tm = metatable_of(ctx, t)
            .map(|mt| mt.get_value(ctx, MetaMethod::NewIndex))
            .unwrap_or_default();
        if tm.is_nil() {
            return match t {
                Value::Table(table) => {
                    table.set_raw(&ctx, key, value)?;
                    Ok(None)
                }
                _ => Err(unary_error(ctx, MetaMethod::NewIndex, t)),
            };
        }
        if let Value::Function(function) = tm {
            return Ok(Some(MetaCall {
                function,
                args: [t, key, value],
            }));
        }
        t = tm;
    }
}

pub fn call<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Result<Function<'gc>, MetaCallError> {
    let metatable = match v {
        Value::Function(f) => return Ok(f),
        Value::Table(t) => t.metatable(),
        Value::UserData(ud) => ud.metatable(),
        _ => None,
    }
    .ok_or_else(|| MetaCallError::for_value(ctx, v))?;

    match metatable.get_value(ctx, MetaMethod::Call) {
        f @ (Value::Function(_) | Value::Table(_) | Value::UserData(_)) => Ok(
            // NOTE: Potential for infinite or arbitrarily long chains here, see note in __index.
            //
            // Example: `t = {}; setmetatable(t, { __call = t }); t()`
            Callback::from_fn_with(&ctx, (v, f), |&(v, f), ctx, _, mut stack| {
                stack.push_front(v);
                Ok(CallbackReturn::Call {
                    function: call(ctx, f)?,
                    then: None,
                })
            })
            .into(),
        ),
        // No `__call`: the error names the value called (`luaG_callerror`).
        Value::Nil => Err(MetaCallError::for_value(ctx, v)),
        f => Err(MetaCallError::for_value(ctx, f)),
    }
}

pub fn len<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Result<MetaResult<'gc, 1>, MetaOperatorError> {
    if let Some(metatable) = match v {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        _ => None,
    } {
        let len = metatable.get_value(ctx, MetaMethod::Len);
        if !len.is_nil() {
            return Ok(MetaResult::Call(MetaCall {
                function: call(ctx, len)
                    .map_err(|e| MetaOperatorError::Call(MetaMethod::Len, e))?,
                args: [v],
            }));
        }
    }

    match v {
        Value::String(s) => Ok(MetaResult::Value(s.len().into())),
        Value::Table(t) => Ok(MetaResult::Value(t.length().into())),
        f => Err(unary_error(ctx, MetaMethod::Len, f)),
    }
}

pub fn tostring<'gc>(
    ctx: Context<'gc>,
    v: Value<'gc>,
) -> Result<MetaResult<'gc, 1>, MetaOperatorError> {
    if let Some(metatable) = match v {
        Value::Table(t) => t.metatable(),
        Value::UserData(u) => u.metatable(),
        _ => None,
    } {
        let tostring = metatable.get_value(ctx, MetaMethod::ToString);
        if !tostring.is_nil() {
            return Ok(MetaResult::Call(MetaCall {
                function: call(ctx, tostring)
                    .map_err(|e| MetaOperatorError::Call(MetaMethod::ToString, e))?,
                args: [v],
            }));
        }
    }

    Ok(match v {
        v @ Value::String(_) => MetaResult::Value(v),
        v => MetaResult::Value(ctx.intern(v.display().to_string().as_bytes()).into()),
    })
}

pub fn equal<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    Ok(match (lhs, rhs) {
        (Value::Nil, Value::Nil) => Value::Boolean(true).into(),
        (Value::Nil, _) => Value::Boolean(false).into(),

        (Value::Boolean(a), Value::Boolean(b)) => Value::Boolean(a == b).into(),
        (Value::Boolean(_), _) => Value::Boolean(false).into(),

        (Value::Integer(a), Value::Integer(b)) => Value::Boolean(a == b).into(),
        (Value::Integer(a), Value::Number(b)) => Value::Boolean(a as f64 == b).into(),
        (Value::Integer(_), _) => Value::Boolean(false).into(),

        (Value::Number(a), Value::Number(b)) => Value::Boolean(a == b).into(),
        (Value::Number(a), Value::Integer(b)) => Value::Boolean(b as f64 == a).into(),
        (Value::Number(_), _) => Value::Boolean(false).into(),

        (Value::String(a), Value::String(b)) => Value::Boolean(a == b).into(),
        (Value::String(_), _) => Value::Boolean(false).into(),

        (Value::Function(a), Value::Function(b)) => Value::Boolean(a == b).into(),
        (Value::Function(_), _) => Value::Boolean(false).into(),

        (Value::Thread(a), Value::Thread(b)) => Value::Boolean(a == b).into(),
        (Value::Thread(_), _) => Value::Boolean(false).into(),

        (Value::Table(a), Value::Table(b)) if a == b => Value::Boolean(true).into(),
        (Value::Table(_), Value::Table(_)) => {
            if let Some(m) = get_metamethod(ctx, lhs, MetaMethod::Eq) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m)
                        .map_err(|e| MetaOperatorError::Call(MetaMethod::Eq, e))?,
                    args: [lhs, rhs],
                })
            } else if let Some(m) = get_metamethod(ctx, rhs, MetaMethod::Eq) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m)
                        .map_err(|e| MetaOperatorError::Call(MetaMethod::Eq, e))?,
                    args: [lhs, rhs],
                })
            } else {
                Value::Boolean(false).into()
            }
        }
        (Value::Table(_), _) => Value::Boolean(false).into(),

        (Value::UserData(a), Value::UserData(b)) if a == b => Value::Boolean(true).into(),
        (Value::UserData(_), Value::UserData(_)) => {
            if let Some(m) = get_metamethod(ctx, lhs, MetaMethod::Eq) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m)
                        .map_err(|e| MetaOperatorError::Call(MetaMethod::Eq, e))?,
                    args: [lhs, rhs],
                })
            } else if let Some(m) = get_metamethod(ctx, rhs, MetaMethod::Eq) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m)
                        .map_err(|e| MetaOperatorError::Call(MetaMethod::Eq, e))?,
                    args: [lhs, rhs],
                })
            } else {
                Value::Boolean(false).into()
            }
        }
        (Value::UserData(_), _) => Value::Boolean(false).into(),
    })
}

fn meta_metaop<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
    method: MetaMethod,
    const_op: impl Fn(Context<'gc>, Value<'gc>, Value<'gc>) -> Option<Value<'gc>>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    Ok(match (lhs, rhs) {
        (Value::Table(_) | Value::UserData(_), Value::Table(_) | Value::UserData(_)) => {
            if let Some(m) = get_metamethod(ctx, lhs, method) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m).map_err(|e| MetaOperatorError::Call(method, e))?,
                    args: [lhs, rhs],
                })
            } else if let Some(m) = get_metamethod(ctx, rhs, method) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m).map_err(|e| MetaOperatorError::Call(method, e))?,
                    args: [lhs, rhs],
                })
            } else {
                return Err(binary_error(ctx, method, lhs, rhs));
            }
        }
        (Value::Table(_) | Value::UserData(_), _) => {
            if let Some(m) = get_metamethod(ctx, lhs, method) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m).map_err(|e| MetaOperatorError::Call(method, e))?,
                    args: [lhs, rhs],
                })
            } else {
                return Err(binary_error(ctx, method, lhs, rhs));
            }
        }
        (_, Value::Table(_) | Value::UserData(_)) => {
            if let Some(m) = get_metamethod(ctx, rhs, method) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m).map_err(|e| MetaOperatorError::Call(method, e))?,
                    args: [lhs, rhs],
                })
            } else {
                return Err(binary_error(ctx, method, lhs, rhs));
            }
        }
        (a, b) => const_op(ctx, a, b)
            .ok_or_else(|| binary_error(ctx, method, lhs, rhs))?
            .into(),
    })
}

fn meta_unary_metaop<'gc>(
    ctx: Context<'gc>,
    arg: Value<'gc>,
    method: MetaMethod,
    const_op: impl Fn(Value<'gc>) -> Option<Value<'gc>>,
) -> Result<MetaResult<'gc, 1>, MetaOperatorError> {
    Ok(match arg {
        Value::Table(_) | Value::UserData(_) => {
            if let Some(m) = get_metamethod(ctx, arg, method) {
                MetaResult::Call(MetaCall {
                    function: call(ctx, m).map_err(|e| MetaOperatorError::Call(method, e))?,
                    args: [arg],
                })
            } else {
                return Err(unary_error(ctx, method, arg));
            }
        }
        val => const_op(val)
            .ok_or_else(|| unary_error(ctx, method, arg))?
            .into(),
    })
}

pub fn add<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Add, |_, a, b| {
        Some(a.to_constant()?.add(&b.to_constant()?)?.into())
    })
}

pub fn subtract<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Sub, |_, a, b| {
        Some(a.to_constant()?.subtract(&b.to_constant()?)?.into())
    })
}

pub fn multiply<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Mul, |_, a, b| {
        Some(a.to_constant()?.multiply(&b.to_constant()?)?.into())
    })
}

pub fn float_divide<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Div, |_, a, b| {
        Some(a.to_constant()?.float_divide(&b.to_constant()?)?.into())
    })
}

pub fn floor_divide<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::IDiv, |_, a, b| {
        Some(a.to_constant()?.floor_divide(&b.to_constant()?)?.into())
    })
}

pub fn modulo<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Mod, |_, a, b| {
        Some(a.to_constant()?.modulo(&b.to_constant()?)?.into())
    })
}

pub fn exponentiate<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Pow, |_, a, b| {
        Some(a.to_constant()?.exponentiate(&b.to_constant()?)?.into())
    })
}

pub fn negate<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
) -> Result<MetaResult<'gc, 1>, MetaOperatorError> {
    meta_unary_metaop(ctx, lhs, MetaMethod::Unm, |val| {
        Some(val.to_constant()?.negate()?.into())
    })
}

pub fn bitwise_not<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
) -> Result<MetaResult<'gc, 1>, MetaOperatorError> {
    meta_unary_metaop(ctx, lhs, MetaMethod::BNot, |val| {
        Some(val.to_constant()?.bitwise_not()?.into())
    })
}

pub fn bitwise_and<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::BAnd, |_, a, b| {
        Some(a.to_constant()?.bitwise_and(&b.to_constant()?)?.into())
    })
}

pub fn bitwise_or<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::BOr, |_, a, b| {
        Some(a.to_constant()?.bitwise_or(&b.to_constant()?)?.into())
    })
}

pub fn bitwise_xor<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::BXor, |_, a, b| {
        Some(a.to_constant()?.bitwise_xor(&b.to_constant()?)?.into())
    })
}

pub fn shift_left<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Shl, |_, a, b| {
        Some(a.to_constant()?.shift_left(&b.to_constant()?)?.into())
    })
}

pub fn shift_right<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Shr, |_, a, b| {
        Some(a.to_constant()?.shift_right(&b.to_constant()?)?.into())
    })
}

pub fn less_than<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Lt, |_, a, b| {
        Some(a.to_constant()?.less_than(&b.to_constant()?)?.into())
    })
}

pub fn less_equal<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Le, |_, a, b| {
        Some(a.to_constant()?.less_equal(&b.to_constant()?)?.into())
    })
}

/// The result of a concat metaoperation, either a completed [`Value`]
/// or a [`Function`] that must be called with the values to
/// concatenate.
#[derive(Debug, Clone, Collect)]
#[collect(no_drop)]
pub enum ConcatMetaResult<'gc> {
    Value(Value<'gc>),
    /// A `__concat` metamethod, to call with the values: one call level, as
    /// `luaT_callTMres` takes.
    Call(Function<'gc>),
    /// A function that concatenates the values itself, calling each
    /// metamethod it meets. It stands for `luaV_concat`'s loop, which is no
    /// call, so it takes no call level of its own.
    Concatenate(Function<'gc>),
}

pub fn concat<'gc>(
    ctx: Context<'gc>,
    lhs: Value<'gc>,
    rhs: Value<'gc>,
) -> Result<MetaResult<'gc, 2>, MetaOperatorError> {
    meta_metaop(ctx, lhs, rhs, MetaMethod::Concat, |ctx, a, b| {
        if a.is_implicit_string() && b.is_implicit_string() {
            let mut bytes = Vec::new();
            for value in [a, b] {
                match value {
                    Value::Integer(i) => write!(&mut bytes, "{}", i).unwrap(),
                    Value::Number(n) => {
                        write!(&mut bytes, "{}", number_format::display_float(n)).unwrap()
                    }
                    Value::String(s) => bytes.extend(s.as_bytes()),
                    _ => return None,
                }
            }
            Some(Value::String(ctx.intern(&bytes)))
        } else {
            None
        }
    })
}

/// Returns an estimate of the length of the concatenation of a list of values,
/// or returns [`None`] if any value is not implicitly coercible to a string.
fn estimate_concatenated_len<'gc>(
    values: &[Value<'gc>],
) -> Result<Option<usize>, MetaOperatorError> {
    let mut len = 0usize;
    for value in values {
        let value_len = match value {
            // `unsigned_abs`, not `abs`: `i64::MIN.abs()` overflows, and under
            // this workspace's `overflow-checks` that is a process abort rather
            // than a wrong number. It was reachable straight from a script --
            // `math.mininteger .. '' .. ''` -- and a host-language panic is not
            // a Lua error, so `pcall` could not contain it.
            // `max(1)` remains because `ilog10` panics for 0.
            Value::Integer(i) => {
                i.unsigned_abs().max(1).ilog10() as usize + 1 + i.is_negative() as usize
            }
            // `%.14g` plus a sign, a point and an exponent: `-4.9406564584125e-324`
            // is 21 bytes, and `tostring`'s trailing `.0` can add two more.
            Value::Number(_n) => 24,
            Value::String(s) => s.as_bytes().len(),
            _ => return Ok(None),
        };
        len = len
            .checked_add(value_len)
            .ok_or(MetaOperatorError::ConcatOverflow)?;
    }
    Ok(Some(len))
}

pub fn concat_many<'gc>(
    ctx: Context<'gc>,
    values: &[Value<'gc>],
) -> Result<ConcatMetaResult<'gc>, MetaOperatorError> {
    // Fast path scope; never loops, returns if successful, otherwise
    // breaks to fall back to the slow impl.
    loop {
        // Since we have to make two passes to check for complex types,
        // estimate the length in the first pass.
        let Some(len) = estimate_concatenated_len(values)? else {
            break;
        };

        // A result past the memory budget is refused before it is built; the
        // instruction then fails with "not enough memory".
        if len >= crate::lua::REFUSE_FROM && !ctx.can_allocate(len) {
            return Ok(ConcatMetaResult::Value(Value::String(ctx.intern(b""))));
        }
        let mut bytes = Vec::with_capacity(len);
        for value in values {
            match value {
                Value::Integer(i) => write!(&mut bytes, "{}", i).unwrap(),
                Value::Number(n) => {
                    write!(&mut bytes, "{}", number_format::display_float(*n)).unwrap()
                }
                Value::String(s) => bytes.extend(s.as_bytes()),
                _ => unreachable!(),
            }
        }
        return Ok(ConcatMetaResult::Value(Value::String(ctx.intern(&bytes))));
    }

    // `a .. b` with a metamethod: call it straight from the Lua frame.
    if let [a, b] = *values {
        if let MetaResult::Call(call) = concat(ctx, a, b)? {
            return Ok(ConcatMetaResult::Call(call.function));
        }
    }

    // Without a `__concat` anywhere the operation cannot succeed: raise
    // `luaV_concat`'s error here, from the Lua frame, rather than from inside
    // the fallback's callback, where it would lose its position. Lua
    // concatenates from the right, so the first pair to fail is the
    // rightmost one with a value that is not a string or number.
    let has_concat_mm = values.iter().any(|v| {
        match v {
            Value::Table(t) => t.metatable(),
            Value::UserData(u) => u.metatable(),
            _ => None,
        }
        .is_some_and(|mt| !mt.get_value(ctx, MetaMethod::Concat).is_nil())
    });
    if !has_concat_mm {
        if let Some(i) = values.iter().rposition(|v| !v.is_implicit_string()) {
            // The last value is the first right-hand side; after it, the
            // right-hand side is the string built so far. `luaG_concaterror`
            // blames the left value unless it is a string or number.
            let n = values.len();
            let culprit = if i + 1 == n && n >= 2 && !values[n - 2].is_implicit_string() {
                values[n - 2]
            } else {
                values[i]
            };
            return Err(MetaOperatorError::Message(format!(
                "attempt to concatenate a {} value",
                objtypename(ctx, culprit)
            )));
        }
    }

    // Fall back to a sequence-based implemenation to handle metamethods
    let func = Callback::from_fn(&ctx, |ctx, _, stack| {
        let args = stack.len();
        let s = async_sequence(&ctx, |_, mut seq| async move {
            for i in (1..args).into_iter().rev() {
                let call = seq.try_enter(|ctx, locals, _, mut stack| {
                    let bottom = i - 1;
                    let call = concat(ctx, stack[i - 1], stack[i])?;
                    let p = prepare_async_metaop(ctx, &mut stack, locals, bottom, call, 1);
                    Ok(p)
                })?;
                call.execute(&mut seq).await?;
            }
            Ok(SequenceReturn::Return)
        });
        Ok(CallbackReturn::Sequence(s))
    });
    Ok(ConcatMetaResult::Concatenate(func.into()))
}

pub fn concat_separated<'gc>(
    ctx: Context<'gc>,
    values: &[Value<'gc>],
    separator: Value<'gc>,
) -> Result<ConcatMetaResult<'gc>, MetaOperatorError> {
    if separator.is_nil() {
        return concat_many(ctx, values);
    }

    // Fast path scope; never loops, returns if successful, otherwise
    // breaks to fall back to the slow impl.
    loop {
        let sep_str = match separator.into_string(ctx) {
            Some(s) => s,
            None => break,
        };

        // Since we have to make two passes to check for complex types,
        // estimate the length in the first pass.
        let Some(len) = estimate_concatenated_len(values)? else {
            break;
        };

        let sep_count = values.len().saturating_sub(1);
        let total_len = sep_count
            .checked_mul(sep_str.len() as usize)
            .and_then(|l| l.checked_add(len))
            .ok_or(MetaOperatorError::ConcatOverflow)?;

        // Should this be allocated in-place in the GC heap?
        let mut bytes = Vec::with_capacity(total_len);

        let mut iter = values.iter();
        if let Some(val) = iter.next() {
            match val {
                Value::Integer(i) => write!(&mut bytes, "{}", i).unwrap(),
                Value::Number(n) => {
                    write!(&mut bytes, "{}", number_format::display_float(*n)).unwrap()
                }
                Value::String(s) => bytes.extend(s.as_bytes()),
                _ => unreachable!(),
            }

            while let Some(val) = iter.next() {
                bytes.extend(&*sep_str);
                match val {
                    Value::Integer(i) => write!(&mut bytes, "{}", i).unwrap(),
                    Value::Number(n) => {
                        write!(&mut bytes, "{}", number_format::display_float(*n)).unwrap()
                    }
                    Value::String(s) => bytes.extend(s.as_bytes()),
                    _ => unreachable!(),
                }
            }
        }
        drop(iter);

        return Ok(ConcatMetaResult::Value(Value::String(ctx.intern(&bytes))));
    }

    // Without a `__concat` anywhere the operation cannot succeed: raise
    // `luaV_concat`'s error here, from the Lua frame, rather than from inside
    // the fallback's callback, where it would lose its position. Lua
    // concatenates from the right, so the first pair to fail is the
    // rightmost one with a value that is not a string or number.
    let has_concat_mm = values.iter().any(|v| {
        match v {
            Value::Table(t) => t.metatable(),
            Value::UserData(u) => u.metatable(),
            _ => None,
        }
        .is_some_and(|mt| !mt.get_value(ctx, MetaMethod::Concat).is_nil())
    });
    if !has_concat_mm {
        if let Some(i) = values.iter().rposition(|v| !v.is_implicit_string()) {
            let (lhs, rhs) = if i + 1 == values.len() && i > 0 {
                (values[i - 1], values[i])
            } else {
                (values[i], Value::Nil)
            };
            let culprit = if i + 1 == values.len() && i > 0 && !lhs.is_implicit_string() {
                lhs
            } else if i + 1 == values.len() && i > 0 {
                rhs
            } else {
                values[i]
            };
            let _ = (lhs, rhs);
            return Err(MetaOperatorError::Message(format!(
                "attempt to concatenate a {} value",
                objtypename(ctx, culprit)
            )));
        }
    }

    // Fall back to a sequence-based implemenation to handle metamethods
    let func = Callback::from_fn_with(&ctx, separator, move |&sep, ctx, _, stack| {
        let args = stack.len();
        let b = async_sequence(&ctx, |locals, mut seq| {
            let sep = locals.stash(&ctx, sep);
            async move {
                for i in (1..args).into_iter().rev() {
                    let call = seq.try_enter(|ctx, locals, _, mut stack| {
                        let bottom = i;
                        let call = concat(ctx, locals.fetch(&sep), stack[i])?;
                        let p = prepare_async_metaop(ctx, &mut stack, locals, bottom, call, 1);
                        Ok(p)
                    })?;
                    call.execute(&mut seq).await?;

                    let call = seq.try_enter(|ctx, locals, _, mut stack| {
                        let bottom = i - 1;
                        let call = concat(ctx, stack[i - 1], stack[i])?;
                        let p = prepare_async_metaop(ctx, &mut stack, locals, bottom, call, 1);
                        Ok(p)
                    })?;
                    call.execute(&mut seq).await?;
                }
                Ok(SequenceReturn::Return)
            }
        });
        Ok(CallbackReturn::Sequence(b))
    });
    Ok(ConcatMetaResult::Call(func.into()))
}

#[must_use]
struct PreparedCall {
    func: Option<crate::StashedFunction>,
    bottom: usize,
    returns: usize,
}

impl PreparedCall {
    async fn execute(self, seq: &mut AsyncSequence) -> Result<(), crate::StashedError> {
        if let Some(func) = self.func {
            seq.call(&func, self.bottom).await?;
        }
        seq.enter(|_, _, _, mut stack| {
            stack.resize(self.bottom + self.returns);
        });
        Ok(())
    }
}

fn prepare_async_metaop<'gc, const N: usize>(
    ctx: Context<'gc>,
    stack: &mut Stack<'gc, '_>,
    locals: Locals<'gc, '_>,
    bottom: usize,
    call: MetaResult<'gc, N>,
    returns: usize,
) -> PreparedCall {
    match call {
        MetaResult::Value(v) => {
            stack.resize(bottom);
            stack.push_back(v);
            PreparedCall {
                func: None,
                bottom,
                returns,
            }
        }
        MetaResult::Call(MetaCall { function, args }) => {
            stack.resize(bottom);
            stack.extend(args);
            PreparedCall {
                func: Some(locals.stash(&ctx, function)),
                bottom,
                returns,
            }
        }
    }
}
