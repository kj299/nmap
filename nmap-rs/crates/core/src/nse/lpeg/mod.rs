//! LPeg 0.12 (`lpeg.c`, built by `nse_lpeg.cc`): patterns as values.
//!
//! The port is in two parts (`docs/M6.6-ANALYSIS.md`, E1):
//! - [`tree`], pure: the pattern trees, laid out as the C lays them out, their
//!   constructors, and the walkers construction runs — `finalfix`, the
//!   grammar verifier, `checkaux`, `fixedlenx` — as resumable state machines
//!   with explicit stacks. Fuzzed and run under Miri on its own.
//! - this file, the binding: Lua values into trees and back. A pattern is a
//!   userdata holding its tree and its constant table (`ktable`); the
//!   constant table is a Lua table only this module can reach, never a
//!   user value a script can replace (`lpeg-uservalue-type-confusion`).
//!
//! **What step b ports.** Every constructor and operator, `type`,
//! `version`, `setmaxstack`, `locale`, the `ptree`/`pcode` stubs and the
//! pattern metatable. Not `match`: there is no compiler or matching
//! machine yet (steps c and d), and the module is not registered — no script
//! can `require` it (E9). [`register_for_tests`] installs it for the test
//! suites only, with a `match` that says it is not there yet.
//!
//! **Calls take time.** Building a grammar runs the verifier, `B` measures
//! its pattern and `+` and `^n` ask whether one can match the empty string;
//! each can take time exponential in a grammar's depth (§1.1). A call first
//! tries to finish with the fuel the VM has left; if it cannot, it returns a
//! [`Sequence`] that goes on from where it stopped, one slice of fuel at a
//! time, so the interpreter — and the stall watchdog above it — sees every
//! slice (D3). Nothing is held across slices but indices and GC handles.
//!
//! **Errors** are raised as `luaL_error` and `luaL_argerror` raise them: the
//! C's words, after the position of the Lua code that made the call
//! (`luaL_where(L, 1)`). The function is named as `nmapdb` names its own
//! (`nmapdb-bad-argument-naming`): from Lua code, by its registered name
//! (`'P'`; a metamethod by its event, `'mul'`, as an operator names it);
//! otherwise as `pushglobalfuncname` finds it, `'lpeg.P'`, and a metamethod,
//! which is in no table it searches, `'?'`.
//!
//! **`not enough memory`** is raised, without a position, for any tree past
//! the C's `int` sizes and for any growth the memory budget refuses. A
//! pattern's tree is accounted to the VM's heap for as long as the pattern
//! lives, so the budget and the collector both see it (E4).

pub mod tree;

use std::pin::Pin;

use gc_arena::metrics::Metrics;
use gc_arena::{Collect, Rootable};
use piccolo::meta_ops::{self, MetaResult};
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Context, Error, Execution, Function, Sequence,
    SequencePoll, Singleton, Stack, Table, UserData, Value,
};

use self::tree::{
    CapKind, Charset, CheckAux, FinalFix, FixedLen, GrammarLayout, Key, Pred, Tag, Tree, TreeError,
    VerifyGrammar, MAXBEHIND, MAXRULES, SHRT_MAX,
};
use super::nmaplib::{c_str, Fail};
use super::stdlib::{check_integer, lua_error_bytes, type_error};

/// `VERSION` (`lpeg.c:20`).
pub const VERSION: &str = "0.12";

/// `PATTERN_T`: the metatable's `__name`, and the type name in errors.
pub const PATTERN_T: &str = "lpeg-pattern";

/// `MAXBACK` (`lpeg.c:52`), which `luaopen_lpeg` stores as a float.
const MAXBACK: f64 = 100.0;

/// The fewest walker steps a call takes per slice, whatever fuel is left, so
/// a slice always makes progress.
const MIN_STEPS: u32 = 1024;

/// A C `int` from a `lua_Integer`, as gcc converts one: the low 32 bits, two's
/// complement. `P(2^32 + 2)` is `P(2)`; `p^(2^32 + 1)` is `p^1`
/// (`lpeg-integer-args-narrowed-to-int`, E11).
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "the truncation is the C's, reproduced on purpose (E11)"
)]
pub fn narrow(n: i64) -> i32 {
    n as i32
}

/// `lua_tointeger` of a number: an integer as itself, a float with an exact
/// integer value in range as that, anything else 0.
fn to_integer_or_zero(v: Value<'_>) -> i64 {
    match v {
        Value::Integer(i) => i,
        Value::Number(f) => Value::Number(f).to_integer().unwrap_or(0),
        _ => 0,
    }
}

/// A pattern's tree, accounted to the VM's heap while it lives.
struct Accounted {
    tree: Tree,
    metrics: Metrics,
    bytes: usize,
}

impl Drop for Accounted {
    fn drop(&mut self) {
        self.metrics.mark_external_deallocation(self.bytes);
    }
}

/// A pattern (`Pattern`, `lpeg.c:198`): its tree, and its constant table,
/// shared with the patterns it was built from as the C shares its user
/// value (`copyktable`), and never handed to a script.
#[derive(Collect)]
#[collect(no_drop)]
pub struct Pattern<'gc> {
    #[collect(require_static)]
    tree: Accounted,
    ktable: Option<Table<'gc>>,
}

impl<'gc> Pattern<'gc> {
    /// The tree.
    #[must_use]
    pub fn tree(&self) -> &Tree {
        &self.tree.tree
    }

    /// The constant table, if it has one.
    #[must_use]
    pub fn ktable(&self) -> Option<Table<'gc>> {
        self.ktable
    }
}

type PatternRoot = Rootable![Pattern<'_>];

/// What `luaopen_lpeg` keeps in the registry: the pattern metatable
/// (`luaL_newmetatable(L, PATTERN_T)`) and `lpeg-maxstack`.
#[derive(Collect, Clone, Copy)]
#[collect(no_drop)]
struct Registry<'gc> {
    metatable: Table<'gc>,
    /// Holds `maxstack`: the value `setmaxstack` stored, raw.
    store: Table<'gc>,
}

impl<'gc> Singleton<'gc> for Registry<'gc> {
    fn create(ctx: Context<'gc>) -> Self {
        let metatable = Table::new(&ctx);
        metatable.set_field(ctx, "__name", PATTERN_T);
        for func in [
            Func::Seq,
            Func::Choice,
            Func::Star,
            Func::And,
            Func::Div,
            Func::Not,
            Func::Sub,
            Func::Gc,
        ] {
            metatable.set_field(ctx, func.field(), callback(ctx, func));
        }
        let store = Table::new(&ctx);
        store.set_field(ctx, "maxstack", MAXBACK);
        Registry { metatable, store }
    }
}

fn registry<'gc>(ctx: Context<'gc>) -> Registry<'gc> {
    *ctx.singleton::<Rootable![Registry<'_>]>()
}

/// `testpattern`: the pattern `v` is, if it is one.
#[must_use]
pub fn pattern<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<&'gc Pattern<'gc>> {
    let Value::UserData(u) = v else {
        return None;
    };
    let p = u.downcast::<PatternRoot>().ok()?;
    (u.metatable() == Some(registry(ctx).metatable)).then_some(p)
}

/// A new pattern userdata (`newtree`), with the pattern metatable.
fn new_pattern<'gc>(ctx: Context<'gc>, tree: Tree, ktable: Option<Table<'gc>>) -> Value<'gc> {
    let bytes = tree.len().saturating_mul(std::mem::size_of::<tree::Node>());
    let metrics = ctx.metrics().clone();
    metrics.mark_external_allocation(bytes);
    let p = Pattern {
        tree: Accounted {
            tree,
            metrics,
            bytes,
        },
        ktable,
    };
    let u = UserData::new::<PatternRoot>(&ctx, p);
    u.set_metatable(&ctx, Some(registry(ctx).metatable));
    Value::UserData(u)
}

/// The library's functions and metamethods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Collect)]
#[collect(require_static)]
enum Func {
    P,
    Seq,
    Choice,
    Star,
    And,
    Not,
    Sub,
    Div,
    Gc,
    B,
    V,
    C,
    Cc,
    Cmt,
    Cb,
    Carg,
    Cp,
    Cs,
    Ct,
    Cf,
    Cg,
    S,
    R,
    Locale,
    Version,
    SetMaxStack,
    Type,
    Match,
    Ptree,
    Pcode,
}

/// `pattreg` (`lpeg.c:3290`), in the C's order.
const LIBRARY: [Func; 22] = [
    Func::Ptree,
    Func::Pcode,
    Func::Match,
    Func::B,
    Func::V,
    Func::C,
    Func::Cc,
    Func::Cmt,
    Func::Cb,
    Func::Carg,
    Func::Cp,
    Func::Cs,
    Func::Ct,
    Func::Cf,
    Func::Cg,
    Func::P,
    Func::S,
    Func::R,
    Func::Locale,
    Func::Version,
    Func::SetMaxStack,
    Func::Type,
];

impl Func {
    /// The registered name: the library field, or the metatable field.
    const fn field(self) -> &'static str {
        match self {
            Func::P => "P",
            Func::Seq => "__mul",
            Func::Choice => "__add",
            Func::Star => "__pow",
            Func::And => "__len",
            Func::Not => "__unm",
            Func::Sub => "__sub",
            Func::Div => "__div",
            Func::Gc => "__gc",
            Func::B => "B",
            Func::V => "V",
            Func::C => "C",
            Func::Cc => "Cc",
            Func::Cmt => "Cmt",
            Func::Cb => "Cb",
            Func::Carg => "Carg",
            Func::Cp => "Cp",
            Func::Cs => "Cs",
            Func::Ct => "Ct",
            Func::Cf => "Cf",
            Func::Cg => "Cg",
            Func::S => "S",
            Func::R => "R",
            Func::Locale => "locale",
            Func::Version => "version",
            Func::SetMaxStack => "setmaxstack",
            Func::Type => "type",
            Func::Match => "match",
            Func::Ptree => "ptree",
            Func::Pcode => "pcode",
        }
    }

    /// The name `luaL_argerror` gives the function: see the module's
    /// "Errors".
    fn name(self, lua_caller: bool) -> String {
        let field = self.field();
        match (field.strip_prefix("__"), lua_caller) {
            (Some(event), true) => event.to_string(),
            (Some(_), false) => "?".to_string(),
            (None, true) => field.to_string(),
            (None, false) => format!("lpeg.{field}"),
        }
    }

    /// The arguments `getpatt` converts, in order.
    const fn converts(self) -> &'static [usize] {
        match self {
            Func::P | Func::And | Func::Not | Func::Div | Func::B | Func::C | Func::Cs => &[1],
            Func::Ct | Func::Cg | Func::Cf | Func::Cmt | Func::Ptree => &[1],
            Func::Seq | Func::Choice | Func::Sub => &[1, 2],
            _ => &[],
        }
    }
}

/// Why a call failed.
enum Failure<'gc> {
    /// `luaL_error` or `luaL_argerror`: positioned and named when raised.
    Lua(Fail),
    /// A memory error, which carries no position.
    Memory,
    /// An error already made (a metamethod's, or a call's).
    Raised(Error<'gc>),
}

impl From<Fail> for Failure<'_> {
    fn from(f: Fail) -> Self {
        Failure::Lua(f)
    }
}

impl From<super::stdlib::strpack::PackError> for Failure<'_> {
    fn from(e: super::stdlib::strpack::PackError) -> Self {
        Failure::Lua(e.into())
    }
}

/// `val2str` (`lpeg.c:2148`): a value as `lua_tostring` shows it, else as
/// `(a TYPE)`; up to its first NUL, as `%s` reads it.
fn val2str<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Vec<u8> {
    match v.into_string(ctx) {
        Some(s) => c_str(s.as_bytes()).to_vec(),
        None => format!("(a {})", v.type_name()).into_bytes(),
    }
}

/// A [`TreeError`] in the C's words, naming a rule by the value at its key
/// in `ktable`.
fn tree_failure<'gc>(ctx: Context<'gc>, ktable: Option<Table<'gc>>, e: TreeError) -> Failure<'gc> {
    let name = |k: Key| {
        let v = ktable.map_or(Value::Nil, |t| t.get_raw(Value::Integer(i64::from(k))));
        val2str(ctx, v)
    };
    let rule = |pre: &[u8], k: Key, post: &[u8]| {
        let mut m = pre.to_vec();
        m.extend_from_slice(&name(k));
        m.extend_from_slice(post);
        Failure::Lua(Fail::err(m))
    };
    match e {
        TreeError::NotEnoughMemory => Failure::Memory,
        TreeError::LoopBodyNullable => Failure::Lua(Fail::err("loop body may accept empty string")),
        TreeError::UsedOutsideGrammar(k) => rule(b"rule '", k, b"' used outside a grammar"),
        TreeError::UndefinedRule(k) => rule(b"rule '", k, b"' undefined in given grammar"),
        TreeError::LeftRecursive(k) => rule(b"rule '", k, b"' may be left recursive"),
        TreeError::TooManyLeftCalls => Failure::Lua(Fail::err("too many left calls in grammar")),
        TreeError::EmptyLoop(k) => rule(b"empty loop in rule '", k, b"'"),
        TreeError::Malformed => Failure::Lua(Fail::err("lpeg: malformed pattern tree")),
    }
}

/// A raw set refused for its key (`lua_settable` on a NaN key): the
/// VM's message, unpositioned, as the C's `luaG_runerror` leaves it when
/// raised from inside a C function.
fn key_failure<'gc>(ctx: Context<'gc>, e: piccolo::table::InvalidTableKey) -> Failure<'gc> {
    Failure::Raised(lua_error_bytes(ctx, e.to_string().as_bytes()))
}

/// The length of a constant table (`ktablelen`): 0 for none.
fn klen(t: Option<Table<'_>>) -> Result<Key, Failure<'static>> {
    let n = t.map_or(0, Table::length);
    Key::try_from(n).map_err(|_| Failure::Memory)
}

/// `addtoktable`: add `v` to the constant table of the pattern being built,
/// making a fresh table if it has none or an empty one; the new key, or 0
/// for `nil`.
fn add_to_ktable<'gc>(
    ctx: Context<'gc>,
    kt: &mut Option<Table<'gc>>,
    v: Option<Value<'gc>>,
) -> Result<Key, Failure<'gc>> {
    let v = match v {
        None | Some(Value::Nil) => return Ok(0),
        Some(v) => v,
    };
    let n = klen(*kt).map_err(|_| Failure::Memory)?;
    let t = match *kt {
        Some(t) if n > 0 => t,
        _ => Table::new(&ctx),
    };
    let key = n.checked_add(1).ok_or(Failure::Memory)?;
    t.set_raw(&ctx, Value::Integer(i64::from(key)), v)
        .map_err(|e| key_failure(ctx, e))?;
    *kt = Some(t);
    Ok(key)
}

/// `concattable`: append `from`'s entries to `to`.
fn concat_ktable<'gc>(
    ctx: Context<'gc>,
    from: Table<'gc>,
    to: Table<'gc>,
) -> Result<(), Failure<'gc>> {
    let n1 = from.length();
    let n2 = to.length();
    for i in 1..=n1 {
        let v = from.get_raw(Value::Integer(i));
        let k = n2.checked_add(i).ok_or(Failure::Memory)?;
        to.set_raw(&ctx, Value::Integer(k), v)
            .map_err(|e| key_failure(ctx, e))?;
    }
    Ok(())
}

/// `joinktables`: the constant table of a pattern built from `p1` and `p2`,
/// and the shift `p2`'s keys take.
fn join_ktables<'gc>(
    ctx: Context<'gc>,
    k1: Option<Table<'gc>>,
    k2: Option<Table<'gc>>,
) -> Result<(Option<Table<'gc>>, Key), Failure<'gc>> {
    let (n1, n2) = (
        klen(k1).map_err(|_| Failure::Memory)?,
        klen(k2).map_err(|_| Failure::Memory)?,
    );
    if n1 == 0 && n2 == 0 {
        return Ok((None, 0));
    }
    if n2 == 0 || k1 == k2 {
        return Ok((k1, 0));
    }
    if n1 == 0 {
        return Ok((k2, 0));
    }
    let t = Table::new(&ctx);
    if let Some(k1) = k1 {
        concat_ktable(ctx, k1, t)?;
    }
    if let Some(k2) = k2 {
        concat_ktable(ctx, k2, t)?;
    }
    Ok((Some(t), n1))
}

/// `luaL_typeerror(L, arg, "lpeg-pattern")`, `luaL_checkudata`'s failure.
fn not_a_pattern<'gc>(ctx: Context<'gc>, v: Option<Value<'gc>>, arg: usize) -> Failure<'gc> {
    type_error(ctx, v, arg, PATTERN_T).into()
}

/// `lua_isstring`: a string or a number.
fn is_string(v: Value<'_>) -> bool {
    matches!(v, Value::String(_) | Value::Integer(_) | Value::Number(_))
}

// ---------------------------------------------------------------------------
// Grammars.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GStage {
    /// `getfirstrule`: read `t[1]`.
    First,
    /// Its `__index` was called for the initial rule.
    AwaitFirst,
    /// `collectrules`, `buildgrammar`.
    Collect,
    /// `finalfix`.
    Fix,
    /// `verifygrammar`.
    Verify,
}

/// `newgrammar` (`lpeg.c:3140`) of the table at argument `arg`, as a
/// resumable job: reading the initial rule may call an `__index`
/// metamethod, and fixing and verifying take steps.
#[derive(Collect)]
#[collect(no_drop)]
struct GrammarJob<'gc> {
    table: Table<'gc>,
    #[collect(require_static)]
    arg: usize,
    #[collect(require_static)]
    stage: GStage,
    /// The initial rule's key (`frule`), and then every rule, in order.
    first_key: Value<'gc>,
    rules: Vec<(Value<'gc>, Value<'gc>)>,
    /// The position table: rule name to the index of its `Rule` node.
    postab: Option<Table<'gc>>,
    ktable: Option<Table<'gc>>,
    #[collect(require_static)]
    tree: Option<Tree>,
    #[collect(require_static)]
    fix: Option<FinalFix>,
    #[collect(require_static)]
    verify: Option<VerifyGrammar>,
}

/// What a job does next.
enum Flow<'gc, T> {
    Done(T),
    /// The budget ran out.
    Pending,
    /// Call a function with these arguments; its first result comes back.
    Call(Function<'gc>, Vec<Value<'gc>>),
}

impl<'gc> GrammarJob<'gc> {
    fn new(table: Table<'gc>, arg: usize) -> Self {
        GrammarJob {
            table,
            arg,
            stage: GStage::First,
            first_key: Value::Nil,
            rules: Vec::new(),
            postab: None,
            ktable: None,
            tree: None,
            fix: None,
            verify: None,
        }
    }

    /// The value a call made for this job returned.
    fn resume(&mut self, ctx: Context<'gc>, v: Value<'gc>) -> Result<(), Failure<'gc>> {
        if self.stage == GStage::AwaitFirst {
            self.first_rule(ctx, v)?;
        }
        Ok(())
    }

    /// The end of `getfirstrule`: the initial rule must be a pattern.
    fn first_rule(&mut self, ctx: Context<'gc>, rule: Value<'gc>) -> Result<(), Failure<'gc>> {
        if pattern(ctx, rule).is_none() {
            if rule.is_nil() {
                return Err(Fail::err("grammar has no initial rule").into());
            }
            let mut m = b"initial rule '".to_vec();
            m.extend_from_slice(&val2str(ctx, self.first_key));
            m.extend_from_slice(b"' is not a pattern");
            return Err(Fail::err(m).into());
        }
        let postab = Table::new(&ctx);
        postab
            .set_raw(&ctx, self.first_key, Value::Integer(1))
            .map_err(|e| key_failure(ctx, e))?;
        self.postab = Some(postab);
        self.rules.push((self.first_key, rule));
        self.stage = GStage::Collect;
        Ok(())
    }

    fn advance(
        &mut self,
        ctx: Context<'gc>,
        budget: &mut u32,
    ) -> Result<Flow<'gc, Value<'gc>>, Failure<'gc>> {
        loop {
            match self.stage {
                GStage::First => {
                    let v = self.table.get_raw(Value::Integer(1));
                    if is_string(v) {
                        // The name of the initial rule: `lua_gettable`, which
                        // honours `__index`.
                        self.first_key = v;
                        match meta_ops::index(ctx, Value::Table(self.table), v)
                            .map_err(|e| Failure::Raised(e.into()))?
                        {
                            MetaResult::Value(rule) => self.first_rule(ctx, rule)?,
                            MetaResult::Call(call) => {
                                self.stage = GStage::AwaitFirst;
                                return Ok(Flow::Call(call.function, call.args.to_vec()));
                            }
                        }
                    } else {
                        self.first_key = Value::Integer(1);
                        self.first_rule(ctx, v)?;
                    }
                }
                GStage::AwaitFirst => return Err(Fail::err("lpeg: grammar call lost").into()),
                GStage::Collect => self.collect(ctx, budget)?,
                GStage::Fix => {
                    let (Some(tree), Some(fix), Some(ktable), Some(postab)) = (
                        self.tree.as_mut(),
                        self.fix.as_mut(),
                        self.ktable,
                        self.postab,
                    ) else {
                        return Err(Fail::err("lpeg: grammar state lost").into());
                    };
                    // `fixonecall`'s lookup: the rule name at the key, in the
                    // position table.
                    let resolve = |k: Key| {
                        let name = ktable.get_raw(Value::Integer(i64::from(k)));
                        match postab.get_raw(name) {
                            Value::Integer(n) => n,
                            _ => 0,
                        }
                    };
                    match fix.step(tree, &resolve, budget) {
                        std::task::Poll::Pending => return Ok(Flow::Pending),
                        std::task::Poll::Ready(r) => {
                            r.map_err(|e| tree_failure(ctx, Some(ktable), e))?;
                        }
                    }
                    // `initialrulename`: an initial rule no call names is named
                    // by its key, for the errors that name it.
                    if tree.node(1).is_some_and(|n| n.key == 0) {
                        let n = klen(Some(ktable)).map_err(|_| Failure::Memory)?;
                        let k = n.checked_add(1).ok_or(Failure::Memory)?;
                        ktable
                            .set_raw(&ctx, Value::Integer(i64::from(k)), self.first_key)
                            .map_err(|e| key_failure(ctx, e))?;
                        tree.set_key(1, k);
                    }
                    self.fix = None;
                    self.verify = Some(VerifyGrammar::new(0));
                    self.stage = GStage::Verify;
                }
                GStage::Verify => {
                    let (Some(tree), Some(verify)) = (self.tree.as_ref(), self.verify.as_mut())
                    else {
                        return Err(Fail::err("lpeg: grammar state lost").into());
                    };
                    match verify.step(tree, budget) {
                        std::task::Poll::Pending => return Ok(Flow::Pending),
                        std::task::Poll::Ready(r) => {
                            r.map_err(|e| tree_failure(ctx, self.ktable, e))?
                        }
                    }
                    let tree = self.tree.take().unwrap_or_default();
                    return Ok(Flow::Done(new_pattern(ctx, tree, self.ktable)));
                }
            }
        }
    }

    /// `collectrules` and `buildgrammar`: every other rule, in the table's
    /// order, then the tree.
    fn collect(&mut self, ctx: Context<'gc>, budget: &mut u32) -> Result<(), Failure<'gc>> {
        let postab = self.postab.ok_or(Failure::Memory)?;
        let mut sizes = Vec::new();
        let first_size = self
            .rules
            .first()
            .and_then(|&(_, r)| pattern(ctx, r))
            .map_or(0, |p| p.tree().len());
        sizes.push(first_size);
        let mut size = 2usize.checked_add(first_size).ok_or(Failure::Memory)?;
        for (k, v) in self.table.iter() {
            *budget = budget.saturating_sub(1);
            // A key that converts to 1 is the initial rule's slot, and so is
            // the initial rule's name.
            if k.to_number() == Some(1.0) || raw_equal(k, self.first_key) {
                continue;
            }
            let Some(p) = pattern(ctx, v) else {
                let mut m = b"rule '".to_vec();
                m.extend_from_slice(&val2str(ctx, k));
                m.extend_from_slice(b"' is not a pattern");
                return Err(Fail::err(m).into());
            };
            let pos = i64::try_from(size).map_err(|_| Failure::Memory)?;
            postab
                .set_raw(&ctx, k, Value::Integer(pos))
                .map_err(|e| key_failure(ctx, e))?;
            let s = p.tree().len();
            size = size
                .checked_add(1)
                .and_then(|n| n.checked_add(s))
                .ok_or(Failure::Memory)?;
            if !super::stdlib::reserve(&mut sizes, 1) || !super::stdlib::reserve(&mut self.rules, 1)
            {
                return Err(Failure::Memory);
            }
            sizes.push(s);
            self.rules.push((k, v));
        }
        let layout = GrammarLayout::new(&sizes).map_err(|_| Failure::Memory)?;
        let space = layout.space().map_err(|_| Failure::Memory)?;
        if self.rules.len() > MAXRULES {
            return Err(Fail::arg(self.arg, "grammar has too many rules").into());
        }
        // `buildgrammar`: each rule's table appended to the grammar's
        // (`mergektable`), and its keys shifted by what was there before.
        let ktable = Table::new(&ctx);
        let mut parts: Vec<(&Tree, Key)> = Vec::new();
        for &(_, r) in &self.rules {
            let p = pattern(ctx, r).ok_or(Failure::Memory)?;
            let correction = match p.ktable() {
                Some(rk) if rk.length() > 0 => {
                    let n2 = klen(Some(ktable)).map_err(|_| Failure::Memory)?;
                    concat_ktable(ctx, rk, ktable)?;
                    n2
                }
                _ => 0,
            };
            parts.push((p.tree(), correction));
        }
        let tree = layout
            .build(&parts, space)
            .map_err(|e| tree_failure(ctx, Some(ktable), e))?;
        *budget = budget.saturating_sub(u32::try_from(tree.len() / 16).unwrap_or(u32::MAX));
        self.tree = Some(tree);
        self.ktable = Some(ktable);
        self.fix = Some(FinalFix::new(Some(0), 1));
        self.stage = GStage::Fix;
        Ok(())
    }
}

/// `lua_rawequal`, which for a string or number key is `lua_equal`.
fn raw_equal(a: Value<'_>, b: Value<'_>) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.as_bytes() == y.as_bytes(),
        (Value::Integer(x), Value::Integer(y)) => x == y,
        #[allow(clippy::float_cmp, reason = "Lua's raw equality of two floats is ==")]
        (Value::Number(x), Value::Number(y)) => x == y,
        // An integer and a float are equal when the float is exactly it.
        (Value::Integer(x), Value::Number(y)) | (Value::Number(y), Value::Integer(x)) => {
            Value::Number(y).to_integer() == Some(x)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Calls.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The argument checks that come before any conversion.
    Pre,
    /// `getpatt` of the n-th argument of [`Func::converts`].
    Convert(usize),
    /// Start the analysis the function needs, if any.
    Analyse,
    /// Run it.
    Walk,
    /// Build the result.
    Finish,
    /// `locale`: set the classes, in order, into the table.
    Locale,
}

/// An analysis in progress, and what it answered.
enum Walk {
    Check(CheckAux),
    Fixed(FixedLen),
    /// `ptree`'s `finalfix`, on a copy of the pattern's tree.
    Fix(FinalFix, Tree),
}

/// One call of a library function or metamethod, from its arguments to its
/// results. Runs inline when it can, and as a [`Sequence`] when it needs
/// more fuel than the slice has or a call into Lua.
#[derive(Collect)]
#[collect(no_drop)]
struct Job<'gc> {
    #[collect(require_static)]
    func: Func,
    /// The arguments, converted in place as `getpatt`'s `lua_replace` does.
    args: Vec<Value<'gc>>,
    #[collect(require_static)]
    stage: Stage,
    grammar: Option<GrammarJob<'gc>>,
    #[collect(require_static)]
    walk: Option<Walk>,
    /// An analysis's answer: a truth for `checkaux`, a length for `fixedlen`.
    #[collect(require_static)]
    answer: i64,
    /// Integer arguments read before the conversions, as the C reads them.
    #[collect(require_static)]
    n: i32,
    /// `p^n`'s tree, allocated before the empty-loop check.
    #[collect(require_static)]
    space: Option<Vec<tree::Node>>,
    /// `locale`: the table, and the next class.
    #[collect(require_static)]
    class: usize,
    /// A call to make on the first poll.
    call: Option<(Function<'gc>, Vec<Value<'gc>>)>,
    /// A call was made: its result is on the stack.
    #[collect(require_static)]
    awaiting: bool,
}

impl<'gc> Job<'gc> {
    fn new(func: Func, args: Vec<Value<'gc>>) -> Self {
        Job {
            func,
            args,
            stage: Stage::Pre,
            grammar: None,
            walk: None,
            answer: 0,
            n: 0,
            space: None,
            class: 0,
            call: None,
            awaiting: false,
        }
    }

    fn arg(&self, i: usize) -> Option<Value<'gc>> {
        i.checked_sub(1).and_then(|i| self.args.get(i)).copied()
    }

    fn none_or_nil(&self, i: usize) -> bool {
        self.arg(i).is_none_or(Value::is_nil)
    }

    /// The pattern argument `i` was converted to.
    fn pat(&self, ctx: Context<'gc>, i: usize) -> Result<&'gc Pattern<'gc>, Failure<'gc>> {
        self.arg(i)
            .and_then(|v| pattern(ctx, v))
            .ok_or_else(|| not_a_pattern(ctx, self.arg(i), i))
    }

    fn set_arg(&mut self, i: usize, v: Value<'gc>) {
        if let Some(slot) = i.checked_sub(1).and_then(|i| self.args.get_mut(i)) {
            *slot = v;
        }
    }

    /// The value a call made for this job returned.
    fn resume(&mut self, ctx: Context<'gc>, v: Value<'gc>) -> Result<(), Failure<'gc>> {
        if let Some(g) = &mut self.grammar {
            return g.resume(ctx, v);
        }
        // `locale`'s `__newindex` returned: its results are not used.
        Ok(())
    }

    /// Run until done, out of budget, or waiting on a call.
    fn advance(
        &mut self,
        ctx: Context<'gc>,
        budget: &mut u32,
    ) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        loop {
            match self.stage {
                Stage::Pre if self.func == Func::Locale => {
                    self.locale_table(ctx)?;
                    self.stage = Stage::Locale;
                }
                Stage::Locale => return self.locale(ctx),
                Stage::Pre => {
                    if let Some(done) = self.pre(ctx)? {
                        return Ok(Flow::Done(done));
                    }
                    self.stage = Stage::Convert(0);
                }
                Stage::Convert(i) => {
                    let Some(&idx) = self.func.converts().get(i) else {
                        self.stage = Stage::Analyse;
                        continue;
                    };
                    if let Some(g) = &mut self.grammar {
                        match g.advance(ctx, budget)? {
                            Flow::Done(p) => {
                                self.grammar = None;
                                self.set_arg(idx, p);
                                self.stage = Stage::Convert(i.saturating_add(1));
                            }
                            Flow::Pending => return Ok(Flow::Pending),
                            Flow::Call(f, args) => return Ok(Flow::Call(f, args)),
                        }
                        continue;
                    }
                    match self.arg(idx) {
                        Some(Value::Table(t)) => {
                            self.grammar = Some(GrammarJob::new(t, idx));
                            continue;
                        }
                        v => {
                            let p = getpatt(ctx, v, idx)?;
                            self.set_arg(idx, p);
                            self.stage = Stage::Convert(i.saturating_add(1));
                        }
                    }
                }
                Stage::Analyse => {
                    self.walk = self.analysis(ctx)?;
                    self.stage = if self.walk.is_some() {
                        Stage::Walk
                    } else {
                        Stage::Finish
                    };
                }
                Stage::Walk => {
                    let p = self.pat(ctx, 1)?;
                    let t = p.tree();
                    let ready = match self.walk.as_mut() {
                        Some(Walk::Check(w)) => w.step(t, budget).map(|r| r.map(i64::from)),
                        Some(Walk::Fixed(w)) => w.step(t, budget),
                        Some(Walk::Fix(w, copy)) => {
                            w.step(copy, &|_| 0, budget).map(|r| r.map(|()| 0))
                        }
                        None => std::task::Poll::Ready(Ok(0)),
                    };
                    match ready {
                        std::task::Poll::Pending => return Ok(Flow::Pending),
                        std::task::Poll::Ready(r) => {
                            self.answer = r.map_err(|e| tree_failure(ctx, p.ktable(), e))?;
                        }
                    }
                    self.walk = None;
                    self.stage = Stage::Finish;
                }
                Stage::Finish => return self.finish(ctx),
            }
        }
    }

    /// The checks each function makes before converting any argument; the
    /// whole call, for the functions that convert none.
    fn pre(&mut self, ctx: Context<'gc>) -> Result<Option<Vec<Value<'gc>>>, Failure<'gc>> {
        let check_int = |job: &Self, i| -> Result<i32, Failure<'gc>> {
            Ok(narrow(check_integer(ctx, job.arg(i), i)?))
        };
        match self.func {
            // `luaL_checkany`.
            Func::P if self.arg(1).is_none() => {
                return Err(Fail::arg(1, "value expected").into());
            }
            Func::Star => {
                // `luaL_checkint(L, 2)`, then `gettree(L, 1)`: no conversion.
                self.n = check_int(self, 2)?;
                self.pat(ctx, 1)?;
            }
            Func::Div => match self.arg(2) {
                Some(Value::Function(_) | Value::Table(_) | Value::String(_)) => {}
                Some(v @ (Value::Integer(_) | Value::Number(_))) => {
                    self.n = narrow(to_integer_or_zero(v));
                }
                _ => return Err(Fail::arg(2, "invalid replacement value").into()),
            },
            Func::Cg if !self.none_or_nil(2) => {
                let s = self.check_string(ctx, 2)?;
                self.set_arg(2, s);
            }
            Func::Cf | Func::Cmt => {
                if !matches!(self.arg(2), Some(Value::Function(_))) {
                    return Err(type_error(ctx, self.arg(2), 2, "function").into());
                }
            }
            Func::V => {
                let mut t = Tree::leaf(Tag::OpenCall).map_err(|_| Failure::Memory)?;
                if self.args.is_empty() {
                    // `lp_V` pushes the new pattern before it checks argument
                    // 1, so with no argument the check sees the pattern, and
                    // the rule is named by the pattern itself.
                    t.set_key(0, 1);
                    let kt = Table::new(&ctx);
                    let p = new_pattern(ctx, t, Some(kt));
                    kt.set_raw(&ctx, Value::Integer(1), p)
                        .map_err(|e| key_failure(ctx, e))?;
                    return Ok(Some(vec![p]));
                }
                if self.none_or_nil(1) {
                    return Err(Fail::arg(1, "non-nil value expected").into());
                }
                let mut kt = None;
                let key = add_to_ktable(ctx, &mut kt, self.arg(1))?;
                t.set_key(0, key);
                return Ok(Some(vec![new_pattern(ctx, t, kt)]));
            }
            Func::Cp => {
                let t = Tree::empty_capture(CapKind::Position, 0).map_err(|_| Failure::Memory)?;
                return Ok(Some(vec![new_pattern(ctx, t, None)]));
            }
            Func::Carg => {
                let n = check_int(self, 1)?;
                if n <= 0 || i64::from(n) > SHRT_MAX {
                    return Err(Fail::arg(1, "invalid argument index").into());
                }
                let key = Key::try_from(n).map_err(|_| Failure::Memory)?;
                let t = Tree::empty_capture(CapKind::Arg, key).map_err(|_| Failure::Memory)?;
                return Ok(Some(vec![new_pattern(ctx, t, None)]));
            }
            Func::Cb => {
                let s = self.check_string(ctx, 1)?;
                let mut kt = None;
                let key = add_to_ktable(ctx, &mut kt, Some(s))?;
                let t = Tree::empty_capture(CapKind::Backref, key).map_err(|_| Failure::Memory)?;
                return Ok(Some(vec![new_pattern(ctx, t, kt)]));
            }
            Func::Cc => return self.constant(ctx).map(Some),
            Func::S => {
                let s = self.check_lstring(ctx, 1)?;
                let mut cs = Charset::empty();
                for &b in &s {
                    cs.add(b);
                }
                let t = Tree::charset(&cs).map_err(|_| Failure::Memory)?;
                return Ok(Some(vec![new_pattern(ctx, t, None)]));
            }
            Func::R => {
                let mut cs = Charset::empty();
                for i in 1..=self.args.len() {
                    let r = self.check_lstring(ctx, i)?;
                    let [lo, hi] = r[..] else {
                        return Err(Fail::arg(i, "range must have two characters").into());
                    };
                    for c in lo..=hi {
                        cs.add(c);
                    }
                }
                let t = Tree::charset(&cs).map_err(|_| Failure::Memory)?;
                return Ok(Some(vec![new_pattern(ctx, t, None)]));
            }
            Func::Pcode => {
                self.pat(ctx, 1)?;
                return Err(Fail::err("function only implemented in debug mode").into());
            }
            Func::Gc => {
                // `lp_gc`: `getpattern(L, 1)`; the code it would free is not
                // there, and nothing here is freed by hand.
                self.pat(ctx, 1)?;
                return Ok(Some(Vec::new()));
            }
            Func::Type => {
                let v = match self.arg(1).and_then(|v| pattern(ctx, v)) {
                    Some(_) => Value::String(ctx.intern(b"pattern")),
                    None => Value::Nil,
                };
                return Ok(Some(vec![v]));
            }
            Func::Version => return Ok(Some(vec![Value::String(ctx.intern(VERSION.as_bytes()))])),
            Func::SetMaxStack => {
                // `luaL_optinteger(L, 1, -1)`, then the value is stored as it
                // was given: a string stays a string, and is read at every
                // growth of the stack (step c).
                if !self.none_or_nil(1) {
                    check_integer(ctx, self.arg(1), 1)?;
                }
                let v = self.arg(1).unwrap_or(Value::Nil);
                registry(ctx).store.set_field(ctx, "maxstack", v);
                return Ok(Some(Vec::new()));
            }
            Func::Match => {
                return Err(Fail::err("lpeg.match is not implemented until M6.6 step c").into());
            }
            Func::Locale => return Err(Fail::err("lpeg: locale runs as its own job").into()),
            _ => {}
        }
        Ok(None)
    }

    /// `luaL_checklstring`.
    fn check_lstring(&self, ctx: Context<'gc>, i: usize) -> Result<Vec<u8>, Failure<'gc>> {
        Ok(self
            .check_string(ctx, i)?
            .into_string(ctx)
            .map_or_else(Vec::new, |s| s.as_bytes().to_vec()))
    }

    /// `luaL_checkstring`, which converts a number to a string in place.
    fn check_string(&self, ctx: Context<'gc>, i: usize) -> Result<Value<'gc>, Failure<'gc>> {
        match self.arg(i) {
            Some(v @ Value::String(_)) => Ok(v),
            Some(v @ (Value::Integer(_) | Value::Number(_))) => v
                .into_string(ctx)
                .map(Value::String)
                .ok_or_else(|| type_error(ctx, Some(v), i, "string").into()),
            v => Err(type_error(ctx, v, i, "string").into()),
        }
    }

    /// `lp_constcapture`.
    fn constant(&self, ctx: Context<'gc>) -> Result<Vec<Value<'gc>>, Failure<'gc>> {
        let mut kt = None;
        let tree = match self.args.len() {
            0 => Tree::leaf(Tag::True),
            1 => {
                let key = add_to_ktable(ctx, &mut kt, self.arg(1))?;
                Tree::empty_capture(CapKind::Const, key)
            }
            n => {
                let mut keys = Vec::new();
                if !super::stdlib::reserve(&mut keys, n) {
                    return Err(Failure::Memory);
                }
                for i in 1..=n {
                    keys.push(add_to_ktable(ctx, &mut kt, self.arg(i))?);
                }
                Tree::const_group(&keys)
            }
        }
        .map_err(|_| Failure::Memory)?;
        Ok(vec![new_pattern(ctx, tree, kt)])
    }

    /// The analysis the function needs, once its arguments are patterns.
    fn analysis(&mut self, ctx: Context<'gc>) -> Result<Option<Walk>, Failure<'gc>> {
        Ok(match self.func {
            Func::Choice => {
                let (t1, t2) = (self.pat(ctx, 1)?.tree(), self.pat(ctx, 2)?.tree());
                // `nofail(t1)` decides only when neither the charset case nor
                // `x / false` already has.
                if (t1.to_charset().is_some() && t2.to_charset().is_some())
                    || t2.root().tag == Tag::False
                {
                    None
                } else {
                    Some(Walk::Check(CheckAux::new(0, Pred::NoFail)))
                }
            }
            Func::Star => {
                let size1 = self.pat(ctx, 1)?.tree().len();
                self.space = Some(Tree::star_space(size1, self.n).map_err(|_| Failure::Memory)?);
                (self.n >= 0).then(|| Walk::Check(CheckAux::new(0, Pred::Nullable)))
            }
            Func::B => Some(Walk::Fixed(FixedLen::new(0))),
            Func::Ptree if self.arg(2).is_some_and(Value::to_bool) => {
                let copy = self.pat(ctx, 1)?.tree().clone();
                Some(Walk::Fix(FinalFix::new(None, 0), copy))
            }
            _ => None,
        })
    }

    /// Build the result, once the analysis (if any) has answered.
    fn finish(&mut self, ctx: Context<'gc>) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let mem = |_| Failure::Memory;
        let one = |v| Ok(Flow::Done(vec![v]));
        match self.func {
            Func::P => one(self.arg(1).unwrap_or(Value::Nil)),
            Func::Seq => {
                let (p1, p2) = (self.pat(ctx, 1)?, self.pat(ctx, 2)?);
                let (t1, t2) = (p1.tree(), p2.tree());
                // false x => false, x true => x, true x => x.
                if t1.root().tag == Tag::False || t2.root().tag == Tag::True {
                    one(self.arg(1).unwrap_or(Value::Nil))
                } else if t1.root().tag == Tag::True {
                    one(self.arg(2).unwrap_or(Value::Nil))
                } else {
                    self.two(ctx, Tag::Seq)
                }
            }
            Func::Choice => {
                let (p1, p2) = (self.pat(ctx, 1)?, self.pat(ctx, 2)?);
                let (t1, t2) = (p1.tree(), p2.tree());
                if let (Some(c1), Some(c2)) = (t1.to_charset(), t2.to_charset()) {
                    one(new_pattern(
                        ctx,
                        Tree::charset(&c1.union(&c2)).map_err(mem)?,
                        None,
                    ))
                } else if t2.root().tag == Tag::False || self.answer != 0 {
                    // true / x => true, x / false => x.
                    one(self.arg(1).unwrap_or(Value::Nil))
                } else if t1.root().tag == Tag::False {
                    one(self.arg(2).unwrap_or(Value::Nil))
                } else {
                    self.two(ctx, Tag::Choice)
                }
            }
            Func::Star => {
                if self.n >= 0 && self.answer != 0 {
                    return Err(Fail::err("loop body may accept empty string").into());
                }
                let p = self.pat(ctx, 1)?;
                let space = self.space.take().unwrap_or_default();
                let t = Tree::star(p.tree(), self.n, space).map_err(mem)?;
                one(new_pattern(ctx, t, p.ktable()))
            }
            Func::And => self.one_sib(ctx, Tag::And),
            Func::Not => self.one_sib(ctx, Tag::Not),
            Func::Sub => {
                let (p1, p2) = (self.pat(ctx, 1)?, self.pat(ctx, 2)?);
                if let (Some(c1), Some(c2)) = (p1.tree().to_charset(), p2.tree().to_charset()) {
                    return one(new_pattern(
                        ctx,
                        Tree::charset(&c1.minus(&c2)).map_err(mem)?,
                        None,
                    ));
                }
                let (kt, n) = join_ktables(ctx, p1.ktable(), p2.ktable())?;
                let t = Tree::difference(p1.tree(), p2.tree(), n).map_err(mem)?;
                one(new_pattern(ctx, t, kt))
            }
            Func::Div => match self.arg(2) {
                Some(Value::Function(_)) => self.capture(ctx, CapKind::Function, 2),
                Some(Value::Table(_)) => self.capture(ctx, CapKind::Query, 2),
                Some(Value::String(_)) => self.capture(ctx, CapKind::String, 2),
                _ => {
                    // `newroot1sib` first, then the check.
                    let p = self.pat(ctx, 1)?;
                    let mut t = Tree::capture(CapKind::Num, 0, p.tree()).map_err(mem)?;
                    // Argument #1, though the number is the second operand.
                    if self.n < 0 || i64::from(self.n) > SHRT_MAX {
                        return Err(Fail::arg(1, "invalid number").into());
                    }
                    t.set_key(0, Key::try_from(self.n).map_err(|_| Failure::Memory)?);
                    one(new_pattern(ctx, t, p.ktable()))
                }
            },
            Func::B => {
                let p = self.pat(ctx, 1)?;
                let n = self.answer;
                if p.tree().has_captures() {
                    return Err(Fail::arg(1, "pattern have captures").into());
                }
                if n <= 0 {
                    return Err(Fail::arg(1, "pattern may not have fixed length").into());
                }
                if n > MAXBEHIND {
                    return Err(Fail::arg(1, "pattern too long to look behind").into());
                }
                let n = i32::try_from(n).map_err(|_| Failure::Memory)?;
                one(new_pattern(
                    ctx,
                    Tree::behind(n, p.tree()).map_err(mem)?,
                    p.ktable(),
                ))
            }
            Func::C => self.capture(ctx, CapKind::Simple, 0),
            Func::Cs => self.capture(ctx, CapKind::Subst, 0),
            Func::Ct => self.capture(ctx, CapKind::Table, 0),
            Func::Cg if self.none_or_nil(2) => self.capture(ctx, CapKind::Group, 0),
            Func::Cg => self.capture(ctx, CapKind::Group, 2),
            Func::Cf => self.capture(ctx, CapKind::Fold, 2),
            Func::Cmt => {
                let p = self.pat(ctx, 1)?;
                let mut t = Tree::root1(Tag::RunTime, p.tree()).map_err(mem)?;
                let mut kt = p.ktable();
                let key = add_to_ktable(ctx, &mut kt, self.arg(2))?;
                t.set_key(0, key);
                one(new_pattern(ctx, t, kt))
            }
            Func::Ptree => Err(Fail::err("function only implemented in debug mode").into()),
            _ => Err(Fail::err("lpeg: no such function").into()),
        }
    }

    /// `lp_locale`'s table: argument 1, or a new one.
    fn locale_table(&mut self, ctx: Context<'gc>) -> Result<(), Failure<'gc>> {
        let t = if self.none_or_nil(1) {
            Table::new(&ctx)
        } else {
            match self.arg(1) {
                Some(Value::Table(t)) => t,
                v => return Err(type_error(ctx, v, 1, "table").into()),
            }
        };
        self.args = vec![Value::Table(t)];
        Ok(())
    }

    /// `createcat` for each class in turn: a charset of the bytes the C
    /// locale puts in it, set with `lua_setfield`, which honours
    /// `__newindex` (a call, after which this goes on with the next class).
    fn locale(&mut self, ctx: Context<'gc>) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let Some(Value::Table(t)) = self.arg(1) else {
            return Err(Fail::err("lpeg: locale table lost").into());
        };
        while let Some(&(name, class)) = CLASSES.get(self.class) {
            self.class = self.class.saturating_add(1);
            let mut cs = Charset::empty();
            for b in 0..=u8::MAX {
                if class(b) {
                    cs.add(b);
                }
            }
            let p = new_pattern(ctx, Tree::charset(&cs).map_err(|_| Failure::Memory)?, None);
            let key = Value::String(ctx.intern(name.as_bytes()));
            match meta_ops::new_index(ctx, Value::Table(t), key, p) {
                Ok(None) => {}
                Ok(Some(call)) => return Ok(Flow::Call(call.function, call.args.to_vec())),
                Err(e) => return Err(Failure::Raised(e.into())),
            }
        }
        Ok(Flow::Done(vec![Value::Table(t)]))
    }

    /// [`Job::advance`] with the fuel the VM has left, at least
    /// [`MIN_STEPS`] steps; what it spent is taken from that fuel.
    fn run(
        &mut self,
        ctx: Context<'gc>,
        exec: &mut Execution<'gc, '_>,
    ) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let fuel = exec.fuel();
        let start = u32::try_from(fuel.remaining()).unwrap_or(0).max(MIN_STEPS);
        let mut budget = start;
        let r = self.advance(ctx, &mut budget);
        fuel.consume(i32::try_from(start.saturating_sub(budget)).unwrap_or(i32::MAX));
        r
    }

    /// The Lua error for `e`: see the module's "Errors".
    fn raise(&self, ctx: Context<'gc>, exec: &Execution<'gc, '_>, e: Failure<'gc>) -> Error<'gc> {
        match e {
            Failure::Memory => ctx.not_enough_memory(),
            Failure::Raised(e) => e,
            Failure::Lua(f) => {
                let lua_caller = exec.frame_info(1).is_some_and(|f| f.lua.is_some());
                let mut msg = exec.where_at(1);
                msg.extend_from_slice(&f.message(&self.func.name(lua_caller)));
                lua_error_bytes(ctx, &msg)
            }
        }
    }

    /// `newroot1sib`.
    fn one_sib(
        &self,
        ctx: Context<'gc>,
        tag: Tag,
    ) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let p = self.pat(ctx, 1)?;
        let t = Tree::root1(tag, p.tree()).map_err(|_| Failure::Memory)?;
        Ok(Flow::Done(vec![new_pattern(ctx, t, p.ktable())]))
    }

    /// `newroot2sib`.
    fn two(&self, ctx: Context<'gc>, tag: Tag) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let (p1, p2) = (self.pat(ctx, 1)?, self.pat(ctx, 2)?);
        let (kt, n) = join_ktables(ctx, p1.ktable(), p2.ktable())?;
        let t = Tree::root2(tag, p1.tree(), p2.tree(), n).map_err(|_| Failure::Memory)?;
        Ok(Flow::Done(vec![new_pattern(ctx, t, kt)]))
    }

    /// `capture_aux`: a capture over argument 1, labelled with argument
    /// `label` (0: none).
    fn capture(
        &self,
        ctx: Context<'gc>,
        cap: CapKind,
        label: usize,
    ) -> Result<Flow<'gc, Vec<Value<'gc>>>, Failure<'gc>> {
        let p = self.pat(ctx, 1)?;
        let mut kt = p.ktable();
        let key = if label == 0 {
            0
        } else {
            add_to_ktable(ctx, &mut kt, self.arg(label))?
        };
        let t = Tree::capture(cap, key, p.tree()).map_err(|_| Failure::Memory)?;
        Ok(Flow::Done(vec![new_pattern(ctx, t, kt)]))
    }
}

/// `getpatt` of a value that is not a table: the pattern it converts to.
fn getpatt<'gc>(
    ctx: Context<'gc>,
    v: Option<Value<'gc>>,
    idx: usize,
) -> Result<Value<'gc>, Failure<'gc>> {
    let mem = |_| Failure::Memory;
    let tree = match v {
        Some(Value::String(s)) => Tree::literal(s.as_bytes()).map_err(mem)?,
        Some(n @ (Value::Integer(_) | Value::Number(_))) => {
            Tree::number(narrow(to_integer_or_zero(n))).map_err(mem)?
        }
        Some(Value::Boolean(b)) => {
            Tree::leaf(if b { Tag::True } else { Tag::False }).map_err(mem)?
        }
        Some(f @ Value::Function(_)) => {
            let mut kt = None;
            let key = add_to_ktable(ctx, &mut kt, Some(f))?;
            return Ok(new_pattern(ctx, Tree::runtime(key).map_err(mem)?, kt));
        }
        Some(v) if pattern(ctx, v).is_some() => return Ok(v),
        other => return Err(not_a_pattern(ctx, other, idx)),
    };
    Ok(new_pattern(ctx, tree, None))
}

/// The C locale's classes (`lp_locale`), in the C's order. nmap never sets
/// `LC_CTYPE`, so no byte of 128 or more is in any of them.
type Class = fn(u8) -> bool;
const CLASSES: [(&str, Class); 11] = [
    ("alnum", |b| b.is_ascii_alphanumeric()),
    ("alpha", |b| b.is_ascii_alphabetic()),
    ("cntrl", |b| b.is_ascii_control()),
    ("digit", |b| b.is_ascii_digit()),
    ("graph", |b| b.is_ascii_graphic()),
    ("lower", |b| b.is_ascii_lowercase()),
    ("print", |b| b == b' ' || b.is_ascii_graphic()),
    ("punct", |b| b.is_ascii_punctuation()),
    // `isspace` holds `\v`, which `is_ascii_whitespace` does not.
    ("space", |b| matches!(b, b'\t'..=b'\r' | b' ')),
    ("upper", |b| b.is_ascii_uppercase()),
    ("xdigit", |b| b.is_ascii_hexdigit()),
];

/// A library function or metamethod as a Lua function.
fn callback<'gc>(ctx: Context<'gc>, func: Func) -> Callback<'gc> {
    Callback::from_fn_with(&ctx, func, |&func, ctx, mut exec, mut stack| {
        let mut job = Job::new(func, stack.drain(..).collect());
        match job.run(ctx, &mut exec) {
            Ok(Flow::Done(vs)) => {
                stack.extend(vs);
                Ok(CallbackReturn::Return)
            }
            Ok(Flow::Pending) => Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, job))),
            Ok(Flow::Call(f, args)) => {
                job.call = Some((f, args));
                Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, job)))
            }
            Err(e) => Err(job.raise(ctx, &exec, e)),
        }
    })
}

impl<'gc> Sequence<'gc> for Job<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        mut exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        if let Some((f, args)) = this.call.take() {
            stack.clear();
            stack.extend(args);
            this.awaiting = true;
            return Ok(SequencePoll::Call {
                bottom: 0,
                function: f,
            });
        }
        if std::mem::take(&mut this.awaiting) {
            // `lua_gettable` and `lua_setfield` keep one result, or none.
            let v = stack.get(0);
            stack.clear();
            if let Err(e) = this.resume(ctx, v) {
                return Err(this.raise(ctx, &exec, e));
            }
        }
        match this.run(ctx, &mut exec) {
            Ok(Flow::Done(vs)) => {
                stack.clear();
                stack.extend(vs);
                Ok(SequencePoll::Return)
            }
            Ok(Flow::Pending) => Ok(SequencePoll::Pending),
            Ok(Flow::Call(f, args)) => {
                stack.clear();
                stack.extend(args);
                this.awaiting = true;
                Ok(SequencePoll::Call {
                    bottom: 0,
                    function: f,
                })
            }
            Err(e) => Err(this.raise(ctx, &exec, e)),
        }
    }
}

/// `luaopen_lpeg` (`lpeg.c:3326`): the library table. Opening it resets
/// `lpeg-maxstack` to `MAXBACK`, as the C does, and makes the table the
/// pattern metatable's `__index`.
fn open<'gc>(ctx: Context<'gc>) -> Table<'gc> {
    let reg = registry(ctx);
    reg.store.set_field(ctx, "maxstack", MAXBACK);
    let lib = Table::new(&ctx);
    for func in LIBRARY {
        lib.set_field(ctx, func.field(), callback(ctx, func));
    }
    reg.metatable.set_field(ctx, "__index", lib);
    lib
}

/// **For tests only.** Open `lpeg` in this state and put it in `loaded`
/// (the state's `package.loaded`), and return it.
///
/// No script can reach the module yet (E9): the NSE runtime never calls this
/// (`runtime::tests::lpeg_is_not_registered`), and `match` here only raises
/// "not implemented until M6.6 step c". Step e registers the module for
/// real, when every capture kind works.
pub fn register_for_tests<'gc>(ctx: Context<'gc>, loaded: Option<Table<'gc>>) -> Table<'gc> {
    let lib = open(ctx);
    if let Some(loaded) = loaded {
        loaded.set_field(ctx, "lpeg", lib);
    }
    lib
}

/// The value `setmaxstack` stored (`lpeg-maxstack`), as given: `100.0` until
/// a script calls it. Step c reads it at every growth of the backtrack
/// stack, as the C does.
#[must_use]
pub fn max_stack_value<'gc>(ctx: Context<'gc>) -> Value<'gc> {
    registry(ctx).store.get_value(ctx, "maxstack")
}

#[cfg(test)]
mod tests {
    //! The binding through the VM, in-module so that Miri runs it. The
    //! differential corpus (`tests/lpeg_tree_differential.rs`) holds the
    //! oracle's answers; these pin what the corpus cannot reach.
    use super::*;
    use crate::nse::stdlib::{load_format, load_patterns, load_tail};
    use piccolo::{Closure, Executor, Lua, Variadic};

    fn run(src: &str) -> Vec<String> {
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            load_patterns(ctx).expect("string table");
            load_format(ctx).expect("string table");
            load_tail(ctx).expect("string and coroutine tables");
            ctx.set_global("lpeg", register_for_tests(ctx, None));
            let c = Closure::load(ctx, Some("=t"), src.as_bytes()).expect("compiles");
            ctx.stash(Executor::start(ctx, c.into(), ()))
        });
        lua.finish(&ex).expect("finishes");
        lua.enter(|ctx| {
            let vs: Variadic<Vec<Value>> = ctx
                .fetch(&ex)
                .take_result(ctx)
                .expect("done")
                .expect("no error");
            vs.0.iter()
                .map(|v| match v {
                    Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                    v => v.type_name().to_string(),
                })
                .collect()
        })
    }

    #[test]
    fn the_c_locales_classes_have_the_cs_sizes() {
        let sizes: Vec<usize> = CLASSES
            .iter()
            .map(|(_, class)| (0..=u8::MAX).filter(|&b| class(b)).count())
            .collect();
        assert_eq!(sizes, [62, 52, 33, 10, 94, 26, 95, 32, 6, 26, 22]);
        // No byte of 128 or more is in any class: nmap never sets LC_CTYPE.
        assert!(CLASSES.iter().all(|(_, c)| (128..=u8::MAX).all(|b| !c(b))));
        let names: Vec<&str> = CLASSES.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names.join(","),
            "alnum,alpha,cntrl,digit,graph,lower,print,punct,space,upper,xdigit"
        );
    }

    #[test]
    fn narrowing_is_the_cs() {
        assert_eq!(narrow((1 << 32) + 2), 2);
        assert_eq!(narrow((1 << 31) + 1), -2_147_483_647);
        assert_eq!(narrow(i64::MAX), -1);
        assert_eq!(narrow(i64::MIN), 0);
        assert_eq!(to_integer_or_zero(Value::Number(1.5)), 0);
        assert_eq!(to_integer_or_zero(Value::Number(9.3e18)), 0);
        assert_eq!(to_integer_or_zero(Value::Number(-0.0)), 0);
        assert_eq!(
            to_integer_or_zero(Value::Number(-9_223_372_036_854_775_808.0)),
            i64::MIN
        );
    }

    /// Construction through the VM: identity, the metatable, a grammar whose
    /// initial rule comes from an `__index` call, `locale` through
    /// `__newindex` calls, and errors with their names and positions.
    #[test]
    fn the_binding_builds_patterns_as_the_c_does() {
        let got = run("local P, V = lpeg.P, lpeg.V \
             local p = P'a' \
             local order = {} \
             local t = setmetatable({}, { __newindex = function(t, k, v) order[#order + 1] = k rawset(t, k, v) end }) \
             lpeg.locale(t) \
             local g = P(setmetatable({ 'S' }, { __index = function(_, k) return P'x' * k end })) \
             local ok, e = pcall(function() return p ^ 1.5 end) \
             return tostring(rawequal(P(p), p)), tostring(rawequal(p * true, p)), \
                    lpeg.type(g), table.concat(order, ','), e, \
                    select(2, pcall(lpeg.P, { 'S', S = V'S' })), \
                    select(2, pcall(getmetatable(p).__add, p, nil)), \
                    (tostring(p):gsub('0x%x+', '')), lpeg.version()");
        assert_eq!(
            got,
            [
                "true",
                "true",
                "pattern",
                "alnum,alpha,cntrl,digit,graph,lower,print,punct,space,upper,xdigit",
                "t:1: bad argument #2 to 'pow' (number has no integer representation)",
                "rule 'S' may be left recursive",
                "bad argument #2 to '?' (lpeg-pattern expected, got nil)",
                "lpeg-pattern: ",
                "0.12",
            ]
        );
    }
}
