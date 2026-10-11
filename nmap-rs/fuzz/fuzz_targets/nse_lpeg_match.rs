// cargo-fuzz target for LPeg matching (M6.6 steps c and d):
// `nmap_core::nse::lpeg::code` (the compiler), `nmap_core::nse::lpeg::vm`
// (the matching machine) and `vm::capture` (capture evaluation), pure and
// through the binding.
//
// The network controls subjects; scripts control patterns. The input is a
// pattern, written as a small prefix program over the pure constructors —
// literals, sets, numbers, sequences, choices, repetitions, predicates,
// look-behinds, grammars with calls, and every capture that calls no Lua —
// then a subject. The first byte picks the slice (its low six bits) and,
// with its top three bits set, the binding as well (an eighth of inputs: a
// run through a Lua state costs some ten pure ones).
//
// Pure, on every input (the program as a tree, a subject of up to 48 bytes
// of `a`/`b`/`c`, constants of a few bytes). Checked:
//   * nothing panics or aborts, whatever the pattern and subject;
//   * the compiler refuses only what the C refuses at compile time — a left
//     call through `B`, whose `getfirst` recursion the C never ends, and
//     "not enough memory" — and nothing else (an open call outside a
//     grammar is `finalfix`'s, run first); the machine never fails;
//   * compiling, matching and evaluating in slices of 1 to 64 units of
//     budget gives what one slice gives (a slice boundary is invisible);
//   * what capture evaluation holds — buffers, strings, tables' chunks — is
//     counted as it changes, and the count is what a walk finds at every
//     slice;
//   * the answer — no match, or the match's end and its values, or the
//     error evaluation raises — is what a direct interpreter of the tree
//     gives: PEG semantics over the tree itself, recursively, with the
//     capture list LPeg's compiler implies (a capture of a fixed-length
//     pattern with no captures is one entry placed after it; an
//     and-predicate of one keeps a called rule's captures, `hascaptures`
//     following no call), evaluated by a transliteration of `lpcap.c`.
//   Where either side runs past its bound — the interpreter's recursion or
//   step count, the machine's budget (an exponential grammar), a compile
//   that refuses a left call through `B` — the case is not compared; nor is
//   a program with a partial commit in a loop coded with a test, where
//   0.12's code generation departs from PEG semantics and the interpreter
//   does not follow it (`commits_through_a_test_loop`: seed
//   `opt_partial_commit_in_a_test_loop`, which was artefact `crash-bd846150...`).
//
// Through the binding, when the first byte's top three bits are set (the same
// program as Lua, built by the constructors and run by `lpeg.match` in a
// Lua state with the test-only registration: `getpatt`, the binding's
// `MatchJob` and `LuaEnv`, `init`, extra arguments, the values' conversion,
// what a match holds accounted to the heap), and, from step d, the captures
// that call Lua: a quarter of its composite nodes (op bytes from 200) are a
// `Cmt`, a function coerced as `P(f)`, a `/function`, a `Cf` or a `/table`,
// with callbacks from a fixed set (`chunk`'s `F`, `G`, `H`, `T`): returning
// false, true, positions (the current, one on, one back, past the end,
// `3.5`, a padded string), the captures' values or their count, a table,
// nothing, or 300 values; raising an error table or a string; running a
// nested match; calling `setmaxstack`, `collectgarbage()` or the pattern's
// `__gc`; yielding (the match runs in a coroutine, resumed with what it
// yields until it ends, so a callback that yields returns what it yielded:
// `lpeg-callback-may-yield`); `__index` functions and tables. A pattern
// holding one is checked through the binding alone. Constants are larger
// here: strings of up to 3,600 bytes by repetition, `/string` formats of up
// to 128 copies of theirs (256 `%n`), a subject repeated up to 64 times
// (3 KiB), `init` from -3 to 3, a backtrack ceiling of 100 or 150, a memory
// budget of 16 MiB. Checked:
//   * the same chunk run in one slice and in slices of 64 to 4,096 units of
//     fuel (a match takes 1,024 at least), one after the other in one state,
//     with a full collection before each and every 64th slice, gives the
//     same answer — what `pcall` of the match returns, and how often it
//     yielded, serialised here, a table by its sorted pairs — or "not enough
//     memory" on either side (`lpeg-memory-errors-depend-on-slicing`);
//   * in every slice of both runs, LPeg's work (`lpeg::take_work`) is within
//     four times what the slice's fuel pays for, and a few units: the step d
//     review's F1 (bookkeeping after each call, in proportion to what the
//     cursor held) would fail it on the seeds `binding_*_to_calls_in_a_loop`;
//   * no error the binding raises for its own defects ("lpeg: malformed
//     program", "lpeg: ... lost", "lpeg: capture call refused") is ever
//     seen.
//   A run past 300,000 units of fuel is not compared. Seeds
//   `close_after_kept_capture_binding`, `binding_table_of_many_captures`,
//   the `binding_cmt_*`, `binding_function_*`, `binding_fold_*` and
//   `binding_query_*` ones, and from the step d review `binding_callbacks_yield`,
//   `binding_fold_and_query_yield`, `binding_collect_and_gc`,
//   `binding_many_results` and the two `binding_*_to_calls_in_a_loop`, reach
//   the checks.
#![no_main]

use std::borrow::Cow;
use std::task::Poll;

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::lpeg::code::{CodeError, Compiler, Op, Program};
use nmap_core::nse::lpeg::tree::{
    CapKind, Charset, CheckAux, FinalFix, FixedLen, GrammarLayout, Key, Pred, Tag, Tree,
    VerifyGrammar,
};
use nmap_core::nse::lpeg::vm::capture::{CapCursor, CapEnv, CapError, CapVal, TableKey, View};
use nmap_core::nse::lpeg::vm::{Capture, Vm, VmPoll};
use nmap_core::nse::lpeg::{register_for_tests, take_work, BYTES_PER_FUEL};
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{Closure, Executor, Fuel, Lua, Value, Variadic};

/// The most budget a match may take, in units.
const BUDGET: u64 = 400_000;
/// The interpreter's bounds.
const DEPTH: u32 = 400;
const STEPS: u64 = 400_000;

struct Input<'a> {
    data: &'a [u8],
    at: usize,
    /// Binding mode: patterns may hold captures that call Lua.
    lua: bool,
    /// The pattern holds one: the pure checks do not run.
    calls: bool,
}

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }
}

// ---------------------------------------------------------------- constants

/// The constants the trees' keys name: 1 "a" and 2 "k" (group names), 3 and
/// 4 formats for `/string`, 5 the number 7, 6 a table. Arguments: 1 "x",
/// 2 the number 2.5 (`match` called with five, so `Carg(3)` is absent).
struct Env;

const PTOP: usize = 5;

impl CapEnv for Env {
    fn constant(&self, k: Key) -> View<'_> {
        match k {
            1 => View::Str(Cow::Borrowed(b"a")),
            2 => View::Str(Cow::Borrowed(b"k")),
            3 => View::Str(Cow::Borrowed(b"%1-%0%%")),
            4 => View::Str(Cow::Borrowed(b"<%2%9>")),
            5 => View::Num(Cow::Borrowed(b"7")),
            6 => View::Other("table"),
            _ => View::Nil,
        }
    }
    fn argument(&self, n: u32) -> View<'_> {
        match n {
            1 => View::Str(Cow::Borrowed(b"x")),
            2 => View::Num(Cow::Borrowed(b"2.5")),
            _ => View::Nil,
        }
    }
    fn same_constant(&self, a: Key, b: Key) -> (bool, usize) {
        (a != 0 && a == b, 0)
    }
}

// ---------------------------------------------------------------- patterns

fn lit(s: &[u8]) -> Tree {
    Tree::literal(s).unwrap()
}

fn drive<T>(slice: u32, mut f: impl FnMut(&mut u32) -> Poll<T>) -> T {
    loop {
        let mut b = slice;
        if let Poll::Ready(v) = f(&mut b) {
            return v;
        }
    }
}

fn nullable(t: &Tree) -> bool {
    let mut w = CheckAux::new(0, Pred::Nullable);
    drive(u32::MAX, |b| w.step(t, b)).unwrap_or(true)
}

fn fixedlen_of(t: &Tree, i: usize) -> i64 {
    let mut w = FixedLen::new(i);
    drive(u32::MAX, |b| w.step(t, b)).unwrap_or(-1)
}

/// The constant a `Cc` with key byte `b` makes, as Lua: key `b % 7` as
/// `Env` has it, a string of up to 3,600 bytes for key 1 when the rest of
/// the byte is large.
fn const_lua(b: u8) -> String {
    let r = usize::from(b / 7);
    match b % 7 {
        0 => "nil".to_string(),
        1 if r > 18 => format!("('a'):rep({})", r * 100),
        1 => "'a'".to_string(),
        2 => "'k'".to_string(),
        3 => "'%1-%0%%'".to_string(),
        4 => "'<%2%9>'".to_string(),
        5 => "7".to_string(),
        _ => "{}".to_string(),
    }
}

/// A group's name, as Lua (keys 1 and 2 as `Env` has them).
fn name_lua(k: Key) -> &'static str {
    if k == 1 {
        "'a'"
    } else {
        "'k'"
    }
}

/// A pattern of depth at most `d` from the input, as a tree and as the Lua
/// that builds it; open calls name rules `1..=rules`.
fn pattern(inp: &mut Input, d: u32, rules: u32) -> (Tree, String) {
    let op = inp.byte();
    if d == 0 || op < 40 {
        return match op % 12 {
            0 => {
                let n = usize::from(inp.byte() % 4);
                let s: Vec<u8> = (0..n)
                    .map(|_| b"abc"[usize::from(inp.byte() % 3)])
                    .collect();
                let lua = format!("P'{}'", String::from_utf8_lossy(&s));
                (lit(&s), lua)
            }
            1 => {
                let n = i32::from(inp.byte() % 5) - 2;
                (Tree::number(n).unwrap(), format!("P({n})"))
            }
            2 => (Tree::leaf(Tag::True).unwrap(), "P(true)".to_string()),
            3 => (Tree::leaf(Tag::False).unwrap(), "P(false)".to_string()),
            4 if rules > 0 => {
                let mut v = Tree::leaf(Tag::OpenCall).unwrap();
                let k = 1 + Key::from(inp.byte()) % rules;
                v.set_key(0, k);
                (v, format!("V({k})"))
            }
            5 => {
                let mut cs = Charset::empty();
                let mut chars = String::new();
                for _ in 0..inp.byte() % 3 {
                    let c = b'a' + inp.byte() % 3;
                    cs.add(c);
                    chars.push(char::from(c));
                }
                (Tree::charset(&cs).unwrap(), format!("S'{chars}'"))
            }
            6 => (
                Tree::empty_capture(CapKind::Position, 0).unwrap(),
                "Cp()".to_string(),
            ),
            7 => {
                let b = inp.byte();
                (
                    Tree::empty_capture(CapKind::Const, Key::from(b % 7)).unwrap(),
                    format!("Cc({})", const_lua(b)),
                )
            }
            8 => {
                let n = 1 + Key::from(inp.byte() % 3);
                (
                    Tree::empty_capture(CapKind::Arg, n).unwrap(),
                    format!("Carg({n})"),
                )
            }
            9 => {
                let k = 1 + Key::from(inp.byte() % 2);
                (
                    Tree::empty_capture(CapKind::Backref, k).unwrap(),
                    format!("Cb({})", name_lua(k)),
                )
            }
            10 => (
                Tree::charset(&Charset([0xff; 32])).unwrap(),
                "P(1)".to_string(),
            ),
            _ => (lit(b"b"), "P'b'".to_string()),
        };
    }
    // Binding mode: a quarter of the composite nodes (ops 200 and up) call
    // Lua.
    if inp.lua && op >= 200 {
        return lua_capture(inp, d, rules);
    }
    let sub = |inp: &mut Input| pattern(inp, d - 1, rules);
    match op % 16 {
        0 | 1 => {
            let ((a, la), (b, lb)) = (sub(inp), sub(inp));
            (
                Tree::root2(Tag::Seq, &a, &b, 0).unwrap(),
                format!("({la} * {lb})"),
            )
        }
        2 | 3 => {
            let ((a, la), (b, lb)) = (sub(inp), sub(inp));
            (
                Tree::root2(Tag::Choice, &a, &b, 0).unwrap(),
                format!("({la} + {lb})"),
            )
        }
        4 => {
            let (a, la) = sub(inp);
            (Tree::root1(Tag::Not, &a).unwrap(), format!("(-{la})"))
        }
        5 => {
            let (a, la) = sub(inp);
            (Tree::root1(Tag::And, &a).unwrap(), format!("(#{la})"))
        }
        6 => {
            let (t, lt) = sub(inp);
            let mut n = i32::from(inp.byte() % 5) - 2;
            if n >= 0 && nullable(&t) {
                n = -1 - n;
            }
            (
                Tree::star(&t, n, Tree::star_space(t.len(), n).unwrap()).unwrap(),
                format!("({lt} ^ ({n}))"),
            )
        }
        7 => {
            let ((a, la), (b, lb)) = (sub(inp), sub(inp));
            (
                Tree::difference(&a, &b, 0).unwrap(),
                format!("({la} - {lb})"),
            )
        }
        8 => {
            let (a, la) = sub(inp);
            (
                Tree::capture(CapKind::Simple, 0, &a).unwrap(),
                format!("C({la})"),
            )
        }
        9 => {
            let (a, la) = sub(inp);
            (
                Tree::capture(CapKind::Table, 0, &a).unwrap(),
                format!("Ct({la})"),
            )
        }
        10 => {
            let (a, la) = sub(inp);
            (
                Tree::capture(CapKind::Subst, 0, &a).unwrap(),
                format!("Cs({la})"),
            )
        }
        11 => {
            let k = Key::from(inp.byte() % 3);
            let (a, la) = sub(inp);
            let lua = if k == 0 {
                format!("Cg({la})")
            } else {
                format!("Cg({la}, {})", name_lua(k))
            };
            (Tree::capture(CapKind::Group, k, &a).unwrap(), lua)
        }
        // A format, as `Env` has it; to Lua, up to 128 copies of it.
        12 => {
            let b = inp.byte();
            let k = 3 + Key::from(b % 2);
            let (a, la) = sub(inp);
            let fmt = if k == 3 { "%1-%0%%" } else { "<%2%9>" };
            (
                Tree::capture(CapKind::String, k, &a).unwrap(),
                format!("({la} / ('{fmt}'):rep({}))", 1 + b / 2),
            )
        }
        13 => {
            let k = Key::from(inp.byte() % 4);
            let (a, la) = sub(inp);
            (
                Tree::capture(CapKind::Num, k, &a).unwrap(),
                format!("({la} / {k})"),
            )
        }
        // `lpeg.B`: a fixed length up to 255 and no captures, or refused.
        14 => {
            let (t, lt) = sub(inp);
            match fixedlen_of(&t, 0) {
                n @ 1..=255 if !t.has_captures() => {
                    (Tree::behind(n as i32, &t).unwrap(), format!("B({lt})"))
                }
                _ => (Tree::root1(Tag::And, &t).unwrap(), format!("(#{lt})")),
            }
        }
        _ => grammar(inp, d - 1).unwrap_or_else(|| (lit(b"c"), "P'c'".to_string())),
    }
}

/// A capture that calls Lua (binding mode only: the pure checks do not run
/// on a pattern holding one), over a sub-pattern, with one of the chunk's
/// fixed callbacks ([`chunk`]): a match-time capture (`Cmt`, or a function
/// coerced as `P(f)`), `/function`, `Cf` or `/table`. The tree is a
/// stand-in.
fn lua_capture(inp: &mut Input, d: u32, rules: u32) -> (Tree, String) {
    inp.calls = true;
    let (t, lt) = pattern(inp, d - 1, rules);
    let k = usize::from(inp.byte());
    let lua = match k % 5 {
        0 => format!("Cmt({lt}, F[{}])", 1 + k / 5 % 16),
        1 => format!("({lt} / G[{}])", 1 + k / 5 % 10),
        2 => format!("Cf({lt}, H[{}])", 1 + k / 5 % 5),
        3 => format!("({lt} / T[{}])", 1 + k / 5 % 4),
        _ => format!("({lt} * P(F[{}]))", 1 + k / 5 % 16),
    };
    (Tree::capture(CapKind::Function, 0, &t).unwrap(), lua)
}

/// A grammar of one to three rules, built, fixed and verified as `lpeg.P`
/// builds one, and its Lua; `None` if refused.
fn grammar(inp: &mut Input, d: u32) -> Option<(Tree, String)> {
    let n = 1 + u32::from(inp.byte() % 3);
    let made: Vec<(Tree, String)> = (0..n).map(|_| pattern(inp, d, n)).collect();
    let lua = format!(
        "P{{ {} }}",
        made.iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let rules: Vec<Tree> = made.into_iter().map(|(t, _)| t).collect();
    let sizes: Vec<usize> = rules.iter().map(Tree::len).collect();
    let layout = GrammarLayout::new(&sizes).ok()?;
    let pairs: Vec<(&Tree, Key)> = rules.iter().map(|t| (t, 0)).collect();
    let mut g = layout.build(&pairs, layout.space().ok()?).ok()?;
    let positions = layout.positions.clone();
    let resolve = move |k: Key| positions.get(k as usize - 1).map_or(0, |&p| p as i64);
    let mut w = FinalFix::new(Some(0), 1);
    drive(u32::MAX, |b| w.step(&mut g, &resolve, b)).ok()?;
    if g.node(1)?.key == 0 {
        g.set_key(1, 9);
    }
    // Step b's verifier is exponential in nested grammars: a grammar it
    // takes past the bound is not made.
    let mut v = VerifyGrammar::new(0);
    for _ in 0..64 {
        let mut b = 1 << 14;
        if let Poll::Ready(r) = v.step(&g, &mut b) {
            return r.ok().map(|()| (g, lua));
        }
    }
    None
}

// ---------------------------------------------------------------- the interpreter

/// PEG semantics over the (fixed) tree, with the capture list LPeg's code
/// would build.
struct Interp<'a> {
    t: &'a Tree,
    s: &'a [u8],
    caps: Vec<Capture>,
    steps: u64,
    /// `fixedlen` and `hascaptures` of each node, once asked (`fixedlen`
    /// follows calls up to 200 deep: asked at every visit, it is most of
    /// the time an exponential grammar takes).
    facts: Vec<Option<(i64, bool)>>,
}

/// The interpreter ran past its bounds.
struct Bail;

fn has_caps(t: &Tree, i: usize) -> bool {
    let n = t.node(i).unwrap();
    match n.tag {
        Tag::Capture | Tag::RunTime => true,
        tag => match tag.siblings() {
            1 => has_caps(t, i + 1),
            2 => has_caps(t, i + 1) || has_caps(t, t.sib2(i).unwrap()),
            _ => false,
        },
    }
}

impl Interp<'_> {
    fn facts(&mut self, i: usize) -> (i64, bool) {
        if let Some(f) = self.facts[i] {
            return f;
        }
        let f = (fixedlen_of(self.t, i), has_caps(self.t, i));
        self.facts[i] = Some(f);
        f
    }

    /// Match node `i` at `p`: the position after, or `None`.
    fn m(&mut self, i: usize, p: usize, depth: u32) -> Result<Option<usize>, Bail> {
        self.steps += 1;
        if depth > DEPTH || self.steps > STEPS {
            return Err(Bail);
        }
        let d = depth + 1;
        let t = self.t;
        let n = t.node(i).unwrap();
        let sib2 = || t.sib2(i).unwrap();
        Ok(match n.tag {
            Tag::Char => (p < self.s.len() && i32::from(self.s[p]) == n.u).then_some(p + 1),
            Tag::Any => (p < self.s.len()).then_some(p + 1),
            Tag::Set => {
                let cs = t.charset_at(i).unwrap();
                (p < self.s.len() && cs.has(self.s[p])).then_some(p + 1)
            }
            Tag::True => Some(p),
            Tag::False => None,
            Tag::Seq => match self.m(i + 1, p, d)? {
                Some(q) => self.m(sib2(), q, d)?,
                None => None,
            },
            Tag::Choice => {
                let level = self.caps.len();
                match self.m(i + 1, p, d)? {
                    Some(q) => Some(q),
                    None => {
                        self.caps.truncate(level);
                        self.m(sib2(), p, d)?
                    }
                }
            }
            Tag::Rep => {
                let mut q = p;
                loop {
                    let level = self.caps.len();
                    match self.m(i + 1, q, d)? {
                        Some(r) => q = r,
                        None => {
                            self.caps.truncate(level);
                            break Some(q);
                        }
                    }
                }
            }
            Tag::Not => {
                let level = self.caps.len();
                let r = self.m(i + 1, p, d)?;
                self.caps.truncate(level);
                if r.is_some() {
                    None
                } else {
                    Some(p)
                }
            }
            // `codeand`: a fixed length and no captures is the pattern,
            // then a look back (its called rules' captures kept); anything
            // else is a choice and a back-commit (none kept).
            Tag::And => {
                let level = self.caps.len();
                let (len, caps) = self.facts(i + 1);
                let r = self.m(i + 1, p, d)?;
                if r.is_none() || !(0..=255).contains(&len) || caps {
                    self.caps.truncate(level);
                }
                r.map(|_| p)
            }
            Tag::Behind => {
                let n = usize::try_from(n.u).unwrap();
                if n > p {
                    None
                } else {
                    self.m(i + 1, p - n, d)?
                }
            }
            Tag::Call => self.m(sib2() + 1, p, d)?,
            Tag::Rule | Tag::Grammar => self.m(i + 1, p, d)?,
            Tag::Capture => {
                let kind = n.cap;
                let (len, caps) = self.facts(i + 1);
                if (0..=15).contains(&len) && !caps {
                    // One entry after the pattern.
                    match self.m(i + 1, p, d)? {
                        Some(q) => {
                            self.caps.push(Capture {
                                s: q - usize::try_from(len).unwrap(),
                                idx: n.key,
                                kind,
                                siz: u8::try_from(len + 1).unwrap(),
                            });
                            Some(q)
                        }
                        None => None,
                    }
                } else {
                    let open = self.caps.len();
                    self.caps.push(Capture {
                        s: p,
                        idx: n.key,
                        kind,
                        siz: 0,
                    });
                    match self.m(i + 1, p, d)? {
                        Some(q) => {
                            // A close right after its open folds into it.
                            if self.caps.len() == open + 1 && q - p < 255 {
                                self.caps[open].siz = u8::try_from(q - p + 1).unwrap();
                            } else {
                                self.caps.push(Capture {
                                    s: q,
                                    idx: 0,
                                    kind: CapKind::Close as u8,
                                    siz: 1,
                                });
                            }
                            Some(q)
                        }
                        None => {
                            self.caps.truncate(open);
                            None
                        }
                    }
                }
            }
            Tag::OpenCall | Tag::RunTime => return Err(Bail),
        })
    }
}

// ---------------------------------------------------------------- lpcap.c

/// A value, comparable on both sides.
#[derive(Debug, Clone, PartialEq)]
enum Val {
    Nil,
    Int(i64),
    Str(Vec<u8>),
    K(Key),
    Arg(u32),
    Table(Vec<(TableKey, Val)>),
}

#[derive(Debug, Clone, PartialEq)]
enum Err {
    Backref(Key),
    AbsentArg(u32),
    NoCapture(u32),
    BadIndex(u32),
    NoValues(u32),
    Invalid(&'static str, &'static str),
    BufferTooLarge,
    Memory,
}

/// `lpcap.c`, recursively, over a capture list.
struct Eval<'a> {
    caps: &'a [Capture],
    s: &'a [u8],
    pos: usize,
    depth: u32,
}

fn text(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Int(i) => Some(i.to_string().into_bytes()),
        Val::Str(s) => Some(s.clone()),
        Val::K(k) => match Env.constant(*k) {
            View::Str(s) | View::Num(s) => Some(s.into_owned()),
            _ => None,
        },
        Val::Arg(n) => match Env.argument(*n) {
            View::Str(s) | View::Num(s) => Some(s.into_owned()),
            _ => None,
        },
        _ => None,
    }
}

fn type_name(v: &Val) -> &'static str {
    let view = |w: View| match w {
        View::Nil => "nil",
        View::Str(_) => "string",
        View::Num(_) => "number",
        View::Other(t) => t,
    };
    match v {
        Val::Nil => "nil",
        Val::Int(_) => "number",
        Val::Str(_) => "string",
        Val::Table(_) => "table",
        Val::K(k) => view(Env.constant(*k)),
        Val::Arg(n) => view(Env.argument(*n)),
    }
}

impl Eval<'_> {
    fn c(&self) -> Capture {
        self.caps[self.pos]
    }

    fn nextcap(&mut self) {
        let mut cap = self.pos;
        if self.caps[cap].siz == 0 {
            let mut n = 0;
            loop {
                cap += 1;
                let c = self.caps[cap];
                if c.kind == 0 {
                    if n == 0 {
                        break;
                    }
                    n -= 1;
                } else if c.siz == 0 {
                    n += 1;
                }
            }
        }
        self.pos = cap + 1;
    }

    fn nested(&mut self, addextra: bool) -> Result<Vec<Val>, Err> {
        let co = self.c();
        self.pos += 1;
        if co.siz != 0 {
            return Ok(vec![Val::Str(
                self.s[co.s..co.s + usize::from(co.siz) - 1].to_vec(),
            )]);
        }
        let mut out = Vec::new();
        while self.c().kind != 0 {
            out.extend(self.push()?);
        }
        if addextra || out.is_empty() {
            out.push(Val::Str(self.s[co.s..self.c().s].to_vec()));
        }
        self.pos += 1;
        Ok(out)
    }

    fn findopen(&self, mut cap: usize) -> usize {
        let mut n = 0;
        loop {
            cap -= 1;
            let c = self.caps[cap];
            if c.kind == 0 {
                n += 1;
            } else if c.siz == 0 {
                if n == 0 {
                    return cap;
                }
                n -= 1;
            }
        }
    }

    fn push(&mut self) -> Result<Vec<Val>, Err> {
        self.depth += 1;
        let r = self.push1();
        self.depth -= 1;
        r
    }

    fn push1(&mut self) -> Result<Vec<Val>, Err> {
        let c = self.c();
        let k = c.kind;
        Ok(if k == CapKind::Position as u8 {
            self.pos += 1;
            vec![Val::Int(c.s as i64 + 1)]
        } else if k == CapKind::Const as u8 {
            self.pos += 1;
            vec![if c.idx == 0 { Val::Nil } else { Val::K(c.idx) }]
        } else if k == CapKind::Arg as u8 {
            self.pos += 1;
            if c.idx as usize + 3 > PTOP {
                return Err(Err::AbsentArg(c.idx));
            }
            vec![Val::Arg(c.idx)]
        } else if k == CapKind::Simple as u8 {
            let mut v = self.nested(true)?;
            let whole = v.pop().unwrap();
            v.insert(0, whole);
            v
        } else if k == CapKind::String as u8 {
            let mut buf = Vec::new();
            self.stringcap(&mut buf)?;
            vec![Val::Str(buf)]
        } else if k == CapKind::Subst as u8 {
            let mut buf = Vec::new();
            self.substcap(&mut buf)?;
            vec![Val::Str(buf)]
        } else if k == CapKind::Group as u8 {
            if c.idx == 0 {
                self.nested(false)?
            } else {
                self.nextcap();
                vec![]
            }
        } else if k == CapKind::Backref as u8 {
            let curr = self.pos;
            let mut cap = curr;
            let g = loop {
                if cap == 0 {
                    return Err(Err::Backref(c.idx));
                }
                cap -= 1;
                if self.caps[cap].kind == 0 {
                    cap = self.findopen(cap);
                } else if self.caps[cap].siz == 0 {
                    continue;
                }
                let g = self.caps[cap];
                if g.kind == CapKind::Group as u8 && Env.same_constant(g.idx, c.idx).0 {
                    break cap;
                }
            };
            self.pos = g;
            let v = self.nested(false)?;
            self.pos = curr + 1;
            v
        } else if k == CapKind::Table as u8 {
            let mut t = Vec::new();
            let full = c.siz != 0;
            self.pos += 1;
            if !full {
                let mut n = 0i64;
                while self.c().kind != 0 {
                    let e = self.c();
                    if e.kind == CapKind::Group as u8 && e.idx != 0 {
                        let v = self.nested(false)?.swap_remove(0);
                        t.push((TableKey::K(e.idx), v));
                    } else {
                        let vs = self.push()?;
                        let k = vs.len() as i64;
                        for (i, v) in vs.into_iter().enumerate().rev() {
                            t.push((TableKey::Int(n + i as i64 + 1), v));
                        }
                        n += k;
                    }
                }
                self.pos += 1;
            }
            vec![Val::Table(t)]
        } else if k == CapKind::Num as u8 {
            if c.idx == 0 {
                self.nextcap();
                return Ok(vec![]);
            }
            let v = self.nested(false)?;
            if (v.len() as u32) < c.idx {
                return Err(Err::NoCapture(c.idx));
            }
            vec![v[c.idx as usize - 1].clone()]
        } else {
            unreachable!("no Lua-calling captures are made");
        })
    }

    /// `getstrcaps`: (start, end) or a nested capture's index, per slot.
    fn strcaps(&mut self, cps: &mut Vec<Result<(usize, usize), usize>>) {
        let k = cps.len();
        let c = self.c();
        cps.push(Ok((c.s, 0)));
        self.pos += 1;
        if c.siz == 0 {
            while self.c().kind != 0 {
                if cps.len() >= 10 {
                    self.nextcap();
                } else if self.c().kind == CapKind::Simple as u8 {
                    self.strcaps(cps);
                } else {
                    cps.push(Err(self.pos));
                    self.nextcap();
                }
            }
            self.pos += 1;
        }
        let last = self.caps[self.pos - 1];
        let e = last.s + usize::from(last.siz) - 1;
        cps[k] = Ok((c.s, e));
    }

    fn stringcap(&mut self, buf: &mut Vec<u8>) -> Result<(), Err> {
        let fmt = match Env.constant(self.c().idx) {
            View::Str(s) => s.into_owned(),
            _ => vec![],
        };
        let mut cps = Vec::new();
        self.strcaps(&mut cps);
        let n = cps.len() - 1;
        let mut i = 0;
        while i < fmt.len() {
            if fmt[i] != b'%' {
                buf.push(fmt[i]);
            } else {
                i += 1;
                let d = fmt.get(i).copied().unwrap_or(0);
                if !d.is_ascii_digit() {
                    buf.push(d);
                } else {
                    let l = usize::from(d - b'0');
                    if l > n {
                        return Err(Err::BadIndex(l as u32));
                    }
                    match cps[l] {
                        Ok((s, e)) => buf.extend_from_slice(&self.s[s..e]),
                        Err(cp) => {
                            let saved = self.pos;
                            self.pos = cp;
                            if self.addone(buf, "capture")? == 0 {
                                return Err(Err::NoValues(l as u32));
                            }
                            self.pos = saved;
                        }
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }

    fn add(&self, buf: &mut Vec<u8>, a: usize, b: usize) -> Result<(), Err> {
        if b >= a {
            buf.extend_from_slice(&self.s[a..b]);
            Ok(())
        } else if buf.len() >= a - b {
            Err(Err::BufferTooLarge)
        } else {
            Err(Err::Memory)
        }
    }

    fn substcap(&mut self, buf: &mut Vec<u8>) -> Result<(), Err> {
        let c = self.c();
        let mut curr = c.s;
        if c.siz != 0 {
            self.add(buf, curr, curr + usize::from(c.siz) - 1)?;
        } else {
            self.pos += 1;
            while self.c().kind != 0 {
                let next = self.c().s;
                self.add(buf, curr, next)?;
                curr = if self.addone(buf, "replacement")? > 0 {
                    let l = self.caps[self.pos - 1];
                    l.s + usize::from(l.siz) - 1
                } else {
                    next
                };
            }
            self.add(buf, curr, self.c().s)?;
        }
        self.pos += 1;
        Ok(())
    }

    fn addone(&mut self, buf: &mut Vec<u8>, what: &'static str) -> Result<usize, Err> {
        let k = self.c().kind;
        if k == CapKind::String as u8 {
            self.stringcap(buf)?;
            return Ok(1);
        }
        if k == CapKind::Subst as u8 {
            self.substcap(buf)?;
            return Ok(1);
        }
        let v = self.push()?;
        if let Some(first) = v.first() {
            match text(first) {
                Some(t) => buf.extend_from_slice(&t),
                None => return Err(Err::Invalid(what, type_name(first))),
            }
        }
        Ok(v.len())
    }
}

/// `getcaptures`.
fn evaluate(caps: &[Capture], s: &[u8], end: usize) -> Result<Vec<Val>, Err> {
    let mut e = Eval {
        caps,
        s,
        pos: 0,
        depth: 0,
    };
    let mut out = Vec::new();
    if caps[0].kind != 0 {
        loop {
            out.extend(e.push()?);
            if e.c().kind == 0 {
                break;
            }
        }
    }
    if out.is_empty() {
        out.push(Val::Int(end as i64 + 1));
    }
    Ok(out)
}

// ---------------------------------------------------------------- the port

fn port_value(c: &CapCursor, s: &[u8], v: CapVal) -> Val {
    match v {
        CapVal::Nil | CapVal::Buf | CapVal::Callee => Val::Nil,
        CapVal::Int(i) => Val::Int(i),
        CapVal::Str(a, b) => Val::Str(s[a..b].to_vec()),
        CapVal::Bytes(i) => Val::Str(c.string(i).to_vec()),
        CapVal::K(k) => Val::K(k),
        CapVal::Arg(n) => Val::Arg(n),
        CapVal::Table(t) => Val::Table(
            c.table(t)
                .into_iter()
                .map(|(k, v)| (k, port_value(c, s, v)))
                .collect(),
        ),
    }
}

fn port_error(e: CapError) -> Err {
    match e {
        CapError::BackrefNotFound(k) => Err::Backref(k),
        CapError::AbsentArgument(n) => Err::AbsentArg(n),
        CapError::NoCapture(n) => Err::NoCapture(n),
        CapError::InvalidCaptureIndex(n) => Err::BadIndex(n),
        CapError::NoValues(n) => Err::NoValues(n),
        CapError::InvalidValue { what, type_name } => Err::Invalid(what, type_name),
        CapError::BufferTooLarge => Err::BufferTooLarge,
        CapError::NotEnoughMemory => Err::Memory,
        e => panic!("evaluation failed: {e:?}"),
    }
}

/// Whether `p` holds a partial commit that `lpeg.c:1656` puts in a loop
/// coded with a test (`L1: test -> L2; <p>; jmp L1; L2:`, which pushes no
/// choice of its own): 0.12's `coderep` codes such a loop's body under the
/// `opt` it was given, so an optional `q + ''` in it (`codechoice`'s
/// `IPartialCommit; q`) or a loop in it coded for `opt` commits the frame of
/// the choice around the loop, and a `q` that fails there ends that choice
/// — the C's answer and the port's (`lpeg-coderep-opt-reaches-a-test-loop`),
/// where the PEG semantics the interpreter has go on looping. Such a
/// program is not compared with the interpreter. A loop is found as a jump
/// back to a test; a tail call to a rule that starts with one is taken for a
/// loop too, which only leaves more out.
fn commits_through_a_test_loop(p: &Program) -> bool {
    let insts = || {
        let mut i = 0;
        std::iter::from_fn(move || {
            let (op, _, _) = p.inst(i)?;
            let at = i;
            i += op.size();
            Some((at, op))
        })
    };
    let loops: Vec<(usize, usize)> = insts()
        .filter(|&(_, op)| op == Op::Jmp)
        .filter_map(|(i, _)| {
            let t = p.target(i)?;
            let test = matches!(
                p.inst(t),
                Some((Op::TestAny | Op::TestChar | Op::TestSet, _, _))
            );
            (t < i && test).then_some((t, i))
        })
        .collect();
    insts().any(|(i, op)| {
        op == Op::PartialCommit
            && p.target(i) == Some(i + op.size())
            && loops.iter().any(|&(a, b)| a < i && i < b)
    })
}

/// Compile, match and evaluate in slices of `slice`: `None` past the budget
/// or where the compiler refuses what the C refuses at compile time.
/// `quirk` is set where the program is one the interpreter cannot model
/// ([`commits_through_a_test_loop`]).
fn port(t: &Tree, s: &[u8], slice: u32, quirk: &mut bool) -> Option<Result<Option<Vec<Val>>, Err>> {
    let mut spent = 0u64;
    let mut c = Compiler::new();
    let program = loop {
        let mut b = slice;
        match c.step(t, &mut b) {
            Poll::Ready(Ok(p)) => break p,
            // The compile-time errors the C raises: `getfirst`'s recursion
            // on a left call through `B` (which never ends in the C:
            // `lpeg-getfirst-unbounded-recursion`) and `reallocprog`'s "not
            // enough memory". `finalfix`'s "used outside a grammar" was
            // ruled out before; anything else is a compiler defect.
            Poll::Ready(Err(CodeError::LeftRecursive(_) | CodeError::NotEnoughMemory)) => {
                return None
            }
            Poll::Ready(Err(e)) => panic!("the compiler failed: {e:?}"),
            Poll::Pending => {}
        }
        spent += u64::from(slice);
        if spent >= BUDGET {
            return None;
        }
    };
    *quirk = commits_through_a_test_loop(&program);
    let mut vm = Vm::new(0);
    let end = loop {
        let mut b = slice;
        match vm.run(&program, s, i32::MAX, &mut b) {
            Ok(VmPoll::RunTime(rt)) => panic!("a match-time capture in a pure run: {rt:?}"),
            Ok(VmPoll::Done(None)) => return Some(Ok(None)),
            Ok(VmPoll::Done(Some(e))) => break e,
            Ok(VmPoll::Pending) => {}
            Err(e) => panic!("the machine failed: {e:?}"),
        }
        spent += u64::from(slice);
        if spent >= BUDGET {
            return None;
        }
    };
    let caps = vm.take_captures();
    let mut cur = CapCursor::new(end, 0, PTOP);
    loop {
        let mut b = slice;
        let r = cur.step(&caps, s, &Env, &mut b);
        // What the cursor holds is counted as it changes, never walked when
        // asked (the step d review's F1): the count is what a walk finds.
        assert_eq!(
            cur.heap_bytes(),
            cur.heap_bytes_walked(),
            "the cursor's count"
        );
        match r {
            Ok(Some(())) => break,
            Ok(None) => {}
            Err(e) => return Some(Err(port_error(e))),
        }
        spent += u64::from(slice);
        if spent >= BUDGET {
            return None;
        }
    }
    Some(Ok(Some(
        cur.values()
            .iter()
            .map(|&v| port_value(&cur, s, v))
            .collect(),
    )))
}

// ---------------------------------------------------------------- the binding

/// The binding's run's fuel cap, in units: past it, not compared.
const LUA_FUEL: i32 = 300_000;
/// The binding's memory budget, past what the state holds before the chunk.
const LUA_BUDGET: usize = 16 << 20;

/// A state with the first-party stdlib and the test-only registration.
fn new_lua() -> Lua {
    let mut lua = Lua::core();
    lua.enter(|ctx| {
        load_patterns(ctx).expect("string table");
        load_strpack(ctx).expect("string table");
        load_format(ctx).expect("string table");
        load_tail(ctx).expect("string and coroutine tables");
        ctx.set_global("lpeg", register_for_tests(ctx, None));
    });
    lua
}

/// Run `src` in `lua`, after a full collection, in slices of `slice` fuel
/// (a full collection every 64th), with [`LUA_BUDGET`] more than the state
/// holds, at most [`LUA_FUEL`] in all: what it returned, or raised; `None`
/// past the cap.
fn run_lua(lua: &mut Lua, src: &str, slice: i32) -> Option<String> {
    lua.set_memory_limit(usize::MAX);
    lua.gc_collect();
    let ex = lua.enter(|ctx| {
        let c = Closure::load(ctx, Some("=fuzz"), src.as_bytes()).expect("the chunk compiles");
        ctx.stash(Executor::start(ctx, c.into(), ()))
    });
    lua.set_memory_limit(lua.total_memory() + LUA_BUDGET);
    let (mut used, mut slices) = (0i64, 0u64);
    let per = BYTES_PER_FUEL as u64;
    let _ = take_work();
    loop {
        let mut fuel = Fuel::with(slice);
        let done = lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .expect("steps");
        let this = i64::from(slice) - i64::from(fuel.remaining());
        used += this;
        slices += 1;
        // LPeg's work in the slice (`take_work`: a step `BYTES_PER_FUEL`
        // bytes, every byte copied, hashed, compared, moved or filled one),
        // within what its fuel pays for, four times over, and a few units'
        // slack: what a match does after each call it makes — its
        // bookkeeping included — must be paid for.
        let work = take_work();
        let fuel_used = this.max(1) as u64;
        assert!(
            work <= 4 * per * fuel_used + 8 * per,
            "slice {slices} did {work} bytes' work on {fuel_used} units of fuel:\n{src}"
        );
        if done {
            break;
        }
        if slices % 64 == 0 {
            lua.gc_collect();
        }
        if used > i64::from(LUA_FUEL) {
            return None;
        }
    }
    Some(lua.enter(|ctx| {
        match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
            Ok(Ok(vs)) => {
                vs.0.iter()
                    .map(|&v| ser(v, 0))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
            Ok(Err(e)) => format!("raised: {e:#}"),
            Err(e) => format!("result: {e}"),
        }
    }))
}

/// A value as the comparison sees it: a string by its length and bytes, a
/// table by its pairs in the order of their keys so rendered, four deep.
/// Done here, not in the chunk, so the fuel cap bounds the matching only.
fn ser(v: Value, d: u32) -> String {
    match v {
        Value::String(s) => format!("{}:{}", s.len(), String::from_utf8_lossy(s.as_bytes())),
        Value::Table(t) if d < 4 => {
            let mut kv: Vec<(String, String)> = t
                .iter()
                .map(|(k, v)| (ser(k, d + 1), ser(v, d + 1)))
                .collect();
            kv.sort();
            let parts: Vec<String> = kv.into_iter().map(|(k, v)| format!("[{k}]={v}")).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Table(_) => "{...}".to_string(),
        Value::UserData(_) => "<userdata>".to_string(),
        Value::Function(_) => "<function>".to_string(),
        Value::Thread(_) => "<thread>".to_string(),
        v => v.display().to_string(),
    }
}

/// The chunk that builds `expr` and matches it against `subject`, repeated
/// `times`, from `init`, with two extra arguments, under `setmaxstack(max)`;
/// it returns what `pcall` of the match returns (or "build" and the error
/// building it raised).
fn chunk(expr: &str, subject: &[u8], times: usize, init: i64, max: u32) -> String {
    format!(
        r#"local L = lpeg
local P, S, V, B, C, Cc, Cp, Carg, Cb, Cg, Ct, Cs, Cmt, Cf =
  L.P, L.S, L.V, L.B, L.C, L.Cc, L.Cp, L.Carg, L.Cb, L.Cg, L.Ct, L.Cs, L.Cmt, L.Cf
-- A value as text, the same in every run (a table's `tostring` is its
-- address).
local function show(v)
  if type(v) == 'table' then return '{{' .. #v .. '}}' end
  return tostring(v)
end
local MANY = {{}} for i = 1, 300 do MANY[i] = i end
local PAT
-- The pattern's `__gc`, called from a callback (inert: it frees nothing).
local function gc() if PAT then getmetatable(PAT).__gc(PAT) end end
local F = {{
  function(s, i) return false end,
  function(s, i) return true end,
  function(s, i) return i end,
  function(s, i) return i + 1 end,
  function(s, i) return i - 1 end,
  function(s, i, ...) return true, ... end,
  function(s, i, ...) return i, select('#', ...), ... end,
  function() error({{ code = 1 }}) end,
  function(s, i) return true, L.match(C(1)^0, s, i) end,
  function(s, i) L.setmaxstack(150) return true end,
  function(s, i) return 3.5 end,
  function(s, i, a) return ' ' .. i .. ' ', a end,
  function(s, i) collectgarbage() return true end,
  function(s, i) gc() collectgarbage() return i end,
  function(s, i, ...) return coroutine.yield(i, ...) end,
  function(s, i) return true, table.unpack(MANY) end,
}}
local G = {{
  function(...) return ... end,
  function(...) return select('#', ...) end,
  function() end,
  function(a) return {{ a }} end,
  function() error('G', 0) end,
  function(a) return L.match(C(1), show(a)) end,
  function() return table.unpack(MANY) end,
  function(...) collectgarbage() return ... end,
  function(...) gc() return select('#', ...), ... end,
  function(...) return coroutine.yield(...) end,
}}
local H = {{
  function(a, b) return show(a) .. show(b) end,
  function(a, ...) return select('#', ...) end,
  function(a) return nil end,
  function(a, b) return coroutine.yield(show(a) .. show(b)) end,
  function(a, ...) gc() collectgarbage() return select('#', ...) end,
}}
local T = {{
  {{ a = 'A', b = false }},
  setmetatable({{}}, {{ __index = function(t, k) return type(k) end }}),
  setmetatable({{}}, {{ __index = {{ c = 'C' }} }}),
  setmetatable({{}}, {{ __index = function(t, k) return coroutine.yield(k) end }}),
}}
L.setmaxstack({max})
local ok, p = pcall(function() return {expr} end)
if not ok then return "build", p end
PAT = p
-- The match in a coroutine, resumed with what it yields until it ends: a
-- callback that yields returns what it yielded.
local co = coroutine.create(function()
  return pcall(L.match, p, ("{subject}"):rep({times}), {init}, "x", 2.5)
end)
local r, yields = table.pack(coroutine.resume(co)), 0
while coroutine.status(co) == "suspended" do
  yields = yields + 1
  r = table.pack(coroutine.resume(co, table.unpack(r, 2, r.n)))
end
if not r[1] then return "resume", r[2] end
return yields, table.unpack(r, 2, r.n)
"#,
        subject = String::from_utf8_lossy(subject),
    )
}

/// The same chunk in one slice and in slices of `slice`, one after the
/// other in one state (each chunk sets the backtrack ceiling it uses): the
/// same answer, or "not enough memory" on either side; never the binding's
/// own defects.
fn binding(src: &str, slice: i32) {
    let mut lua = new_lua();
    let Some(whole) = run_lua(&mut lua, src, LUA_FUEL) else {
        return;
    };
    let internal = |s: &str| s.contains("lpeg: ");
    assert!(!internal(&whole), "the binding failed:\n{src}\n{whole}");
    let Some(sliced) = run_lua(&mut lua, src, slice) else {
        return;
    };
    assert!(!internal(&sliced), "the binding failed:\n{src}\n{sliced}");
    let nem = |s: &str| s.contains("not enough memory");
    let cut = |s: &str| s.chars().take(2_000).collect::<String>();
    assert!(
        whole == sliced || nem(&whole) || nem(&sliced),
        "the answer depends on the fuel slice:\n{src}\n  whole: {}\n sliced: {}",
        cut(&whole),
        cut(&sliced)
    );
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input {
        data,
        at: 0,
        lua: data.first().is_some_and(|&b| b >= 224),
        calls: false,
    };
    let first = inp.byte();
    let slice = 1 + u32::from(first % 64);
    let (t, lua) = pattern(&mut inp, 5, 0);
    let rest = data.get(inp.at.min(data.len())..).unwrap_or(&[]);
    let subject: Vec<u8> = rest
        .iter()
        .take(48)
        .map(|b| b"abc"[usize::from(b % 3)])
        .collect();
    if first >= 224 {
        // The subject repeated, `init` and the ceiling from what is at hand.
        let sum: usize = rest.iter().take(4).map(|&b| usize::from(b)).sum();
        let init = i64::from(first % 7) - 3;
        let max = if first & 16 != 0 { 150 } else { 100 };
        let src = chunk(&lua, &subject, 1 + sum % 64, init, max);
        binding(&src, i32::try_from(64 * slice).unwrap_or(4096));
    }
    if inp.calls {
        // The pure side has no Lua to call: the binding was the check.
        return;
    }
    let mut fixed = t.clone();
    let mut w = FinalFix::new(None, 0);
    if drive(u32::MAX, |b| w.step(&mut fixed, &|_| 0, b)).is_err() {
        return;
    }
    let mut quirk = false;
    let whole = port(&fixed, &subject, BUDGET as u32, &mut quirk);
    let sliced = port(&fixed, &subject, slice, &mut false);
    if let (Some(a), Some(b)) = (&whole, &sliced) {
        assert_eq!(a, b, "a slice boundary changed the answer");
    }
    let Some(got) = whole else { return };
    if quirk {
        return;
    }
    let mut interp = Interp {
        t: &fixed,
        s: &subject,
        caps: Vec::new(),
        steps: 0,
        facts: vec![None; fixed.len()],
    };
    let Ok(r) = interp.m(0, 0, 0) else { return };
    let want = match r {
        None => Ok(None),
        Some(end) => {
            let mut caps = interp.caps;
            caps.push(Capture {
                s: end,
                idx: 0,
                kind: 0,
                siz: 1,
            });
            evaluate(&caps, &subject, end).map(Some)
        }
    };
    assert_eq!(got, want, "the machine and the interpreter disagree");
});
