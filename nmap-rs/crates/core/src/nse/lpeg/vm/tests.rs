//! The matching machine and capture evaluation, pure: slicing invariance on
//! random patterns, the backtrack ceilings of D2, the Lua-stack ceiling on
//! captures, and pre-emption where the C's time is exponential. Patterns
//! from Lua, against the C, are `tests/lpeg_match_*.rs` and the corpus.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code over small trees"
)]

use std::borrow::Cow;

use super::capture::{
    CallKind, CapCursor, CapEnv, CapError, CapVal, Step, TableKey, View, LUAI_MAXSTACK,
};
use super::*;
use crate::nse::lpeg::code::{Compiler, Program};
use crate::nse::lpeg::testkit::*;
use crate::nse::lpeg::tree::{CapKind, Key, Tag, Tree};

/// Constants and arguments: the string `"a"` at key 1, `"k"` at 2, the
/// number 7 at 3, a table at 4; arguments `"x"` and 2.5.
struct Env;

impl CapEnv for Env {
    fn constant(&self, k: Key) -> View<'_> {
        match k {
            1 => View::Str(Cow::Borrowed(b"a")),
            2 => View::Str(Cow::Borrowed(b"k")),
            3 => View::Num(Cow::Borrowed(b"7")),
            4 => View::Other("table"),
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

/// A value as the binding would make it, for comparing.
#[derive(Debug, Clone, PartialEq)]
enum Out {
    Nil,
    Int(i64),
    Str(Vec<u8>),
    K(Key),
    Arg(u32),
    Table(Vec<(TableKey, Out)>),
}

fn out(c: &CapCursor, subj: &[u8], v: CapVal) -> Out {
    match v {
        CapVal::Nil | CapVal::Buf | CapVal::Callee => Out::Nil,
        CapVal::Int(i) => Out::Int(i),
        CapVal::Str(a, b) => Out::Str(subj[a..b].to_vec()),
        CapVal::Bytes(i) => Out::Str(c.string(i).to_vec()),
        CapVal::K(k) => Out::K(k),
        CapVal::Arg(n) => Out::Arg(n),
        CapVal::Table(t) => Out::Table(
            c.table(t)
                .iter()
                .map(|&(k, v)| (k, out(c, subj, v)))
                .collect(),
        ),
    }
}

fn compile(t: &Tree) -> Program {
    let mut c = Compiler::new();
    drive(1_000, |b| c.step(t, b)).expect("compiles")
}

/// Run `p` on `subj` in slices of `slice`; the outcome and the capture
/// list.
fn run(
    p: &Program,
    subj: &[u8],
    maxstack: MaxStack,
    slice: u32,
) -> (Result<Option<usize>, VmError>, Vec<Capture>, u64) {
    let mut vm = Vm::new(0);
    let mut slices = 0u64;
    let r = loop {
        let mut b = slice;
        slices += 1;
        assert!(
            slices < 50_000_000 / u64::from(slice.min(1_000_000)) + 10,
            "the match runs on: {:?}",
            p.dump()
        );
        match vm.run(p, subj, maxstack, &mut b) {
            Ok(VmPoll::Pending) => {}
            Ok(VmPoll::Done(d)) => break Ok(d),
            Ok(VmPoll::RunTime(rt)) => panic!("a match-time capture in a pure run: {rt:?}"),
            Err(e) => break Err(e),
        }
    };
    (r, vm.take_captures(), slices)
}

/// Evaluate a capture list in slices of `slice`.
fn evaluate(
    caps: &[Capture],
    subj: &[u8],
    end: usize,
    u0: usize,
    ptop: usize,
    slice: u32,
) -> (Result<Vec<Out>, CapError>, u64) {
    let mut c = CapCursor::new(end, u0, ptop);
    let mut slices = 0u64;
    loop {
        let mut b = slice;
        slices += 1;
        match c.step(caps, subj, &Env, &mut b) {
            Ok(None) => {}
            Ok(Some(())) => {
                let vs = c.values().iter().map(|&v| out(&c, subj, v)).collect();
                return (Ok(vs), slices);
            }
            Err(e) => return (Err(e), slices),
        }
    }
}

/// A match and its values, whole.
fn matched(t: &Tree, subj: &[u8]) -> Result<Option<Vec<Out>>, String> {
    let p = compile(&fix(t).unwrap());
    let (r, caps, _) = run(&p, subj, 100, u32::MAX);
    match r {
        Ok(Some(end)) => evaluate(&caps, subj, end, 0, 5, u32::MAX)
            .0
            .map(Some)
            .map_err(|e| format!("{e:?}")),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Neither the machine nor capture evaluation depends on where its slices
/// fall: the same outcome, capture list and values in slices of one to
/// seven units as in one.
#[test]
fn matching_does_not_depend_on_the_slicing() {
    let mut r = Rng(0x0123_4567_89ab_cdef);
    let rounds = if cfg!(miri) { 10 } else { 1_000 };
    let mut matched_some = 0usize;
    for round in 0..rounds {
        let t = random_fixed(&mut r);
        let mut c = Compiler::new();
        let Ok(p) = drive(1_000, |b| c.step(&t, b)) else {
            continue;
        };
        if p.calls_lua() {
            continue;
        }
        for _ in 0..4 {
            let n = r.below(6) as usize;
            let subj: Vec<u8> = (0..n).map(|_| b"abc"[r.below(3) as usize]).collect();
            let slice = 1 + (round % 7) as u32;
            let whole = run(&p, &subj, i32::MAX, u32::MAX);
            let sliced = run(&p, &subj, i32::MAX, slice);
            assert_eq!(whole.0, sliced.0);
            assert_eq!(whole.1, sliced.1);
            if let Ok(Some(end)) = whole.0 {
                matched_some += 1;
                let a = evaluate(&whole.1, &subj, end, 0, 5, u32::MAX).0;
                let b = evaluate(&whole.1, &subj, end, 0, 5, slice).0;
                assert_eq!(a, b);
            }
        }
    }
    assert!(
        matched_some > if cfg!(miri) { 2 } else { 500 },
        "{matched_some}"
    );
}

/// `S <- 'a' S 'b' / ''`: two entries a level (a choice and a call), so
/// with the default ceiling depth 49 matches and 50 raises.
fn nested_ab() -> Program {
    let s = choice(&seq(&seq(&lit(b"a"), &open_call(1)), &lit(b"b")), &lit(b""));
    compile(&grammar(&[s]).unwrap())
}

fn ab(n: usize) -> Vec<u8> {
    let mut v = vec![b'a'; n];
    v.extend(std::iter::repeat_n(b'b', n));
    v
}

/// D2: the C's backtrack ceilings, exactly — the default, `INITBACK` as the
/// floor, and growth to the stored maximum.
#[test]
fn the_backtrack_ceilings_are_the_cs() {
    let p = nested_ab();
    let at = |n: usize, max: MaxStack| run(&p, &ab(n), max, u32::MAX).0;
    assert_eq!(at(49, 100), Ok(Some(98)));
    assert_eq!(at(50, 100), Err(VmError::TooManyPending));
    assert_eq!(
        run(&p, &[b'a'; 50], 100, u32::MAX).0,
        Err(VmError::TooManyPending)
    );
    // A maximum below INITBACK, or negative (`setmaxstack(2^31)`), acts as
    // INITBACK: it is read only when the first 100 entries are full.
    for max in [5, 0, -1, i32::MIN] {
        assert_eq!(at(49, max), Ok(Some(98)), "{max}");
        assert_eq!(at(50, max), Err(VmError::TooManyPending), "{max}");
    }
    assert_eq!(at(74, 150), Ok(Some(148)));
    assert_eq!(at(75, 150), Err(VmError::TooManyPending));
    if !cfg!(miri) {
        assert_eq!(at(499, 1000), Ok(Some(998)));
        assert_eq!(at(500, 1000), Err(VmError::TooManyPending));
    }
    // `S <- '(' S ')' / 'x'`: the alternatives are disjoint, so a test
    // guards them and a level takes one entry, the call.
    let s = choice(
        &seq(&seq(&lit(b"("), &open_call(1)), &lit(b")")),
        &lit(b"x"),
    );
    let p = compile(&grammar(&[s]).unwrap());
    let paren = |n: usize, max: MaxStack| {
        let mut v = vec![b'('; n];
        v.push(b'x');
        v.extend(std::iter::repeat_n(b')', n));
        run(&p, &v, max, u32::MAX).0
    };
    assert_eq!(paren(98, 100), Ok(Some(197)));
    assert_eq!(paren(99, 100), Err(VmError::TooManyPending));
    // One entry a level makes the growth exact: from 100 to 150, not 151.
    assert_eq!(paren(148, 150), Ok(Some(297)));
    assert_eq!(paren(149, 150), Err(VmError::TooManyPending));
    // `S <- 'a' S / ''`: the call is a tail call, a jump: no entry at all.
    let s = choice(&seq(&lit(b"a"), &open_call(1)), &lit(b""));
    let p = compile(&grammar(&[s]).unwrap());
    let n = if cfg!(miri) { 2_000 } else { 100_000 };
    let (r, _, _) = run(&p, &vec![b'a'; n], 100, u32::MAX);
    assert_eq!(r, Ok(Some(n)));
}

/// `S <- 'a' S 'b' / 'a' S 'c' / ''` on `aⁿd` takes time exponential in `n`
/// with a stack `n` deep: the machine returns between slices, and the
/// answer and the instruction count are those of one slice.
#[test]
fn an_exponential_match_is_pre_empted() {
    let s = choice(
        &seq(&seq(&lit(b"a"), &open_call(1)), &lit(b"b")),
        &choice(&seq(&seq(&lit(b"a"), &open_call(1)), &lit(b"c")), &lit(b"")),
    );
    let p = compile(&grammar(&[s]).unwrap());
    let n = if cfg!(miri) { 6 } else { 14 };
    let mut subj = vec![b'a'; n];
    subj.push(b'd');
    let (whole, _, one) = run(&p, &subj, i32::MAX, u32::MAX);
    let (sliced, _, slices) = run(&p, &subj, i32::MAX, 1_000);
    assert_eq!(whole, Ok(Some(0)));
    assert_eq!(sliced, whole);
    assert_eq!(one, 1);
    assert!(slices > if cfg!(miri) { 1 } else { 100 }, "{slices}");
}

/// `Cg(Cb'a' * Cb'a', 'a')` nested `k` deep over `Cg(C(1), 'a')`: each
/// reference evaluates the group before it again, `2^k` values with no Lua
/// call at all. Evaluation returns between slices.
#[test]
fn nested_back_references_are_pre_empted() {
    let k = if cfg!(miri) { 4 } else { 14 };
    let cb = Tree::empty_capture(CapKind::Backref, 1).unwrap();
    let mut g = Tree::capture(
        CapKind::Group,
        1,
        &Tree::capture(CapKind::Simple, 0, &Tree::number(1).unwrap()).unwrap(),
    )
    .unwrap();
    for _ in 0..k {
        let body = seq(
            &g,
            &Tree::capture(CapKind::Group, 1, &seq(&cb, &cb)).unwrap(),
        );
        g = body;
    }
    let t = seq(&g, &cb);
    let p = compile(&fix(&t).unwrap());
    let (r, caps, _) = run(&p, b"x", 100, u32::MAX);
    let end = r.unwrap().unwrap();
    let (whole, one) = evaluate(&caps, b"x", end, 0, 2, u32::MAX);
    // Slices small enough that even Miri's 16 values take several.
    let slice = if cfg!(miri) { 10 } else { 1_000 };
    let (sliced, slices) = evaluate(&caps, b"x", end, 0, 2, slice);
    let whole = whole.unwrap();
    assert_eq!(whole.len(), 1 << k);
    assert!(whole.iter().all(|v| *v == Out::Str(b"x".to_vec())));
    assert_eq!(sliced.unwrap(), whole);
    assert_eq!(one, 1);
    assert!(slices > if cfg!(miri) { 1 } else { 50 }, "{slices}");
}

/// `luaL_checkstack(L, 4, "too many captures")` at each `pushcapture`:
/// with `u0` slots in use below, `C(1)^0` gives at most
/// `LUAI_MAXSTACK - 3 - u0` values.
#[test]
fn the_capture_ceiling_is_luas() {
    let n = if cfg!(miri) { 50 } else { 5_000 };
    let t = star(
        &Tree::capture(CapKind::Simple, 0, &Tree::number(1).unwrap()).unwrap(),
        0,
    );
    let p = compile(&fix(&t).unwrap());
    let subj = vec![b'a'; n];
    let (r, caps, _) = run(&p, &subj, 100, u32::MAX);
    let end = r.unwrap().unwrap();
    let u0 = LUAI_MAXSTACK - 3 - n;
    let (ok, _) = evaluate(&caps, &subj, end, u0, 2, 997);
    assert_eq!(ok.unwrap().len(), n);
    let (err, _) = evaluate(&caps, &subj, end, u0 + 1, 2, 997);
    assert_eq!(err, Err(CapError::StackOverflow));
    // A table holds its values off the stack: no ceiling.
    let t = Tree::capture(CapKind::Table, 0, &t).unwrap();
    let p = compile(&fix(&t).unwrap());
    let (r, caps, _) = run(&p, &subj, 100, u32::MAX);
    let (ok, _) = evaluate(
        &caps,
        &subj,
        r.unwrap().unwrap(),
        LUAI_MAXSTACK - 10,
        2,
        997,
    );
    assert!(matches!(&ok.unwrap()[..], [Out::Table(t)] if t.len() == n));
}

/// What the cursor does with constants, arguments and strings, through the
/// paths `/string`, `Cs`, `Ct` and `/number` take.
#[test]
fn captures_evaluate_as_the_cs() {
    let a = || lit(b"a");
    let simple = |t: &Tree| Tree::capture(CapKind::Simple, 0, t).unwrap();
    // `Cc(nil)`: key 0 is nil, read from no table.
    let cc_nil = Tree::empty_capture(CapKind::Const, 0).unwrap();
    assert_eq!(matched(&cc_nil, b""), Ok(Some(vec![Out::Nil])));
    // `Carg(1) * Carg(2)` with two extra arguments; `Carg(3)` absent.
    let args = seq(
        &Tree::empty_capture(CapKind::Arg, 1).unwrap(),
        &Tree::empty_capture(CapKind::Arg, 2).unwrap(),
    );
    assert_eq!(
        matched(&args, b""),
        Ok(Some(vec![Out::Arg(1), Out::Arg(2)]))
    );
    let absent = Tree::empty_capture(CapKind::Arg, 3).unwrap();
    assert_eq!(matched(&absent, b""), Err("AbsentArgument(3)".into()));
    // `Cs(Carg(2))`: a number's text; `Cs(Cc(<table>))`: an error.
    let cs = |t: &Tree| Tree::capture(CapKind::Subst, 0, t).unwrap();
    assert_eq!(
        matched(&cs(&Tree::empty_capture(CapKind::Arg, 2).unwrap()), b""),
        Ok(Some(vec![Out::Str(b"2.5".to_vec())]))
    );
    assert_eq!(
        matched(&cs(&Tree::empty_capture(CapKind::Const, 4).unwrap()), b""),
        Err("InvalidValue { what: \"replacement\", type_name: \"table\" }".into())
    );
    // `C(C'a' * C'a') / 2`: the second of three values.
    let two = Tree::capture(CapKind::Num, 2, &simple(&seq(&simple(&a()), &simple(&a())))).unwrap();
    assert_eq!(
        matched(&two, b"aa"),
        Ok(Some(vec![Out::Str(b"a".to_vec())]))
    );
    // `Ct(Cg(C'a', 'k') * C'a')`: the group by name, the rest by position.
    let named = Tree::capture(CapKind::Group, 2, &simple(&a())).unwrap();
    let ct = Tree::capture(CapKind::Table, 0, &seq(&named, &simple(&a()))).unwrap();
    assert_eq!(
        matched(&ct, b"aa"),
        Ok(Some(vec![Out::Table(vec![
            (TableKey::K(2), Out::Str(b"a".to_vec())),
            (TableKey::Int(1), Out::Str(b"a".to_vec()))
        ])]))
    );
    // A failed match has no values; one with no captures, its end.
    assert_eq!(matched(&a(), b"b"), Ok(None));
    assert_eq!(matched(&a(), b"ab"), Ok(Some(vec![Out::Int(2)])));
}

/// `d` nested table captures over `P"a"`, built directly: through the
/// constructors each level copies the tree, as in the C.
fn nested_tables(d: usize) -> Tree {
    nested(d, Tag::Capture, CapKind::Table)
}

/// `d` nodes of `tag`, each over the next, over `P"a"`.
fn nested_one(d: usize, tag: Tag) -> Tree {
    nested(d, tag, CapKind::Close)
}

fn nested(d: usize, tag: Tag, cap: CapKind) -> Tree {
    use crate::nse::lpeg::tree::Node;
    let mut nodes = vec![
        Node {
            cap: cap as u8,
            ..Node::new(tag)
        };
        d
    ];
    nodes.push(Node {
        u: i32::from(b'a'),
        ..Node::new(Tag::Char)
    });
    Tree::from_nodes(nodes)
}

/// `d` grammars nested in one another's only rule, over `P"a"`, built
/// directly: `P{P{...P{'a'}...}}`.
fn nested_grammars(d: usize) -> Tree {
    use crate::nse::lpeg::tree::Node;
    let mut nodes = Vec::with_capacity(3 * d + 1);
    for j in 0..d {
        nodes.push(Node {
            u: 1,
            ..Node::new(Tag::Grammar)
        });
        nodes.push(Node {
            key: 1,
            u: i32::try_from(3 * (d - j - 1) + 2).unwrap(),
            ..Node::new(Tag::Rule)
        });
    }
    nodes.push(Node {
        u: i32::from(b'a'),
        ..Node::new(Tag::Char)
    });
    nodes.extend(std::iter::repeat_n(Node::new(Tag::True), d));
    Tree::from_nodes(nodes)
}

/// Ten times the depths at which the C's recursive code generator and
/// capture evaluator crash it (6,159 levels of `Ct`, 7,699 of `P{}`, 45,898
/// of `-`), compiled, matched and evaluated on a thread with a 256 KiB
/// stack: a walker that recursed would abort the process. (Miri: 300.)
#[test]
fn deep_patterns_compile_match_and_capture_without_recursion() {
    let scale = |n: usize| if cfg!(miri) { 300 } else { n };
    std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(move || {
            let d = scale(61_590);
            let p = compile(&nested_tables(d));
            let (r, caps, _) = run(&p, b"a", 100, 100_000);
            let end = r.unwrap().unwrap();
            let mut c = CapCursor::new(end, 0, 2);
            while c.step(&caps, b"a", &Env, &mut 100_000).unwrap().is_none() {}
            assert_eq!(c.values(), [CapVal::Table(0)]);
            assert_eq!(c.tables(), d);
            // The innermost `Ct(P"a")` is a full capture: an empty table.
            assert_eq!(c.table(u32::try_from(d - 1).unwrap()), []);
            assert_eq!(
                c.table(u32::try_from(d - 2).unwrap()),
                [(
                    TableKey::Int(1),
                    CapVal::Table(u32::try_from(d - 1).unwrap())
                )]
            );
            // A grammar's first call pushes an entry a level: past the
            // default ceiling, as in the C; within a raised one, a match.
            let d = scale(76_990);
            let p = compile(&nested_grammars(d));
            assert_eq!(run(&p, b"a", 100, 100_000).0, Err(VmError::TooManyPending));
            assert_eq!(run(&p, b"a", i32::MAX, 100_000).0, Ok(Some(1)));
            // `-(-(...(-'a')))`, an even number of them: a choice a level.
            let p = compile(&nested_one(scale(458_980), Tag::Not));
            assert_eq!(run(&p, b"a", 100, 100_000).0, Err(VmError::TooManyPending));
            assert_eq!(run(&p, b"a", i32::MAX, 100_000).0, Ok(Some(0)));
            // `P'a'^-n`, through the constructor (linear in `n`).
            let p = compile(&star(&lit(b"a"), -i32::try_from(scale(200_000)).unwrap()));
            assert_eq!(run(&p, b"aaa", 100, 100_000).0, Ok(Some(3)));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Group names whose comparison costs bytes (equal hashes, two strings):
/// `Cb`'s scan charges a unit per `BYTES_PER_FUEL` bytes compared, what the
/// budget cannot pay past it (`CapCursor::take_over`), all at once.
#[test]
fn a_name_compared_byte_by_byte_is_charged() {
    struct Costly;
    impl CapEnv for Costly {
        fn constant(&self, k: Key) -> View<'_> {
            Env.constant(k)
        }
        fn argument(&self, n: u32) -> View<'_> {
            Env.argument(n)
        }
        fn same_constant(&self, a: Key, b: Key) -> (bool, usize) {
            (a != 0 && a == b, 1 << 20)
        }
    }
    // `Cg(C(1), 'a') * Cb'a'`: the reference scans back to the group.
    let g = Tree::capture(
        CapKind::Group,
        1,
        &Tree::capture(CapKind::Simple, 0, &Tree::number(1).unwrap()).unwrap(),
    )
    .unwrap();
    let t = seq(&g, &Tree::empty_capture(CapKind::Backref, 1).unwrap());
    let p = compile(&fix(&t).unwrap());
    let (r, caps, _) = run(&p, b"x", 100, u32::MAX);
    let end = r.unwrap().unwrap();
    let mut c = CapCursor::new(end, 0, 2);
    let (mut spent, mut over) = (0u64, 0u64);
    loop {
        let mut b = 1_000u32;
        let done = c.step(&caps, b"x", &Costly, &mut b).unwrap();
        spent += u64::from(1_000 - b);
        over += c.take_over();
        if done.is_some() {
            break;
        }
    }
    let per = crate::nse::lpeg::BYTES_PER_FUEL as u64;
    assert!(
        spent + over >= (1 << 20) / per,
        "{spent} units and {over} past the budget for a 1 MiB comparison"
    );
}

// ---------------------------------------------------------------- step d

/// A Lua value, as a mock binding hands the cursor one: the cursor holds
/// its values without looking at them, but for their text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mv {
    Nil,
    True,
    Int(i64),
    /// A string, by its index in [`Mock::texts`].
    Text(u32),
}

/// A binding for the cursor's and the machine's calls, the C's rules
/// written out over [`Mv`]s (the real one is `lpeg::MatchJob`, through the
/// VM): constants as [`Env`] has them, and the window of dynamic values.
#[derive(Default)]
struct Mock {
    texts: Vec<Vec<u8>>,
    window: Vec<Mv>,
    /// Each call made, in order: its key and how many arguments it took.
    calls: Vec<(Key, usize)>,
}

impl CapEnv<Mv> for Mock {
    fn constant(&self, k: Key) -> View<'_> {
        Env.constant(k)
    }
    fn argument(&self, n: u32) -> View<'_> {
        Env.argument(n)
    }
    fn same_constant(&self, a: Key, b: Key) -> (bool, usize) {
        Env.same_constant(a, b)
    }
    fn dynamic(&self, i: Key) -> Option<Mv> {
        self.window.get(i as usize).copied()
    }
    fn value(&self, v: Mv) -> View<'_> {
        match v {
            Mv::Nil => View::Nil,
            Mv::True => View::Other("boolean"),
            Mv::Int(i) => View::Num(Cow::Owned(i.to_string().into_bytes())),
            Mv::Text(t) => View::Str(Cow::Borrowed(&self.texts[t as usize])),
        }
    }
}

/// The match-time functions (keys 10-13), function captures (20-21), fold
/// functions (30) and query tables (40) of the mock.
const CMT_TRUE: Key = 10;
const CMT_VALUE: Key = 11;
const CMT_FALSE: Key = 12;
const CMT_COUNT: Key = 13;
const F_REVERSE: Key = 20;
const F_NONE: Key = 21;
const FOLD_ADD: Key = 30;
const QUERY_ID: Key = 40;

impl Mock {
    fn text(&mut self, b: &[u8]) -> Mv {
        self.texts.push(b.to_vec());
        Mv::Text(self.texts.len() as u32 - 1)
    }

    /// A capture value as the binding makes it a Lua value.
    fn lua(&mut self, c: &CapCursor<Mv>, subj: &[u8], v: CapVal<Mv>) -> Mv {
        match v {
            CapVal::Int(i) => Mv::Int(i),
            CapVal::Str(a, b) => self.text(&subj[a..b]),
            CapVal::Bytes(i) => self.text(c.string(i)),
            CapVal::K(k) => match Env.constant(k) {
                View::Str(s) => self.text(&s),
                View::Num(_) => Mv::Int(7),
                _ => Mv::True,
            },
            CapVal::Lua(m) => m,
            // A table, by its number (the real binding makes it).
            CapVal::Table(t) => Mv::Int(-1 - i64::from(t)),
            CapVal::Nil | CapVal::Arg(_) | CapVal::Buf | CapVal::Callee => Mv::Nil,
        }
    }

    /// The function or table at `key`, called with `args`.
    fn call(&mut self, key: Key, args: &[Mv]) -> Vec<Mv> {
        self.calls.push((key, args.len()));
        match key {
            CMT_TRUE => vec![Mv::True],
            // `i, "v"`: the position (the second argument) and a value.
            CMT_VALUE => {
                let v = self.text(b"v");
                vec![args[1], v]
            }
            CMT_FALSE => vec![],
            CMT_COUNT => vec![Mv::True, Mv::Int(args.len() as i64 - 2)],
            F_REVERSE => args.iter().rev().copied().collect(),
            F_NONE => vec![],
            FOLD_ADD => {
                let n = args
                    .iter()
                    .map(|a| if let Mv::Int(i) = a { *i } else { 1 })
                    .sum();
                vec![Mv::Int(n)]
            }
            QUERY_ID => args
                .iter()
                .take(1)
                .copied()
                .filter(|a| *a != Mv::Nil)
                .collect(),
            _ => vec![Mv::Nil],
        }
    }

    /// Evaluate with `c` to its end, in slices of `slice`, making the calls
    /// it asks for.
    fn evaluate(
        &mut self,
        c: &mut CapCursor<Mv>,
        caps: &[Capture],
        subj: &[u8],
        slice: u32,
    ) -> Result<(), CapError> {
        loop {
            let mut b = slice;
            match c.run_step(caps, subj, &*self, &mut b)? {
                Step::Done => return Ok(()),
                Step::Pending => {}
                Step::Call(req) => {
                    let vals: Vec<CapVal<Mv>> = c.values()[req.args..].to_vec();
                    let args: Vec<Mv> = vals.into_iter().map(|v| self.lua(c, subj, v)).collect();
                    let mut r = self.call(req.key, &args);
                    // What each capture keeps of the results.
                    match req.kind {
                        CallKind::Function => {}
                        CallKind::Fold => r.resize(1, Mv::Nil),
                        CallKind::Query => r.truncate(1),
                    }
                    c.returned(&r)?;
                }
            }
        }
    }

    /// Match `p` on `subj` in slices of `slice`, a match-time capture's
    /// function called as `runtimecap` calls it and its results decoded as
    /// `resdyncaptures` decodes them; the outcome, and the window's size at
    /// the end.
    fn run(
        &mut self,
        p: &Program,
        subj: &[u8],
        slice: u32,
    ) -> (Result<Option<Vec<Mv>>, String>, usize) {
        let mut vm = Vm::new(0);
        let err = |e: &dyn std::fmt::Debug| format!("{e:?}");
        let end = loop {
            let mut b = slice;
            let r = vm.run(p, subj, i32::MAX, &mut b);
            self.window.truncate(vm.dyn_top());
            match r {
                Ok(VmPoll::Pending) => {}
                Ok(VmPoll::Done(None)) => return (Ok(None), self.window.len()),
                Ok(VmPoll::Done(Some(end))) => break end,
                Ok(VmPoll::RunTime(rt)) => {
                    let mut c = CapCursor::<Mv>::nested_at(rt.open, 0, 5);
                    if let Err(e) = self.evaluate(&mut c, vm.captures(), subj, slice) {
                        return (Err(err(&e)), self.window.len());
                    }
                    let mut args = vec![Mv::Nil, Mv::Int(rt.s as i64 + 1)];
                    for &v in c.values() {
                        let m = self.lua(&c, subj, v);
                        args.push(m);
                    }
                    let res = self.call(rt.key, &args);
                    let fr = rt.first_dyn.unwrap_or(self.window.len());
                    self.window.truncate(fr);
                    let mut b = u32::MAX;
                    match res.first() {
                        None | Some(Mv::Nil) => vm.runtime_failed(fr).unwrap(),
                        Some(&first) => {
                            let s = match first {
                                Mv::True => rt.s,
                                Mv::Int(i) if i > rt.s as i64 && i - 1 <= subj.len() as i64 => {
                                    (i - 1) as usize
                                }
                                _ => {
                                    return (Err("invalid position".to_string()), self.window.len())
                                }
                            };
                            self.window.extend_from_slice(&res[1..]);
                            vm.runtime_kept(s, fr, res.len() - 1, &mut b).unwrap();
                        }
                    }
                }
                Err(e) => return (Err(err(&e)), self.window.len()),
            }
        };
        let caps = vm.take_captures();
        let mut c = CapCursor::<Mv>::with_values(end, 0, 5);
        if let Err(e) = self.evaluate(&mut c, &caps, subj, slice) {
            return (Err(err(&e)), self.window.len());
        }
        let vals: Vec<CapVal<Mv>> = c.values().to_vec();
        let out = vals.into_iter().map(|v| self.lua(&c, subj, v)).collect();
        (Ok(Some(out)), self.window.len())
    }

    /// A value's text, for comparing.
    fn show(&self, v: Mv) -> String {
        match v {
            Mv::Text(t) => String::from_utf8_lossy(&self.texts[t as usize]).into_owned(),
            v => format!("{v:?}"),
        }
    }
}

fn cmt(body: &Tree, key: Key) -> Tree {
    let mut t = Tree::root1(Tag::RunTime, body).unwrap();
    t.set_key(0, key);
    t
}

/// Run `t` through the mock, whole: its values as text, and the window.
fn mock_matched(t: &Tree, subj: &[u8]) -> (Result<Option<Vec<String>>, String>, usize, Mock) {
    let p = compile(&fix(t).unwrap());
    let mut m = Mock::default();
    let (r, w) = m.run(&p, subj, u32::MAX);
    let r = r.map(|o| o.map(|vs| vs.into_iter().map(|v| m.show(v)).collect()));
    (r, w, m)
}

/// S08, white-box: a failure drops the dynamic values of the match-time
/// captures it drops, and every one above them (`removedyncap`), so the
/// window holds only the values of the captures that stand; an
/// and-predicate's back-commit drops a capture's entries and keeps its
/// values, as orphans, where the C keeps them on its Lua stack
/// (`lpeg-and-predicate-keeps-dynamic-captures`).
#[test]
fn dynamic_values_go_with_their_captures_but_not_through_and_predicates() {
    let n = if cfg!(miri) { 5 } else { 200 };
    let subj = vec![b'a'; n];
    let simple = |t: &Tree| Tree::capture(CapKind::Simple, 0, t).unwrap();
    // `(Cmt(1, i, "v") * 'z' + C(1))^0`: each value goes on the failure.
    let t = star(
        &choice(
            &seq(&cmt(&Tree::number(1).unwrap(), CMT_VALUE), &lit(b"z")),
            &simple(&Tree::number(1).unwrap()),
        ),
        0,
    );
    let (r, window, m) = mock_matched(&t, &subj);
    assert_eq!(r, Ok(Some(vec!["a".to_string(); n])));
    assert_eq!(window, 0, "a backtrack kept dynamic values");
    assert_eq!(m.calls.len(), n);
    // `Cmt(1, i, "v")^0`: each kept, one value a capture.
    let t = star(&cmt(&Tree::number(1).unwrap(), CMT_VALUE), 0);
    let (r, window, _) = mock_matched(&t, &subj);
    assert_eq!(r, Ok(Some(vec!["v".to_string(); n])));
    assert_eq!(window, n);
    // `(#Cmt(1, i, "v") * 1)^0`: the entries go, the values stay.
    let t = star(
        &seq(
            &Tree::root1(Tag::And, &cmt(&Tree::number(1).unwrap(), CMT_VALUE)).unwrap(),
            &Tree::number(1).unwrap(),
        ),
        0,
    );
    let (r, window, _) = mock_matched(&t, &subj);
    assert_eq!(r, Ok(Some(vec![format!("Int({})", n + 1)])));
    assert_eq!(window, n, "an and-predicate dropped its orphans");
    // The same returning only `true`: nothing kept.
    let t = star(
        &seq(
            &Tree::root1(Tag::And, &cmt(&Tree::number(1).unwrap(), CMT_TRUE)).unwrap(),
            &Tree::number(1).unwrap(),
        ),
        0,
    );
    let (_, window, _) = mock_matched(&t, &subj);
    assert_eq!(window, 0);
    // A match-time capture over orphans: its call drops its body's values
    // and every one above them, orphans included (`runtimecap`).
    let body = seq(
        &cmt(&Tree::number(1).unwrap(), CMT_VALUE),
        &star(
            &seq(
                &Tree::root1(Tag::And, &cmt(&Tree::number(1).unwrap(), CMT_VALUE)).unwrap(),
                &Tree::number(1).unwrap(),
            ),
            0,
        ),
    );
    let (r, window, _) = mock_matched(&cmt(&body, CMT_COUNT), &subj);
    assert_eq!(r, Ok(Some(vec!["Int(1)".to_string()])));
    assert_eq!(window, 1, "the call kept what its body left");
}

/// The order and timing of the calls, as the C's (the brief's F01, F12,
/// F22, F28 and C05): a `/f` inside a match-time capture runs when the
/// capture closes, inner ones first; nested values before the capture's
/// own call; a fold's accumulator first, then each value's call.
#[test]
fn calls_come_in_the_cs_order() {
    let c1 = || Tree::capture(CapKind::Simple, 0, &Tree::number(1).unwrap()).unwrap();
    let f = |t: &Tree, k: Key| Tree::capture(CapKind::Function, k, t).unwrap();
    // F28: `Cmt((C(1)/f) * Cmt(C(1)/f, g), g)/f` on "xy": the inner
    // capture's `/f`, its function, the outer's `/f`, its function, the
    // match's.
    let t = f(
        &cmt(
            &seq(&f(&c1(), F_REVERSE), &cmt(&f(&c1(), F_REVERSE), CMT_COUNT)),
            CMT_COUNT,
        ),
        F_REVERSE,
    );
    let (r, _, m) = mock_matched(&t, b"xy");
    assert_eq!(r, Ok(Some(vec!["Int(2)".to_string()])));
    assert_eq!(
        m.calls,
        [
            (F_REVERSE, 1),
            (CMT_COUNT, 3),
            (F_REVERSE, 1),
            (CMT_COUNT, 4),
            (F_REVERSE, 1)
        ]
    );
    // A fold: `Cf(C(1) * C(1) * C(1), add)`: two calls, the accumulator and
    // a value each (the mock's add counts a string as 1: 1 + 1, then 2 + 1).
    let fold = Tree::capture(CapKind::Fold, FOLD_ADD, &seq(&c1(), &seq(&c1(), &c1()))).unwrap();
    let (r, _, m) = mock_matched(&fold, b"abc");
    assert_eq!(r, Ok(Some(vec!["Int(3)".to_string()])));
    assert_eq!(m.calls, [(FOLD_ADD, 2), (FOLD_ADD, 2)]);
    // No initial value: a fold of a capture with none.
    let fold = Tree::capture(CapKind::Fold, FOLD_ADD, &lit(b"a")).unwrap();
    assert_eq!(
        mock_matched(&fold, b"a").0,
        Err("NoInitialFold".to_string())
    );
    // A query keeps its first value; nil is none.
    let q = Tree::capture(CapKind::Query, QUERY_ID, &seq(&c1(), &c1())).unwrap();
    assert_eq!(mock_matched(&q, b"ab").0, Ok(Some(vec!["a".to_string()])));
    // A function capture returning nothing gives no value.
    let t = seq(&f(&c1(), F_NONE), &c1());
    assert_eq!(mock_matched(&t, b"ab").0, Ok(Some(vec!["b".to_string()])));
}

/// Calls do not depend on where the slices fall: random patterns holding
/// match-time captures, function captures, folds and queries, through the
/// mock, give the same values, window and calls in slices of one to seven
/// units as in one.
#[test]
fn calls_do_not_depend_on_the_slicing() {
    let mut r = Rng(0x5eed_d00d_0000_0001);
    let rounds = if cfg!(miri) { 6 } else { 600 };
    let mut called = 0usize;
    let keys = [CMT_TRUE, CMT_VALUE, CMT_FALSE, CMT_COUNT];
    for round in 0..rounds {
        let base = random_tree(&mut r, 4, 0);
        let k = r.below(4) as usize;
        let t = match r.below(4) {
            0 => cmt(&base, keys[k]),
            1 => Tree::capture(CapKind::Function, [F_REVERSE, F_NONE][k % 2], &base).unwrap(),
            2 => Tree::capture(CapKind::Fold, FOLD_ADD, &base).unwrap(),
            _ => seq(
                &cmt(&base, keys[k]),
                &star(&cmt(&Tree::number(1).unwrap(), CMT_VALUE), 0),
            ),
        };
        let Ok(fixed) = fix(&t) else { continue };
        let mut c = Compiler::new();
        let Ok(p) = drive(1_000, |b| c.step(&fixed, b)) else {
            continue;
        };
        for _ in 0..3 {
            let n = r.below(6) as usize;
            let subj: Vec<u8> = (0..n).map(|_| b"abc"[r.below(3) as usize]).collect();
            let slice = 1 + (round % 7) as u32;
            let mut a = Mock::default();
            let (ra, wa) = a.run(&p, &subj, u32::MAX);
            let mut b = Mock::default();
            let (rb, wb) = b.run(&p, &subj, slice);
            let show = |m: &Mock, r: Result<Option<Vec<Mv>>, String>| {
                r.map(|o| o.map(|vs| vs.into_iter().map(|v| m.show(v)).collect::<Vec<_>>()))
            };
            assert_eq!(show(&a, ra), show(&b, rb), "{:?}", p.dump());
            assert_eq!(wa, wb);
            assert_eq!(a.calls, b.calls);
            called += a.calls.len();
        }
    }
    assert!(called > if cfg!(miri) { 2 } else { 500 }, "{called}");
}
