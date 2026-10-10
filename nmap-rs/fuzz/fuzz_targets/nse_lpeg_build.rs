// cargo-fuzz target for LPeg pattern construction (M6.6 step b):
// `nmap_core::nse::lpeg::tree`, and the binding through the VM.
//
// A script builds patterns from constants, and an operator reaches the
// integers (`fingerprint-strings.n`); the C crashed on sizes past its `int`
// and recursed without bound on deep trees and on left recursion its
// verifier missed. The input is a small program over the constructors, with
// adversarial integers; byte 0 picks how it runs:
//
//   * PURE (even): a stack machine over the pure constructors and walkers,
//     inside a VM whose memory budget is 16 MiB, so a size the budget refuses
//     is an error. Checked: nothing panics or aborts; a refused size is
//     `NotEnoughMemory` or the C's "block too big"; every walker gives the
//     same answer run to the end at once and in slices of 1 to 16 steps (a
//     slice boundary is invisible); each answers as a recursive
//     transliteration of the C's walker does (`checkaux`, `fixedlenx`,
//     `checkloops`, and `verifygrammar` with the port's hidden pass); and
//     each finishes within a bound on its steps — the size of a walk that
//     follows no call, or else the steps the transliteration counted. Only
//     when the transliteration itself runs past `STEP_CAP` steps, or past its
//     recursion limit, is a walker not run: the work is then exponential (a
//     grammar's rules calling the next twice) or deep, legitimately, by an
//     independent count, and a walker that loops cannot hide behind the cap.
//   * VM (odd): the bytes become a Lua chunk over the `lpeg` functions and
//     operators — byte 0 of 1 mod 4: the operators, `B`, `^n`, `/n`,
//     `Carg`, `Cg`, `Ct`, `Cmt` and grammars, nested three deep (the first
//     seeds' language); 3 mod 4: nested five deep, with constants of 0 to 5
//     values, `S`/`R` of bytes from the input, the other captures, `locale`
//     and `ptree` too — run with the test-only registration
//     under a 16 MiB budget, twice, in slices of 1,000 fuel and of 10^7, and
//     the two outcomes must be the same (the type of each result, or the
//     error message). Near the budget whether a call fails can depend on the
//     slices (`lpeg-memory-errors-depend-on-slicing`): a "not enough memory"
//     on either side is compatible with any answer on the other.
#![no_main]

use std::task::Poll;

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::lpeg::tree::{
    CapKind, Charset, CheckAux, CheckLoops, FinalFix, FindOpenCall, FixedLen, GrammarLayout, Key,
    Pred, Tag, Tree, TreeError, VerifyGrammar, MAXRULES,
};
use nmap_core::nse::lpeg::{narrow, register_for_tests};
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use piccolo::{Closure, Executor, Fuel, Lua, Table, Value, Variadic};

/// The memory budget: a tree of more than about a million nodes is refused.
const LIMIT: usize = 16 << 20;
/// Trees larger than this are walked once, not also in slices.
const SLICED_MAX: usize = 50_000;
/// The most steps a transliteration may count for one walk before the walk
/// is judged too long to run (see the header).
const STEP_CAP: u64 = 2_000_000;

struct Input<'a> {
    data: &'a [u8],
    at: usize,
}

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn int(&mut self) -> Option<i64> {
        let sel = self.byte()?;
        let mut raw = [0u8; 8];
        for b in &mut raw {
            *b = self.byte().unwrap_or(0);
        }
        let raw = i64::from_le_bytes(raw);
        // Small ones mostly; the C's boundaries and anything at all too.
        Some(match sel % 8 {
            0..=3 => raw % 8,
            4 => (1i64 << 31) + raw % 4,
            5 => (1i64 << 32) + raw % 4,
            6 => -(1i64 << 31) + raw % 4,
            _ => raw,
        })
    }
}

// ---------------------------------------------------------------- the C, recursively

/// Node visits a transliteration may still make: each costs one, and `None`
/// is "past the cap" (or past the recursion limit).
struct Visits(u64);

impl Visits {
    fn visit(&mut self) -> Option<()> {
        self.0 = self.0.checked_sub(1)?;
        Some(())
    }
}

/// A walker's step bound: what a transliteration counted (`c`), with room
/// for the iterative walker's bookkeeping, or a walk with no call in it.
fn bound(t: &Tree, counted: Option<u64>) -> Option<u64> {
    let follows_calls = t.nodes().iter().any(|n| n.tag == Tag::Call);
    match counted {
        Some(c) => Some(c.saturating_mul(4).saturating_add(64)),
        None if !follows_calls => Some((t.len() as u64).saturating_mul(4).saturating_add(64)),
        None => None,
    }
}

fn checkaux_ref(t: &Tree, i: usize, nullable: bool, depth: u32, v: &mut Visits) -> Option<bool> {
    if depth > 200 {
        return None;
    }
    v.visit()?;
    let n = t.node(i)?;
    let d = depth + 1;
    Some(match n.tag {
        Tag::Char | Tag::Set | Tag::Any | Tag::False | Tag::OpenCall => false,
        Tag::Rep | Tag::True => true,
        Tag::Not | Tag::Behind => nullable,
        Tag::And => nullable || checkaux_ref(t, i + 1, nullable, d, v)?,
        Tag::RunTime => nullable && checkaux_ref(t, i + 1, nullable, d, v)?,
        Tag::Seq => {
            checkaux_ref(t, i + 1, nullable, d, v)? && checkaux_ref(t, t.sib2(i)?, nullable, d, v)?
        }
        Tag::Choice => {
            checkaux_ref(t, t.sib2(i)?, nullable, d, v)? || checkaux_ref(t, i + 1, nullable, d, v)?
        }
        Tag::Capture | Tag::Grammar | Tag::Rule => checkaux_ref(t, i + 1, nullable, d, v)?,
        Tag::Call => checkaux_ref(t, t.sib2(i)?, nullable, d, v)?,
    })
}

fn fixedlen_ref(
    t: &Tree,
    i: usize,
    count: usize,
    len: i64,
    depth: u32,
    v: &mut Visits,
) -> Option<i64> {
    if depth > 400 {
        return None;
    }
    v.visit()?;
    let n = t.node(i)?;
    let d = depth + 1;
    Some(match n.tag {
        // `len + 1` wraps past `INT_MAX` in the C, and is then -1.
        Tag::Char | Tag::Set | Tag::Any if len >= i64::from(i32::MAX) => -1,
        Tag::Char | Tag::Set | Tag::Any => len + 1,
        Tag::False | Tag::True | Tag::Not | Tag::And | Tag::Behind => len,
        Tag::Rep | Tag::RunTime | Tag::OpenCall => -1,
        Tag::Capture | Tag::Rule | Tag::Grammar => fixedlen_ref(t, i + 1, count, len, d, v)?,
        Tag::Call if count >= MAXRULES => -1,
        Tag::Call => fixedlen_ref(t, t.sib2(i)?, count + 1, len, d, v)?,
        Tag::Seq => {
            let l = fixedlen_ref(t, i + 1, count, len, d, v)?;
            if l < 0 {
                -1
            } else {
                fixedlen_ref(t, t.sib2(i)?, count, l, d, v)?
            }
        }
        Tag::Choice => {
            let n1 = fixedlen_ref(t, i + 1, count, len, d, v)?;
            if n1 < 0 {
                return Some(-1);
            }
            let n2 = fixedlen_ref(t, t.sib2(i)?, count, len, d, v)?;
            if n1 == n2 {
                n1
            } else {
                -1
            }
        }
    })
}

fn checkloops_ref(t: &Tree, i: usize, depth: u32, v: &mut Visits) -> Option<bool> {
    if depth > 200 {
        return None;
    }
    v.visit()?;
    let n = t.node(i)?;
    if n.tag == Tag::Rep && checkaux_ref(t, i + 1, true, 0, v)? {
        return Some(true);
    }
    if n.tag == Tag::Grammar {
        return Some(false);
    }
    Some(match n.tag.siblings() {
        1 => checkloops_ref(t, i + 1, depth + 1, v)?,
        2 => {
            checkloops_ref(t, i + 1, depth + 1, v)? || checkloops_ref(t, t.sib2(i)?, depth + 1, v)?
        }
        _ => false,
    })
}

/// `verifyrule` (`lpeg.c:3047`); `fixed`: the port's hidden pass, where a
/// sub-grammar in a nullable context is nullable. Its recursion limit is
/// well past a left-recursive path of `MAXRULES` rules (two levels each, a
/// call and a rule, and the nodes before the call), so that such a grammar
/// is answered, not skipped.
fn verifyrule_ref(
    t: &Tree,
    i: usize,
    passed: &mut Vec<Key>,
    npassed: usize,
    nullable: bool,
    fixed: bool,
    depth: u32,
    v: &mut Visits,
) -> Option<Result<bool, TreeError>> {
    if depth > 4_000 {
        return None;
    }
    v.visit()?;
    let n = t.node(i)?;
    let d = depth + 1;
    Some(Ok(match n.tag {
        Tag::Char | Tag::Set | Tag::Any | Tag::False => nullable,
        Tag::True | Tag::Behind => true,
        Tag::Not | Tag::And | Tag::Rep => {
            return verifyrule_ref(t, i + 1, passed, npassed, true, fixed, d, v)
        }
        Tag::Capture | Tag::RunTime => {
            return verifyrule_ref(t, i + 1, passed, npassed, nullable, fixed, d, v)
        }
        Tag::Call => return verifyrule_ref(t, t.sib2(i)?, passed, npassed, nullable, fixed, d, v),
        Tag::Seq => match verifyrule_ref(t, i + 1, passed, npassed, false, fixed, d, v)? {
            Err(e) => return Some(Err(e)),
            Ok(false) => nullable,
            Ok(true) => {
                return verifyrule_ref(t, t.sib2(i)?, passed, npassed, nullable, fixed, d, v)
            }
        },
        Tag::Choice => match verifyrule_ref(t, i + 1, passed, npassed, nullable, fixed, d, v)? {
            Err(e) => return Some(Err(e)),
            Ok(nb) => return verifyrule_ref(t, t.sib2(i)?, passed, npassed, nb, fixed, d, v),
        },
        Tag::Rule => {
            if npassed >= MAXRULES {
                passed.truncate(npassed);
                for a in (0..npassed).rev() {
                    for b in (0..a).rev() {
                        if passed[a] == passed[b] {
                            return Some(Err(TreeError::LeftRecursive(passed[a])));
                        }
                    }
                }
                return Some(Err(TreeError::TooManyLeftCalls));
            }
            passed.truncate(npassed);
            passed.push(n.key);
            return verifyrule_ref(t, i + 1, passed, npassed + 1, nullable, fixed, d, v);
        }
        Tag::Grammar => (fixed && nullable) || checkaux_ref(t, i, true, 0, v)?,
        Tag::OpenCall => return Some(Err(TreeError::Malformed)),
    }))
}

/// `verifygrammar` (`lpeg.c:3090`) of the grammar at 0, then the hidden pass
/// where the C's passes: the answer `VerifyGrammar` must give.
fn verifygrammar_ref(t: &Tree, v: &mut Visits) -> Option<Result<(), TreeError>> {
    let rules = |t: &Tree| {
        let mut out = Vec::new();
        let mut r = 1;
        while t.node(r)?.tag == Tag::Rule {
            out.push(r);
            r = t.sib2(r)?;
        }
        Some(out)
    };
    let rules = rules(t)?;
    let mut passed = Vec::new();
    for &r in &rules {
        if t.node(r)?.key != 0 {
            if let Err(e) = verifyrule_ref(t, r + 1, &mut passed, 0, false, false, 0, v)? {
                return Some(Err(e));
            }
        }
    }
    for &r in &rules {
        let key = t.node(r)?.key;
        if key != 0 && checkloops_ref(t, r + 1, 0, v)? {
            return Some(Err(TreeError::EmptyLoop(key)));
        }
    }
    if t.nodes()[1..].iter().any(|n| n.tag == Tag::Grammar) {
        for &r in &rules {
            if t.node(r)?.key != 0 {
                if let Err(e) = verifyrule_ref(t, r + 1, &mut passed, 0, false, true, 0, v)? {
                    return Some(Err(e));
                }
            }
        }
    }
    Some(Ok(()))
}

// ---------------------------------------------------------------- driving walkers

/// Run a walker to its answer, `slice` steps at a time; it must finish
/// within `cap` steps.
fn drive<T>(
    slice: u32,
    cap: u64,
    mut f: impl FnMut(&mut u32) -> Poll<Result<T, TreeError>>,
) -> Result<T, TreeError> {
    let mut left = cap;
    loop {
        let mut budget = slice.min(u32::try_from(left).unwrap_or(u32::MAX)).max(1);
        let asked = budget;
        let r = f(&mut budget);
        if let Poll::Ready(r) = r {
            return r;
        }
        assert_eq!(budget, 0, "pending with budget left");
        left = left
            .checked_sub(u64::from(asked))
            .filter(|&l| l > 0)
            .unwrap_or_else(|| panic!("a walker ran past {cap} steps, the bound its walk allows"));
    }
}

/// A walker's answer at once and in slices of `slice`, each within `cap`:
/// they must agree.
fn both<T: PartialEq + std::fmt::Debug>(
    slice: u32,
    cap: u64,
    mut make: impl FnMut() -> Box<dyn FnMut(&mut u32) -> Poll<Result<T, TreeError>>>,
) -> Result<T, TreeError> {
    let whole = drive(u32::MAX, cap, make());
    if slice != u32::MAX {
        let sliced = drive(slice, cap.saturating_mul(2), make());
        assert_eq!(whole, sliced, "a slice boundary changed the answer");
    }
    whole
}

fn check_walkers(t: &Tree, slice: u32) {
    let slice = if t.len() > SLICED_MAX {
        u32::MAX
    } else {
        slice
    };
    for pred in [Pred::Nullable, Pred::NoFail] {
        let mut v = Visits(STEP_CAP);
        let want = checkaux_ref(t, 0, pred == Pred::Nullable, 0, &mut v);
        let Some(cap) = bound(t, want.map(|_| STEP_CAP - v.0)) else {
            continue;
        };
        let got = both(slice, cap, || {
            let mut w = CheckAux::new(0, pred);
            let t = t.clone();
            Box::new(move |b| w.step(&t, b))
        });
        if let Some(want) = want {
            assert_eq!(got, Ok(want), "checkaux {pred:?}");
        }
    }
    let mut v = Visits(STEP_CAP);
    let want = fixedlen_ref(t, 0, 0, 0, 0, &mut v);
    if let Some(cap) = bound(t, want.map(|_| STEP_CAP - v.0)) {
        let got = both(slice, cap, || {
            let mut w = FixedLen::new(0);
            let t = t.clone();
            Box::new(move |b| w.step(&t, b))
        });
        if let Some(want) = want {
            assert_eq!(got, Ok(want), "fixedlen");
        }
    }
    let mut v = Visits(STEP_CAP);
    let want = checkloops_ref(t, 0, 0, &mut v);
    if let Some(cap) = bound(t, want.map(|_| STEP_CAP - v.0)) {
        let got = both(slice, cap.saturating_mul(2), || {
            let mut w = CheckLoops::new(0);
            let t = t.clone();
            Box::new(move |b| w.step(&t, b))
        });
        if let Some(want) = want {
            assert_eq!(got, Ok(want), "checkloops");
        }
    }
    // `ptree`'s scan for an open call, and `finalfix` outside a grammar:
    // neither follows a call; `finalfix`'s rotations move up to the whole
    // tree at each of its nodes.
    let n = t.len() as u64;
    let open = both(slice, n + 1, || {
        let mut w = FindOpenCall::new();
        let t = t.clone();
        Box::new(move |b| w.step(&t, b))
    });
    let first_open = t
        .nodes()
        .iter()
        .find(|n| n.tag == Tag::OpenCall)
        .map(|n| n.key);
    assert_eq!(open, Ok(first_open), "the scan for an open call");
    let fixed = both(
        slice,
        n.saturating_mul(n).saturating_add(n).saturating_add(64),
        || {
            let mut w = FinalFix::new(None, 0);
            let mut t = t.clone();
            Box::new(move |b| w.step(&mut t, &|_| 0, b))
        },
    );
    // Every open call is outside any grammar (a grammar closes its own), and
    // `finalfix` outside a grammar reaches them all: it fails exactly when
    // there is one.
    let has_open = t.nodes().iter().any(|n| n.tag == Tag::OpenCall);
    if fixed != Err(TreeError::NotEnoughMemory) {
        assert_eq!(
            fixed.is_ok(),
            !has_open,
            "finalfix and the open calls disagree"
        );
        if let (Err(TreeError::UsedOutsideGrammar(k)), Some(o)) = (fixed, first_open) {
            assert_eq!(k, o, "finalfix and the scan name different open calls");
        }
    }
}

/// A grammar of the top `k` trees, open calls naming rules `1..=k` by key.
fn grammar(rules: &[Tree], slice: u32) -> Option<Result<Tree, TreeError>> {
    let sizes: Vec<usize> = rules.iter().map(Tree::len).collect();
    let layout = match GrammarLayout::new(&sizes) {
        Ok(l) => l,
        Err(e) => return Some(Err(e)),
    };
    let space = match layout.space() {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    let pairs: Vec<(&Tree, Key)> = rules.iter().map(|t| (t, 0)).collect();
    let g = match layout.build(&pairs, space) {
        Ok(g) => g,
        Err(e) => return Some(Err(e)),
    };
    let positions = layout.positions.clone();
    let resolve = move |k: Key| {
        positions
            .get((k as usize).wrapping_sub(1))
            .map_or(0, |&p| p as i64)
    };
    let n = g.len() as u64;
    let fixed = {
        let mut once = None;
        for s in [u32::MAX, slice] {
            let mut copy = g.clone();
            let mut w = FinalFix::new(Some(0), 1);
            let r = drive(
                s,
                n.saturating_mul(n).saturating_add(n).saturating_add(64),
                |b| w.step(&mut copy, &resolve, b),
            );
            match &once {
                None => once = Some((r, copy)),
                Some((r0, t0)) => {
                    assert_eq!(&r, r0, "finalfix depends on the slice");
                    if r.is_ok() {
                        assert_eq!(&copy, t0, "finalfix's tree depends on the slice");
                    }
                }
            }
        }
        once?
    };
    let (r, mut g) = fixed;
    if let Err(e) = r {
        return Some(Err(e));
    }
    if g.node(1)?.key == 0 {
        g.set_key(1, rules.len() as Key + 1);
    }
    // The C's verifier, then the hidden pass, transliterated: the answer,
    // and the steps the walk takes.
    let mut visits = Visits(STEP_CAP);
    let want = verifygrammar_ref(&g, &mut visits)?;
    let cap = (STEP_CAP - visits.0)
        .saturating_mul(4)
        .saturating_add(g.len() as u64 * 4)
        .saturating_add(64);
    let v = both(slice, cap, || {
        let mut w = VerifyGrammar::new(0);
        let g = g.clone();
        Box::new(move |b| w.step(&g, b))
    });
    assert_eq!(v, want, "the verifier and its transliteration disagree");
    Some(v.map(|()| g))
}

fn pure(input: &mut Input) -> Option<()> {
    let slice = u32::from(input.byte()? % 16) + 1;
    let mut stack: Vec<Tree> = Vec::new();
    let nem = |r: &Result<Tree, TreeError>| {
        if let Err(e) = r {
            assert!(
                matches!(e, TreeError::NotEnoughMemory | TreeError::BlockTooBig),
                "only size can refuse a constructor: {e:?}"
            );
        }
    };
    for _ in 0..48 {
        let op = input.byte()?;
        let r = match op % 16 {
            0 => {
                let n = usize::from(input.byte()? % 6);
                let s: Vec<u8> = (0..n).filter_map(|_| input.byte()).collect();
                Tree::literal(&s)
            }
            1 => Tree::number(narrow(input.int()?)),
            2 => Tree::leaf([Tag::True, Tag::False, Tag::Any][usize::from(input.byte()? % 3)]),
            3 => {
                let mut cs = Charset::empty();
                for _ in 0..input.byte()? % 4 {
                    cs.add(input.byte()?);
                }
                Tree::charset(&cs)
            }
            4 => {
                let mut v = Tree::leaf(Tag::OpenCall).ok()?;
                v.set_key(0, Key::from(input.byte()? % 5));
                Ok(v)
            }
            5 => Tree::runtime(Key::from(input.byte()? % 3)),
            6 => Tree::empty_capture(CapKind::Position, 0),
            7 | 8 => {
                let t = stack.pop()?;
                let tag = [Tag::Not, Tag::And][usize::from(op % 2)];
                if input.byte()? % 2 == 0 {
                    Tree::root1(tag, &t)
                } else {
                    Tree::capture(CapKind::Simple, 0, &t)
                }
            }
            9 | 10 => {
                let b = stack.pop()?;
                let a = stack.pop()?;
                let tag = if op % 2 == 0 { Tag::Seq } else { Tag::Choice };
                Tree::root2(tag, &a, &b, Key::from(input.byte()? % 3))
            }
            11 => {
                let b = stack.pop()?;
                let a = stack.pop()?;
                Tree::difference(&a, &b, 0)
            }
            12 => {
                let t = stack.pop()?;
                let n = narrow(input.int()?);
                match Tree::star_space(t.len(), n) {
                    Err(e) => Err(e),
                    Ok(space) => {
                        if n >= 0 {
                            let mut v = Visits(STEP_CAP);
                            let want = checkaux_ref(&t, 0, true, 0, &mut v);
                            // Too long a walk by the transliteration's count:
                            // the operation is skipped, not the input.
                            let Some(cap) = bound(&t, want.map(|_| STEP_CAP - v.0)) else {
                                continue;
                            };
                            let mut w = CheckAux::new(0, Pred::Nullable);
                            match drive(slice, cap, |b| w.step(&t, b)) {
                                Ok(true) => Err(TreeError::LoopBodyNullable),
                                _ => Tree::star(&t, n, space),
                            }
                        } else {
                            Tree::star(&t, n, space)
                        }
                    }
                }
            }
            13 => {
                let t = stack.pop()?;
                let mut v = Visits(STEP_CAP);
                let want = fixedlen_ref(&t, 0, 0, 0, 0, &mut v);
                let Some(cap) = bound(&t, want.map(|_| STEP_CAP - v.0)) else {
                    continue;
                };
                let mut w = FixedLen::new(0);
                match drive(slice, cap, |b| w.step(&t, b)) {
                    Ok(n) if n > 0 && n <= 255 && !t.has_captures() => Tree::behind(n as i32, &t),
                    _ => Ok(t),
                }
            }
            14 => {
                let k = usize::from(input.byte()? % 4) + 1;
                if stack.len() < k {
                    return Some(());
                }
                let rules = stack.split_off(stack.len() - k);
                let Some(built) = grammar(&rules, slice) else {
                    continue;
                };
                match built {
                    Ok(g) => Ok(g),
                    Err(TreeError::NotEnoughMemory) => Err(TreeError::NotEnoughMemory),
                    // A grammar error: the rules are dropped.
                    Err(_) => continue,
                }
            }
            _ => {
                let n = input.byte()? % 4 + 2;
                let keys: Vec<Key> = (0..n).map(|i| Key::from(i % 3)).collect();
                Tree::const_group(&keys)
            }
        };
        let r = match r {
            Err(TreeError::LoopBodyNullable) => continue,
            r => r,
        };
        nem(&r);
        if let Ok(t) = r {
            check_walkers(&t, slice);
            stack.push(t);
            if stack.len() > 8 {
                stack.remove(0);
            }
        }
    }
    Some(())
}

// ---------------------------------------------------------------- through the VM

const LEAVES: [&str; 20] = [
    "P'a'",
    "P'ab'",
    "P''",
    "P(1)",
    "P(-1)",
    "P(true)",
    "P(false)",
    "S'ab'",
    "R'az'",
    "Cp()",
    "Cc(1, nil)",
    "P(F)",
    "V'A'",
    "'x'",
    "Cc()",
    "Cb'g'",
    "locale().alpha",
    "locale(T).digit",
    "Carg(1)",
    "P{ 'A', A = P'a' }",
];
/// The narrow language's leaves: the first 14.
const NARROW_LEAVES: usize = 14;

/// `n` bytes of the input as a Lua string literal.
fn lua_bytes(input: &mut Input, n: u8) -> String {
    let mut s = String::from("'");
    for _ in 0..n {
        let b = input.byte().unwrap_or(b'a');
        s.push_str(&format!("\\{b:03}"));
    }
    s.push('\'');
    s
}

fn lua_expr(input: &mut Input, depth: u32, wide: bool) -> Option<String> {
    let b = input.byte()?;
    let leaves = if wide {
        &LEAVES[..]
    } else {
        &LEAVES[..NARROW_LEAVES]
    };
    if depth == 0 || b < if wide { 48 } else { 64 } {
        let leaf = leaves[usize::from(b) % leaves.len()];
        return Some(leaf.to_string());
    }
    let sub = |input: &mut Input| lua_expr(input, depth - 1, wide);
    if wide && b >= 192 {
        // The rest of the constructors: constants, sets, captures, ptree.
        let k = input.byte()?;
        return Some(match b % 12 {
            0 => {
                let vals = ["1", "nil", "'x'", "true", "2.5", "P'a'"];
                let n = usize::from(k % 6);
                let vs: Vec<&str> = (0..n)
                    .map(|i| vals[(usize::from(k) + i) % vals.len()])
                    .collect();
                format!("Cc({})", vs.join(", "))
            }
            1 => format!("S({})", lua_bytes(input, k % 5)),
            2 => {
                let n = k % 3;
                let rs: Vec<String> = (0..n).map(|_| lua_bytes(input, 2)).collect();
                format!("R({})", rs.join(", "))
            }
            3 => format!("C({})", sub(input)?),
            4 => format!("Cs({})", sub(input)?),
            5 => format!("Cf({}, F)", sub(input)?),
            6 => format!("Cg({})", sub(input)?),
            7 => format!("Cb({})", lua_bytes(input, k % 3)),
            8 => format!(
                "(P({}) / {})",
                sub(input)?,
                ["'%1'", "F", "{}", "0", "2"][usize::from(k % 5)]
            ),
            9 => format!("P(select(2, pcall(lpeg.ptree, {}, true)))", sub(input)?),
            10 => format!("P{{ {}, x = {} }}", sub(input)?, sub(input)?),
            _ => format!("P(locale({{ {} }})[1])", sub(input)?),
        });
    }
    Some(match b % 14 {
        0 => format!("(P({}) * {})", sub(input)?, sub(input)?),
        1 => format!("(P({}) + {})", sub(input)?, sub(input)?),
        2 => format!("(P({}) - {})", sub(input)?, sub(input)?),
        3 => format!("(-P({}))", sub(input)?),
        4 => format!("(#P({}))", sub(input)?),
        5 => format!("(P({}) ^ {})", sub(input)?, input.int()?),
        6 => format!("(P({}) / {})", sub(input)?, input.int()?),
        7 => format!("B({})", sub(input)?),
        8 => format!("P({})", input.int()?),
        9 => format!("Cg({}, 'g')", sub(input)?),
        10 => format!("Ct({})", sub(input)?),
        11 => format!(
            "P{{ 'A', A = {}, B = {} }}",
            sub(input)?.replace("V'A'", "V'B'"),
            sub(input)?
        ),
        12 => format!("Carg({})", input.int()?),
        _ => format!("Cmt({}, F)", sub(input)?),
    })
}

/// Run `src` under the test registration, in slices of `slice` fuel: what
/// it returned (rendered) or raised.
fn run_vm(src: &str, slice: i32) -> String {
    let mut lua = Lua::core();
    lua.set_memory_limit(LIMIT);
    let ex = lua.try_enter(|ctx| {
        load_patterns(ctx).expect("string table");
        load_strpack(ctx).expect("string table");
        load_format(ctx).expect("string table");
        load_tail(ctx).expect("string and coroutine tables");
        let lpeg = register_for_tests(ctx, None);
        let env = Table::new(&ctx);
        for (k, v) in lpeg.iter() {
            env.set(ctx, k, v).expect("string keys");
        }
        env.set(ctx, "F", ctx.globals().get_value(ctx, "type"))
            .expect("string key");
        env.set(ctx, "pcall", ctx.globals().get_value(ctx, "pcall"))
            .expect("string key");
        env.set(ctx, "select", ctx.globals().get_value(ctx, "select"))
            .expect("string key");
        env.set(ctx, "T", Table::new(&ctx)).expect("string key");
        env.set(ctx, "lpeg", lpeg).expect("string key");
        let c = Closure::load_with_env(ctx, Some("=fuzz"), src.as_bytes(), env)?;
        Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
    });
    let ex = match ex {
        Ok(ex) => ex,
        Err(e) => return format!("load: {e}"),
    };
    let mut slices = 0u64;
    loop {
        let mut fuel = Fuel::with(slice);
        match lua.enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel)) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => return format!("step: {e}"),
        }
        slices += 1;
        if slices > 2_000_000 {
            return "unfinished".to_string();
        }
    }
    lua.enter(
        |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
            Ok(Ok(vs)) => {
                vs.0.iter()
                    .map(|v| match v {
                        Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                        v => v.type_name().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            }
            Ok(Err(e)) => format!("error: {e}"),
            Err(e) => format!("result: {e}"),
        },
    )
}

fn vm(input: &mut Input, wide: bool) -> Option<()> {
    let n = usize::from(input.byte()? % 4) + 1;
    let mut body = String::new();
    for i in 0..n {
        let e = lua_expr(input, if wide { 5 } else { 3 }, wide)?;
        body.push_str(&format!(
            "local ok{i}, r{i} = pcall(function() return {e} end) \
             out[#out + 1] = ok{i} and lpeg.type(r{i}) or r{i} "
        ));
    }
    let src = format!("local out = {{}} {body} return out[1], out[2], out[3], out[4]");
    let small = run_vm(&src, 1_000);
    let big = run_vm(&src, 10_000_000);
    // Each answer, or "not enough memory" on either side
    // (`lpeg-memory-errors-depend-on-slicing`); a whole run that ran out of
    // memory is compatible with anything.
    let nem = |s: &str| s.contains("not enough memory");
    if !nem(&small) || !nem(&big) {
        let (a, b): (Vec<&str>, Vec<&str>) = (small.split('|').collect(), big.split('|').collect());
        let whole =
            |s: &str| s.starts_with("error:") || s.starts_with("step:") || s.starts_with("result:");
        let compatible = (whole(&small) && nem(&small))
            || (whole(&big) && nem(&big))
            || (a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| x == y || nem(x) || nem(y)));
        assert!(
            compatible,
            "the answer depends on the fuel slice:\n{src}\n  left: {small}\n right: {big}"
        );
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input { data, at: 0 };
    let Some(mode) = input.byte() else { return };
    if mode % 2 == 0 {
        let mut lua = Lua::core();
        lua.set_memory_limit(LIMIT);
        lua.enter(|_| {
            let _ = pure(&mut input);
        });
    } else {
        let _ = vm(&mut input, mode % 4 == 3);
    }
});
