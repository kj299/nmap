//! The compiler and its analyses against transliterations of the C, on
//! random patterns and grammars, in budget slices; the programs the C
//! prints for a few patterns; and the shapes whose analyses blow up in the
//! C (`docs/M6.6-ANALYSIS.md` E10).
//!
//! The binding's view — patterns built from Lua, programs compared with a
//! debug build of the C (`lpeg.pcode`) — is `tests/lpeg_match_limits.rs`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code over small trees"
)]

use std::task::Poll;

use super::super::testkit::*;
use super::super::tree::{
    CapKind, Charset, CheckAux, FixedLen, Pred, Tag, Tree, TreeError, CHARSET_SIZE,
};
use super::analysis::{Analyses, First};
use super::*;

// ------------------------------------------------------------------------
// The C, recursively (`lpeg.c:1046-1302`).

const FULLSET: Charset = Charset([0xff; CHARSET_SIZE]);

fn nullable_ref(t: &Tree, i: usize) -> bool {
    let mut w = CheckAux::new(i, Pred::Nullable);
    drive(u32::MAX, |b| w.step(t, b)).unwrap()
}

fn nofail_ref(t: &Tree, i: usize) -> bool {
    let mut w = CheckAux::new(i, Pred::NoFail);
    drive(u32::MAX, |b| w.step(t, b)).unwrap()
}

fn fixedlen_ref(t: &Tree, i: usize) -> i64 {
    let mut w = FixedLen::new(i);
    drive(u32::MAX, |b| w.step(t, b)).unwrap()
}

fn tocharset_ref(t: &Tree, i: usize) -> Option<Charset> {
    analysis::to_charset(t, i)
}

/// `getfirst` (`lpeg.c:1175-1250`), transliterated; `None` past `depth`
/// (a cycle the C would recurse on for ever).
fn getfirst_ref(t: &Tree, i: usize, follow: &Charset, depth: u32) -> Option<(Charset, u8)> {
    if depth == 0 {
        return None;
    }
    let d = depth - 1;
    let n = t.node(i)?;
    Some(match n.tag {
        Tag::Char | Tag::Set | Tag::Any => (tocharset_ref(t, i)?, 0),
        Tag::True => (*follow, 1),
        Tag::False => (Charset::empty(), 0),
        Tag::Choice => {
            let (a, e1) = getfirst_ref(t, i + 1, follow, d)?;
            let (b, e2) = getfirst_ref(t, t.sib2(i)?, follow, d)?;
            (a.union(&b), e1 | e2)
        }
        Tag::Seq => {
            if !nullable_ref(t, i + 1) {
                getfirst_ref(t, i + 1, &FULLSET, d)?
            } else {
                let (csaux, e2) = getfirst_ref(t, t.sib2(i)?, follow, d)?;
                let (cs, e1) = getfirst_ref(t, i + 1, &csaux, d)?;
                let e = if e1 == 0 {
                    0
                } else if (e1 | e2) & 2 != 0 {
                    2
                } else {
                    e2
                };
                (cs, e)
            }
        }
        Tag::Rep => {
            let (cs, _) = getfirst_ref(t, i + 1, follow, d)?;
            (cs.union(follow), 1)
        }
        Tag::Capture | Tag::Grammar | Tag::Rule => getfirst_ref(t, i + 1, follow, d)?,
        Tag::RunTime => {
            let (cs, e) = getfirst_ref(t, i + 1, &FULLSET, d)?;
            (cs, if e != 0 { 2 } else { 0 })
        }
        Tag::Call => getfirst_ref(t, t.sib2(i)?, follow, d)?,
        Tag::And => {
            let (cs, e) = getfirst_ref(t, i + 1, follow, d)?;
            let mut out = cs;
            for (o, f) in out.0.iter_mut().zip(follow.0) {
                *o &= f;
            }
            (out, e)
        }
        Tag::Not if tocharset_ref(t, i + 1).is_some() => {
            let cs = tocharset_ref(t, i + 1)?;
            let mut out = cs;
            for o in &mut out.0 {
                *o = !*o;
            }
            (out, 1)
        }
        Tag::Not | Tag::Behind => {
            let (_, e) = getfirst_ref(t, i + 1, follow, d)?;
            (*follow, e | 1)
        }
        Tag::OpenCall => return None,
    })
}

/// `headfail` (`lpeg.c:1257`), transliterated.
fn headfail_ref(t: &Tree, i: usize, depth: u32) -> Option<bool> {
    if depth == 0 {
        return None;
    }
    let d = depth - 1;
    let n = t.node(i)?;
    Some(match n.tag {
        Tag::Char | Tag::Set | Tag::Any | Tag::False => true,
        Tag::True | Tag::Rep | Tag::RunTime | Tag::Not | Tag::Behind => false,
        Tag::Capture | Tag::Grammar | Tag::Rule | Tag::And => headfail_ref(t, i + 1, d)?,
        Tag::Call => headfail_ref(t, t.sib2(i)?, d)?,
        Tag::Seq => nofail_ref(t, t.sib2(i)?) && headfail_ref(t, i + 1, d)?,
        Tag::Choice => headfail_ref(t, i + 1, d)? && headfail_ref(t, t.sib2(i)?, d)?,
        Tag::OpenCall => return None,
    })
}

/// `hascaptures` (`lpeg.c:1046`), which follows no call.
fn hascaptures_ref(t: &Tree, i: usize) -> bool {
    let n = t.node(i).unwrap();
    match n.tag {
        Tag::Capture | Tag::RunTime => true,
        tag => match tag.siblings() {
            1 => hascaptures_ref(t, i + 1),
            2 => hascaptures_ref(t, i + 1) || hascaptures_ref(t, t.sib2(i).unwrap()),
            _ => false,
        },
    }
}

/// Ask an analysis in slices of `slice` steps.
fn ask<T>(
    an: &mut Analyses,
    t: &Tree,
    slice: u32,
    mut f: impl FnMut(&mut Analyses, &Tree, &mut u32) -> Result<Option<T>, CodeError>,
) -> Result<T, CodeError> {
    loop {
        let mut b = slice;
        if let Some(v) = f(an, t, &mut b)? {
            return Ok(v);
        }
    }
}

fn random_follow(r: &mut Rng) -> Charset {
    match r.below(4) {
        0 => FULLSET,
        1 => Charset::empty(),
        _ => {
            let mut cs = Charset::empty();
            for _ in 0..1 + r.below(4) {
                cs.add(b'a' + r.below(4) as u8);
            }
            cs
        }
    }
}

/// The closed form `FIRST(t, fl) = Y ∪ (fl ∩ X)`, and the flag, at every
/// node of random patterns and grammars, against the C's `getfirst` with
/// random follow sets; and the other analyses against theirs. In slices of
/// one to seven steps, so a pause inside any walk is crossed.
#[test]
fn analyses_agree_with_the_c_at_every_node() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let rounds = if cfg!(miri) { 12 } else { 1_500 };
    let mut checked = 0usize;
    for round in 0..rounds {
        let t = random_fixed(&mut r);
        let mut an = Analyses::new();
        let slice = 1 + (round % 7) as u32;
        for i in node_slots(&t) {
            let tag = t.node(i).unwrap().tag;
            if tag == Tag::Rule {
                continue; // reached only through calls, as in the C
            }
            let first = ask(&mut an, &t, slice, |a, t, b| a.first(t, i, b));
            let Some((want, e)) = getfirst_ref(&t, i, &FULLSET, 400) else {
                // The C would recurse for ever: the port must refuse. An
                // error ends a compilation: start afresh.
                assert!(
                    matches!(first, Err(CodeError::LeftRecursive(_))),
                    "{first:?}"
                );
                an = Analyses::new();
                continue;
            };
            let first: First = first.unwrap();
            assert_eq!(first.e, e, "e at {i}");
            let fl = an.intern(FULLSET).unwrap();
            assert_eq!(an.first_set(first, fl), want, "FIRST(t, FULL) at {i}");
            for _ in 0..3 {
                let follow = random_follow(&mut r);
                let (want, e2) = getfirst_ref(&t, i, &follow, 400).unwrap();
                assert_eq!(e2, e, "e does not depend on the follow set");
                let fl = an.intern(follow).unwrap();
                assert_eq!(an.first_set(first, fl), want, "FIRST(t, fl) at {i}");
                checked += 1;
            }
            let nul = ask(&mut an, &t, slice, |a, t, b| a.nullable(t, i, b)).unwrap();
            assert_eq!(nul, nullable_ref(&t, i), "nullable at {i}");
            let nof = ask(&mut an, &t, slice, |a, t, b| a.nofail(t, i, b)).unwrap();
            assert_eq!(nof, nofail_ref(&t, i), "nofail at {i}");
            let hf = ask(&mut an, &t, slice, |a, t, b| a.headfail(t, i, b)).unwrap();
            assert_eq!(Some(hf), headfail_ref(&t, i, 400), "headfail at {i}");
            let fl = ask(&mut an, &t, slice, |a, t, b| a.fixedlen(t, i, b)).unwrap();
            assert_eq!(fl, fixedlen_ref(&t, i), "fixedlen at {i}");
            let hc = ask(&mut an, &t, slice, |a, t, b| a.hascaptures(t, i, b)).unwrap();
            assert_eq!(hc, hascaptures_ref(&t, i), "hascaptures at {i}");
        }
    }
    assert!(checked > if cfg!(miri) { 10 } else { 10_000 }, "{checked}");
}

/// `fixedlenx` with its call count: a recursive rule is "variable" once
/// 200 calls are followed, and a node first asked deep in calls is asked
/// again at the top.
#[test]
fn fixedlen_follows_calls_to_the_cs_limit() {
    // S <- 'a' S / 'b': variable (the C gives up at 200 calls).
    let s = choice(&seq(&lit(b"a"), &open_call(1)), &lit(b"b"));
    let g = grammar(&[s]).unwrap();
    let mut an = Analyses::new();
    assert_eq!(
        ask(&mut an, &g, 3, |a, t, b| a.fixedlen(t, 0, b)).unwrap(),
        -1
    );
    assert_eq!(fixedlen_ref(&g, 0), -1);
    // A chain of 150 rules each calling the next, then 'ab': 2 at the top.
    let mut rules: Vec<Tree> = (1..150).map(|k| open_call(k + 1)).collect();
    rules.push(lit(b"ab"));
    let g = grammar(&rules).unwrap();
    let mut an = Analyses::new();
    // The last rule first, deep in calls; then from the top.
    for i in node_slots(&g).into_iter().rev() {
        let got = ask(&mut an, &g, 5, |a, t, b| a.fixedlen(t, i, b)).unwrap();
        assert_eq!(got, fixedlen_ref(&g, i), "at {i}");
    }
}

// ------------------------------------------------------------------------
// Compiling.

fn compile(t: &Tree, slice: u32) -> Result<Program, CodeError> {
    let mut c = Compiler::new();
    drive(slice, |b| c.step(t, b))
}

/// Code is the same however the budget is sliced: each job asks for its
/// analyses before it emits anything.
#[test]
fn programs_do_not_depend_on_the_slicing() {
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    let rounds = if cfg!(miri) { 8 } else { 600 };
    for _ in 0..rounds {
        let t = random_fixed(&mut r);
        let whole = compile(&t, u32::MAX);
        for slice in [1, 2, 3, 7] {
            assert_eq!(compile(&t, slice), whole);
        }
        if let Ok(p) = whole {
            // Every label in range, every instruction aligned.
            let mut i = 0;
            while i < p.len() {
                let (op, _, _) = p.inst(i).expect("aligned");
                if op.has_label() {
                    let tgt = p.target(i).expect("a label");
                    assert!(tgt < p.len(), "label past the code");
                }
                assert_ne!(op, Op::OpenCall);
                i += op.size();
            }
            assert_eq!(p.inst(p.len() - 1).map(|i| i.0), Some(Op::End));
        }
    }
}

/// The programs the C prints (a debug build of the tree's `lpeg.c` with its
/// peephole fixed, which prints the same as without the fix on these).
#[test]
fn programs_are_the_cs() {
    let ab = lit(b"ab");
    let cases: Vec<(Tree, &str)> = vec![
        (
            choice(&lit(b"ab"), &lit(b"ac")),
            "00: testchar 'a'-> 8\n02: choice -> 8\n04: any \n05: char 'b'\n06: commit -> 10\n08: char 'a'\n09: char 'c'\n10: end \n",
        ),
        (
            choice(&lit(b"ab"), &lit(b"cd")),
            "00: testchar 'a'-> 6\n02: any \n03: char 'b'\n04: end \n05: any \n06: char 'c'\n07: char 'd'\n08: end \n",
        ),
        (
            star(&ab, 0),
            "00: testchar 'a'-> 8\n02: choice -> 8\n04: char 'a'\n05: char 'b'\n06: partial_commit -> 4\n08: end \n",
        ),
        (
            seq(&star(&ab, 0), &lit(b"c")),
            "00: testchar 'a'-> 6\n02: any \n03: char 'b'\n04: jmp -> 0\n06: char 'c'\n07: end \n",
        ),
        (
            star(&ab, -2),
            "00: testchar 'a'-> 12\n02: choice -> 12\n04: any \n05: char 'b'\n06: partial_commit -> 8\n08: char 'a'\n09: char 'b'\n10: commit -> 12\n12: end \n",
        ),
        (
            Tree::root1(Tag::And, &ab).unwrap(),
            "00: char 'a'\n01: char 'b'\n02: behind 2\n03: end \n",
        ),
        (
            Tree::root1(Tag::And, &Tree::capture(CapKind::Simple, 0, &lit(b"a")).unwrap()).unwrap(),
            "00: choice -> 6\n02: char 'a'\n03: fullcapture simple (size = 1)  (idx = 0)\n04: back_commit -> 7\n06: fail \n07: end \n",
        ),
        (
            Tree::root1(Tag::Not, &ab).unwrap(),
            "00: testchar 'a'-> 7\n02: choice -> 7\n04: char 'a'\n05: char 'b'\n06: failtwice \n07: end \n",
        ),
        (
            Tree::capture(CapKind::Simple, 0, &star(&lit(b"a"), 0)).unwrap(),
            "00: opencapture simple (idx = 0)\n01: span [(61)]\n10: closecapture \n11: end \n",
        ),
        // P{S = "a" * V"S" * "b" + ""}
        (
            grammar(&[choice(&seq(&seq(&lit(b"a"), &open_call(1)), &lit(b"b")), &lit(b""))]).unwrap(),
            "00: call -> 4\n02: end \n03: any \n04: testchar 'a'-> 14\n06: choice -> 14\n08: any \n09: call -> 4\n11: char 'b'\n12: commit -> 14\n14: ret \n15: end \n",
        ),
        // P{S = "a" * V"S" + ""}: the call is a tail call.
        (
            grammar(&[choice(&seq(&lit(b"a"), &open_call(1)), &lit(b""))]).unwrap(),
            "00: call -> 4\n02: end \n03: any \n04: testchar 'a'-> 9\n06: any \n07: jmp -> 4\n09: ret \n10: end \n",
        ),
        // H06, `P{P""}^-1`, and H07, `-(S"" * "a") + "c"`: the C's peephole
        // loses its alignment on these (`lpeg-codegen-jump-out-of-code`).
        (
            star(&grammar(&[lit(b"")]).unwrap(), -1),
            "00: choice -> 9\n02: call -> 6\n04: commit -> 9\n06: ret \n07: commit -> 9\n09: end \n",
        ),
        (
            choice(&Tree::root1(Tag::Not, &seq(&set(&[]), &lit(b"a"))).unwrap(), &lit(b"c")),
            "00: choice -> 11\n02: commit -> 12\n04: choice -> 9\n06: fail \n07: char 'a'\n08: failtwice \n09: commit -> 12\n11: char 'c'\n12: end \n",
        ),
    ];
    for (t, want) in cases {
        let t = fix(&t).unwrap();
        let p = compile(&t, 3).unwrap();
        assert_eq!(p.dump(), want, "{:?}", t.nodes().first());
    }
}

/// Deep trees compile without recursion, here at Miri's size; the binding's
/// tests go to ten times the C's crash depths.
#[test]
fn deep_trees_compile_without_recursion() {
    let depth = if cfg!(miri) { 200 } else { 20_000 };
    // Nested captures, each with a choice inside: open/close pairs.
    let mut t = lit(b"a");
    for i in 0..depth {
        t = if i % 2 == 0 {
            Tree::capture(CapKind::Table, 0, &choice(&t, &lit(b"b"))).unwrap()
        } else {
            Tree::root1(Tag::Not, &seq(&t, &lit(b"c"))).unwrap()
        };
    }
    let t = fix(&t).unwrap();
    let p = compile(&t, 1_000).unwrap();
    assert_eq!(p.inst(p.len() - 1).map(|i| i.0), Some(Op::End));
}

/// The nullable-suffix chain `Rᵢ ← Rᵢ₋₁ cᵢ^-1 / Rᵢ₋₁ dᵢ^-1`, `R₀ ← ''`:
/// the C's `getfirst` walks it in time exponential in `n` (0.062 s at
/// n = 18), and a memo per (node, follow set) would hold 2^(n+1) - 1 keys.
/// Memoised per node in closed form, it compiles in steps linear in `n`,
/// with at most one memo entry per node (D3 condition 3).
#[test]
fn a_nullable_chain_compiles_with_one_memo_entry_per_node() {
    // The verifier, which `lpeg.P` runs, walks this chain in time
    // exponential in `n` too (as the C's does): `n` is kept where building
    // it is quick.
    let n: u32 = if cfg!(miri) { 6 } else { 18 };
    // Rules in the order R_n, R_0, R_1, ..., R_{n-1}: R_n's key is 1 and
    // R_j's is j + 2, so R_i calls R_{i-1} by key i + 1.
    let rule = |i: u32| {
        let c = star(&lit(&[b'a' + (i % 26) as u8]), -1);
        let d = star(&lit(&[b'A' + (i % 26) as u8]), -1);
        choice(&seq(&open_call(i + 1), &c), &seq(&open_call(i + 1), &d))
    };
    let mut rules = vec![rule(n), lit(b"")];
    rules.extend((1..n).map(rule));
    let g = grammar(&rules).expect("a verified grammar");
    let mut c = Compiler::new();
    let mut spent = 0u64;
    // Linear: a few hundred steps a rule. The C's walk, and a memo per
    // (node, follow set), take time exponential in `n`.
    let cap = 2_000 * u64::from(n);
    let p = loop {
        let mut b = 1_000;
        match c.step(&g, &mut b) {
            Poll::Ready(p) => break p.unwrap(),
            Poll::Pending => {
                spent += 1_000;
                assert!(spent < cap, "the compile ran out of steps: {spent}");
            }
        }
    };
    let (steps, memo) = c.stats();
    assert!(memo <= g.len(), "{memo} memo entries for {} nodes", g.len());
    assert!(steps < cap, "{steps} steps");
    assert!(p.len() > 10);
}

/// A left call through `lpeg.B`, which the verifier does not follow: the
/// pattern builds, as in the C, and compiling a use whose `getfirst`
/// reaches the cycle is an error where the C recurses for ever
/// (`lpeg-getfirst-unbounded-recursion`). A use that never asks for the
/// first set of the cycle compiles, as in the C.
#[test]
fn a_left_call_through_behind_raises_at_compile() {
    // A <- B(P"a" - V"A")
    let body = Tree::difference(&lit(b"a"), &open_call(1), 0).unwrap();
    let g = grammar(&[Tree::behind(1, &body).unwrap()]).expect("builds");
    match compile(&g, 7) {
        Err(CodeError::LeftRecursive(k)) => assert_eq!(k, 1, "named by the call's key"),
        other => panic!("{other:?}"),
    }
    // A <- P"a" + B(#V"A" * "a"): compiles alone, and refuses as `P(g) + "q"`.
    let and = seq(&Tree::root1(Tag::And, &open_call(1)).unwrap(), &lit(b"a"));
    let g = grammar(&[choice(&lit(b"a"), &Tree::behind(1, &and).unwrap())]).unwrap();
    assert!(compile(&g, 7).is_ok());
    let alt = fix(&choice(&g, &lit(b"q"))).unwrap();
    assert!(matches!(compile(&alt, 7), Err(CodeError::LeftRecursive(_))));
}

/// The charset helpers the codegen classifies sets with.
#[test]
fn charsets_classify_by_their_members() {
    assert_eq!(set_kind(&Charset::empty()), SetKind::Fail);
    let mut cs = Charset::empty();
    cs.add(200);
    assert_eq!(set_kind(&cs), SetKind::Char(200));
    cs.add(3);
    assert_eq!(set_kind(&cs), SetKind::Set);
    assert_eq!(set_kind(&FULLSET), SetKind::Any);
    // A program's charset reads back.
    let p = compile(&fix(&star(&set(b"xyz"), 0)).unwrap(), 9).unwrap();
    assert_eq!(
        p.charset(1)
            .map(|c| (0..=255u8).filter(|&b| c.has(b)).collect::<Vec<_>>()),
        Some(b"xyz".to_vec())
    );
    // An open call outside a grammar is `finalfix`'s error.
    assert_eq!(
        compile(&open_call(5), 2),
        Err(CodeError::Tree(TreeError::UsedOutsideGrammar(5)))
    );
}
