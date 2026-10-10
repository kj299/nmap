//! The tree constructors against the C's layouts, and every walker against
//! a transliteration of the recursive C function it replaces.
//!
//! The transliterations below recurse, as the C does; they run only on the
//! small trees these tests build. Each iterative walker is run both with an
//! unlimited budget and in slices of one to seven steps, and must reach the
//! same answer — the same error, naming the same rule — either way. Small
//! enough for Miri (`cargo +nightly miri test -p nmap-core --lib lpeg::`).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test trees are tiny; indices and counters in them cannot overflow"
)]

use std::task::Poll;

use super::*;

// ------------------------------------------------------------------------
// The C, recursively, as test oracles.

const PRED_NULLABLE: bool = true;

/// `checkaux` (`lpeg.c:1084`).
fn checkaux_ref(t: &Tree, i: usize, nullable: bool) -> bool {
    let n = t.node(i).expect("in tree");
    match n.tag {
        Tag::Char | Tag::Set | Tag::Any | Tag::False | Tag::OpenCall => false,
        Tag::Rep | Tag::True => true,
        Tag::Not | Tag::Behind => nullable,
        Tag::And => nullable || checkaux_ref(t, i + 1, nullable),
        Tag::RunTime => nullable && checkaux_ref(t, i + 1, nullable),
        Tag::Seq => {
            checkaux_ref(t, i + 1, nullable) && checkaux_ref(t, t.sib2(i).unwrap(), nullable)
        }
        Tag::Choice => {
            checkaux_ref(t, t.sib2(i).unwrap(), nullable) || checkaux_ref(t, i + 1, nullable)
        }
        Tag::Capture | Tag::Grammar | Tag::Rule => checkaux_ref(t, i + 1, nullable),
        Tag::Call => checkaux_ref(t, t.sib2(i).unwrap(), nullable),
    }
}

/// `fixedlenx` (`lpeg.c:1125`).
fn fixedlen_ref(t: &Tree, i: usize, mut count: usize, len: i64) -> i64 {
    let n = t.node(i).expect("in tree");
    match n.tag {
        Tag::Char | Tag::Set | Tag::Any => len + 1,
        Tag::False | Tag::True | Tag::Not | Tag::And | Tag::Behind => len,
        Tag::Rep | Tag::RunTime | Tag::OpenCall => -1,
        Tag::Capture | Tag::Rule | Tag::Grammar => fixedlen_ref(t, i + 1, count, len),
        Tag::Call => {
            let c = count;
            count += 1;
            if c >= MAXRULES {
                -1
            } else {
                fixedlen_ref(t, t.sib2(i).unwrap(), count, len)
            }
        }
        Tag::Seq => {
            let len = fixedlen_ref(t, i + 1, count, len);
            if len < 0 {
                -1
            } else {
                fixedlen_ref(t, t.sib2(i).unwrap(), count, len)
            }
        }
        Tag::Choice => {
            let n1 = fixedlen_ref(t, i + 1, count, len);
            if n1 < 0 {
                return -1;
            }
            let n2 = fixedlen_ref(t, t.sib2(i).unwrap(), count, len);
            if n1 == n2 {
                n1
            } else {
                -1
            }
        }
    }
}

/// `verifyerror` and `verifyrule` (`lpeg.c:3020-3088`). `fixed`: with the
/// port's two corrections (`lpeg-getfirst-unbounded-recursion`): a
/// look-behind's body is checked, and a sub-grammar in a nullable context
/// is nullable. Without them, the C exactly.
fn verifyrule_ref(
    t: &Tree,
    i: usize,
    passed: &mut [Key; MAXRULES],
    npassed: usize,
    nullable: bool,
    fixed: bool,
) -> Result<bool, TreeError> {
    let n = t.node(i).expect("in tree");
    match n.tag {
        Tag::Char | Tag::Set | Tag::Any | Tag::False => Ok(nullable),
        Tag::True => Ok(true),
        Tag::Behind if !fixed => Ok(true),
        Tag::Not | Tag::And | Tag::Rep | Tag::Behind => {
            verifyrule_ref(t, i + 1, passed, npassed, true, fixed)
        }
        Tag::Capture | Tag::RunTime => verifyrule_ref(t, i + 1, passed, npassed, nullable, fixed),
        Tag::Call => verifyrule_ref(t, t.sib2(i).unwrap(), passed, npassed, nullable, fixed),
        Tag::Seq => {
            if !verifyrule_ref(t, i + 1, passed, npassed, false, fixed)? {
                Ok(nullable)
            } else {
                verifyrule_ref(t, t.sib2(i).unwrap(), passed, npassed, nullable, fixed)
            }
        }
        Tag::Choice => {
            let nullable = verifyrule_ref(t, i + 1, passed, npassed, nullable, fixed)?;
            verifyrule_ref(t, t.sib2(i).unwrap(), passed, npassed, nullable, fixed)
        }
        Tag::Rule => {
            if npassed >= MAXRULES {
                for a in (0..npassed).rev() {
                    for b in (0..a).rev() {
                        if passed[a] == passed[b] {
                            return Err(TreeError::LeftRecursive(passed[a]));
                        }
                    }
                }
                return Err(TreeError::TooManyLeftCalls);
            }
            passed[npassed] = n.key;
            verifyrule_ref(t, i + 1, passed, npassed + 1, nullable, fixed)
        }
        Tag::Grammar => Ok(fixed && nullable || checkaux_ref(t, i, PRED_NULLABLE)),
        Tag::OpenCall => Err(TreeError::Malformed),
    }
}

/// `checkloops` (`lpeg.c:3000`).
fn checkloops_ref(t: &Tree, i: usize) -> bool {
    let n = t.node(i).expect("in tree");
    if n.tag == Tag::Rep && checkaux_ref(t, i + 1, PRED_NULLABLE) {
        return true;
    }
    if n.tag == Tag::Grammar {
        return false;
    }
    match n.tag.siblings() {
        1 => checkloops_ref(t, i + 1),
        2 => checkloops_ref(t, i + 1) || checkloops_ref(t, t.sib2(i).unwrap()),
        _ => false,
    }
}

/// `verifygrammar` (`lpeg.c:3090`); `fixed` as for [`verifyrule_ref`].
fn verifygrammar_ref(t: &Tree, g: usize, fixed: bool) -> Result<(), TreeError> {
    let mut passed = [0; MAXRULES];
    let mut rule = g + 1;
    while t.node(rule).unwrap().tag == Tag::Rule {
        if t.node(rule).unwrap().key != 0 {
            verifyrule_ref(t, rule + 1, &mut passed, 0, false, fixed)?;
        }
        rule = t.sib2(rule).unwrap();
    }
    let mut rule = g + 1;
    while t.node(rule).unwrap().tag == Tag::Rule {
        let key = t.node(rule).unwrap().key;
        if key != 0 && checkloops_ref(t, rule + 1) {
            return Err(TreeError::EmptyLoop(key));
        }
        rule = t.sib2(rule).unwrap();
    }
    Ok(())
}

/// `correctassociativity` and `finalfix` (`lpeg.c:2191-2240`).
fn finalfix_ref(
    t: &mut Tree,
    g: Option<usize>,
    i: usize,
    resolve: &dyn Fn(Key) -> i64,
) -> Result<(), TreeError> {
    let tag = t.node(i).unwrap().tag;
    match tag {
        Tag::Grammar => return Ok(()),
        Tag::OpenCall => {
            let key = t.node(i).unwrap().key;
            let Some(g) = g else {
                return Err(TreeError::UsedOutsideGrammar(key));
            };
            let n = resolve(key);
            if n == 0 {
                return Err(TreeError::UndefinedRule(key));
            }
            let nodes = t.nodes_mut();
            nodes[i].tag = Tag::Call;
            nodes[i].u = (n - (i - g) as i64) as i32;
            let r = t.sib2(i).unwrap();
            t.nodes_mut()[r].key = key;
        }
        Tag::Seq | Tag::Choice => loop {
            let t1 = i + 1;
            if t.node(t1).unwrap().tag != tag {
                break;
            }
            let n1size = t.node(i).unwrap().u as usize - 1;
            let n11size = t.node(t1).unwrap().u as usize - 1;
            let n12size = n1size - n11size - 1;
            let nodes = t.nodes_mut();
            nodes.copy_within(t1 + 1..t1 + 1 + n11size, i + 1);
            nodes[i].u = (n11size + 1) as i32;
            let s2 = i + n11size + 1;
            nodes[s2].tag = tag;
            nodes[s2].cap = 0;
            nodes[s2].key = 0;
            nodes[s2].u = (n12size + 1) as i32;
        },
        _ => {}
    }
    let tag = t.node(i).unwrap().tag;
    match tag.siblings() {
        1 => finalfix_ref(t, g, i + 1, resolve),
        2 => {
            finalfix_ref(t, g, i + 1, resolve)?;
            let s2 = t.sib2(i).unwrap();
            finalfix_ref(t, g, s2, resolve)
        }
        _ => Ok(()),
    }
}

// ------------------------------------------------------------------------
// Driving the walkers.

/// Run a walker to its answer, `slice` steps at a time (`u32::MAX`: at once).
fn drive<T>(
    slice: u32,
    mut f: impl FnMut(&mut u32) -> Poll<Result<T, TreeError>>,
) -> Result<T, TreeError> {
    let mut slices = 0u64;
    loop {
        let mut budget = slice;
        if let Poll::Ready(r) = f(&mut budget) {
            return r;
        }
        assert_eq!(budget, 0, "pending with budget left");
        slices += 1;
        assert!(slices < 10_000_000, "no progress");
    }
}

const SLICES: [u32; 5] = [u32::MAX, 1, 2, 3, 7];

fn checkaux(t: &Tree, root: usize, pred: Pred) -> bool {
    let mut answers = SLICES.iter().map(|&s| {
        let mut w = CheckAux::new(root, pred);
        drive(s, |b| w.step(t, b)).expect("checkaux")
    });
    let first = answers.next().unwrap();
    assert!(answers.all(|a| a == first), "checkaux depends on the slice");
    first
}

fn fixedlen(t: &Tree, root: usize) -> i64 {
    let mut answers = SLICES.iter().map(|&s| {
        let mut w = FixedLen::new(root);
        drive(s, |b| w.step(t, b)).expect("fixedlen")
    });
    let first = answers.next().unwrap();
    assert!(answers.all(|a| a == first), "fixedlen depends on the slice");
    first
}

fn verify(t: &Tree, g: usize) -> Result<(), TreeError> {
    let mut answers = SLICES.iter().map(|&s| {
        let mut w = VerifyGrammar::new(g);
        drive(s, |b| w.step(t, b))
    });
    let first = answers.next().unwrap();
    assert!(answers.all(|a| a == first), "verify depends on the slice");
    first
}

fn finalfix(
    t: &Tree,
    g: Option<usize>,
    resolve: &dyn Fn(Key) -> i64,
) -> (Tree, Result<(), TreeError>) {
    let mut out: Option<(Tree, Result<(), TreeError>)> = None;
    // Inside a grammar, from its first rule, as `newgrammar` calls it.
    let root = g.map_or(0, |g| g + 1);
    for &s in &SLICES {
        let mut copy = t.clone();
        let mut w = FinalFix::new(g, root);
        let r = drive(s, |b| w.step(&mut copy, resolve, b));
        match &out {
            None => out = Some((copy, r)),
            Some((t0, r0)) => {
                assert_eq!(&r, r0, "finalfix depends on the slice");
                if r.is_ok() {
                    assert_eq!(&copy, t0, "finalfix's tree depends on the slice");
                }
            }
        }
    }
    out.unwrap()
}

// ------------------------------------------------------------------------
// Layouts.

fn tags(t: &Tree) -> Vec<(Tag, i32)> {
    t.nodes().iter().map(|n| (n.tag, n.u)).collect()
}

#[test]
fn literals_numbers_and_booleans_have_the_cs_layout() {
    assert_eq!(tags(&Tree::literal(b"").unwrap()), [(Tag::True, 0)]);
    assert_eq!(
        tags(&Tree::literal(b"ab").unwrap()),
        [(Tag::Seq, 2), (Tag::Char, 97), (Tag::Char, 98)]
    );
    assert_eq!(tags(&Tree::number(0).unwrap()), [(Tag::True, 0)]);
    assert_eq!(
        tags(&Tree::number(3).unwrap()),
        [
            (Tag::Seq, 2),
            (Tag::Any, 0),
            (Tag::Seq, 2),
            (Tag::Any, 0),
            (Tag::Any, 0)
        ]
    );
    assert_eq!(
        tags(&Tree::number(-2).unwrap()),
        [(Tag::Not, 0), (Tag::Seq, 2), (Tag::Any, 0), (Tag::Any, 0)]
    );
    // A byte of 128 or more is its value, not a negative `char`.
    assert_eq!(tags(&Tree::literal(b"\xff").unwrap()), [(Tag::Char, 255)]);
}

#[test]
fn a_charset_takes_four_slots_and_reads_back() {
    let mut cs = Charset::empty();
    for b in [0u8, 7, 8, 97, 200, 255] {
        cs.add(b);
    }
    let t = Tree::charset(&cs).unwrap();
    assert_eq!(t.len(), 1 + SET_SLOTS);
    assert_eq!(t.to_charset(), Some(cs));
    assert!((0..=255u8).all(|b| cs.has(b) == [0u8, 7, 8, 97, 200, 255].contains(&b)));
    let a = Tree::literal(b"a").unwrap().to_charset().unwrap();
    assert!(a.has(b'a') && !a.has(b'b'));
    assert_eq!(
        Tree::number(1).unwrap().to_charset(),
        Some(Charset([0xff; CHARSET_SIZE]))
    );
    assert_eq!(Tree::number(2).unwrap().to_charset(), None);
    assert_eq!(cs.union(&a).minus(&cs), Charset::empty());
}

#[test]
fn repetitions_have_the_cs_layout() {
    let a = Tree::literal(b"a").unwrap();
    let star = |n| Tree::star(&a, n, Tree::star_space(a.len(), n).unwrap()).unwrap();
    assert_eq!(tags(&star(0)), [(Tag::Rep, 0), (Tag::Char, 97)]);
    assert_eq!(
        tags(&star(2)),
        [
            (Tag::Seq, 2),
            (Tag::Char, 97),
            (Tag::Seq, 2),
            (Tag::Char, 97),
            (Tag::Rep, 0),
            (Tag::Char, 97)
        ]
    );
    assert_eq!(
        tags(&star(-1)),
        [(Tag::Choice, 2), (Tag::Char, 97), (Tag::True, 0)]
    );
    assert_eq!(
        tags(&star(-2)),
        [
            (Tag::Choice, 6),
            (Tag::Seq, 2),
            (Tag::Char, 97),
            (Tag::Choice, 2),
            (Tag::Char, 97),
            (Tag::True, 0),
            (Tag::True, 0)
        ]
    );
}

#[test]
fn sizes_the_cs_int_cannot_hold_are_not_enough_memory() {
    let nem = Err(TreeError::NotEnoughMemory);
    // `P(2^31 + 1)` narrows to -2147483647: 2 * 2147483647 nodes.
    assert_eq!(Tree::number(-2_147_483_647).map(|_| ()), nem);
    assert_eq!(Tree::number(i32::MIN).map(|_| ()), nem);
    assert_eq!(Tree::number(i32::MAX).map(|_| ()), nem);
    // `p^n`: (n + 1) * (size + 1) and -n * (size + 3) - 1.
    assert_eq!(Tree::star_len(1, i32::MAX).map(|_| ()), nem);
    assert_eq!(Tree::star_len(1, i32::MIN).map(|_| ()), nem);
    assert_eq!(Tree::star_len(usize::MAX, 1).map(|_| ()), nem);
    assert_eq!(Tree::star_len(1, 3), Ok(8));
    assert_eq!(Tree::star_len(1, -3), Ok(11));
    // The largest the C's `int` holds is still a size, if memory allows.
    assert_eq!(Tree::star_len(0, 0x3fff_ffff), Ok(0x4000_0000));
    assert_eq!(Tree::star_len(1, 0x3fff_ffff).map(|_| ()), nem);
    assert_eq!(GrammarLayout::new(&[MAX_TREE]).map(|_| ()), nem);
    assert_eq!(GrammarLayout::new(&[usize::MAX]).map(|_| ()), nem);
}

#[test]
fn joins_shift_only_the_second_operands_table_keys() {
    let mut k = Tree::empty_capture(CapKind::Const, 1).unwrap();
    k = Tree::root2(
        Tag::Seq,
        &k,
        &Tree::empty_capture(CapKind::Arg, 2).unwrap(),
        0,
    )
    .unwrap();
    let num = Tree::capture(CapKind::Num, 5, &Tree::number(1).unwrap()).unwrap();
    let call = Tree::root2(
        Tag::Seq,
        &Tree::runtime(1).unwrap(),
        &{
            let mut v = Tree::leaf(Tag::OpenCall).unwrap();
            v.set_key(0, 2);
            v
        },
        0,
    )
    .unwrap();
    let rhs = Tree::root2(Tag::Seq, &num, &call, 0).unwrap();
    let t = Tree::root2(Tag::Choice, &k, &rhs, 10).unwrap();
    let keys: Vec<(Tag, Key)> = t.nodes().iter().map(|n| (n.tag, n.key)).collect();
    assert_eq!(
        keys,
        [
            (Tag::Choice, 0),
            (Tag::Seq, 0),
            (Tag::Capture, 1), // left operand: unshifted
            (Tag::True, 0),
            (Tag::Capture, 2), // Carg: a number
            (Tag::True, 0),
            (Tag::Seq, 0),
            (Tag::Capture, 5), // Cnum: a number
            (Tag::Any, 0),
            (Tag::Seq, 0),
            (Tag::RunTime, 11),
            (Tag::True, 0),
            (Tag::OpenCall, 12),
        ]
    );
    // A key of 0 (no value: `Cc(nil)`) stays 0.
    let mut z = Tree::empty_capture(CapKind::Const, 0).unwrap();
    z.correct_keys(0, 2, 7).unwrap();
    assert_eq!(z.root().key, 0);
    // A charset's data is not a node: its bytes are not shifted.
    let mut cs = Charset::empty();
    cs.add(0);
    let mut set = Tree::charset(&cs).unwrap();
    set.correct_keys(0, set.len(), 3).unwrap();
    assert_eq!(set.to_charset(), Some(cs));
}

#[test]
fn constant_groups_and_differences_have_the_cs_layout() {
    let g = Tree::const_group(&[1, 0, 2]).unwrap();
    let got: Vec<(Tag, u8, Key, i32)> = g
        .nodes()
        .iter()
        .map(|n| (n.tag, n.cap, n.key, n.u))
        .collect();
    let (cap, cst) = (Tag::Capture, CapKind::Const as u8);
    assert_eq!(
        got,
        [
            (cap, CapKind::Group as u8, 0, 0),
            (Tag::Seq, 0, 0, 3),
            (cap, cst, 1, 0),
            (Tag::True, 0, 0, 0),
            (Tag::Seq, 0, 0, 3),
            (cap, cst, 0, 0),
            (Tag::True, 0, 0, 0),
            (cap, cst, 2, 0),
            (Tag::True, 0, 0, 0),
        ]
    );
    let d = Tree::difference(
        &Tree::literal(b"ab").unwrap(),
        &Tree::runtime(1).unwrap(),
        4,
    )
    .unwrap();
    assert_eq!(
        d.nodes()
            .iter()
            .map(|n| (n.tag, n.key, n.u))
            .collect::<Vec<_>>(),
        [
            (Tag::Seq, 0, 4),
            (Tag::Not, 0, 0),
            (Tag::RunTime, 5, 0),
            (Tag::True, 0, 0),
            (Tag::Seq, 0, 2),
            (Tag::Char, 0, 97),
            (Tag::Char, 0, 98),
        ]
    );
}

// ------------------------------------------------------------------------
// Random trees: every walker against its C original.

/// xorshift64*: deterministic, so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random pattern of depth at most `d`, whose open calls name rules
/// `1..=rules` (by key).
fn random_tree(r: &mut Rng, d: u32, rules: u32) -> Tree {
    if d == 0 || r.below(5) == 0 {
        return match r.below(9) {
            0 => Tree::literal(&[b'a'; 3][..r.below(3) as usize]).unwrap(),
            1 => Tree::number(r.below(5) as i32 - 2).unwrap(),
            2 => Tree::leaf(Tag::True).unwrap(),
            3 => Tree::leaf(Tag::False).unwrap(),
            4 if rules > 0 => {
                let mut v = Tree::leaf(Tag::OpenCall).unwrap();
                v.set_key(0, 1 + r.below(u64::from(rules)) as Key);
                v
            }
            5 => Tree::runtime(0).unwrap(),
            6 => Tree::empty_capture(CapKind::Position, 0).unwrap(),
            7 => {
                let mut cs = Charset::empty();
                cs.add(r.below(256) as u8);
                Tree::charset(&cs).unwrap()
            }
            _ => Tree::literal(b"b").unwrap(),
        };
    }
    let sub = |r: &mut Rng| random_tree(r, d - 1, rules);
    match r.below(10) {
        0 | 1 => Tree::root2(Tag::Seq, &sub(r), &sub(r), 0).unwrap(),
        2 | 3 => Tree::root2(Tag::Choice, &sub(r), &sub(r), 0).unwrap(),
        4 => Tree::root1(Tag::Not, &sub(r)).unwrap(),
        5 => Tree::root1(Tag::And, &sub(r)).unwrap(),
        6 => Tree::capture(CapKind::Simple, 0, &sub(r)).unwrap(),
        7 => {
            let t = sub(r);
            let n = r.below(5) as i32 - 2;
            Tree::star(&t, n, Tree::star_space(t.len(), n).unwrap()).unwrap()
        }
        8 => Tree::difference(&sub(r), &sub(r), 0).unwrap(),
        _ => {
            let t = sub(r);
            Tree::behind(1, &t).unwrap()
        }
    }
}

/// A random grammar of `n` rules (keys `1..=n`), built and fixed; `None`
/// when `finalfix` rejects it, after checking it rejects it as the C does.
fn random_grammar(r: &mut Rng, n: u32, d: u32) -> Option<Tree> {
    let rules: Vec<Tree> = (0..n).map(|_| random_tree(r, d, n)).collect();
    let sizes: Vec<usize> = rules.iter().map(Tree::len).collect();
    let layout = GrammarLayout::new(&sizes).unwrap();
    let pairs: Vec<(&Tree, Key)> = rules.iter().map(|t| (t, 0)).collect();
    let g = layout.build(&pairs, layout.space().unwrap()).unwrap();
    // Rule `k` is named by key `k`; key `n + 1` names nothing.
    let positions = layout.positions.clone();
    let resolve = move |k: Key| positions.get(k as usize - 1).map_or(0, |&p| p as i64);
    let mut want = g.clone();
    let want_r = finalfix_ref(&mut want, Some(0), 1, &resolve);
    let (mut got, got_r) = {
        let mut out: Option<(Tree, Result<(), TreeError>)> = None;
        for &s in &SLICES {
            let mut copy = g.clone();
            let mut w = FinalFix::new(Some(0), 1);
            let res = drive(s, |b| w.step(&mut copy, &resolve, b));
            if let Some((t0, r0)) = &out {
                assert_eq!(&res, r0);
                if res.is_ok() {
                    assert_eq!(&copy, t0);
                }
            } else {
                out = Some((copy, res));
            }
        }
        out.unwrap()
    };
    assert_eq!(got_r, want_r, "finalfix");
    got_r.ok()?;
    assert_eq!(got, want, "finalfix's tree");
    // `initialrulename`: an unreferenced first rule gets a name.
    if got.node(1).unwrap().key == 0 {
        got.set_key(1, n + 1);
    }
    Some(got)
}

#[test]
fn walkers_agree_with_the_c_on_random_patterns() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let rounds = if cfg!(miri) { 30 } else { 3_000 };
    for _ in 0..rounds {
        let t = random_tree(&mut r, 5, 0);
        assert_eq!(checkaux(&t, 0, Pred::Nullable), checkaux_ref(&t, 0, true));
        assert_eq!(checkaux(&t, 0, Pred::NoFail), checkaux_ref(&t, 0, false));
        assert_eq!(fixedlen(&t, 0), fixedlen_ref(&t, 0, 0, 0));
        let mut w = CheckLoops::new(0);
        assert_eq!(drive(3, |b| w.step(&t, b)).unwrap(), checkloops_ref(&t, 0));
        let fixed = finalfix(&t, None, &|_| 0);
        let mut want = t.clone();
        assert_eq!(fixed.1, finalfix_ref(&mut want, None, 0, &|_| 0));
        if fixed.1.is_ok() {
            assert_eq!(fixed.0, want);
        }
    }
}

#[test]
fn walkers_agree_with_the_c_on_random_grammars() {
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    let rounds = if cfg!(miri) { 20 } else { 2_000 };
    let mut verified = [0usize; 2];
    let mut corrected = 0usize;
    for i in 0..rounds {
        let n = 1 + (i % 4) as u32;
        let Some(g) = random_grammar(&mut r, n, 3) else {
            continue;
        };
        // The C's answer where it refuses the grammar; where it accepts it,
        // the hidden pass's.
        let c = verifygrammar_ref(&g, 0, false);
        let want = match c {
            Ok(()) => verifygrammar_ref(&g, 0, true),
            e => e,
        };
        assert_eq!(verify(&g, 0), want);
        verified[usize::from(want.is_ok())] += 1;
        if c != want {
            assert!(
                matches!(want, Err(TreeError::LeftRecursive(_))),
                "{c:?} {want:?}"
            );
            corrected += 1;
        }
        if want.is_ok() {
            assert_eq!(checkaux(&g, 0, Pred::Nullable), checkaux_ref(&g, 0, true));
            assert_eq!(checkaux(&g, 0, Pred::NoFail), checkaux_ref(&g, 0, false));
            assert_eq!(fixedlen(&g, 0), fixedlen_ref(&g, 0, 0, 0));
            // A grammar inside a pattern: walkers stop at it or enter it.
            let outer = Tree::root2(Tag::Seq, &Tree::literal(b"x").unwrap(), &g, 0).unwrap();
            assert_eq!(fixedlen(&outer, 0), fixedlen_ref(&outer, 0, 0, 0));
            let mut w = CheckLoops::new(0);
            assert!(!drive(2, |b| w.step(&outer, b)).unwrap());
        }
    }
    // Both kinds of answer were seen, so neither path went untested.
    assert!(verified[0] > 0 && verified[1] > 0, "{verified:?}");
    assert!(
        corrected > 0,
        "no random grammar reached the hidden pass's errors"
    );
}

/// `S <- S 'a'`, `A <- B; B <- A`, `S <- ('')*`, and the names they give.
#[test]
fn the_verifier_names_the_rule_the_c_names() {
    let call = open_call;
    let build = grammar_of;
    let a = Tree::literal(b"a").unwrap();
    let left = build(vec![Tree::root2(Tag::Seq, &call(1), &a, 0).unwrap()]);
    assert_eq!(verify(&left, 0), Err(TreeError::LeftRecursive(1)));
    let mutual = build(vec![call(2), call(1)]);
    assert_eq!(verify(&mutual, 0), verifygrammar_ref(&mutual, 0, false));
    assert!(matches!(
        verify(&mutual, 0),
        Err(TreeError::LeftRecursive(_))
    ));
    let empty = Tree::leaf(Tag::True).unwrap();
    let loop_ = build(vec![
        Tree::star(&empty, 0, Tree::star_space(1, 0).unwrap()).unwrap()
    ]);
    assert_eq!(verify(&loop_, 0), Err(TreeError::EmptyLoop(99)));
    // Right recursion is fine.
    let right = build(vec![Tree::root2(
        Tag::Choice,
        &Tree::root2(Tag::Seq, &a, &call(1), 0).unwrap(),
        &empty,
        0,
    )
    .unwrap()]);
    assert_eq!(verify(&right, 0), Ok(()));
    // An open call outside a grammar, and one to a rule there is none of.
    let open = Tree::root2(Tag::Seq, &a, &call(7), 0).unwrap();
    assert_eq!(
        finalfix(&open, None, &|_| 0).1,
        Err(TreeError::UsedOutsideGrammar(7))
    );
    let sizes = [open.len()];
    let layout = GrammarLayout::new(&sizes).unwrap();
    let g = layout
        .build(&[(&open, 0)], layout.space().unwrap())
        .unwrap();
    let mut w = FinalFix::new(Some(0), 1);
    let mut g2 = g.clone();
    assert_eq!(
        drive(u32::MAX, |b| w.step(&mut g2, &|_| 0, b)),
        Err(TreeError::UndefinedRule(7))
    );
}

/// Build a one- or two-rule grammar from rule bodies whose open calls name
/// rules by key `1..`, fix it and name its first rule (key 99) if unused.
fn grammar_of(rules: Vec<Tree>) -> Tree {
    let sizes: Vec<usize> = rules.iter().map(Tree::len).collect();
    let layout = GrammarLayout::new(&sizes).unwrap();
    let pairs: Vec<(&Tree, Key)> = rules.iter().map(|t| (t, 0)).collect();
    let g = layout.build(&pairs, layout.space().unwrap()).unwrap();
    let positions = layout.positions.clone();
    let (mut g, r) = finalfix(&g, Some(0), &move |k: Key| {
        positions.get(k as usize - 1).map_or(0, |&p| p as i64)
    });
    r.unwrap();
    if g.node(1).unwrap().key == 0 {
        g.set_key(1, 99);
    }
    g
}

fn open_call(k: Key) -> Tree {
    let mut v = Tree::leaf(Tag::OpenCall).unwrap();
    v.set_key(0, k);
    v
}

/// The two left recursions the C's verifier lets through, each of which then
/// recursed without bound in its `getfirst` (measured on the tree's oracle:
/// a crash or a hang, depending on how the rule is reached), are refused
/// here as any other left recursion is (`lpeg-getfirst-unbounded-recursion`).
#[test]
fn left_recursion_through_behind_or_a_sub_grammar_is_refused() {
    let a = Tree::literal(b"a").unwrap();
    // `A <- B(P"a" - V"A")`: `B`'s body has fixed length 1.
    let body = Tree::difference(&a, &open_call(1), 0).unwrap();
    let behind = Tree::behind(1, &body).unwrap();
    let g = grammar_of(vec![behind]);
    assert_eq!(
        verifygrammar_ref(&g, 0, false),
        Ok(()),
        "the C lets it through"
    );
    assert_eq!(verify(&g, 0), Err(TreeError::LeftRecursive(1)));
    // `A <- B(#V"A" * "a")`, which the C compiles unless a choice reaches it.
    let and = Tree::root2(
        Tag::Seq,
        &Tree::root1(Tag::And, &open_call(1)).unwrap(),
        &a,
        0,
    )
    .unwrap();
    let g = grammar_of(vec![Tree::behind(1, &and).unwrap()]);
    assert_eq!(verify(&g, 0), Err(TreeError::LeftRecursive(1)));
    // `A <- -P{P"x"} * V"A"`.
    let sub = grammar_of(vec![Tree::literal(b"x").unwrap()]);
    let not = Tree::root1(Tag::Not, &sub).unwrap();
    let g = grammar_of(vec![Tree::root2(Tag::Seq, &not, &open_call(1), 0).unwrap()]);
    assert_eq!(
        verifygrammar_ref(&g, 0, false),
        Ok(()),
        "the C lets it through"
    );
    assert_eq!(verify(&g, 0), Err(TreeError::LeftRecursive(1)));
    // A call in a look-behind that is not a cycle is fine, as in the C.
    let g = grammar_of(vec![
        Tree::behind(1, &Tree::difference(&a, &open_call(2), 0).unwrap()).unwrap(),
        Tree::literal(b"b").unwrap(),
    ]);
    assert_eq!(verify(&g, 0), Ok(()));
    // The C's quirk is kept where it decides nothing: a sub-grammar that
    // consumes, in a sequence that needs no further check.
    let g = grammar_of(vec![Tree::root2(Tag::Seq, &sub, &open_call(1), 0).unwrap()]);
    assert_eq!(verify(&g, 0), Ok(()));
    assert_eq!(verifygrammar_ref(&g, 0, false), Ok(()));
}

#[test]
fn the_charset_of_a_choice_is_the_union() {
    let ab = Tree::literal(b"a")
        .unwrap()
        .to_charset()
        .unwrap()
        .union(&Tree::literal(b"b").unwrap().to_charset().unwrap());
    assert!(ab.has(b'a') && ab.has(b'b') && !ab.has(b'c'));
}

/// Deep trees: every walker answers without recursing. (The integration
/// tests go to ten times the C's crash depths; this is Miri-sized.)
#[test]
fn walkers_do_not_recurse_on_deep_trees() {
    let depth = if cfg!(miri) { 300 } else { 50_000 };
    let mut t = Tree::literal(b"a").unwrap();
    for i in 0..depth {
        t = if i % 2 == 1 {
            Tree::root1(Tag::Not, &t).unwrap()
        } else {
            Tree::root2(Tag::Seq, &t, &Tree::literal(b"b").unwrap(), 0).unwrap()
        };
    }
    assert!(checkaux(&t, 0, Pred::Nullable));
    assert_eq!(fixedlen(&t, 0), 0);
    let mut w = CheckLoops::new(0);
    assert!(!drive(u32::MAX, |b| w.step(&t, b)).unwrap());
    let (fixed, r) = finalfix(&t, None, &|_| 0);
    r.unwrap();
    // Left-nested sequences were made right-associative.
    let mut w = FinalFix::new(None, 0);
    let mut again = fixed.clone();
    drive(u32::MAX, |b| w.step(&mut again, &|_| 0, b)).unwrap();
    assert_eq!(again, fixed, "finalfix is idempotent");
}

// ------------------------------------------------------------------------
// Depth: ten times the C's crash depths (docs/M6.6-ANALYSIS.md §1.3).

/// `d` nodes of `tag` (and `cap`), each the only sibling of the one before,
/// over `P"a"`: `Ct`, `Cs`, `Cmt`, `-` and `#` nested `d` deep, built
/// directly — building them through the constructors copies the tree at
/// each level, as the C does, which is quadratic in `d`.
fn one_sibling_chain(d: usize, tag: Tag, cap: CapKind) -> Tree {
    let mut nodes = vec![
        Node {
            cap: cap as u8,
            ..Node::new(tag)
        };
        d
    ];
    nodes.push(Node::with_u(Tag::Char, i32::from(b'a')));
    Tree { nodes }
}

/// `d` choices and sequences, alternating, each the first sibling of the
/// one before: `(((P"a" * "b") + true) * "b") + true ...`. The C's
/// `finalfix`, `checkaux` and `fixedlenx` recurse on first siblings, and
/// alternating tags leave nothing for `correctassociativity` to rotate
/// (a left-nested chain of one tag it rotates a level at a time, moving
/// the rest each time: quadratic, in the C as here, and so not a depth test).
fn alternating_chain(d: usize) -> Tree {
    let mut nodes = Vec::with_capacity(2 * d + 1);
    for j in 0..d {
        let tag = if j % 2 == 0 { Tag::Choice } else { Tag::Seq };
        nodes.push(Node::with_u(tag, (2 * (d - j)) as i32));
    }
    nodes.push(Node::with_u(Tag::Char, i32::from(b'a')));
    for j in (0..d).rev() {
        nodes.push(if j % 2 == 0 {
            Node::new(Tag::True)
        } else {
            Node::with_u(Tag::Char, i32::from(b'b'))
        });
    }
    Tree { nodes }
}

/// `P{ P{ ... P{ P"a" } ... } }`, `d` grammars deep, each of one rule (used,
/// key 1).
fn grammar_chain(d: usize) -> Tree {
    let mut nodes = Vec::with_capacity(3 * d + 1);
    for j in 0..d {
        nodes.push(Node::with_u(Tag::Grammar, 1));
        nodes.push(Node {
            key: 1,
            ..Node::with_u(Tag::Rule, (3 * (d - j - 1) + 2) as i32)
        });
    }
    nodes.push(Node::with_u(Tag::Char, i32::from(b'a')));
    nodes.extend(std::iter::repeat_n(Node::new(Tag::True), d));
    Tree { nodes }
}

/// Every walker over `t`, and over `t` as the one rule of a grammar.
fn walk_everything(t: &Tree) -> (bool, bool, i64, bool, Result<(), TreeError>) {
    let mut w = CheckAux::new(0, Pred::Nullable);
    let nullable = drive(4096, |b| w.step(t, b));
    let mut w = CheckAux::new(0, Pred::NoFail);
    let nofail = drive(4096, |b| w.step(t, b)).unwrap();
    let mut w = FixedLen::new(0);
    let len = drive(4096, |b| w.step(t, b)).unwrap();
    let mut w = CheckLoops::new(0);
    let loops = drive(4096, |b| w.step(t, b)).unwrap();
    let mut fixed = t.clone();
    let mut w = FinalFix::new(None, 0);
    drive(4096, |b| w.step(&mut fixed, &|_| 0, b)).unwrap();
    let layout = GrammarLayout::new(&[t.len()]).unwrap();
    let mut g = layout.build(&[(t, 0)], layout.space().unwrap()).unwrap();
    g.set_key(1, 1);
    let mut w = VerifyGrammar::new(0);
    let verified = drive(4096, |b| w.step(&g, b));
    assert!(
        !t.has_captures()
            || t.nodes()
                .iter()
                .any(|n| n.tag == Tag::Capture || n.tag == Tag::RunTime)
    );
    let mut shifted = t.clone();
    shifted.correct_keys(0, t.len(), 1).unwrap();
    (nullable.unwrap(), nofail, len, loops, verified)
}

#[test]
#[cfg_attr(miri, ignore = "hundreds of thousands of nodes")]
fn walkers_answer_at_ten_times_the_cs_crash_depths() {
    // Ct: 6,159 levels crash the C; P{}: 7,699; - # ^-1 Cmt Cs: 45,898.
    let ct = one_sibling_chain(61_590, Tag::Capture, CapKind::Table);
    assert_eq!(walk_everything(&ct), (false, false, 1, false, Ok(())));
    let cs = one_sibling_chain(458_980, Tag::Capture, CapKind::Subst);
    assert_eq!(walk_everything(&cs), (false, false, 1, false, Ok(())));
    let cmt = one_sibling_chain(458_980, Tag::RunTime, CapKind::Close);
    assert_eq!(walk_everything(&cmt), (false, false, -1, false, Ok(())));
    let not = one_sibling_chain(458_980, Tag::Not, CapKind::Close);
    assert_eq!(walk_everything(&not), (true, false, 0, false, Ok(())));
    let and = one_sibling_chain(458_980, Tag::And, CapKind::Close);
    assert_eq!(walk_everything(&and), (true, false, 0, false, Ok(())));
    let alt = alternating_chain(458_980);
    assert_eq!(walk_everything(&alt), (true, true, -1, false, Ok(())));
    let g = grammar_chain(76_990);
    assert_eq!(walk_everything(&g), (false, false, 1, false, Ok(())));
    // The C recurses on the first sibling of every choice; so does this
    // test's recursive original, which is why it is not run here.
}
