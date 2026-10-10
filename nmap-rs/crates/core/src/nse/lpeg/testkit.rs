//! Trees for the compiler's and the machine's unit tests: constructors,
//! `finalfix`, grammars as `lpeg.P` makes them, and random patterns.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code over small trees"
)]

use std::task::Poll;

use super::tree::{
    CapKind, Charset, CheckAux, FinalFix, FixedLen, GrammarLayout, Key, Pred, Tag, Tree, TreeError,
    VerifyGrammar, CHARSET_SIZE, SET_SLOTS,
};

/// xorshift64*: deterministic, so a failure reproduces.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

pub(crate) fn lit(s: &[u8]) -> Tree {
    Tree::literal(s).unwrap()
}

pub(crate) fn seq(a: &Tree, b: &Tree) -> Tree {
    Tree::root2(Tag::Seq, a, b, 0).unwrap()
}

pub(crate) fn choice(a: &Tree, b: &Tree) -> Tree {
    Tree::root2(Tag::Choice, a, b, 0).unwrap()
}

pub(crate) fn star(t: &Tree, n: i32) -> Tree {
    Tree::star(t, n, Tree::star_space(t.len(), n).unwrap()).unwrap()
}

pub(crate) fn open_call(k: Key) -> Tree {
    let mut v = Tree::leaf(Tag::OpenCall).unwrap();
    v.set_key(0, k);
    v
}

pub(crate) fn set(bytes: &[u8]) -> Tree {
    let mut cs = Charset::empty();
    for &b in bytes {
        cs.add(b);
    }
    Tree::charset(&cs).unwrap()
}

/// Run a walker to its end in slices of `slice` steps.
pub(crate) fn drive<T>(slice: u32, mut f: impl FnMut(&mut u32) -> Poll<T>) -> T {
    loop {
        let mut b = slice;
        if let Poll::Ready(v) = f(&mut b) {
            return v;
        }
    }
}

/// `finalfix` outside any grammar.
pub(crate) fn fix(t: &Tree) -> Result<Tree, TreeError> {
    let mut t = t.clone();
    let mut w = FinalFix::new(None, 0);
    drive(u32::MAX, |b| w.step(&mut t, &|_| 0, b))?;
    Ok(t)
}

/// A grammar of these rules (open calls name rules by key `1..`), built,
/// fixed and verified as `lpeg.P` makes one; `None` if the verifier
/// refuses it. The first rule is named by key 99 if no call names it.
pub(crate) fn grammar(rules: &[Tree]) -> Option<Tree> {
    let sizes: Vec<usize> = rules.iter().map(Tree::len).collect();
    let layout = GrammarLayout::new(&sizes).unwrap();
    let pairs: Vec<(&Tree, Key)> = rules.iter().map(|t| (t, 0)).collect();
    let mut g = layout.build(&pairs, layout.space().unwrap()).unwrap();
    let positions = layout.positions.clone();
    let resolve = move |k: Key| positions.get(k as usize - 1).map_or(0, |&p| p as i64);
    let mut w = FinalFix::new(Some(0), 1);
    drive(u32::MAX, |b| w.step(&mut g, &resolve, b)).ok()?;
    if g.node(1).unwrap().key == 0 {
        g.set_key(1, 99);
    }
    let mut v = VerifyGrammar::new(0);
    drive(u32::MAX, |b| v.step(&g, b)).ok()?;
    Some(g)
}

/// A random pattern of depth at most `d`, whose open calls name rules
/// `1..=rules` (by key).
pub(crate) fn random_tree(r: &mut Rng, d: u32, rules: u32) -> Tree {
    if d == 0 || r.below(5) == 0 {
        return match r.below(10) {
            0 => lit(&b"abc"[..r.below(3) as usize]),
            1 => Tree::number(r.below(5) as i32 - 2).unwrap(),
            2 => Tree::leaf(Tag::True).unwrap(),
            3 => Tree::leaf(Tag::False).unwrap(),
            4 if rules > 0 => open_call(1 + r.below(u64::from(rules)) as Key),
            5 => Tree::empty_capture(CapKind::Position, 0).unwrap(),
            6 => set(&[b'a' + r.below(3) as u8, b'c']),
            7 => set(&[]),
            8 => Tree::charset(&Charset([0xff; CHARSET_SIZE])).unwrap(),
            _ => lit(b"b"),
        };
    }
    let sub = |r: &mut Rng| random_tree(r, d - 1, rules);
    match r.below(12) {
        0 | 1 => seq(&sub(r), &sub(r)),
        2 | 3 => choice(&sub(r), &sub(r)),
        4 => Tree::root1(Tag::Not, &sub(r)).unwrap(),
        5 => Tree::root1(Tag::And, &sub(r)).unwrap(),
        6 => Tree::capture(CapKind::Simple, 0, &sub(r)).unwrap(),
        7 => Tree::capture(CapKind::Group, 0, &sub(r)).unwrap(),
        8 => {
            let t = sub(r);
            let mut n = r.below(5) as i32 - 2;
            // `p^n`, n >= 0, of a body that can match the empty string is
            // refused by `lpeg`'s `__pow` ("loop body may accept empty
            // string"): it would loop for ever.
            let mut w = CheckAux::new(0, Pred::Nullable);
            if n >= 0 && drive(u32::MAX, |b| w.step(&t, b)).unwrap_or(true) {
                n = -1 - n;
            }
            star(&t, n)
        }
        9 => Tree::difference(&sub(r), &sub(r), 0).unwrap(),
        10 => Tree::root1(Tag::RunTime, &sub(r)).unwrap(),
        // `lpeg.B` looks back the pattern's fixed length, and refuses a
        // pattern without one, or with captures: anything else could move
        // back further than it matched (and loop for ever in a repetition).
        _ => {
            let t = sub(r);
            let mut w = FixedLen::new(0);
            match drive(u32::MAX, |b| w.step(&t, b)) {
                Ok(n @ 1..=255) if !t.has_captures() => Tree::behind(n as i32, &t).unwrap(),
                _ => Tree::root1(Tag::And, &t).unwrap(),
            }
        }
    }
}

/// A random fixed pattern, or a random verified grammar, or a pattern
/// holding one.
pub(crate) fn random_fixed(r: &mut Rng) -> Tree {
    loop {
        if r.below(2) == 0 {
            if let Ok(t) = fix(&random_tree(r, 5, 0)) {
                return t;
            }
            continue;
        }
        let n = 1 + r.below(4) as u32;
        let rules: Vec<Tree> = (0..n).map(|_| random_tree(r, 3, n)).collect();
        if let Some(g) = grammar(&rules) {
            return match r.below(3) {
                0 => g,
                1 => fix(&seq(&random_tree(r, 2, 0), &g)).unwrap(),
                _ => fix(&choice(&g, &random_tree(r, 2, 0))).unwrap(),
            };
        }
    }
}

/// The slots of `t` that are nodes, not a charset's data.
pub(crate) fn node_slots(t: &Tree) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(n) = t.node(i) {
        out.push(i);
        i += if n.tag == Tag::Set { 1 + SET_SLOTS } else { 1 };
    }
    out
}
