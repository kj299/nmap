// cargo-fuzz target for LPeg matching (M6.6 step c):
// `nmap_core::nse::lpeg::code` (the compiler), `nmap_core::nse::lpeg::vm`
// (the matching machine) and `vm::capture` (capture evaluation).
//
// The network controls subjects; scripts control patterns. The input is a
// pattern, written as a small prefix program over the pure constructors —
// literals, sets, numbers, sequences, choices, repetitions, predicates,
// look-behinds, grammars with calls, and every capture that calls no Lua —
// then a subject. Checked:
//   * nothing panics or aborts, whatever the pattern and subject;
//   * compiling, matching and evaluating in slices of 1 to 64 units of
//     budget gives what one slice gives (a slice boundary is invisible);
//   * the answer — no match, or the match's end and its values, or the
//     error evaluation raises — is what a direct interpreter of the tree
//     gives: PEG semantics over the tree itself, recursively, with the
//     capture list LPeg's compiler implies (a capture of a fixed-length
//     pattern with no captures is one entry placed after it; an
//     and-predicate of one keeps a called rule's captures, `hascaptures`
//     following no call), evaluated by a transliteration of `lpcap.c`.
// Where either side runs past its bound — the interpreter's recursion or
// step count, the machine's budget (an exponential grammar), a compile that
// refuses a left call through `B` — the case is not compared.
#![no_main]

use std::borrow::Cow;
use std::task::Poll;

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::lpeg::code::Compiler;
use nmap_core::nse::lpeg::tree::{
    CapKind, Charset, CheckAux, FinalFix, FixedLen, GrammarLayout, Key, Pred, Tag, Tree,
    VerifyGrammar,
};
use nmap_core::nse::lpeg::vm::capture::{CapCursor, CapEnv, CapError, CapVal, TableKey, View};
use nmap_core::nse::lpeg::vm::{Capture, Vm, VmPoll};

/// The most budget a match may take, in units.
const BUDGET: u64 = 400_000;
/// The interpreter's bounds.
const DEPTH: u32 = 400;
const STEPS: u64 = 400_000;

struct Input<'a> {
    data: &'a [u8],
    at: usize,
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
    fn same_constant(&self, a: Key, b: Key) -> bool {
        a != 0 && a == b
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

/// A pattern of depth at most `d` from the input; open calls name rules
/// `1..=rules`.
fn pattern(inp: &mut Input, d: u32, rules: u32) -> Tree {
    let op = inp.byte();
    if d == 0 || op < 40 {
        return match op % 12 {
            0 => {
                let n = usize::from(inp.byte() % 4);
                let s: Vec<u8> = (0..n)
                    .map(|_| b"abc"[usize::from(inp.byte() % 3)])
                    .collect();
                lit(&s)
            }
            1 => Tree::number(i32::from(inp.byte() % 5) - 2).unwrap(),
            2 => Tree::leaf(Tag::True).unwrap(),
            3 => Tree::leaf(Tag::False).unwrap(),
            4 if rules > 0 => {
                let mut v = Tree::leaf(Tag::OpenCall).unwrap();
                v.set_key(0, 1 + Key::from(inp.byte()) % rules);
                v
            }
            5 => {
                let mut cs = Charset::empty();
                for _ in 0..inp.byte() % 3 {
                    cs.add(b'a' + inp.byte() % 3);
                }
                Tree::charset(&cs).unwrap()
            }
            6 => Tree::empty_capture(CapKind::Position, 0).unwrap(),
            7 => Tree::empty_capture(CapKind::Const, Key::from(inp.byte() % 7)).unwrap(),
            8 => Tree::empty_capture(CapKind::Arg, 1 + Key::from(inp.byte() % 3)).unwrap(),
            9 => Tree::empty_capture(CapKind::Backref, 1 + Key::from(inp.byte() % 2)).unwrap(),
            10 => Tree::charset(&Charset([0xff; 32])).unwrap(),
            _ => lit(b"b"),
        };
    }
    let sub = |inp: &mut Input| pattern(inp, d - 1, rules);
    match op % 16 {
        0 | 1 => Tree::root2(Tag::Seq, &sub(inp), &sub(inp), 0).unwrap(),
        2 | 3 => Tree::root2(Tag::Choice, &sub(inp), &sub(inp), 0).unwrap(),
        4 => Tree::root1(Tag::Not, &sub(inp)).unwrap(),
        5 => Tree::root1(Tag::And, &sub(inp)).unwrap(),
        6 => {
            let t = sub(inp);
            let mut n = i32::from(inp.byte() % 5) - 2;
            if n >= 0 && nullable(&t) {
                n = -1 - n;
            }
            Tree::star(&t, n, Tree::star_space(t.len(), n).unwrap()).unwrap()
        }
        7 => Tree::difference(&sub(inp), &sub(inp), 0).unwrap(),
        8 => Tree::capture(CapKind::Simple, 0, &sub(inp)).unwrap(),
        9 => Tree::capture(CapKind::Table, 0, &sub(inp)).unwrap(),
        10 => Tree::capture(CapKind::Subst, 0, &sub(inp)).unwrap(),
        11 => {
            let k = Key::from(inp.byte() % 3);
            Tree::capture(CapKind::Group, k, &sub(inp)).unwrap()
        }
        12 => {
            let k = 3 + Key::from(inp.byte() % 2);
            Tree::capture(CapKind::String, k, &sub(inp)).unwrap()
        }
        13 => {
            let k = Key::from(inp.byte() % 4);
            Tree::capture(CapKind::Num, k, &sub(inp)).unwrap()
        }
        // `lpeg.B`: a fixed length up to 255 and no captures, or refused.
        14 => {
            let t = sub(inp);
            match fixedlen_of(&t, 0) {
                n @ 1..=255 if !t.has_captures() => Tree::behind(n as i32, &t).unwrap(),
                _ => Tree::root1(Tag::And, &t).unwrap(),
            }
        }
        _ => grammar(inp, d - 1).unwrap_or_else(|| lit(b"c")),
    }
}

/// A grammar of one to three rules, built, fixed and verified as `lpeg.P`
/// builds one; `None` if refused.
fn grammar(inp: &mut Input, d: u32) -> Option<Tree> {
    let n = 1 + u32::from(inp.byte() % 3);
    let rules: Vec<Tree> = (0..n).map(|_| pattern(inp, d, n)).collect();
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
            return r.ok().map(|()| g);
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
                if g.kind == CapKind::Group as u8 && Env.same_constant(g.idx, c.idx) {
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
        CapVal::Nil | CapVal::Buf => Val::Nil,
        CapVal::Int(i) => Val::Int(i),
        CapVal::Str(a, b) => Val::Str(s[a..b].to_vec()),
        CapVal::Bytes(i) => Val::Str(c.string(i).to_vec()),
        CapVal::K(k) => Val::K(k),
        CapVal::Arg(n) => Val::Arg(n),
        CapVal::Table(t) => Val::Table(
            c.table(t)
                .iter()
                .map(|&(k, v)| (k, port_value(c, s, v)))
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

/// Compile, match and evaluate in slices of `slice`: `None` past the budget
/// or where the compiler refuses (a left call through `B`).
fn port(t: &Tree, s: &[u8], slice: u32) -> Option<Result<Option<Vec<Val>>, Err>> {
    let mut spent = 0u64;
    let mut c = Compiler::new();
    let program = loop {
        let mut b = slice;
        match c.step(t, &mut b) {
            Poll::Ready(Ok(p)) => break p,
            Poll::Ready(Err(_)) => return None,
            Poll::Pending => {}
        }
        spent += u64::from(slice);
        if spent >= BUDGET {
            return None;
        }
    };
    let mut vm = Vm::new(0);
    let end = loop {
        let mut b = slice;
        match vm.run(&program, s, i32::MAX, &mut b) {
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
        match cur.step(&caps, s, &Env, &mut b) {
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

fuzz_target!(|data: &[u8]| {
    let mut inp = Input { data, at: 0 };
    let slice = 1 + u32::from(inp.byte() % 64);
    let t = pattern(&mut inp, 5, 0);
    let mut fixed = t.clone();
    let mut w = FinalFix::new(None, 0);
    if drive(u32::MAX, |b| w.step(&mut fixed, &|_| 0, b)).is_err() {
        return;
    }
    let subject: Vec<u8> = data
        .get(inp.at.min(data.len())..)
        .unwrap_or(&[])
        .iter()
        .take(48)
        .map(|b| b"abc"[usize::from(b % 3)])
        .collect();
    let whole = port(&fixed, &subject, BUDGET as u32);
    let sliced = port(&fixed, &subject, slice);
    if let (Some(a), Some(b)) = (&whole, &sliced) {
        assert_eq!(a, b, "a slice boundary changed the answer");
    }
    let Some(got) = whole else { return };
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
