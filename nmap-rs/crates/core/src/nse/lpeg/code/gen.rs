//! `compile` (`lpeg.c:1866`): `finalfix` on a copy of the pattern's tree,
//! then `codegen`, `End` and the peephole, as one resumable machine.
//!
//! The C's `codegen` (`:1784-1809`) dispatches on a node's tag, recursing
//! for every child but a sequence's second, and emitting more after each
//! recursive call returns. Here each "generate this child, then go on" is
//! two jobs on an explicit stack: the continuation, then the child's
//! `Gen` on top of it. A job first asks for every analysis it needs — each
//! memoised, so asking again after a pause costs nothing — and only then
//! pops itself and emits, all at once; so the code does not depend on where
//! the budget ran out. The jobs mirror the C's functions one to one, and
//! keep its order of emission and of analysis calls.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "slot indices are below the code's length, which is kept below i32::MAX, and \
              node indices below MAX_TREE: no sum of two overflows usize"
)]

use std::task::Poll;

use super::super::tree::{CapKind, Charset, FinalFix, Key, Node, Tag, Tree, TreeError, MAX_TREE};
use super::analysis::{to_charset, Analyses, SetId, FULL};
use super::{inst_at, set_kind, target_at, CodeError, Op, Program, SetKind, Slot, MAXOFF};
use crate::nse::stdlib::reserve;

/// `MAXBEHIND` (`lpeg.c:121`): the most an and-predicate may look behind
/// to undo its match.
const MAXBEHIND: i64 = 255;

/// Nodes one unit of budget copies.
const COPY_PER_FUEL: usize = 16;

/// One pending piece of code generation. `tt` is the test instruction that
/// protects the code (`NOINST` is `None`), `fl` the follow set.
#[derive(Debug, Clone, Copy)]
enum Job {
    /// `codegen(t, opt, tt, fl)`.
    Gen {
        t: usize,
        opt: bool,
        tt: Option<usize>,
        fl: SetId,
    },
    /// `codeseq1` has coded `p1`: code `p2` (the C's tail call), under
    /// `tt` only if `p1` consumes nothing.
    SeqThen {
        p1: usize,
        p2: usize,
        opt: bool,
        tt: Option<usize>,
        fl: SetId,
    },
    /// `codechoice`, test form, after `p1`.
    ChoiceTest {
        p2: usize,
        opt: bool,
        fl: SetId,
        test: usize,
        emptyp2: bool,
    },
    /// `codechoice`, general form, after `p1`.
    ChoiceGeneral {
        p2: usize,
        opt: bool,
        fl: SetId,
        test: Option<usize>,
        pchoice: usize,
    },
    /// `jumptohere(i)`.
    Here(Option<usize>),
    /// `codeand`, fixed-length form, after the pattern: look back `n`.
    AndBehind { n: u8 },
    /// `codeand`, general form, after the pattern.
    AndGeneral { pchoice: usize },
    /// `codecapture`, full form, after the pattern.
    CapFull { kind: u8, key: Key, len: u8 },
    /// `codecapture`, open form, after the pattern.
    CapClose,
    /// `coderuntime`, after the pattern.
    RunTimeClose,
    /// `coderep`, test form, after the body.
    RepTest { test: usize },
    /// `coderep`, general form, after the body.
    RepChoice {
        pchoice: Option<usize>,
        l2: usize,
        test: Option<usize>,
    },
    /// `codenot`, general form, after the pattern.
    NotEnd { pchoice: usize, test: Option<usize> },
    /// `codegrammar`, after rule `r`'s pattern.
    RuleEnd { r: usize },
    /// `correctcalls` of the innermost grammar, from its `k`-th open call.
    CorrectCalls { k: usize },
}

/// A grammar being coded (`codegrammar`'s locals).
#[derive(Debug, Clone)]
struct GrammarFrame {
    /// Where each rule's code starts, by rule number.
    positions: Vec<usize>,
    /// Where its open calls are, in the order coded: the `IOpenCall`s
    /// `correctcalls` would meet in its scan of the grammar's code (an inner
    /// grammar's code has none left by then).
    calls: Vec<usize>,
    jumptoend: usize,
}

#[derive(Debug, Clone)]
enum Phase {
    /// Copying the pattern's tree, from this node.
    Copy(usize),
    /// `finalfix` on the copy.
    Fix(FinalFix),
    /// `codegen`.
    Gen,
    /// The peephole, from this slot.
    Peephole(usize),
    Done,
}

/// `compile` of one pattern, resumable: [`Compiler::step`] with the
/// pattern's tree until it answers.
#[derive(Debug)]
pub struct Compiler {
    phase: Phase,
    nodes: Vec<Node>,
    tree: Tree,
    an: Analyses,
    code: Vec<Slot>,
    jobs: Vec<Job>,
    grammars: Vec<GrammarFrame>,
    calls_lua: bool,
    /// Units of budget spent, for the tests.
    spent: u64,
}

/// `?` for an analysis that may not be ready: the job waits.
macro_rules! ready {
    ($e:expr) => {
        match $e? {
            Some(v) => v,
            None => return Ok(None),
        }
    };
}

fn malformed() -> CodeError {
    CodeError::Tree(TreeError::Malformed)
}

fn disjoint(a: &Charset, b: &Charset) -> bool {
    a.0.iter().zip(b.0).all(|(x, y)| x & y == 0)
}

impl Default for Compiler {
    fn default() -> Self {
        Compiler::new()
    }
}

impl Compiler {
    #[must_use]
    pub fn new() -> Compiler {
        Compiler {
            phase: Phase::Copy(0),
            nodes: Vec::new(),
            tree: Tree::default(),
            an: Analyses::new(),
            code: Vec::new(),
            jobs: Vec::new(),
            grammars: Vec::new(),
            calls_lua: false,
            spent: 0,
        }
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        let b = |cap: usize, size: usize| cap.saturating_mul(size);
        [
            b(self.nodes.capacity(), std::mem::size_of::<Node>()),
            self.tree.heap_bytes(),
            self.an.heap_bytes(),
            b(self.code.capacity(), std::mem::size_of::<Slot>()),
            b(self.jobs.capacity(), std::mem::size_of::<Job>()),
            self.grammars.iter().fold(0usize, |n, g| {
                n.saturating_add(b(
                    g.positions.capacity().saturating_add(g.calls.capacity()),
                    std::mem::size_of::<usize>(),
                ))
            }),
            match &self.phase {
                Phase::Fix(f) => f.heap_bytes(),
                _ => 0,
            },
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }

    /// For the tests: units of budget spent, and the nodes whose `getfirst`
    /// is memoised.
    #[must_use]
    pub fn stats(&self) -> (u64, usize) {
        (self.spent, self.an.stats().1)
    }

    /// Run until the program is made or `budget` is spent. `src` is the
    /// pattern's tree, the same at every step.
    pub fn step(&mut self, src: &Tree, budget: &mut u32) -> Poll<Result<Program, CodeError>> {
        let start = *budget;
        let r = self.run(src, budget);
        self.spent = self
            .spent
            .saturating_add(u64::from(start.saturating_sub(*budget)));
        match r {
            Ok(Some(p)) => Poll::Ready(Ok(p)),
            Ok(None) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn run(&mut self, src: &Tree, budget: &mut u32) -> Result<Option<Program>, CodeError> {
        loop {
            match &mut self.phase {
                Phase::Copy(from) => {
                    let from = *from;
                    if from == 0 && (src.len() > MAX_TREE || !reserve(&mut self.nodes, src.len())) {
                        return Err(CodeError::NotEnoughMemory);
                    }
                    if *budget == 0 {
                        return Ok(None);
                    }
                    let max = usize::try_from(*budget)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(COPY_PER_FUEL);
                    let end = src.len().min(from.saturating_add(max));
                    if let Some(part) = src.nodes().get(from..end) {
                        self.nodes.extend_from_slice(part);
                    }
                    let cost =
                        u32::try_from((end - from).div_ceil(COPY_PER_FUEL)).unwrap_or(u32::MAX);
                    *budget = budget.saturating_sub(cost.max(1));
                    if end < src.len() {
                        self.phase = Phase::Copy(end);
                    } else {
                        self.tree = Tree::from_nodes(std::mem::take(&mut self.nodes));
                        self.phase = Phase::Fix(FinalFix::new(None, 0));
                    }
                }
                Phase::Fix(fix) => match fix.step(&mut self.tree, &|_| 0, budget) {
                    Poll::Pending => return Ok(None),
                    Poll::Ready(r) => {
                        r?;
                        self.an.ensure_memos(self.tree.len())?;
                        self.push_job(Job::Gen {
                            t: 0,
                            opt: false,
                            tt: None,
                            fl: FULL,
                        })?;
                        self.phase = Phase::Gen;
                    }
                },
                Phase::Gen => {
                    let tree = std::mem::take(&mut self.tree);
                    let r = self.gen(&tree, budget);
                    self.tree = tree;
                    if !r? {
                        return Ok(None);
                    }
                    self.emit(Op::End, 0)?;
                    self.phase = Phase::Peephole(0);
                }
                Phase::Peephole(i) => {
                    let i = *i;
                    match self.peephole(i, budget)? {
                        Some(next) => {
                            self.phase = Phase::Peephole(next);
                            return Ok(None);
                        }
                        None => self.phase = Phase::Done,
                    }
                }
                Phase::Done => {
                    let mut slots = std::mem::take(&mut self.code);
                    slots.shrink_to_fit();
                    return Ok(Some(Program {
                        slots,
                        calls_lua: self.calls_lua,
                    }));
                }
            }
        }
    }

    // ------------------------------------------------------------ emission

    fn push_job(&mut self, job: Job) -> Result<(), CodeError> {
        if self.jobs.len() == self.jobs.capacity() && !reserve(&mut self.jobs, 1) {
            return Err(CodeError::NotEnoughMemory);
        }
        self.jobs.push(job);
        Ok(())
    }

    fn here(&self) -> usize {
        self.code.len()
    }

    /// `nextinstruction`: a slot, through the memory budget, and never past
    /// what the C's `int` offsets reach.
    fn slot(&mut self, s: Slot) -> Result<usize, CodeError> {
        let i = self.code.len();
        if i >= i32::MAX as usize {
            return Err(CodeError::NotEnoughMemory);
        }
        if i == self.code.capacity() && !reserve(&mut self.code, 1) {
            return Err(CodeError::NotEnoughMemory);
        }
        self.code.push(s);
        Ok(i)
    }

    /// `addinstruction`.
    fn emit(&mut self, op: Op, aux: u8) -> Result<usize, CodeError> {
        self.slot(Slot::Inst { op, aux, key: 0 })
    }

    /// `addoffsetinst`: an instruction and room for its label.
    fn emit_label(&mut self, op: Op) -> Result<usize, CodeError> {
        let i = self.emit(op, 0)?;
        self.slot(Slot::Offset(0))?;
        Ok(i)
    }

    /// `addinstcap`.
    fn emit_cap(&mut self, op: Op, kind: u8, key: Key, off: u8) -> Result<usize, CodeError> {
        if op == Op::CloseRunTime || super::kind_calls_lua(kind) {
            self.calls_lua = true;
        }
        self.slot(Slot::Inst {
            op,
            aux: kind | (off << 4),
            key,
        })
    }

    /// `addcharset`.
    fn emit_set(&mut self, cs: &Charset) -> Result<(), CodeError> {
        for chunk in cs.0.chunks_exact(4) {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            self.slot(Slot::Bytes(b))?;
        }
        Ok(())
    }

    /// `jumptothere`: instruction `i`'s label is `target`.
    fn jump_to(&mut self, i: Option<usize>, target: usize) -> Result<(), CodeError> {
        let Some(i) = i else {
            return Ok(());
        };
        let off = i64::try_from(target).map_err(|_| malformed())?
            - i64::try_from(i).map_err(|_| malformed())?;
        let off = i32::try_from(off).map_err(|_| CodeError::NotEnoughMemory)?;
        match self.code.get_mut(i + 1) {
            Some(s) => {
                *s = Slot::Offset(off);
                Ok(())
            }
            None => Err(malformed()),
        }
    }

    /// `jumptohere`.
    fn jump_here(&mut self, i: Option<usize>) -> Result<(), CodeError> {
        self.jump_to(i, self.here())
    }

    /// The test instruction at `tt`, if any.
    fn test_at(&self, tt: Option<usize>) -> Option<(Op, u8)> {
        tt.and_then(|i| inst_at(&self.code, i))
            .map(|(op, aux, _)| (op, aux))
    }

    /// `codechar`: `Char`, or `Any` where a test for the same byte guards it.
    fn code_char(&mut self, c: u8, tt: Option<usize>) -> Result<(), CodeError> {
        if self.test_at(tt) == Some((Op::TestChar, c)) {
            self.emit(Op::Any, 0)?;
        } else {
            self.emit(Op::Char, c)?;
        }
        Ok(())
    }

    /// `codecharset`.
    fn code_charset(&mut self, cs: &Charset, tt: Option<usize>) -> Result<(), CodeError> {
        match set_kind(cs) {
            SetKind::Char(c) => self.code_char(c, tt),
            SetKind::Set => {
                let guarded = matches!(self.test_at(tt), Some((Op::TestSet, _)))
                    && tt.and_then(|i| super::charset_at(&self.code, i + 2)) == Some(*cs);
                if guarded {
                    self.emit(Op::Any, 0)?;
                } else {
                    self.emit(Op::Set, 0)?;
                    self.emit_set(cs)?;
                }
                Ok(())
            }
            SetKind::Fail => self.emit(Op::Fail, 0).map(|_| ()),
            SetKind::Any => self.emit(Op::Any, 0).map(|_| ()),
        }
    }

    /// `codetestset`: a test that fails where the charset cannot start the
    /// pattern; none if `e` (the pattern may match the empty string).
    fn code_test(&mut self, cs: &Charset, e: bool) -> Result<Option<usize>, CodeError> {
        if e {
            return Ok(None);
        }
        let i = match set_kind(cs) {
            // Always jumps.
            SetKind::Fail => self.emit_label(Op::Jmp)?,
            SetKind::Any => self.emit_label(Op::TestAny)?,
            SetKind::Char(c) => {
                let i = self.emit_label(Op::TestChar)?;
                if let Some(Slot::Inst { aux, .. }) = self.code.get_mut(i) {
                    *aux = c;
                }
                i
            }
            SetKind::Set => {
                let i = self.emit_label(Op::TestSet)?;
                self.emit_set(cs)?;
                i
            }
        };
        Ok(Some(i))
    }

    /// `finaltarget`: where a chain of `Jmp`s from `i` ends, at a unit of
    /// budget a jump (the units are taken whatever is left: a chain is never
    /// longer than the code).
    fn final_target(&self, mut i: usize, budget: &mut u32) -> Result<usize, CodeError> {
        let mut hops = 0usize;
        while matches!(inst_at(&self.code, i), Some((Op::Jmp, _, _))) {
            i = target_at(&self.code, i).ok_or_else(malformed)?;
            hops += 1;
            if hops > self.code.len() {
                return Err(malformed());
            }
            *budget = budget.saturating_sub(1);
        }
        Ok(i)
    }

    /// `finallabel`.
    fn final_label(&self, i: usize, budget: &mut u32) -> Result<usize, CodeError> {
        self.final_target(target_at(&self.code, i).ok_or_else(malformed)?, budget)
    }

    // ------------------------------------------------------------ codegen

    /// Run jobs until none is left (true) or the budget is spent.
    fn gen(&mut self, tree: &Tree, budget: &mut u32) -> Result<bool, CodeError> {
        while let Some(&job) = self.jobs.last() {
            if *budget == 0 {
                return Ok(false);
            }
            if self.job(tree, job, budget)?.is_none() {
                return Ok(false);
            }
            *budget = budget.saturating_sub(1);
        }
        Ok(true)
    }

    /// One job: `None` if an analysis it needs is not ready (the job stays,
    /// nothing emitted).
    fn job(&mut self, tree: &Tree, job: Job, budget: &mut u32) -> Result<Option<()>, CodeError> {
        match job {
            Job::Gen { t, opt, tt, fl } => return self.gen_node(tree, t, opt, tt, fl, budget),
            Job::SeqThen {
                p1,
                p2,
                opt,
                tt,
                fl,
            } => {
                let n = ready!(self.an.fixedlen(tree, p1, budget));
                self.jobs.pop();
                // Can `p1` consume anything? Then `tt` no longer protects.
                let tt = if n != 0 { None } else { tt };
                self.push_job(Job::Gen { t: p2, opt, tt, fl })?;
            }
            Job::ChoiceTest {
                p2,
                opt,
                fl,
                test,
                emptyp2,
            } => {
                self.jobs.pop();
                let jmp = if emptyp2 {
                    None
                } else {
                    Some(self.emit_label(Op::Jmp)?)
                };
                self.jump_here(Some(test))?;
                self.push_job(Job::Here(jmp))?;
                self.push_job(Job::Gen {
                    t: p2,
                    opt,
                    tt: None,
                    fl,
                })?;
            }
            Job::ChoiceGeneral {
                p2,
                opt,
                fl,
                test,
                pchoice,
            } => {
                self.jobs.pop();
                let pcommit = self.emit_label(Op::Commit)?;
                self.jump_here(Some(pchoice))?;
                self.jump_here(test)?;
                self.push_job(Job::Here(Some(pcommit)))?;
                self.push_job(Job::Gen {
                    t: p2,
                    opt,
                    tt: None,
                    fl,
                })?;
            }
            Job::Here(i) => {
                self.jobs.pop();
                self.jump_here(i)?;
            }
            Job::AndBehind { n } => {
                self.jobs.pop();
                if n > 0 {
                    self.emit(Op::Behind, n)?;
                }
            }
            Job::AndGeneral { pchoice } => {
                self.jobs.pop();
                let pcommit = self.emit_label(Op::BackCommit)?;
                self.jump_here(Some(pchoice))?;
                self.emit(Op::Fail, 0)?;
                self.jump_here(Some(pcommit))?;
            }
            Job::CapFull { kind, key, len } => {
                self.jobs.pop();
                self.emit_cap(Op::FullCapture, kind, key, len)?;
            }
            Job::CapClose => {
                self.jobs.pop();
                self.emit_cap(Op::CloseCapture, CapKind::Close as u8, 0, 0)?;
            }
            Job::RunTimeClose => {
                self.jobs.pop();
                self.emit_cap(Op::CloseRunTime, CapKind::Close as u8, 0, 0)?;
            }
            Job::RepTest { test } => {
                self.jobs.pop();
                let jmp = self.emit_label(Op::Jmp)?;
                self.jump_here(Some(test))?;
                self.jump_to(Some(jmp), test)?;
            }
            Job::RepChoice { pchoice, l2, test } => {
                self.jobs.pop();
                let commit = self.emit_label(Op::PartialCommit)?;
                self.jump_to(Some(commit), l2)?;
                self.jump_here(pchoice)?;
                self.jump_here(test)?;
            }
            Job::NotEnd { pchoice, test } => {
                self.jobs.pop();
                self.emit(Op::FailTwice, 0)?;
                self.jump_here(Some(pchoice))?;
                self.jump_here(test)?;
            }
            Job::RuleEnd { r } => {
                self.jobs.pop();
                self.emit(Op::Ret, 0)?;
                self.next_rule(tree, tree.sib2(r).ok_or_else(malformed)?)?;
            }
            Job::CorrectCalls { k } => {
                return self.correct_calls(k, budget);
            }
        }
        Ok(Some(()))
    }

    /// `codegen` (`lpeg.c:1784`) of node `t`.
    fn gen_node(
        &mut self,
        tree: &Tree,
        t: usize,
        opt: bool,
        tt: Option<usize>,
        fl: SetId,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        let node = tree.node(t).ok_or_else(malformed)?;
        let s1 = || tree.sib1(t).ok_or_else(malformed);
        let s2 = || tree.sib2(t).ok_or_else(malformed);
        match node.tag {
            Tag::Char => {
                self.jobs.pop();
                self.code_char(u8::try_from(node.u).map_err(|_| malformed())?, tt)?;
            }
            Tag::Any => {
                self.jobs.pop();
                self.emit(Op::Any, 0)?;
            }
            Tag::Set => {
                self.jobs.pop();
                let cs = tree.charset_at(t).ok_or_else(malformed)?;
                self.code_charset(&cs, tt)?;
            }
            Tag::True => {
                self.jobs.pop();
            }
            Tag::False => {
                self.jobs.pop();
                self.emit(Op::Fail, 0)?;
            }
            Tag::Choice => return self.code_choice(tree, s1()?, s2()?, opt, fl, budget),
            Tag::Rep => return self.code_rep(tree, s1()?, opt, fl, budget),
            // `codebehind`.
            Tag::Behind => {
                self.jobs.pop();
                if node.u > 0 {
                    self.emit(Op::Behind, u8::try_from(node.u).map_err(|_| malformed())?)?;
                }
                self.push_job(Job::Gen {
                    t: s1()?,
                    opt: false,
                    tt: None,
                    fl: FULL,
                })?;
            }
            Tag::Not => return self.code_not(tree, s1()?, budget),
            Tag::And => return self.code_and(tree, s1()?, tt, budget),
            Tag::Capture => return self.code_capture(tree, node, s1()?, tt, fl, budget),
            // `coderuntime`.
            Tag::RunTime => {
                self.jobs.pop();
                self.emit_cap(Op::OpenCapture, CapKind::Group as u8, node.key, 0)?;
                self.push_job(Job::RunTimeClose)?;
                self.push_job(Job::Gen {
                    t: s1()?,
                    opt: false,
                    tt,
                    fl: FULL,
                })?;
            }
            // `codegrammar`: call L1; jmp L2; L1: rule 1; ret; rule 2; ret;
            // ...; L2:
            Tag::Grammar => {
                self.jobs.pop();
                let firstcall = self.emit_label(Op::Call)?;
                let jumptoend = self.emit_label(Op::Jmp)?;
                self.jump_here(Some(firstcall))?;
                if self.grammars.len() == self.grammars.capacity()
                    && !reserve(&mut self.grammars, 1)
                {
                    return Err(CodeError::NotEnoughMemory);
                }
                self.grammars.push(GrammarFrame {
                    positions: Vec::new(),
                    calls: Vec::new(),
                    jumptoend,
                });
                self.next_rule(tree, s1()?)?;
            }
            // `codecall`: an open call of the rule's number, closed by
            // `correctcalls` once the grammar is coded.
            Tag::Call => {
                self.jobs.pop();
                let rule = tree.node(s2()?).ok_or_else(malformed)?;
                if rule.tag != Tag::Rule {
                    return Err(malformed());
                }
                let c = self.emit_label(Op::OpenCall)?;
                if let Some(Slot::Inst { key, .. }) = self.code.get_mut(c) {
                    *key = Key::from(rule.cap);
                }
                let frame = self.grammars.last_mut().ok_or_else(malformed)?;
                if frame.calls.len() == frame.calls.capacity() && !reserve(&mut frame.calls, 1) {
                    return Err(CodeError::NotEnoughMemory);
                }
                frame.calls.push(c);
            }
            // `codeseq1`, then the second child in place.
            Tag::Seq => {
                let (p1, p2) = (s1()?, s2()?);
                let fl1 = if ready!(self.an.needfollow(tree, p1, budget)) {
                    // `p1`'s follow is `p2`'s first.
                    let f2 = ready!(self.an.first(tree, p2, budget));
                    let cs = self.an.first_set(f2, fl);
                    self.an.intern(cs)?
                } else {
                    FULL
                };
                self.jobs.pop();
                self.push_job(Job::SeqThen {
                    p1,
                    p2,
                    opt,
                    tt,
                    fl,
                })?;
                self.push_job(Job::Gen {
                    t: p1,
                    opt: false,
                    tt,
                    fl: fl1,
                })?;
            }
            Tag::OpenCall | Tag::Rule => return Err(malformed()),
        }
        Ok(Some(()))
    }

    /// `codechoice` (`lpeg.c:1544`).
    fn code_choice(
        &mut self,
        tree: &Tree,
        p1: usize,
        p2: usize,
        opt: bool,
        fl: SetId,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        let emptyp2 = tree.node(p2).ok_or_else(malformed)?.tag == Tag::True;
        let f1 = ready!(self.an.first(tree, p1, budget));
        let cs1 = self.an.first_set(f1, FULL);
        // `headfail(p1) || (!e1 && disjoint(cs1, first(p2, fl)))`, asked in
        // that order.
        let mut test_form = ready!(self.an.headfail(tree, p1, budget));
        if !test_form && f1.e == 0 {
            let f2 = ready!(self.an.first(tree, p2, budget));
            test_form = disjoint(&cs1, &self.an.first_set(f2, fl));
        }
        self.jobs.pop();
        if test_form {
            // test (fail(p1)) -> L1; p1; jmp L2; L1: p2; L2:
            let test = self.code_test(&cs1, false)?.ok_or_else(malformed)?;
            self.push_job(Job::ChoiceTest {
                p2,
                opt,
                fl,
                test,
                emptyp2,
            })?;
            self.push_job(Job::Gen {
                t: p1,
                opt: false,
                tt: Some(test),
                fl,
            })?;
        } else if opt && emptyp2 {
            // p1? == IPartialCommit; p1
            let pc = self.emit_label(Op::PartialCommit)?;
            self.jump_here(Some(pc))?;
            self.push_job(Job::Gen {
                t: p1,
                opt: true,
                tt: None,
                fl: FULL,
            })?;
        } else {
            // test(fail(p1)) -> L1; choice L1; <p1>; commit L2; L1: <p2>; L2:
            let test = self.code_test(&cs1, f1.e != 0)?;
            let pchoice = self.emit_label(Op::Choice)?;
            self.push_job(Job::ChoiceGeneral {
                p2,
                opt,
                fl,
                test,
                pchoice,
            })?;
            self.push_job(Job::Gen {
                t: p1,
                opt: emptyp2,
                tt: test,
                fl: FULL,
            })?;
        }
        Ok(Some(()))
    }

    /// `coderep` (`lpeg.c:1643`).
    fn code_rep(
        &mut self,
        tree: &Tree,
        b: usize,
        opt: bool,
        fl: SetId,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        if let Some(cs) = to_charset(tree, b) {
            self.jobs.pop();
            self.emit(Op::Span, 0)?;
            self.emit_set(&cs)?;
            return Ok(Some(()));
        }
        let f = ready!(self.an.first(tree, b, budget));
        let st = self.an.first_set(f, FULL);
        let test_form = ready!(self.an.headfail(tree, b, budget))
            || (f.e == 0 && disjoint(&st, &self.an.set(fl)));
        self.jobs.pop();
        if test_form {
            // L1: test (fail(p1)) -> L2; <p>; jmp L1; L2:
            let test = self.code_test(&st, false)?.ok_or_else(malformed)?;
            self.push_job(Job::RepTest { test })?;
            self.push_job(Job::Gen {
                t: b,
                opt,
                tt: Some(test),
                fl: FULL,
            })?;
        } else {
            // test(fail(p1)) -> L2; choice L2; L1: <p>; partialcommit L1; L2:
            // or (if 'opt'): partialcommit L1; L1: <p>; partialcommit L1;
            let test = self.code_test(&st, f.e != 0)?;
            let pchoice = if opt {
                let pc = self.emit_label(Op::PartialCommit)?;
                self.jump_here(Some(pc))?;
                None
            } else {
                Some(self.emit_label(Op::Choice)?)
            };
            let l2 = self.here();
            self.push_job(Job::RepChoice { pchoice, l2, test })?;
            self.push_job(Job::Gen {
                t: b,
                opt: false,
                tt: None,
                fl: FULL,
            })?;
        }
        Ok(Some(()))
    }

    /// `codenot` (`lpeg.c:1689`).
    fn code_not(
        &mut self,
        tree: &Tree,
        b: usize,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        let f = ready!(self.an.first(tree, b, budget));
        let headfail = ready!(self.an.headfail(tree, b, budget));
        self.jobs.pop();
        let st = self.an.first_set(f, FULL);
        let test = self.code_test(&st, f.e != 0)?;
        if headfail {
            // test (fail(p1)) -> L1; fail; L1:
            self.emit(Op::Fail, 0)?;
            self.jump_here(test)?;
        } else {
            // test(fail(p))-> L1; choice L1; <p>; failtwice; L1:
            let pchoice = self.emit_label(Op::Choice)?;
            self.push_job(Job::NotEnd { pchoice, test })?;
            self.push_job(Job::Gen {
                t: b,
                opt: false,
                tt: None,
                fl: FULL,
            })?;
        }
        Ok(Some(()))
    }

    /// `codeand` (`lpeg.c:1587`): with a fixed length and no captures,
    /// `<p>; behind n`.
    fn code_and(
        &mut self,
        tree: &Tree,
        b: usize,
        tt: Option<usize>,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        let n = ready!(self.an.fixedlen(tree, b, budget));
        let fixed = (0..=MAXBEHIND).contains(&n) && !ready!(self.an.hascaptures(tree, b, budget));
        self.jobs.pop();
        if fixed {
            self.push_job(Job::AndBehind {
                n: u8::try_from(n).map_err(|_| malformed())?,
            })?;
        } else {
            // Choice L1; p1; BackCommit L2; L1: Fail; L2:
            let pchoice = self.emit_label(Op::Choice)?;
            self.push_job(Job::AndGeneral { pchoice })?;
        }
        self.push_job(Job::Gen {
            t: b,
            opt: false,
            tt,
            fl: FULL,
        })?;
        Ok(Some(()))
    }

    /// `codecapture` (`lpeg.c:1611`): a pattern of fixed length up to
    /// `MAXOFF` with no captures (`hascaptures` follows no call) gets one
    /// `FullCapture` after it; anything else an open and a close.
    fn code_capture(
        &mut self,
        tree: &Tree,
        node: Node,
        b: usize,
        tt: Option<usize>,
        fl: SetId,
        budget: &mut u32,
    ) -> Result<Option<()>, CodeError> {
        let len = ready!(self.an.fixedlen(tree, b, budget));
        let full = (0..=MAXOFF).contains(&len) && !ready!(self.an.hascaptures(tree, b, budget));
        self.jobs.pop();
        if full {
            self.push_job(Job::CapFull {
                kind: node.cap,
                key: node.key,
                len: u8::try_from(len).map_err(|_| malformed())?,
            })?;
        } else {
            self.emit_cap(Op::OpenCapture, node.cap, node.key, 0)?;
            self.push_job(Job::CapClose)?;
        }
        self.push_job(Job::Gen {
            t: b,
            opt: false,
            tt,
            fl,
        })?;
        Ok(Some(()))
    }

    /// `codegrammar`'s loop: code rule `r`, or, at the list's end, the jump
    /// to the end and `correctcalls`.
    fn next_rule(&mut self, tree: &Tree, r: usize) -> Result<(), CodeError> {
        let node = tree.node(r).ok_or_else(malformed)?;
        let here = self.here();
        let frame = self.grammars.last_mut().ok_or_else(malformed)?;
        if node.tag == Tag::Rule {
            if frame.positions.len() == frame.positions.capacity()
                && !reserve(&mut frame.positions, 1)
            {
                return Err(CodeError::NotEnoughMemory);
            }
            frame.positions.push(here);
            self.push_job(Job::RuleEnd { r })?;
            self.push_job(Job::Gen {
                t: tree.sib1(r).ok_or_else(malformed)?,
                opt: false,
                tt: None,
                fl: FULL,
            })?;
        } else {
            let jumptoend = frame.jumptoend;
            self.jump_here(Some(jumptoend))?;
            self.push_job(Job::CorrectCalls { k: 0 })?;
        }
        Ok(())
    }

    /// `correctcalls` (`lpeg.c:1710`): each open call of the innermost
    /// grammar becomes a call of its rule, or a jump to it where a return
    /// follows (a tail call), in the order of the code. The C scans the
    /// grammar's code for them, nested grammars' included, which makes
    /// grammars nested `n` deep quadratic in `n`; nested grammars were
    /// corrected before, so the scan meets only these, and this visits only
    /// these. A unit of budget a call.
    fn correct_calls(&mut self, mut k: usize, budget: &mut u32) -> Result<Option<()>, CodeError> {
        loop {
            let frame = self.grammars.last().ok_or_else(malformed)?;
            let Some(&i) = frame.calls.get(k) else { break };
            if *budget == 0 {
                if let Some(Job::CorrectCalls { k: at }) = self.jobs.last_mut() {
                    *at = k;
                }
                return Ok(None);
            }
            *budget -= 1;
            let (op, _, key) = inst_at(&self.code, i).ok_or_else(malformed)?;
            if op != Op::OpenCall {
                return Err(malformed());
            }
            let rule = *frame
                .positions
                .get(usize::try_from(key).map_err(|_| malformed())?)
                .ok_or_else(malformed)?;
            let ft = self.final_target(i + 2, budget)?;
            let tail = matches!(inst_at(&self.code, ft), Some((Op::Ret, _, _)));
            if let Some(Slot::Inst { op, .. }) = self.code.get_mut(i) {
                *op = if tail { Op::Jmp } else { Op::Call };
            }
            self.jump_to(Some(i), rule)?;
            k += 1;
        }
        self.jobs.pop();
        self.grammars.pop();
        Ok(Some(()))
    }

    // ------------------------------------------------------------ peephole

    /// `peephole` (`lpeg.c:1821`) from slot `i`: every label made final; a
    /// jump to an instruction that always jumps or ends becomes that
    /// instruction. `Some(i)` to go on from `i` when the budget runs out.
    ///
    /// The C goes on from `i - 1` after turning a jump into a commit, to
    /// re-optimise its label (`lpeg.c:1846`); that slot is the last word of
    /// the instruction before, often an offset or charset bytes, and the
    /// scan that follows is misaligned (`lpeg-codegen-jump-out-of-code`).
    /// The new label is already final, so this goes on after the
    /// instruction, as the C does whenever it stays aligned.
    fn peephole(&mut self, mut i: usize, budget: &mut u32) -> Result<Option<usize>, CodeError> {
        while i < self.code.len() {
            if *budget == 0 {
                return Ok(Some(i));
            }
            *budget -= 1;
            let (op, _, _) = inst_at(&self.code, i).ok_or_else(malformed)?;
            match op {
                Op::Choice
                | Op::Call
                | Op::Commit
                | Op::PartialCommit
                | Op::BackCommit
                | Op::TestChar
                | Op::TestSet
                | Op::TestAny => {
                    let l = self.final_label(i, budget)?;
                    self.jump_to(Some(i), l)?;
                }
                Op::Jmp => {
                    let ft = self.final_target(i, budget)?;
                    let target = *self.code.get(ft).ok_or_else(malformed)?;
                    match inst_at(&self.code, ft) {
                        // Instructions that end or jump on their own: the
                        // jump becomes one, its label slot a filler.
                        Some((Op::Ret | Op::Fail | Op::FailTwice | Op::End, _, _)) => {
                            self.code[i] = target;
                            self.code[i + 1] = Slot::Inst {
                                op: Op::Any,
                                aux: 0,
                                key: 0,
                            };
                        }
                        // Ones that jump explicitly: the jump becomes one,
                        // with its final label.
                        Some((Op::Commit | Op::PartialCommit | Op::BackCommit, _, _)) => {
                            let fft = self.final_label(ft, budget)?;
                            self.code[i] = target;
                            self.jump_to(Some(i), fft)?;
                        }
                        _ => self.jump_to(Some(i), ft)?,
                    }
                }
                _ => {}
            }
            let (op, _, _) = inst_at(&self.code, i).ok_or_else(malformed)?;
            i += op.size();
        }
        Ok(None)
    }
}
