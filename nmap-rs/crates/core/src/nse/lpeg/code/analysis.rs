//! The analyses code generation asks of a tree (`lpeg.c:1046-1302`), each
//! node's answer computed once (E10).
//!
//! The C's `checkaux` (`nullable`, `nofail`), `headfail`, `getfirst` and
//! `fixedlenx` follow calls into rules, and codegen asks them of nested
//! subtrees again and again, so over a grammar whose rules call the next one
//! twice they take time exponential in its depth (`docs/M6.6-ANALYSIS.md`
//! §1.1). Each is a pure function of a node:
//! - `checkaux` and `headfail` carry no other state: memoised per node.
//! - `getfirst(t, fl)` depends on the follow set `fl`, but only in a closed
//!   form: `FIRST(t, fl) = Y(t) ∪ (fl ∩ X(t))`, with `X`, `Y` and the
//!   empty/run-time flag `e` independent of `fl` (each case of
//!   `lpeg.c:1175-1250` admits it; checked against the C at every codegen
//!   call site of two corpora, and here against a transliteration,
//!   `code/tests.rs`). So it is memoised per node, never per (node, follow
//!   set): a memo keyed by the follow set holds 2^(n+1)-1 keys on the
//!   nullable-suffix chain `Rᵢ ← Rᵢ₋₁ cᵢ^-1 / Rᵢ₋₁ dᵢ^-1` (D3 condition 3).
//! - `fixedlenx(t, count)` carries the number of calls already followed,
//!   which stops it at [`MAXRULES`]. Its answer is either the pattern's one
//!   length or -1, and once it is the length at some count it is that at
//!   every smaller count (fewer calls followed so far leave more to follow;
//!   by induction on the walk). So each node keeps the largest count it
//!   answered with its length and the smallest it answered -1, and a node
//!   whose walk met no call answers alike at every count.
//! - `hascaptures` follows no call (`numsiblings[TCall]` is 0, `:2139`), so
//!   it is one pass over the tree's slots, bottom-up.
//!
//! **Cycles.** In a verified grammar only `getfirst` can meet a rule already
//! on its own walk: it descends into a look-behind's pattern, where the
//! verifier does not (`lpeg-getfirst-unbounded-recursion`). The C's descent
//! does not depend on the follow set, so the C's recursion would never end
//! exactly when this walk re-enters a rule it is still in: that is an error
//! here, raised by the first match that compiles such a use. Any other
//! re-entry is reported the same way rather than looped on.
//!
//! **Pre-emption.** Every analysis is a loop over one explicit stack of
//! tasks, a unit of budget a step; an answer not ready when the budget runs
//! out is asked again, and the walk goes on from where it stopped.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "node indices are below MAX_TREE (2^31 - 1) and counts below MAXRULES + 1, so \
              their sums cannot overflow; lengths are summed in i64 from values at most \
              i32::MAX"
)]

use std::collections::HashMap;

use super::super::tree::{Charset, Tag, Tree, TreeError, CHARSET_SIZE, MAXRULES, SET_SLOTS};
use super::CodeError;
use crate::nse::stdlib::reserve;

/// A memo state: not asked yet, being computed, or answered. In the
/// `hascaptures` pass, `NODE` marks a slot that is a node, not yet answered.
const UNKNOWN: u8 = 0;
const NODE: u8 = 1;
const BUSY: u8 = 1;
const NO: u8 = 2;
const YES: u8 = 3;

/// The bytes one entry of the charset map takes, about.
const SET_ENTRY_BYTES: usize = CHARSET_SIZE + 4 + 1 + 8;

/// The id of an interned charset: the full set and the empty one first.
pub(crate) type SetId = u32;
pub(crate) const FULL: SetId = 0;
pub(crate) const EMPTY: SetId = 1;

/// `getfirst`'s answer for a node, independent of the follow set:
/// `FIRST(t, fl) = y ∪ (fl ∩ x)`, and `e` (`lpeg.c:1162-1170`): 0 if a test
/// on the first set may stand in for the pattern, 1 if it can match the
/// empty string, 2 if it holds a match-time capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct First {
    pub x: SetId,
    pub y: SetId,
    pub e: u8,
}

#[derive(Debug, Clone, Copy)]
struct FirstMemo {
    first: First,
    state: u8,
}

/// `fixedlenx`'s answers at the counts asked so far: `value` is the length
/// wherever the count is at most `ok_max`; at `fail_min` and above it is -1.
#[derive(Debug, Clone, Copy)]
struct LenMemo {
    value: i32,
    ok_max: i16,
    fail_min: i16,
}

const LEN_NONE: LenMemo = LenMemo {
    value: 0,
    ok_max: -1,
    fail_min: i16::MAX,
};

/// One pending piece of an analysis.
#[derive(Debug, Clone, Copy)]
enum Task {
    /// `checkaux(t, pred)`.
    Aux { t: usize, nofail: bool, stage: u8 },
    /// `headfail(t)`.
    Head { t: usize, stage: u8 },
    /// `getfirst(t, _)`.
    First { t: usize, stage: u8 },
    /// `fixedlenx(t, count)`: `acc` is the first child's length, `dep`
    /// whether the walk met a call so far.
    Len {
        t: usize,
        count: u8,
        stage: u8,
        acc: i32,
        dep: bool,
    },
}

/// What a step of a task does next.
enum Next {
    /// Wait for this task, then come back.
    Push(Task),
    /// The task is done; its answer is in its memo.
    Pop,
}

/// The memoised analyses of one tree, for one compilation.
#[derive(Debug, Default)]
pub(crate) struct Analyses {
    nullable: Vec<u8>,
    nofail: Vec<u8>,
    head: Vec<u8>,
    first: Vec<FirstMemo>,
    len: Vec<LenMemo>,
    /// Whether a len memo entry was made with no call on its walk.
    len_free: Vec<u8>,
    /// `hascaptures`: per slot, 0 for a charset's data, else a memo state.
    caps: Vec<u8>,
    /// Where the pass computing `caps` is: marking nodes forwards, then
    /// answering backwards.
    caps_pass: Option<(bool, usize)>,
    caps_done: bool,
    /// `needfollow`'s answers, and where a walk for one is.
    follow: Vec<u8>,
    follow_at: Option<usize>,
    sets: Vec<Charset>,
    set_ids: HashMap<[u8; CHARSET_SIZE], SetId>,
    tasks: Vec<Task>,
    /// Steps taken, for the tests.
    steps: u64,
}

fn tag_at(tree: &Tree, i: usize) -> Result<Tag, CodeError> {
    tree.node(i)
        .map(|n| n.tag)
        .ok_or(CodeError::Tree(TreeError::Malformed))
}

fn sib1(tree: &Tree, i: usize) -> Result<usize, CodeError> {
    tree.sib1(i).ok_or(CodeError::Tree(TreeError::Malformed))
}

fn sib2(tree: &Tree, i: usize) -> Result<usize, CodeError> {
    tree.sib2(i).ok_or(CodeError::Tree(TreeError::Malformed))
}

/// Push onto a vector, growing it through the memory budget.
fn push<T>(v: &mut Vec<T>, x: T) -> Result<(), CodeError> {
    if v.len() == v.capacity() && !reserve(v, 1) {
        return Err(CodeError::NotEnoughMemory);
    }
    v.push(x);
    Ok(())
}

/// `n` copies of `x`, through the memory budget.
fn filled<T: Clone>(n: usize, x: T) -> Result<Vec<T>, CodeError> {
    let mut v = Vec::new();
    if !reserve(&mut v, n) {
        return Err(CodeError::NotEnoughMemory);
    }
    v.resize(n, x);
    Ok(v)
}

/// `tocharset` (`lpeg.c:1022`) of node `i`.
pub(crate) fn to_charset(tree: &Tree, i: usize) -> Option<Charset> {
    let n = tree.node(i)?;
    match n.tag {
        Tag::Set => tree.charset_at(i),
        Tag::Char => {
            let mut cs = Charset::empty();
            cs.add(u8::try_from(n.u).ok()?);
            Some(cs)
        }
        Tag::Any => Some(Charset([0xff; CHARSET_SIZE])),
        _ => None,
    }
}

fn inter(a: &Charset, b: &Charset) -> Charset {
    let mut out = *a;
    for (o, x) in out.0.iter_mut().zip(b.0) {
        *o &= x;
    }
    out
}

fn complement(a: &Charset) -> Charset {
    let mut out = *a;
    for o in &mut out.0 {
        *o = !*o;
    }
    out
}

/// A re-entry of node `t`, already on the walk: the cycle runs from `t`'s
/// task to the top of `tasks`, and passes through a call into a rule (a
/// tree without calls has none). It is named by the rule entered last, as
/// a left recursion; with no rule on it, the tree is malformed.
fn cycle(tree: &Tree, tasks: &[Task], t: usize) -> CodeError {
    let node_of = |task: &Task| match *task {
        Task::Aux { t, .. }
        | Task::Head { t, .. }
        | Task::First { t, .. }
        | Task::Len { t, .. } => t,
    };
    let on_cycle = tasks
        .iter()
        .rposition(|task| node_of(task) == t)
        .map_or(&tasks[..0], |i| &tasks[i..]);
    on_cycle
        .iter()
        .rev()
        .filter_map(|task| tree.node(node_of(task)))
        .find(|n| n.tag == Tag::Rule)
        .map_or(CodeError::Tree(TreeError::Malformed), |n| {
            CodeError::LeftRecursive(n.key)
        })
}

impl Analyses {
    /// The analyses of a tree, each memo made on first use.
    pub(crate) fn new() -> Analyses {
        Analyses::default()
    }

    /// The bytes it holds outside the VM's heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        fn b<T>(v: &Vec<T>) -> usize {
            v.capacity().saturating_mul(std::mem::size_of::<T>())
        }
        [
            b(&self.nullable),
            b(&self.nofail),
            b(&self.head),
            b(&self.first),
            b(&self.len),
            b(&self.len_free),
            b(&self.caps),
            b(&self.follow),
            b(&self.sets),
            b(&self.tasks),
            self.set_ids.capacity().saturating_mul(SET_ENTRY_BYTES),
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }

    /// For the tests: steps taken, and nodes whose `getfirst` is memoised.
    pub(crate) fn stats(&self) -> (u64, usize) {
        let firsts = self.first.iter().filter(|m| m.state == YES).count();
        (self.steps, firsts)
    }

    /// The memo vectors for a tree of `n` slots, and the full and empty
    /// sets as [`FULL`] and [`EMPTY`].
    pub(crate) fn ensure_memos(&mut self, n: usize) -> Result<(), CodeError> {
        if self.sets.is_empty() {
            self.intern(Charset([0xff; CHARSET_SIZE]))?;
            self.intern(Charset::empty())?;
        }
        if self.nullable.len() != n {
            self.nullable = filled(n, UNKNOWN)?;
            self.nofail = filled(n, UNKNOWN)?;
            self.head = filled(n, UNKNOWN)?;
            self.first = filled(
                n,
                FirstMemo {
                    first: First {
                        x: EMPTY,
                        y: EMPTY,
                        e: 0,
                    },
                    state: UNKNOWN,
                },
            )?;
            self.len = filled(n, LEN_NONE)?;
            self.len_free = filled(n, 0)?;
            self.follow = filled(n, UNKNOWN)?;
        }
        Ok(())
    }

    /// The id of `cs`, interning it.
    pub(crate) fn intern(&mut self, cs: Charset) -> Result<SetId, CodeError> {
        if let Some(&id) = self.set_ids.get(&cs.0) {
            return Ok(id);
        }
        let id = SetId::try_from(self.sets.len()).map_err(|_| CodeError::NotEnoughMemory)?;
        push(&mut self.sets, cs)?;
        if self.set_ids.len() == self.set_ids.capacity() {
            // A map entry: the key, the value, a control byte, and slack.
            let grown = self.set_ids.capacity().max(4).saturating_mul(2);
            if !piccolo::budget::allows(grown.saturating_mul(SET_ENTRY_BYTES)) {
                return Err(CodeError::NotEnoughMemory);
            }
        }
        self.set_ids
            .try_reserve(1)
            .map_err(|_| CodeError::NotEnoughMemory)?;
        self.set_ids.insert(cs.0, id);
        Ok(id)
    }

    /// The charset with id `id`.
    pub(crate) fn set(&self, id: SetId) -> Charset {
        self.sets
            .get(usize::try_from(id).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(Charset::empty())
    }

    /// `FIRST(t, fl)`'s set: `y ∪ (fl ∩ x)`.
    pub(crate) fn first_set(&self, f: First, fl: SetId) -> Charset {
        self.set(f.y).union(&inter(&self.set(fl), &self.set(f.x)))
    }

    // ------------------------------------------------------------ queries

    /// `nullable(t)`.
    #[cfg(test)]
    pub(crate) fn nullable(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<bool>, CodeError> {
        self.ask(
            tree,
            budget,
            Task::Aux {
                t,
                nofail: false,
                stage: 0,
            },
            |a| known(a.nullable.get(t)),
        )
    }

    /// `nofail(t)`.
    #[cfg(test)]
    pub(crate) fn nofail(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<bool>, CodeError> {
        self.ask(
            tree,
            budget,
            Task::Aux {
                t,
                nofail: true,
                stage: 0,
            },
            |a| known(a.nofail.get(t)),
        )
    }

    /// `headfail(t)`.
    pub(crate) fn headfail(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<bool>, CodeError> {
        self.ask(tree, budget, Task::Head { t, stage: 0 }, |a| {
            known(a.head.get(t))
        })
    }

    /// `getfirst(t, _)`, in closed form.
    pub(crate) fn first(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<First>, CodeError> {
        self.ask(tree, budget, Task::First { t, stage: 0 }, |a| {
            a.first.get(t).filter(|m| m.state == YES).map(|m| m.first)
        })
    }

    /// `fixedlen(t)`: `fixedlenx(t, 0, 0)`, -1 if variable.
    pub(crate) fn fixedlen(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<i64>, CodeError> {
        let task = Task::Len {
            t,
            count: 0,
            stage: 0,
            acc: 0,
            dep: false,
        };
        self.ask(tree, budget, task, |a| a.len_at(t, 0).map(|(v, _)| v))
    }

    /// `hascaptures(t)` (`lpeg.c:1046`), which follows no call.
    pub(crate) fn hascaptures(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<bool>, CodeError> {
        if !self.caps_done && !self.caps_pass(tree, budget)? {
            return Ok(None);
        }
        match self.caps.get(t) {
            Some(&YES) => Ok(Some(true)),
            Some(&NO) => Ok(Some(false)),
            _ => Err(CodeError::Tree(TreeError::Malformed)),
        }
    }

    /// `needfollow(t)` (`lpeg.c:1287`): a walk down a capture's pattern and a
    /// sequence's second child, to a choice or a repetition. Over a whole
    /// compilation these walks are linear in the tree: a node is on the walk
    /// from the first child of at most one sequence.
    pub(crate) fn needfollow(
        &mut self,
        tree: &Tree,
        t: usize,
        budget: &mut u32,
    ) -> Result<Option<bool>, CodeError> {
        self.ensure_memos(tree.len())?;
        if let Some(v) = known(self.follow.get(t)) {
            return Ok(Some(v));
        }
        let mut at = self.follow_at.take().unwrap_or(t);
        let v = loop {
            if *budget == 0 {
                self.follow_at = Some(at);
                return Ok(None);
            }
            *budget -= 1;
            self.steps += 1;
            match tag_at(tree, at)? {
                Tag::Choice | Tag::Rep => break true,
                Tag::Capture => at = sib1(tree, at)?,
                Tag::Seq => at = sib2(tree, at)?,
                Tag::Rule | Tag::OpenCall => return Err(CodeError::Tree(TreeError::Malformed)),
                _ => break false,
            }
        };
        if let Some(m) = self.follow.get_mut(t) {
            *m = if v { YES } else { NO };
        }
        Ok(Some(v))
    }

    /// Answer from the memo, or run `task` (or the task already under way,
    /// which is always the one asked again) until it answers or the budget
    /// runs out.
    fn ask<T>(
        &mut self,
        tree: &Tree,
        budget: &mut u32,
        task: Task,
        get: impl Fn(&Analyses) -> Option<T>,
    ) -> Result<Option<T>, CodeError> {
        self.ensure_memos(tree.len())?;
        if let Some(v) = get(self) {
            return Ok(Some(v));
        }
        if self.tasks.is_empty() {
            push(&mut self.tasks, task)?;
        }
        if !self.run(tree, budget)? {
            return Ok(None);
        }
        get(self)
            .map(Some)
            .ok_or(CodeError::Tree(TreeError::Malformed))
    }

    /// Run the tasks until none is left (true) or the budget is spent.
    fn run(&mut self, tree: &Tree, budget: &mut u32) -> Result<bool, CodeError> {
        while let Some(&task) = self.tasks.last() {
            if *budget == 0 {
                return Ok(false);
            }
            *budget -= 1;
            self.steps += 1;
            let next = match task {
                Task::Aux { t, nofail, stage } => self.step_aux(tree, t, nofail, stage)?,
                Task::Head { t, stage } => self.step_head(tree, t, stage)?,
                Task::First { t, stage } => self.step_first(tree, t, stage)?,
                Task::Len {
                    t,
                    count,
                    stage,
                    acc,
                    dep,
                } => self.step_len(tree, t, count, stage, acc, dep)?,
            };
            match next {
                Next::Pop => {
                    self.tasks.pop();
                }
                Next::Push(child) => push(&mut self.tasks, child)?,
            }
        }
        Ok(true)
    }

    /// Set the top task's stage.
    fn stage(&mut self, s: u8) {
        if let Some(
            Task::Aux { stage, .. }
            | Task::Head { stage, .. }
            | Task::First { stage, .. }
            | Task::Len { stage, .. },
        ) = self.tasks.last_mut()
        {
            *stage = s;
        }
    }

    // ------------------------------------------------------------ checkaux

    fn aux_memo(&mut self, nofail: bool) -> &mut Vec<u8> {
        if nofail {
            &mut self.nofail
        } else {
            &mut self.nullable
        }
    }

    fn aux_get(&self, t: usize, nofail: bool) -> u8 {
        let m = if nofail { &self.nofail } else { &self.nullable };
        m.get(t).copied().unwrap_or(UNKNOWN)
    }

    fn aux_set(&mut self, t: usize, nofail: bool, v: bool) -> Next {
        if let Some(m) = self.aux_memo(nofail).get_mut(t) {
            *m = if v { YES } else { NO };
        }
        Next::Pop
    }

    /// The answer for child `c`, if known; a re-entry is an error.
    fn aux_child(&self, tree: &Tree, c: usize, nofail: bool) -> Result<Option<bool>, CodeError> {
        match self.aux_get(c, nofail) {
            YES => Ok(Some(true)),
            NO => Ok(Some(false)),
            BUSY => Err(cycle(tree, &self.tasks, c)),
            _ => Ok(None),
        }
    }

    /// `checkaux` (`lpeg.c:1084`). Stages: 0 start; 1 a single child's
    /// answer is the node's (`sib1`, or `sib2` of a call); 2 a sequence's
    /// first child; 3 a choice's second child; 4 a sequence's second; 5 a
    /// choice's first.
    fn step_aux(
        &mut self,
        tree: &Tree,
        t: usize,
        nofail: bool,
        stage: u8,
    ) -> Result<Next, CodeError> {
        let malformed = CodeError::Tree(TreeError::Malformed);
        let push_child = |c: usize| {
            Next::Push(Task::Aux {
                t: c,
                nofail,
                stage: 0,
            })
        };
        match stage {
            0 => {
                match self.aux_get(t, nofail) {
                    YES | NO => return Ok(Next::Pop),
                    BUSY => return Err(cycle(tree, &self.tasks, t)),
                    _ => {}
                }
                let tag = tag_at(tree, t)?;
                let single = match tag {
                    Tag::Char | Tag::Set | Tag::Any | Tag::False | Tag::OpenCall => {
                        return Ok(self.aux_set(t, nofail, false));
                    }
                    Tag::Rep | Tag::True => return Ok(self.aux_set(t, nofail, true)),
                    // Can match the empty string, but can fail.
                    Tag::Not | Tag::Behind => return Ok(self.aux_set(t, nofail, !nofail)),
                    // Matches the empty string; fails exactly when its body does.
                    Tag::And if !nofail => return Ok(self.aux_set(t, nofail, true)),
                    // Can fail; matches the empty string exactly when its body does.
                    Tag::RunTime if nofail => return Ok(self.aux_set(t, nofail, false)),
                    Tag::And | Tag::RunTime | Tag::Capture | Tag::Grammar | Tag::Rule => {
                        Some(sib1(tree, t)?)
                    }
                    Tag::Call => Some(sib2(tree, t)?),
                    Tag::Seq | Tag::Choice => None,
                };
                if let Some(m) = self.aux_memo(nofail).get_mut(t) {
                    *m = BUSY;
                }
                match single {
                    Some(c) => match self.aux_child(tree, c, nofail)? {
                        Some(v) => Ok(self.aux_set(t, nofail, v)),
                        None => {
                            self.stage(1);
                            Ok(push_child(c))
                        }
                    },
                    // A sequence holds if both children do, the first asked
                    // first; a choice if either does, the second first.
                    None if tag == Tag::Seq => {
                        let c = sib1(tree, t)?;
                        match self.aux_child(tree, c, nofail)? {
                            Some(v) => self.step_aux_seq(tree, t, nofail, v),
                            None => {
                                self.stage(2);
                                Ok(push_child(c))
                            }
                        }
                    }
                    None => {
                        let c = sib2(tree, t)?;
                        match self.aux_child(tree, c, nofail)? {
                            Some(v) => self.step_aux_choice(tree, t, nofail, v),
                            None => {
                                self.stage(3);
                                Ok(push_child(c))
                            }
                        }
                    }
                }
            }
            1 => {
                let c = match tag_at(tree, t)? {
                    Tag::Call => sib2(tree, t)?,
                    _ => sib1(tree, t)?,
                };
                let v = self.aux_child(tree, c, nofail)?.ok_or(malformed)?;
                Ok(self.aux_set(t, nofail, v))
            }
            2 => {
                let v = self
                    .aux_child(tree, sib1(tree, t)?, nofail)?
                    .ok_or(malformed)?;
                self.step_aux_seq(tree, t, nofail, v)
            }
            3 => {
                let v = self
                    .aux_child(tree, sib2(tree, t)?, nofail)?
                    .ok_or(malformed)?;
                self.step_aux_choice(tree, t, nofail, v)
            }
            4 => {
                let v = self
                    .aux_child(tree, sib2(tree, t)?, nofail)?
                    .ok_or(malformed)?;
                Ok(self.aux_set(t, nofail, v))
            }
            _ => {
                let v = self
                    .aux_child(tree, sib1(tree, t)?, nofail)?
                    .ok_or(malformed)?;
                Ok(self.aux_set(t, nofail, v))
            }
        }
    }

    /// A sequence whose first child answered `v1`.
    fn step_aux_seq(
        &mut self,
        tree: &Tree,
        t: usize,
        nofail: bool,
        v1: bool,
    ) -> Result<Next, CodeError> {
        if !v1 {
            return Ok(self.aux_set(t, nofail, false));
        }
        let c = sib2(tree, t)?;
        match self.aux_child(tree, c, nofail)? {
            Some(v) => Ok(self.aux_set(t, nofail, v)),
            None => {
                self.stage(4);
                Ok(Next::Push(Task::Aux {
                    t: c,
                    nofail,
                    stage: 0,
                }))
            }
        }
    }

    /// A choice whose second child answered `v2`.
    fn step_aux_choice(
        &mut self,
        tree: &Tree,
        t: usize,
        nofail: bool,
        v2: bool,
    ) -> Result<Next, CodeError> {
        if v2 {
            return Ok(self.aux_set(t, nofail, true));
        }
        let c = sib1(tree, t)?;
        match self.aux_child(tree, c, nofail)? {
            Some(v) => Ok(self.aux_set(t, nofail, v)),
            None => {
                self.stage(5);
                Ok(Next::Push(Task::Aux {
                    t: c,
                    nofail,
                    stage: 0,
                }))
            }
        }
    }

    // ------------------------------------------------------------ headfail

    fn head_set(&mut self, t: usize, v: bool) -> Next {
        if let Some(m) = self.head.get_mut(t) {
            *m = if v { YES } else { NO };
        }
        Next::Pop
    }

    fn head_child(&self, tree: &Tree, c: usize) -> Result<Option<bool>, CodeError> {
        match self.head.get(c).copied().unwrap_or(UNKNOWN) {
            YES => Ok(Some(true)),
            NO => Ok(Some(false)),
            BUSY => Err(cycle(tree, &self.tasks, c)),
            _ => Ok(None),
        }
    }

    /// `headfail` (`lpeg.c:1257`). Stages: 0 start; 1 a single child's
    /// answer is the node's (`sib1`, or `sib2` of a call); 2 a sequence's
    /// `nofail(sib2)` is known; 3 a sequence's `headfail(sib1)`; 4 a choice's
    /// `headfail(sib1)`; 5 a choice's `headfail(sib2)`.
    fn step_head(&mut self, tree: &Tree, t: usize, stage: u8) -> Result<Next, CodeError> {
        let malformed = CodeError::Tree(TreeError::Malformed);
        match stage {
            0 => {
                match self.head.get(t).copied().unwrap_or(UNKNOWN) {
                    YES | NO => return Ok(Next::Pop),
                    BUSY => return Err(cycle(tree, &self.tasks, t)),
                    _ => {}
                }
                let tag = tag_at(tree, t)?;
                match tag {
                    Tag::Char | Tag::Set | Tag::Any | Tag::False => {
                        return Ok(self.head_set(t, true))
                    }
                    Tag::True | Tag::Rep | Tag::RunTime | Tag::Not | Tag::Behind => {
                        return Ok(self.head_set(t, false));
                    }
                    Tag::OpenCall => return Err(malformed),
                    _ => {}
                }
                if let Some(m) = self.head.get_mut(t) {
                    *m = BUSY;
                }
                match tag {
                    Tag::Capture | Tag::Grammar | Tag::Rule | Tag::And | Tag::Call => {
                        let c = if tag == Tag::Call {
                            sib2(tree, t)?
                        } else {
                            sib1(tree, t)?
                        };
                        match self.head_child(tree, c)? {
                            Some(v) => Ok(self.head_set(t, v)),
                            None => {
                                self.stage(1);
                                Ok(Next::Push(Task::Head { t: c, stage: 0 }))
                            }
                        }
                    }
                    Tag::Seq => {
                        let c = sib2(tree, t)?;
                        match self.aux_child(tree, c, true)? {
                            Some(v) => self.step_head_seq(tree, t, v),
                            None => {
                                self.stage(2);
                                Ok(Next::Push(Task::Aux {
                                    t: c,
                                    nofail: true,
                                    stage: 0,
                                }))
                            }
                        }
                    }
                    _ => {
                        let c = sib1(tree, t)?;
                        match self.head_child(tree, c)? {
                            Some(v) => self.step_head_choice(tree, t, v),
                            None => {
                                self.stage(4);
                                Ok(Next::Push(Task::Head { t: c, stage: 0 }))
                            }
                        }
                    }
                }
            }
            1 => {
                let c = match tag_at(tree, t)? {
                    Tag::Call => sib2(tree, t)?,
                    _ => sib1(tree, t)?,
                };
                let v = self.head_child(tree, c)?.ok_or(malformed)?;
                Ok(self.head_set(t, v))
            }
            2 => {
                let v = self
                    .aux_child(tree, sib2(tree, t)?, true)?
                    .ok_or(malformed)?;
                self.step_head_seq(tree, t, v)
            }
            3 => {
                let v = self.head_child(tree, sib1(tree, t)?)?.ok_or(malformed)?;
                Ok(self.head_set(t, v))
            }
            4 => {
                let v = self.head_child(tree, sib1(tree, t)?)?.ok_or(malformed)?;
                self.step_head_choice(tree, t, v)
            }
            _ => {
                let v = self.head_child(tree, sib2(tree, t)?)?.ok_or(malformed)?;
                Ok(self.head_set(t, v))
            }
        }
    }

    /// A sequence whose second child is `nofail` or not: if it is, the
    /// sequence is headfail exactly when its first child is.
    fn step_head_seq(&mut self, tree: &Tree, t: usize, nofail2: bool) -> Result<Next, CodeError> {
        if !nofail2 {
            return Ok(self.head_set(t, false));
        }
        let c = sib1(tree, t)?;
        match self.head_child(tree, c)? {
            Some(v) => Ok(self.head_set(t, v)),
            None => {
                self.stage(3);
                Ok(Next::Push(Task::Head { t: c, stage: 0 }))
            }
        }
    }

    /// A choice whose first child is headfail or not.
    fn step_head_choice(&mut self, tree: &Tree, t: usize, h1: bool) -> Result<Next, CodeError> {
        if !h1 {
            return Ok(self.head_set(t, false));
        }
        let c = sib2(tree, t)?;
        match self.head_child(tree, c)? {
            Some(v) => Ok(self.head_set(t, v)),
            None => {
                self.stage(5);
                Ok(Next::Push(Task::Head { t: c, stage: 0 }))
            }
        }
    }

    // ------------------------------------------------------------ getfirst

    fn first_child(&self, tree: &Tree, c: usize) -> Result<Option<First>, CodeError> {
        match self.first.get(c) {
            Some(m) if m.state == YES => Ok(Some(m.first)),
            Some(m) if m.state == BUSY => Err(cycle(tree, &self.tasks, c)),
            Some(_) => Ok(None),
            None => Err(CodeError::Tree(TreeError::Malformed)),
        }
    }

    fn first_set_memo(&mut self, t: usize, f: First) -> Next {
        if let Some(m) = self.first.get_mut(t) {
            *m = FirstMemo {
                first: f,
                state: YES,
            };
        }
        Next::Pop
    }

    fn union_ids(&mut self, a: SetId, b: SetId) -> Result<SetId, CodeError> {
        if a == b || b == EMPTY {
            return Ok(a);
        }
        if a == EMPTY {
            return Ok(b);
        }
        self.intern(self.set(a).union(&self.set(b)))
    }

    fn inter_ids(&mut self, a: SetId, b: SetId) -> Result<SetId, CodeError> {
        if a == b || b == FULL {
            return Ok(a);
        }
        if a == FULL {
            return Ok(b);
        }
        self.intern(inter(&self.set(a), &self.set(b)))
    }

    /// Ask for child `c`'s first set, coming back at `then` if it is not
    /// known.
    fn want_first(
        &mut self,
        tree: &Tree,
        c: usize,
        then: u8,
    ) -> Result<Result<First, Next>, CodeError> {
        match self.first_child(tree, c)? {
            Some(f) => Ok(Ok(f)),
            None => {
                self.stage(then);
                Ok(Err(Next::Push(Task::First { t: c, stage: 0 })))
            }
        }
    }

    /// `getfirst` (`lpeg.c:1175`), in closed form. Stages: 0 start, and
    /// for each tag the point after the child it asked for: 1 a single
    /// child's (`sib1`; `sib2` of a call); 2 a choice's first, 3 its second;
    /// 4 a sequence's `nullable(sib1)`; 5 a non-nullable sequence's first
    /// child; 6 a nullable sequence's second child, 7 its first.
    fn step_first(&mut self, tree: &Tree, t: usize, stage: u8) -> Result<Next, CodeError> {
        let malformed = CodeError::Tree(TreeError::Malformed);
        let tag = tag_at(tree, t)?;
        if stage == 0 {
            match self.first.get(t).map(|m| m.state) {
                Some(YES) => return Ok(Next::Pop),
                Some(BUSY) => return Err(cycle(tree, &self.tasks, t)),
                None => return Err(malformed),
                _ => {}
            }
            let leaf = |x, y, e| First { x, y, e };
            match tag {
                Tag::Char | Tag::Set | Tag::Any => {
                    let cs = to_charset(tree, t).ok_or(malformed)?;
                    let y = self.intern(cs)?;
                    return Ok(self.first_set_memo(t, leaf(EMPTY, y, 0)));
                }
                Tag::True => return Ok(self.first_set_memo(t, leaf(FULL, EMPTY, 1))),
                Tag::False => return Ok(self.first_set_memo(t, leaf(EMPTY, EMPTY, 0))),
                Tag::Not => {
                    if let Some(cs) = to_charset(tree, sib1(tree, t)?) {
                        let y = self.intern(complement(&cs))?;
                        return Ok(self.first_set_memo(t, leaf(EMPTY, y, 1)));
                    }
                }
                Tag::OpenCall => return Err(malformed),
                _ => {}
            }
            if let Some(m) = self.first.get_mut(t) {
                m.state = BUSY;
            }
        }
        // Each arm asks for what it needs, in the C's order, and combines.
        match tag {
            Tag::Capture | Tag::Grammar | Tag::Rule | Tag::Call => {
                let c = if tag == Tag::Call {
                    sib2(tree, t)?
                } else {
                    sib1(tree, t)?
                };
                match self.want_first(tree, c, 1)? {
                    Ok(f) => Ok(self.first_set_memo(t, f)),
                    Err(next) => Ok(next),
                }
            }
            Tag::Choice => {
                let f1 = match self.want_first(tree, sib1(tree, t)?, 2)? {
                    Ok(f) => f,
                    Err(next) => return Ok(next),
                };
                let f2 = match self.want_first(tree, sib2(tree, t)?, 3)? {
                    Ok(f) => f,
                    Err(next) => return Ok(next),
                };
                let x = self.union_ids(f1.x, f2.x)?;
                let y = self.union_ids(f1.y, f2.y)?;
                Ok(self.first_set_memo(
                    t,
                    First {
                        x,
                        y,
                        e: f1.e | f2.e,
                    },
                ))
            }
            Tag::Seq => {
                let s1 = sib1(tree, t)?;
                let nullable = match self.aux_child(tree, s1, false)? {
                    Some(v) => v,
                    None => {
                        self.stage(4);
                        return Ok(Next::Push(Task::Aux {
                            t: s1,
                            nofail: false,
                            stage: 0,
                        }));
                    }
                };
                if !nullable {
                    // FIRST(p1, FULL).
                    let f1 = match self.want_first(tree, s1, 5)? {
                        Ok(f) => f,
                        Err(next) => return Ok(next),
                    };
                    let y = self.union_ids(f1.x, f1.y)?;
                    return Ok(self.first_set_memo(
                        t,
                        First {
                            x: EMPTY,
                            y,
                            e: f1.e,
                        },
                    ));
                }
                // FIRST(p1, FIRST(p2, fl)): the second child first.
                let f2 = match self.want_first(tree, sib2(tree, t)?, 6)? {
                    Ok(f) => f,
                    Err(next) => return Ok(next),
                };
                let f1 = match self.want_first(tree, s1, 7)? {
                    Ok(f) => f,
                    Err(next) => return Ok(next),
                };
                let x = self.inter_ids(f1.x, f2.x)?;
                let y2x1 = self.inter_ids(f2.y, f1.x)?;
                let y = self.union_ids(f1.y, y2x1)?;
                let e = if f1.e == 0 {
                    0
                } else if (f1.e | f2.e) & 2 != 0 {
                    2
                } else {
                    f2.e
                };
                Ok(self.first_set_memo(t, First { x, y, e }))
            }
            Tag::Rep => match self.want_first(tree, sib1(tree, t)?, 1)? {
                Ok(f) => Ok(self.first_set_memo(
                    t,
                    First {
                        x: FULL,
                        y: f.y,
                        e: 1,
                    },
                )),
                Err(next) => Ok(next),
            },
            Tag::RunTime => match self.want_first(tree, sib1(tree, t)?, 1)? {
                Ok(f) => {
                    let y = self.union_ids(f.x, f.y)?;
                    let e = if f.e != 0 { 2 } else { 0 };
                    Ok(self.first_set_memo(t, First { x: EMPTY, y, e }))
                }
                Err(next) => Ok(next),
            },
            Tag::And => match self.want_first(tree, sib1(tree, t)?, 1)? {
                Ok(f) => {
                    let x = self.union_ids(f.x, f.y)?;
                    Ok(self.first_set_memo(
                        t,
                        First {
                            x,
                            y: EMPTY,
                            e: f.e,
                        },
                    ))
                }
                Err(next) => Ok(next),
            },
            // `Not` of anything but a charset, and `Behind`: the follow set,
            // and the child's flag, which is walked for that alone.
            Tag::Not | Tag::Behind => match self.want_first(tree, sib1(tree, t)?, 1)? {
                Ok(f) => Ok(self.first_set_memo(
                    t,
                    First {
                        x: FULL,
                        y: EMPTY,
                        e: f.e | 1,
                    },
                )),
                Err(next) => Ok(next),
            },
            _ => Err(malformed),
        }
    }

    // ------------------------------------------------------------ fixedlen

    /// `fixedlenx(t, count)` if known: the length (-1 if variable), and
    /// whether it depends on the count.
    fn len_at(&self, t: usize, count: u8) -> Option<(i64, bool)> {
        let m = self.len.get(t)?;
        let free = self.len_free.get(t).copied().unwrap_or(0) != 0;
        let c = i16::from(count);
        if c <= m.ok_max {
            Some((i64::from(m.value), !free))
        } else if c >= m.fail_min {
            Some((-1, !free))
        } else {
            None
        }
    }

    fn len_set(&mut self, t: usize, count: u8, v: i64, dep: bool) -> Next {
        // A length the C's `int` cannot hold is -1, as its wrapped `len + 1`
        // makes it.
        let v = if v > i64::from(i32::MAX) { -1 } else { v };
        if let (Some(m), Some(f)) = (self.len.get_mut(t), self.len_free.get_mut(t)) {
            let c = i16::from(count);
            if !dep {
                *f = 1;
                if v >= 0 {
                    m.value = i32::try_from(v).unwrap_or(i32::MAX);
                    m.ok_max = i16::MAX;
                } else {
                    m.fail_min = 0;
                }
            } else if v >= 0 {
                m.value = i32::try_from(v).unwrap_or(i32::MAX);
                m.ok_max = m.ok_max.max(c);
            } else {
                m.fail_min = m.fail_min.min(c);
            }
        }
        Next::Pop
    }

    fn len_child(&self, c: usize, count: u8) -> Option<(i64, bool)> {
        self.len_at(c, count)
    }

    /// `fixedlenx` (`lpeg.c:1125`). Stages: 0 start; 1 a single child's
    /// answer is the node's (at `count + 1` for a call); 2 a sequence's
    /// first child, 3 its second; 4 a choice's first, 5 its second.
    fn step_len(
        &mut self,
        tree: &Tree,
        t: usize,
        count: u8,
        stage: u8,
        acc: i32,
        dep: bool,
    ) -> Result<Next, CodeError> {
        let malformed = CodeError::Tree(TreeError::Malformed);
        let tag = tag_at(tree, t)?;
        let task = |t, count| Task::Len {
            t,
            count,
            stage: 0,
            acc: 0,
            dep: false,
        };
        // The child's answer at `cc`, or ask for it, coming back at `then`
        // with `acc` and `dep` kept.
        let ask = |a: &mut Analyses, c: usize, cc: u8, then: u8, acc: i32, dep: bool| match a
            .len_child(c, cc)
        {
            Some(v) => Ok(v),
            None => {
                if let Some(Task::Len {
                    stage,
                    acc: a0,
                    dep: d0,
                    ..
                }) = a.tasks.last_mut()
                {
                    *stage = then;
                    *a0 = acc;
                    *d0 = dep;
                }
                Err(Next::Push(task(c, cc)))
            }
        };
        if stage == 0 {
            if self.len_at(t, count).is_some() {
                return Ok(Next::Pop);
            }
            match tag {
                Tag::Char | Tag::Set | Tag::Any => return Ok(self.len_set(t, count, 1, false)),
                Tag::False | Tag::True | Tag::Not | Tag::And | Tag::Behind => {
                    return Ok(self.len_set(t, count, 0, false));
                }
                Tag::Rep | Tag::RunTime | Tag::OpenCall => {
                    return Ok(self.len_set(t, count, -1, false))
                }
                // `if (count++ >= MAXRULES) return -1;`: may be a loop.
                Tag::Call if usize::from(count) >= MAXRULES => {
                    return Ok(self.len_set(t, count, -1, true))
                }
                _ => {}
            }
        }
        match tag {
            Tag::Capture | Tag::Rule | Tag::Grammar | Tag::Call => {
                let (c, cc) = if tag == Tag::Call {
                    (sib2(tree, t)?, count.saturating_add(1))
                } else {
                    (sib1(tree, t)?, count)
                };
                match ask(self, c, cc, 1, 0, false) {
                    Ok((v, d)) => Ok(self.len_set(t, count, v, d || tag == Tag::Call)),
                    Err(next) => Ok(next),
                }
            }
            Tag::Seq => {
                let (a, d1) = if stage <= 2 {
                    match ask(self, sib1(tree, t)?, count, 2, 0, false) {
                        Ok(v) => v,
                        Err(next) => return Ok(next),
                    }
                } else {
                    (i64::from(acc), dep)
                };
                if a < 0 {
                    return Ok(self.len_set(t, count, -1, d1));
                }
                let a32 = i32::try_from(a).map_err(|_| malformed)?;
                match ask(self, sib2(tree, t)?, count, 3, a32, d1) {
                    Ok((b, d2)) => {
                        let v = if b < 0 { -1 } else { a + b };
                        Ok(self.len_set(t, count, v, d1 || d2))
                    }
                    Err(next) => Ok(next),
                }
            }
            Tag::Choice => {
                let (n1, d1) = if stage <= 4 {
                    match ask(self, sib1(tree, t)?, count, 4, 0, false) {
                        Ok(v) => v,
                        Err(next) => return Ok(next),
                    }
                } else {
                    (i64::from(acc), dep)
                };
                if n1 < 0 {
                    return Ok(self.len_set(t, count, -1, d1));
                }
                let n32 = i32::try_from(n1).map_err(|_| malformed)?;
                match ask(self, sib2(tree, t)?, count, 5, n32, d1) {
                    Ok((n2, d2)) => {
                        let v = if n1 == n2 { n1 } else { -1 };
                        Ok(self.len_set(t, count, v, d1 || d2))
                    }
                    Err(next) => Ok(next),
                }
            }
            _ => Err(malformed),
        }
    }

    // ------------------------------------------------------------ hascaptures

    /// The pass that answers `hascaptures` for every node: mark the slots
    /// that are nodes (a charset's data follows its `Set` node), then, from
    /// the last slot back, a node has captures if it is a capture or a
    /// run-time capture, or one of its `numsiblings` children has. A child
    /// is always after its parent, except a call's rule, which is not one of
    /// its children here. True when done.
    fn caps_pass(&mut self, tree: &Tree, budget: &mut u32) -> Result<bool, CodeError> {
        let n = tree.len();
        let (mut backwards, mut i) = match self.caps_pass {
            Some(p) => p,
            None => {
                self.caps = filled(n, 0)?;
                (false, 0)
            }
        };
        let nodes = tree.nodes();
        loop {
            if *budget == 0 {
                self.caps_pass = Some((backwards, i));
                return Ok(false);
            }
            *budget -= 1;
            self.steps += 1;
            if !backwards {
                let Some(node) = nodes.get(i) else {
                    backwards = true;
                    i = n;
                    continue;
                };
                if let Some(c) = self.caps.get_mut(i) {
                    *c = NODE;
                }
                i += if node.tag == Tag::Set {
                    1 + SET_SLOTS
                } else {
                    1
                };
                continue;
            }
            if i == 0 {
                self.caps_done = true;
                self.caps_pass = None;
                return Ok(true);
            }
            i -= 1;
            if self.caps.get(i).copied() != Some(NODE) {
                continue;
            }
            let node = nodes.get(i).ok_or(CodeError::Tree(TreeError::Malformed))?;
            let child = |c: usize| self.caps.get(c).copied() == Some(YES);
            let has = match node.tag {
                Tag::Capture | Tag::RunTime => true,
                tag => match tag.siblings() {
                    1 => child(i + 1),
                    2 => child(i + 1) || child(sib2(tree, i)?),
                    _ => false,
                },
            };
            if let Some(c) = self.caps.get_mut(i) {
                *c = if has { YES } else { NO };
            }
        }
    }
}

/// A memo state as an answer.
fn known(m: Option<&u8>) -> Option<bool> {
    match m {
        Some(&YES) => Some(true),
        Some(&NO) => Some(false),
        _ => None,
    }
}
