//! The walkers construction runs over a tree, as resumable state machines.
//!
//! The C writes each as a recursive function with tail calls turned into
//! `goto`s. Two things are wrong with that here:
//! - **Depth.** Recursion on the Rust stack is an abort no `pcall` can catch
//!   at a depth the C survives (`lpeg-recursive-walkers-stack-overflow`; E2).
//!   Each walker keeps what the C keeps on its call stack — the work left
//!   after a child returns — in a `Vec` grown through the memory budget.
//! - **Time.** `checkaux`, `fixedlenx` and `verifyrule` follow calls into
//!   rules, so over a grammar whose rules call the next one twice they take
//!   time exponential in its depth (`docs/M6.6-ANALYSIS.md` §1.1). Each walker
//!   takes a step budget and returns [`Poll::Pending`] when it is spent, its
//!   state intact, so the binding can return to the VM and be resumed: the
//!   interpreter, and the stall watchdog above it, see every slice (D3).
//!
//! A walker holds indices, never a borrow of the tree, so the tree can live
//! in a garbage-collected object between steps. Every step visits one node or
//! finishes one pending piece of work, and costs one unit of budget; a step
//! with a budget of at least one always makes progress.
//!
//! Each walker visits the same nodes in the same order as the C function it
//! replaces, and reaches the same answer, including which rule an error
//! names. The recursive originals are kept as test oracles
//! (`tree/tests.rs`).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "indices into a tree are below MAX_TREE (2^31 - 1), so the sum of two cannot \
              overflow usize; lengths count visited nodes and cannot reach i64::MAX"
)]

use std::task::Poll;

use super::{Key, Tag, Tree, TreeError, MAXRULES};
use crate::nse::stdlib::reserve;

/// Push onto a walker's stack, growing it through the memory budget.
#[inline(always)]
fn push<T>(stack: &mut Vec<T>, v: T) -> Result<(), TreeError> {
    if stack.len() == stack.capacity() && !reserve(stack, 1) {
        return Err(TreeError::NotEnoughMemory);
    }
    stack.push(v);
    Ok(())
}

/// `?` without the trait calls, which an unoptimized build makes on every
/// use: the walkers' inner loops run billions of times in the tests.
macro_rules! hot {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
}

/// `sib2(i)` from node `i`'s offset `u`. Whether it is inside the tree is
/// checked when it is visited.
#[inline(always)]
fn off(i: usize, u: i32) -> Result<usize, TreeError> {
    isize::try_from(u)
        .ok()
        .and_then(|u| i.checked_add_signed(u))
        .ok_or(TreeError::Malformed)
}

/// The bytes a walker's stack holds outside the VM's heap.
fn stack_bytes<T>(v: &Vec<T>) -> usize {
    v.capacity().saturating_mul(std::mem::size_of::<T>())
}

/// Spend one unit of `budget`, or report it spent.
fn spend(budget: &mut u32) -> bool {
    match budget.checked_sub(1) {
        Some(b) => {
            *budget = b;
            true
        }
        None => false,
    }
}

/// `Ok(None)` is "not finished": the budget ran out.
fn poll<T>(r: Result<Option<T>, TreeError>) -> Poll<Result<T, TreeError>> {
    match r {
        Ok(Some(v)) => Poll::Ready(Ok(v)),
        Ok(None) => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

fn sib1(tree: &Tree, i: usize) -> Result<usize, TreeError> {
    tree.sib1(i).ok_or(TreeError::Malformed)
}

fn sib2(tree: &Tree, i: usize) -> Result<usize, TreeError> {
    tree.sib2(i).ok_or(TreeError::Malformed)
}

fn tag_at(tree: &Tree, i: usize) -> Result<Tag, TreeError> {
    tree.node(i).map(|n| n.tag).ok_or(TreeError::Malformed)
}

/// What [`CheckAux`] decides (`PEnullable`, `PEnofail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pred {
    /// The pattern can match without consuming input.
    Nullable,
    /// The pattern never fails.
    NoFail,
}

#[derive(Debug, Clone, Copy)]
enum AuxCont {
    /// A `Seq`'s first child was checked: if it holds, check the second.
    SeqThen(usize),
    /// A `Choice`'s second child was checked: if it does not hold, check the
    /// first.
    ChoiceElse(usize),
}

/// `checkaux` (`lpeg.c:1084`): `nullable` and `nofail`, conservatively.
/// Follows calls into their rules; an open call counts as neither.
#[derive(Debug, Clone)]
pub struct CheckAux {
    pred: Pred,
    at: Option<usize>,
    value: bool,
    stack: Vec<AuxCont>,
}

impl CheckAux {
    /// Check the subtree whose root is node `root`.
    #[must_use]
    pub fn new(root: usize, pred: Pred) -> CheckAux {
        CheckAux {
            pred,
            at: Some(root),
            value: false,
            stack: Vec::new(),
        }
    }

    /// Run until the answer or until `budget` is spent.
    pub fn step(&mut self, tree: &Tree, budget: &mut u32) -> Poll<Result<bool, TreeError>> {
        poll(self.run(tree, budget))
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        stack_bytes(&self.stack)
    }

    /// Each node visited costs one unit of budget. Handing an answer back
    /// up (a pop) costs nothing: each was pushed by a visit that paid.
    fn run(&mut self, tree: &Tree, budget: &mut u32) -> Result<Option<bool>, TreeError> {
        let nodes = tree.nodes();
        let nullable = self.pred == Pred::Nullable;
        loop {
            let Some(i) = self.at else {
                match self.stack.pop() {
                    None => return Ok(Some(self.value)),
                    Some(AuxCont::SeqThen(s2)) => {
                        if self.value {
                            self.at = Some(s2);
                        }
                    }
                    Some(AuxCont::ChoiceElse(s1)) => {
                        if !self.value {
                            self.at = Some(s1);
                        }
                    }
                }
                continue;
            };
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
            let node = match nodes.get(i) {
                Some(n) => *n,
                None => return Err(TreeError::Malformed),
            };
            let s1 = i + 1;
            let (at, value) = match node.tag {
                Tag::Char | Tag::Set | Tag::Any | Tag::False | Tag::OpenCall => (None, false),
                Tag::Rep | Tag::True => (None, true),
                // Can match the empty string, but can fail.
                Tag::Not | Tag::Behind => (None, nullable),
                // Matches the empty string; fails exactly when its body does.
                Tag::And if nullable => (None, true),
                Tag::And => (Some(s1), false),
                // Can fail; matches the empty string exactly when its body does.
                Tag::RunTime if !nullable => (None, false),
                Tag::RunTime => (Some(s1), false),
                Tag::Seq => {
                    hot!(push(
                        &mut self.stack,
                        AuxCont::SeqThen(hot!(off(i, node.u)))
                    ));
                    (Some(s1), false)
                }
                Tag::Choice => {
                    hot!(push(&mut self.stack, AuxCont::ChoiceElse(s1)));
                    (Some(hot!(off(i, node.u))), false)
                }
                Tag::Capture | Tag::Grammar | Tag::Rule => (Some(s1), false),
                Tag::Call => (Some(hot!(off(i, node.u))), false),
            };
            self.at = at;
            self.value = value;
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LenCont {
    /// A `Seq`'s first child measured: measure the second from there.
    SeqThen { s2: usize, count: usize },
    /// A `Choice`'s first child measured: measure the second from `len`.
    ChoiceSecond { s2: usize, count: usize, len: i64 },
    /// Both measured: equal or variable.
    ChoiceCompare { n1: i64 },
}

/// `fixedlenx` (`lpeg.c:1125`): the number of bytes the pattern always
/// matches, or -1 if that varies. Follows calls, at most [`MAXRULES`] deep
/// along any path (`count`), so a recursive rule is "variable" rather than
/// a loop.
///
/// The C's lengths are `int`s, and a length past `INT_MAX` (a grammar that
/// doubles at each of 31 levels, walked in 2^31 steps) is "variable" there:
/// `len + 1` wraps to `INT_MIN`, the next sequence or choice above returns
/// -1 for any negative length, and so does `fixedlen` itself, so the C never
/// reports a wrapped positive length. Here lengths are `i64`, and a length
/// past `i32::MAX` is -1 where it is made.
#[derive(Debug, Clone)]
pub struct FixedLen {
    at: Option<(usize, usize, i64)>,
    value: i64,
    stack: Vec<LenCont>,
}

impl FixedLen {
    /// `fixedlen(tree)`: measure the subtree at `root` from 0.
    #[must_use]
    pub fn new(root: usize) -> FixedLen {
        FixedLen {
            at: Some((root, 0, 0)),
            value: 0,
            stack: Vec::new(),
        }
    }

    /// `fixedlenx(tree, 0, len)`: measure the subtree at `root` from `len`
    /// bytes, as a call deep in a walk would. For the tests: a length near
    /// `INT_MAX` takes 2^31 steps to reach from 0.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn starting_at(root: usize, len: i64) -> FixedLen {
        FixedLen {
            at: Some((root, 0, len)),
            value: 0,
            stack: Vec::new(),
        }
    }

    pub fn step(&mut self, tree: &Tree, budget: &mut u32) -> Poll<Result<i64, TreeError>> {
        poll(self.run(tree, budget))
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        stack_bytes(&self.stack)
    }

    /// Costs as [`CheckAux`]'s.
    fn run(&mut self, tree: &Tree, budget: &mut u32) -> Result<Option<i64>, TreeError> {
        let nodes = tree.nodes();
        loop {
            let Some((i, count, len)) = self.at else {
                let r = self.value;
                match self.stack.pop() {
                    None => return Ok(Some(r)),
                    Some(LenCont::SeqThen { s2, count }) => {
                        if r >= 0 {
                            self.at = Some((s2, count, r));
                        }
                    }
                    Some(LenCont::ChoiceSecond { s2, count, len }) => {
                        if r >= 0 {
                            push(&mut self.stack, LenCont::ChoiceCompare { n1: r })?;
                            self.at = Some((s2, count, len));
                        }
                    }
                    Some(LenCont::ChoiceCompare { n1 }) => {
                        self.value = if n1 == r { n1 } else { -1 };
                    }
                }
                continue;
            };
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
            let node = match nodes.get(i) {
                Some(n) => *n,
                None => return Err(TreeError::Malformed),
            };
            let s1 = i + 1;
            let (at, value) = match node.tag {
                // `len + 1`, which the C's `int` wraps past `INT_MAX`.
                Tag::Char | Tag::Set | Tag::Any if len >= i64::from(i32::MAX) => (None, -1),
                Tag::Char | Tag::Set | Tag::Any => (None, len + 1),
                Tag::False | Tag::True | Tag::Not | Tag::And | Tag::Behind => (None, len),
                Tag::Rep | Tag::RunTime | Tag::OpenCall => (None, -1),
                Tag::Capture | Tag::Rule | Tag::Grammar => (Some((s1, count, len)), 0),
                // `if (count++ >= MAXRULES) return -1;`: may be a loop.
                Tag::Call if count >= MAXRULES => (None, -1),
                Tag::Call => (Some((hot!(off(i, node.u)), count + 1, len)), 0),
                Tag::Seq => {
                    let s2 = hot!(off(i, node.u));
                    hot!(push(&mut self.stack, LenCont::SeqThen { s2, count }));
                    (Some((s1, count, len)), 0)
                }
                Tag::Choice => {
                    let s2 = hot!(off(i, node.u));
                    hot!(push(
                        &mut self.stack,
                        LenCont::ChoiceSecond { s2, count, len }
                    ));
                    (Some((s1, count, len)), 0)
                }
            };
            self.at = at;
            self.value = value;
        }
    }
}

/// `verifyerror` (`lpeg.c:3020`): the latest rule on the left-call path
/// that appears earlier on it, or "too many left calls".
fn verify_error(passed: &[Key]) -> TreeError {
    for i in (0..passed.len()).rev() {
        for j in (0..i).rev() {
            if passed[i] == passed[j] {
                return TreeError::LeftRecursive(passed[i]);
            }
        }
    }
    TreeError::TooManyLeftCalls
}

#[derive(Debug, Clone, Copy)]
enum RuleCont {
    /// A `Seq`'s first child checked as non-nullable: if it is nullable
    /// after all, check the second; if not, the answer is `nullable`.
    SeqFirst {
        s2: usize,
        npassed: usize,
        nullable: bool,
    },
    /// A `Choice`'s first child checked: check the second with its answer.
    ChoiceFirst { s2: usize, npassed: usize },
}

/// `verifyrule` (`lpeg.c:3047`): follow every path a rule can take without
/// consuming input, recording the rules it enters (`passed`). A path of
/// [`MAXRULES`] rules is left recursion. Answers whether the rule is
/// nullable.
///
/// `hidden`: also follow a left call the C misses past a sub-grammar in a
/// nullable context (see the `Grammar` arm). Without it, the C exactly.
#[derive(Debug, Clone)]
struct VerifyRule {
    at: Option<(usize, usize, bool)>,
    value: bool,
    stack: Vec<RuleCont>,
    /// A sub-grammar met on the way: whether it is nullable.
    sub: Option<CheckAux>,
    hidden: bool,
}

impl VerifyRule {
    fn new(root: usize, hidden: bool) -> VerifyRule {
        VerifyRule {
            at: Some((root, 0, false)),
            value: false,
            stack: Vec::new(),
            sub: None,
            hidden,
        }
    }

    /// Costs as [`CheckAux`]'s.
    fn run(
        &mut self,
        tree: &Tree,
        passed: &mut Vec<Key>,
        budget: &mut u32,
    ) -> Result<Option<bool>, TreeError> {
        let nodes = tree.nodes();
        loop {
            if let Some(sub) = &mut self.sub {
                match sub.run(tree, budget)? {
                    None => return Ok(None),
                    Some(v) => {
                        self.value = v;
                        self.sub = None;
                    }
                }
            }
            let Some((i, npassed, nullable)) = self.at else {
                let r = self.value;
                match self.stack.pop() {
                    None => return Ok(Some(r)),
                    Some(RuleCont::SeqFirst {
                        s2,
                        npassed,
                        nullable,
                    }) => {
                        if r {
                            self.at = Some((s2, npassed, nullable));
                        } else {
                            self.value = nullable;
                        }
                    }
                    Some(RuleCont::ChoiceFirst { s2, npassed }) => {
                        self.at = Some((s2, npassed, r));
                    }
                }
                continue;
            };
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
            let node = match nodes.get(i) {
                Some(n) => *n,
                None => return Err(TreeError::Malformed),
            };
            let s1 = i + 1;
            let (at, value) = match node.tag {
                // Cannot pass from here.
                Tag::Char | Tag::Set | Tag::Any | Tag::False => (None, nullable),
                Tag::True => (None, true),
                // "Look-behind cannot have calls", the C says, and returns 1;
                // a call under a predicate in `B`'s body is not followed, in
                // either pass. Such a cycle makes the C's `getfirst` recurse
                // without bound at compile time in some uses, but matching it
                // terminates (each turn looks behind, at a smaller position),
                // and the C builds and matches it in others: step c's
                // compiler refuses it where the C's would recurse
                // (`lpeg-getfirst-unbounded-recursion`).
                Tag::Behind => (None, true),
                Tag::Not | Tag::And | Tag::Rep => (Some((s1, npassed, true)), false),
                Tag::Capture | Tag::RunTime => (Some((s1, npassed, nullable)), false),
                Tag::Call => (Some((hot!(off(i, node.u)), npassed, nullable)), false),
                // Only check the second child if the first is nullable.
                Tag::Seq => {
                    let s2 = hot!(off(i, node.u));
                    hot!(push(
                        &mut self.stack,
                        RuleCont::SeqFirst {
                            s2,
                            npassed,
                            nullable,
                        },
                    ));
                    (Some((s1, npassed, false)), false)
                }
                // Check both children.
                Tag::Choice => {
                    let s2 = hot!(off(i, node.u));
                    hot!(push(&mut self.stack, RuleCont::ChoiceFirst { s2, npassed }));
                    (Some((s1, npassed, nullable)), false)
                }
                Tag::Rule => {
                    passed.truncate(npassed);
                    if npassed >= MAXRULES {
                        return Err(verify_error(passed));
                    }
                    hot!(push(passed, node.key));
                    (Some((s1, npassed + 1, nullable)), false)
                }
                // A sub-grammar cannot be left recursive. The C answers whether
                // it is nullable, dropping a nullable context: under `-`, `#` or
                // `^n` it reports a sub-grammar that consumes as not nullable, so
                // `A <- -P{P"x"} * V"A"` passed its verifier and then hung or
                // crashed (`lpeg-getfirst-unbounded-recursion`). In the hidden
                // pass a nullable context stays nullable.
                Tag::Grammar if nullable && self.hidden => (None, true),
                Tag::Grammar => {
                    self.sub = Some(CheckAux::new(i, Pred::Nullable));
                    (None, false)
                }
                // Fixed before the verifier runs (`assert(0)` in the C).
                Tag::OpenCall => return Err(TreeError::Malformed),
            };
            self.at = at;
            self.value = value;
        }
    }
}

/// `checkloops` (`lpeg.c:3000`): whether a repetition in the subtree has a
/// body that can match the empty string. Does not enter sub-grammars, which
/// were checked when they were built, nor follow calls.
#[derive(Debug, Clone)]
pub struct CheckLoops {
    at: Option<usize>,
    stack: Vec<usize>,
    /// The repetition whose body is being checked, and the check.
    sub: Option<(usize, CheckAux)>,
}

impl CheckLoops {
    #[must_use]
    pub fn new(root: usize) -> CheckLoops {
        CheckLoops {
            at: Some(root),
            stack: Vec::new(),
            sub: None,
        }
    }

    pub fn step(&mut self, tree: &Tree, budget: &mut u32) -> Poll<Result<bool, TreeError>> {
        poll(self.run(tree, budget))
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        stack_bytes(&self.stack)
            .saturating_add(self.sub.as_ref().map_or(0, |(_, s)| s.heap_bytes()))
    }

    fn run(&mut self, tree: &Tree, budget: &mut u32) -> Result<Option<bool>, TreeError> {
        loop {
            if let Some((rep, sub)) = &mut self.sub {
                let rep = *rep;
                match sub.run(tree, budget)? {
                    None => return Ok(None),
                    Some(true) => return Ok(Some(true)),
                    // Not an empty loop: look inside it.
                    Some(false) => {
                        self.sub = None;
                        self.at = Some(sib1(tree, rep)?);
                    }
                }
            }
            if !spend(budget) {
                return Ok(None);
            }
            let Some(i) = self.at else {
                match self.stack.pop() {
                    None => return Ok(Some(false)),
                    next => self.at = next,
                }
                continue;
            };
            let tag = tag_at(tree, i)?;
            self.at = if tag == Tag::Rep {
                self.sub = Some((i, CheckAux::new(sib1(tree, i)?, Pred::Nullable)));
                None
            } else if tag == Tag::Grammar {
                // Sub-grammars were already checked.
                None
            } else {
                match tag.siblings() {
                    1 => Some(sib1(tree, i)?),
                    2 => {
                        push(&mut self.stack, sib2(tree, i)?)?;
                        Some(sib1(tree, i)?)
                    }
                    _ => None,
                }
            };
        }
    }
}

#[derive(Debug, Clone)]
enum Phase {
    /// `verifyrule` on each rule in turn: the `Rule` node; `true` in the
    /// hidden pass.
    LeftRecursion(usize, bool, Option<VerifyRule>),
    /// `checkloops` on each rule in turn.
    Loops(usize, Option<CheckLoops>),
    Done,
}

/// `verifygrammar` (`lpeg.c:3090`) of the grammar whose `Grammar` node is
/// `g`: first every used rule for left recursion, then every used rule for
/// an empty loop. A rule is used when a call to it was fixed (its key is
/// not 0); the first rule always is, by `initialrulename`.
///
/// Then, where the C stops, a **hidden pass** looks for the left calls its
/// verifier misses past a sub-grammar under a predicate or a repetition
/// (`A <- -P{P"x"} * V"A"`), where the C hangs on any subject that reaches
/// the cycle at a position, and its `getfirst` may recurse without bound
/// (`lpeg-getfirst-unbounded-recursion`). It runs last, so that every
/// grammar the C refuses is refused with the C's error, naming the C's rule,
/// and only when the tree has a sub-grammar for it to find anything past. It
/// reports "may be left recursive" like any other.
#[derive(Debug, Clone)]
pub struct VerifyGrammar {
    phase: Phase,
    /// `int passed[MAXRULES]`.
    passed: Vec<Key>,
    first: usize,
}

impl VerifyGrammar {
    #[must_use]
    pub fn new(g: usize) -> VerifyGrammar {
        VerifyGrammar {
            phase: Phase::LeftRecursion(g + 1, false, None),
            passed: Vec::new(),
            first: g + 1,
        }
    }

    pub fn step(&mut self, tree: &Tree, budget: &mut u32) -> Poll<Result<(), TreeError>> {
        poll(self.run(tree, budget))
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        let walker = match &self.phase {
            Phase::LeftRecursion(_, _, Some(w)) => {
                stack_bytes(&w.stack).saturating_add(w.sub.as_ref().map_or(0, CheckAux::heap_bytes))
            }
            Phase::Loops(_, Some(w)) => w.heap_bytes(),
            _ => 0,
        };
        stack_bytes(&self.passed).saturating_add(walker)
    }

    fn run(&mut self, tree: &Tree, budget: &mut u32) -> Result<Option<()>, TreeError> {
        loop {
            match &mut self.phase {
                Phase::LeftRecursion(rule, hidden, walker) => {
                    let (rule, hidden) = (*rule, *hidden);
                    if let Some(w) = walker {
                        if w.run(tree, &mut self.passed, budget)?.is_none() {
                            return Ok(None);
                        }
                        self.phase = Phase::LeftRecursion(sib2(tree, rule)?, hidden, None);
                        continue;
                    }
                    if !spend(budget) {
                        return Ok(None);
                    }
                    let node = tree.node(rule).ok_or(TreeError::Malformed)?;
                    self.phase = match node.tag {
                        Tag::Rule if node.key == 0 => {
                            Phase::LeftRecursion(sib2(tree, rule)?, hidden, None)
                        }
                        Tag::Rule => Phase::LeftRecursion(
                            rule,
                            hidden,
                            Some(VerifyRule::new(sib1(tree, rule)?, hidden)),
                        ),
                        _ if hidden => Phase::Done,
                        _ => Phase::Loops(self.first, None),
                    };
                }
                Phase::Loops(rule, walker) => {
                    let rule = *rule;
                    if let Some(w) = walker {
                        match w.run(tree, budget)? {
                            None => return Ok(None),
                            Some(true) => {
                                let key = tree.node(rule).map_or(0, |n| n.key);
                                return Err(TreeError::EmptyLoop(key));
                            }
                            Some(false) => {
                                self.phase = Phase::Loops(sib2(tree, rule)?, None);
                                continue;
                            }
                        }
                    }
                    if !spend(budget) {
                        return Ok(None);
                    }
                    let node = tree.node(rule).ok_or(TreeError::Malformed)?;
                    self.phase = match node.tag {
                        Tag::Rule if node.key == 0 => Phase::Loops(sib2(tree, rule)?, None),
                        Tag::Rule => Phase::Loops(rule, Some(CheckLoops::new(sib1(tree, rule)?))),
                        // A scan of the slots, as `has_captures`: linear.
                        _ if hides_left_calls(tree, self.first) => {
                            Phase::LeftRecursion(self.first, true, None)
                        }
                        _ => Phase::Done,
                    };
                }
                Phase::Done => return Ok(Some(())),
            }
        }
    }
}

/// Whether the grammar whose first rule is at `first` holds a sub-grammar:
/// the only place the hidden pass can find a left call the C's verifier
/// missed.
fn hides_left_calls(tree: &Tree, first: usize) -> bool {
    let mut i = first;
    while let Some(node) = tree.node(i) {
        if node.tag == Tag::Grammar {
            return true;
        }
        i += if node.tag == Tag::Set {
            1 + super::SET_SLOTS
        } else {
            1
        };
    }
    false
}

/// `finalfix` (`lpeg.c:2213`): close each open call — into a call of the
/// rule its name resolves to, inside a grammar, and an error outside one —
/// and make every sequence and choice right-associative. Sub-grammars were
/// fixed when they were built. Changes the tree in place, as the C does.
#[derive(Debug, Clone)]
pub struct FinalFix {
    /// The `Grammar` node the open calls belong to, if any.
    g: Option<usize>,
    at: Option<usize>,
    stack: Vec<usize>,
}

impl FinalFix {
    /// Fix the subtree at `root`, inside the grammar at `g` (`None`: outside
    /// any grammar).
    #[must_use]
    pub fn new(g: Option<usize>, root: usize) -> FinalFix {
        FinalFix {
            g,
            at: Some(root),
            stack: Vec::new(),
        }
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        stack_bytes(&self.stack)
    }

    /// Run until done or until `budget` is spent. `resolve` is `fixonecall`'s
    /// lookup: the position (relative to the grammar node) of the rule that
    /// the name at a key stands for, or 0 if the grammar has no such rule.
    pub fn step(
        &mut self,
        tree: &mut Tree,
        resolve: &dyn Fn(Key) -> i64,
        budget: &mut u32,
    ) -> Poll<Result<(), TreeError>> {
        poll(self.run(tree, resolve, budget))
    }

    fn run(
        &mut self,
        tree: &mut Tree,
        resolve: &dyn Fn(Key) -> i64,
        budget: &mut u32,
    ) -> Result<Option<()>, TreeError> {
        loop {
            if !spend(budget) {
                return Ok(None);
            }
            let Some(t) = self.at else {
                match self.stack.pop() {
                    None => return Ok(Some(())),
                    next => self.at = next,
                }
                continue;
            };
            let tag = tag_at(tree, t)?;
            match tag {
                // Sub-grammars were already fixed.
                Tag::Grammar => {
                    self.at = None;
                    continue;
                }
                Tag::OpenCall => match self.g {
                    Some(g) => fix_one_call(tree, g, t, resolve)?,
                    None => {
                        let key = tree.node(t).map_or(0, |n| n.key);
                        return Err(TreeError::UsedOutsideGrammar(key));
                    }
                },
                // Spent mid-way: the next step goes on rotating here.
                Tag::Seq | Tag::Choice if !correct_associativity(tree, t, budget)? => {
                    return Ok(None);
                }
                _ => {}
            }
            let tag = tag_at(tree, t)?;
            self.at = match tag.siblings() {
                1 => Some(sib1(tree, t)?),
                2 => {
                    push(&mut self.stack, sib2(tree, t)?)?;
                    Some(sib1(tree, t)?)
                }
                _ => None,
            };
        }
    }
}

/// What `finalfix(L, 0, NULL, tree)` — `ptree`'s, outside any grammar — can
/// tell a script: the key of the first open call it meets, which it raises
/// as "rule '%s' used outside a grammar", or none. `finalfix` visits nodes in
/// pre-order, which is the order of the slots of a tree built here (see
/// [`Tree::correct_keys`]); its rotations keep the order of the leaves; and
/// a sub-grammar, which it skips, holds no open call (each was fixed when
/// the grammar was built). So the first open call in slot order is the one
/// it raises for, and this finds it by a scan that changes and allocates
/// nothing. One unit of budget per node.
#[derive(Debug, Clone)]
pub struct FindOpenCall {
    at: usize,
}

impl FindOpenCall {
    #[must_use]
    pub fn new() -> FindOpenCall {
        FindOpenCall { at: 0 }
    }

    pub fn step(&mut self, tree: &Tree, budget: &mut u32) -> Poll<Result<Option<Key>, TreeError>> {
        loop {
            let Some(node) = tree.node(self.at) else {
                return Poll::Ready(Ok(None));
            };
            if !spend(budget) {
                return Poll::Pending;
            }
            if node.tag == Tag::OpenCall {
                return Poll::Ready(Ok(Some(node.key)));
            }
            self.at += if node.tag == Tag::Set {
                1 + super::SET_SLOTS
            } else {
                1
            };
        }
    }
}

impl Default for FindOpenCall {
    fn default() -> Self {
        FindOpenCall::new()
    }
}

/// `fixonecall` (`lpeg.c:2160`): the open call at `t` becomes a call of the
/// rule its name resolves to, and that rule takes its key (and so counts as
/// used, and is named by the key in errors).
fn fix_one_call(
    tree: &mut Tree,
    g: usize,
    t: usize,
    resolve: &dyn Fn(Key) -> i64,
) -> Result<(), TreeError> {
    let key = tree.node(t).map_or(0, |n| n.key);
    let n = resolve(key);
    if n == 0 {
        return Err(TreeError::UndefinedRule(key));
    }
    let rel = i64::try_from(t.checked_sub(g).ok_or(TreeError::Malformed)?)
        .map_err(|_| TreeError::Malformed)?;
    let ps = i32::try_from(n - rel).map_err(|_| TreeError::Malformed)?;
    let nodes = tree.nodes_mut();
    nodes[t].tag = Tag::Call;
    nodes[t].u = ps;
    let rule = tree.sib2(t).ok_or(TreeError::Malformed)?;
    let nodes = tree.nodes_mut();
    if nodes[rule].tag != Tag::Rule {
        return Err(TreeError::Malformed);
    }
    nodes[rule].key = key;
    Ok(())
}

/// `correctassociativity` (`lpeg.c:2191`): `Op(Op(t11, t12), t2)` becomes
/// `Op(t11, Op(t12, t2))`, repeatedly, moving `t11` up a slot each time.
/// Each rotation costs the nodes it moves; `false` if the budget ran out
/// before the node was right-associative (the rotations done so far stand).
fn correct_associativity(tree: &mut Tree, t: usize, budget: &mut u32) -> Result<bool, TreeError> {
    let mut first = true;
    loop {
        let op = tag_at(tree, t)?;
        let t1 = sib1(tree, t)?;
        if tag_at(tree, t1)? != op {
            return Ok(true);
        }
        // At least one rotation per call, so a step always makes progress.
        if !first && *budget == 0 {
            return Ok(false);
        }
        first = false;
        let n1size = usize::try_from(tree.node(t).map_or(0, |n| n.u))
            .ok()
            .and_then(|u| u.checked_sub(1))
            .ok_or(TreeError::Malformed)?;
        let n11size = usize::try_from(tree.node(t1).map_or(0, |n| n.u))
            .ok()
            .and_then(|u| u.checked_sub(1))
            .ok_or(TreeError::Malformed)?;
        let n12size = n1size
            .checked_sub(n11size)
            .and_then(|n| n.checked_sub(1))
            .ok_or(TreeError::Malformed)?;
        if t1 + 1 + n11size > tree.len() {
            return Err(TreeError::Malformed);
        }
        let nodes = tree.nodes_mut();
        nodes.copy_within(t1 + 1..t1 + 1 + n11size, t + 1);
        nodes[t].u = i32::try_from(n11size + 1).map_err(|_| TreeError::Malformed)?;
        let s2 = t + n11size + 1;
        nodes[s2].tag = op;
        nodes[s2].cap = 0;
        nodes[s2].key = 0;
        nodes[s2].u = i32::try_from(n12size + 1).map_err(|_| TreeError::Malformed)?;
        let cost = u32::try_from(n11size + 1).unwrap_or(u32::MAX);
        *budget = budget.saturating_sub(cost);
    }
}
