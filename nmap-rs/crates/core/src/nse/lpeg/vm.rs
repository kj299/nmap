//! LPeg's matching machine (`lpvm.c`, `lpeg.c:3370-3690`) and capture
//! evaluation (`lpcap.c`, `lpeg.c:388-930`: [`capture`]).
//!
//! **The backtrack stack** is an explicit `Vec` ([`Vm`]), with the C's
//! logical capacity: it starts at `INITBACK` = 100 entries, the giveup
//! entry included, and grows only when full, by doubling up to the value
//! `setmaxstack` stored, read at that moment and narrowed to an `int`; at
//! that size a push raises "too many pending calls/choices" (`doublestack`,
//! `lpeg.c:3403-3418`). So the ceilings it puts on a subject's nesting are
//! the C's exactly (D2): `INITBACK` is the floor, `setmaxstack(150)` passes
//! depth 74 of `S <- 'a' S 'b' / ''` and fails at 75. Its memory grows
//! through the budget (E4); a refusal is "not enough memory".
//!
//! **The capture list** keeps the C's entries and growth points, with
//! 32-bit wide indices where the C's are `short` (D4), and the C's limit of
//! `INT_MAX / 32` entries ("too many captures", `doublecap`), which the
//! memory budget refuses long before.
//!
//! **Fuel.** [`Vm::run`] takes a budget: a unit an instruction, a unit a
//! byte a span scans, a unit an entry a failure pops. When it is spent the
//! machine stops where it is, mid-span or mid-failure included, and returns
//! [`VmPoll::Pending`]; run again with the same program and subject, it goes
//! on. It holds indices only: the binding borrows the program and subject
//! afresh at every slice, from the handles its match holds (E3).
//!
//! Lua is called by match-time captures only (`CloseRunTime`), which are
//! step d's; until then the machine stops with [`VmError::RunTime`].

#![allow(
    clippy::arithmetic_side_effects,
    reason = "positions are below the subject's length and slot indices below the \
              program's, so adding an instruction's size or one byte cannot overflow usize; \
              label targets are computed with checked arithmetic"
)]

pub mod capture;

use super::code::{Op, Program, Slot};
use super::tree::{CapKind, Key};
use crate::nse::stdlib::reserve;

/// `INITBACK` (`lpeg.c:3360`): the backtrack stack's first size, and the
/// floor of its ceiling — the stored maximum is read only when it is full.
pub const INITBACK: usize = 100;

/// `INITCAPSIZE` (`lpeg.c:62`): the capture list's first logical size.
pub const INITCAPSIZE: usize = 32;

/// `doublecap`'s limit (`lpeg.c:3392`): `INT_MAX / (2 * sizeof(Capture))`
/// entries.
pub const CAPLIST_LIMIT: usize = 67_108_863;

/// `UCHAR_MAX`: a close turns its open into a full capture only below this
/// length.
const UCHAR_MAX: usize = 255;

/// An entry of the capture list (`Capture`, `lpeg.c:239-244`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capture {
    /// Where in the subject it starts (or, for a close, ends).
    pub s: usize,
    /// The key: a constant-table index, an argument number, a group's
    /// name, a selected value. 32 bits wide (D4).
    pub idx: Key,
    /// Its [`CapKind`].
    pub kind: u8,
    /// 0 for an open capture; the length plus one for a full one; 1 for a
    /// close.
    pub siz: u8,
}

impl Capture {
    /// `isclosecap`.
    #[must_use]
    pub fn is_close(&self) -> bool {
        self.kind == CapKind::Close as u8
    }

    /// `isfullcap`.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.siz != 0
    }

    /// `closeaddr`: where it ends.
    #[must_use]
    pub fn close_addr(&self) -> usize {
        self.s + usize::from(self.siz) - 1
    }
}

/// `s == NULL` in a backtrack entry: a call's return address.
const CALL: usize = usize::MAX;
/// The giveup entry's "instruction".
const GIVEUP: usize = usize::MAX;

/// A backtrack entry (`Stack`, `lpeg.c:3376-3380`).
#[derive(Debug, Clone, Copy)]
struct Frame {
    /// The position to go back to, or [`CALL`].
    s: usize,
    /// The instruction to go on at, or [`GIVEUP`].
    p: usize,
    caplevel: usize,
}

/// Why a match stopped with an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// "too many pending calls/choices": the backtrack stack is at its
    /// ceiling.
    TooManyPending,
    /// "too many captures" (`doublecap`).
    TooManyCaptures,
    /// The memory budget refused the stack or the capture list.
    NotEnoughMemory,
    /// A match-time capture: step d's.
    RunTime,
    /// A program this compiler cannot have made.
    Malformed,
}

/// How a slice of matching ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmPoll {
    /// The match ended where this says (`Some` position past it), or failed.
    Done(Option<usize>),
    /// The budget is spent.
    Pending,
}

/// A match in progress (`match`, `lpeg.c:3486`).
#[derive(Debug, Clone)]
pub struct Vm {
    pc: usize,
    s: usize,
    stack: Vec<Frame>,
    /// The stack's logical size: when this many entries are on it, the next
    /// push grows it or raises.
    stack_cap: usize,
    caps: Vec<Capture>,
    /// The capture list's logical size.
    capsize: usize,
    /// Popping entries for a failure.
    failing: bool,
    done: Option<Option<usize>>,
    steps: u64,
    deepest: usize,
}

/// The `setmaxstack` value as `doublestack` reads it: `lua_tointeger`, an
/// `int`. Anything below [`INITBACK`] acts as `INITBACK`.
pub type MaxStack = i32;

impl Vm {
    /// A match from position `init`.
    #[must_use]
    pub fn new(init: usize) -> Vm {
        let mut stack = Vec::new();
        // The C's first stack is an array on the C stack: no budget asked.
        stack.reserve_exact(INITBACK);
        stack.push(Frame {
            s: init,
            p: GIVEUP,
            caplevel: 0,
        });
        Vm {
            pc: 0,
            s: init,
            stack,
            stack_cap: INITBACK,
            caps: Vec::new(),
            capsize: INITCAPSIZE,
            failing: false,
            done: None,
            steps: 0,
            deepest: 1,
        }
    }

    /// The capture list: after a match, its entries and the closing `Cclose`.
    #[must_use]
    pub fn captures(&self) -> &[Capture] {
        &self.caps
    }

    /// Hand the capture list over.
    #[must_use]
    pub fn take_captures(&mut self) -> Vec<Capture> {
        std::mem::take(&mut self.caps)
    }

    /// Instructions run so far.
    #[must_use]
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// The most entries the backtrack stack held, the giveup entry included.
    #[must_use]
    pub fn deepest(&self) -> usize {
        self.deepest
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.stack
            .capacity()
            .saturating_mul(std::mem::size_of::<Frame>())
            .saturating_add(
                self.caps
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Capture>()),
            )
    }

    /// Run `prog` on `subj` until the match ends or `budget` is spent.
    /// `maxstack` is the stored maximum as the C reads it at a growth of the
    /// stack; no Lua code runs within a slice, so it cannot change within
    /// one.
    pub fn run(
        &mut self,
        prog: &Program,
        subj: &[u8],
        maxstack: MaxStack,
        budget: &mut u32,
    ) -> Result<VmPoll, VmError> {
        if let Some(d) = self.done {
            return Ok(VmPoll::Done(d));
        }
        let slots = prog.slots();
        let e = subj.len();
        loop {
            if self.failing {
                if !self.fail(budget)? {
                    return Ok(VmPoll::Pending);
                }
                if self.pc == GIVEUP {
                    self.done = Some(None);
                    return Ok(VmPoll::Done(None));
                }
            }
            if *budget == 0 {
                return Ok(VmPoll::Pending);
            }
            *budget -= 1;
            self.steps += 1;
            let p = self.pc;
            let Some(&Slot::Inst { op, aux, key }) = slots.get(p) else {
                return Err(VmError::Malformed);
            };
            match op {
                Op::End => {
                    self.push_cap(Capture {
                        s: self.s,
                        idx: 0,
                        kind: CapKind::Close as u8,
                        siz: 0,
                    })?;
                    self.done = Some(Some(self.s));
                    return Ok(VmPoll::Done(Some(self.s)));
                }
                Op::Ret => {
                    let f = self.stack.pop().ok_or(VmError::Malformed)?;
                    if f.s != CALL {
                        return Err(VmError::Malformed);
                    }
                    self.pc = f.p;
                }
                Op::Any => {
                    if self.s < e {
                        self.s += 1;
                        self.pc = p + 1;
                    } else {
                        self.failing = true;
                    }
                }
                Op::TestAny => {
                    self.pc = if self.s < e { p + 2 } else { target(slots, p)? };
                }
                // The C reads the byte before it tests `s < e` (a Lua string
                // ends in a NUL); the test comes first here.
                Op::Char => {
                    if self.s < e && subj[self.s] == aux {
                        self.s += 1;
                        self.pc = p + 1;
                    } else {
                        self.failing = true;
                    }
                }
                Op::TestChar => {
                    self.pc = if self.s < e && subj[self.s] == aux {
                        p + 2
                    } else {
                        target(slots, p)?
                    };
                }
                Op::Set => {
                    if self.s < e && in_set(slots, p + 1, subj[self.s])? {
                        self.s += 1;
                        self.pc = p + super::code::SET_INST_SLOTS;
                    } else {
                        self.failing = true;
                    }
                }
                Op::TestSet => {
                    self.pc = if self.s < e && in_set(slots, p + 2, subj[self.s])? {
                        p + 1 + super::code::SET_INST_SLOTS
                    } else {
                        target(slots, p)?
                    };
                }
                // Back `aux` bytes from the subject's start, not from `init`.
                Op::Behind => {
                    let n = usize::from(aux);
                    if n > self.s {
                        self.failing = true;
                    } else {
                        self.s -= n;
                        self.pc = p + 1;
                    }
                }
                // A unit a byte, the unit the instruction took paying for
                // the first: a long run is scanned across slices, and every
                // slice scans at least one byte.
                Op::Span => {
                    *budget += 1;
                    while self.s < e && in_set(slots, p + 1, subj[self.s])? {
                        if *budget == 0 {
                            return Ok(VmPoll::Pending);
                        }
                        *budget -= 1;
                        self.s += 1;
                    }
                    self.pc = p + super::code::SET_INST_SLOTS;
                }
                Op::Jmp => self.pc = target(slots, p)?,
                Op::Choice => {
                    self.push_frame(
                        Frame {
                            s: self.s,
                            p: target(slots, p)?,
                            caplevel: self.caps.len(),
                        },
                        maxstack,
                    )?;
                    self.pc = p + 2;
                }
                Op::Call => {
                    self.push_frame(
                        Frame {
                            s: CALL,
                            p: p + 2,
                            caplevel: 0,
                        },
                        maxstack,
                    )?;
                    self.pc = target(slots, p)?;
                }
                Op::Commit => {
                    let f = self.stack.pop().ok_or(VmError::Malformed)?;
                    if f.s == CALL {
                        return Err(VmError::Malformed);
                    }
                    self.pc = target(slots, p)?;
                }
                Op::PartialCommit => {
                    let (s, level) = (self.s, self.caps.len());
                    let top = self.stack.last_mut().ok_or(VmError::Malformed)?;
                    if top.s == CALL {
                        return Err(VmError::Malformed);
                    }
                    top.s = s;
                    top.caplevel = level;
                    self.pc = target(slots, p)?;
                }
                Op::BackCommit => {
                    let f = self.stack.pop().ok_or(VmError::Malformed)?;
                    if f.s == CALL {
                        return Err(VmError::Malformed);
                    }
                    self.s = f.s;
                    self.caps.truncate(f.caplevel);
                    self.pc = target(slots, p)?;
                }
                Op::FailTwice => {
                    self.stack.pop().ok_or(VmError::Malformed)?;
                    self.failing = true;
                }
                Op::Fail => self.failing = true,
                Op::CloseCapture => {
                    let s = self.s;
                    let prev = self.caps.last_mut().ok_or(VmError::Malformed)?;
                    let len = s.checked_sub(prev.s).ok_or(VmError::Malformed)?;
                    // A close right after its open: one full capture.
                    if prev.siz == 0 && len < UCHAR_MAX {
                        prev.siz = u8::try_from(len + 1).map_err(|_| VmError::Malformed)?;
                    } else {
                        self.push_cap(Capture {
                            s,
                            idx: key,
                            kind: aux & 0xf,
                            siz: 1,
                        })?;
                    }
                    self.pc = p + 1;
                }
                Op::OpenCapture => {
                    self.push_cap(Capture {
                        s: self.s,
                        idx: key,
                        kind: aux & 0xf,
                        siz: 0,
                    })?;
                    self.pc = p + 1;
                }
                Op::FullCapture => {
                    let off = aux >> 4;
                    self.push_cap(Capture {
                        s: self
                            .s
                            .checked_sub(usize::from(off))
                            .ok_or(VmError::Malformed)?,
                        idx: key,
                        kind: aux & 0xf,
                        siz: off + 1,
                    })?;
                    self.pc = p + 1;
                }
                Op::CloseRunTime => return Err(VmError::RunTime),
                Op::OpenCall | Op::Giveup => return Err(VmError::Malformed),
            }
        }
    }

    /// The failure sequence (`lpeg.c:3617-3626`): pop entries, a unit each,
    /// to the last one that saved a position (pending calls go with them),
    /// and go back to it. False if the budget ran out first.
    fn fail(&mut self, budget: &mut u32) -> Result<bool, VmError> {
        loop {
            if *budget == 0 {
                return Ok(false);
            }
            *budget -= 1;
            let f = self.stack.pop().ok_or(VmError::Malformed)?;
            if f.s != CALL {
                self.caps.truncate(f.caplevel);
                self.s = f.s;
                self.pc = f.p;
                self.failing = false;
                return Ok(true);
            }
        }
    }

    /// Push a backtrack entry; at the logical size, grow first
    /// (`doublestack`).
    fn push_frame(&mut self, f: Frame, maxstack: MaxStack) -> Result<(), VmError> {
        if self.stack.len() >= self.stack_cap {
            let n = self.stack_cap;
            let max = i64::from(maxstack);
            if i64::try_from(n).unwrap_or(i64::MAX) >= max {
                return Err(VmError::TooManyPending);
            }
            // `newn = 2 * n`, at most `max`: an `int` in the C, which cannot
            // pass `max` here.
            let newn = n
                .saturating_mul(2)
                .min(usize::try_from(max).unwrap_or(usize::MAX));
            let more = newn.saturating_sub(self.stack.len());
            if !reserve(&mut self.stack, more) {
                return Err(VmError::NotEnoughMemory);
            }
            self.stack_cap = newn;
        }
        if self.stack.len() == self.stack.capacity() && !reserve(&mut self.stack, 1) {
            return Err(VmError::NotEnoughMemory);
        }
        self.stack.push(f);
        self.deepest = self.deepest.max(self.stack.len());
        Ok(())
    }

    /// Push a capture; at the logical size, grow first (`doublecap`).
    fn push_cap(&mut self, c: Capture) -> Result<(), VmError> {
        if self.caps.len() == self.caps.capacity() && !reserve(&mut self.caps, 1) {
            return Err(VmError::NotEnoughMemory);
        }
        self.caps.push(c);
        let captop = self.caps.len();
        if captop >= self.capsize {
            if captop >= CAPLIST_LIMIT {
                return Err(VmError::TooManyCaptures);
            }
            self.capsize = captop.saturating_mul(2);
        }
        Ok(())
    }
}

/// The label of the instruction at `p`.
#[inline]
fn target(slots: &[Slot], p: usize) -> Result<usize, VmError> {
    super::code::target_at(slots, p).ok_or(VmError::Malformed)
}

/// Whether byte `c` is in the charset whose eight slots start at `at`.
#[inline]
fn in_set(slots: &[Slot], at: usize, c: u8) -> Result<bool, VmError> {
    match slots.get(at + usize::from(c >> 5)) {
        Some(Slot::Bytes(b)) => Ok(b[usize::from((c >> 3) & 3)] & (1 << (c & 7)) != 0),
        _ => Err(VmError::Malformed),
    }
}

#[cfg(test)]
mod tests;
