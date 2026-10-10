//! LPeg's compiler (`lpcode.c`, `lpeg.c:930-1880`): a pattern's tree into a
//! program for the matching machine ([`super::vm`]).
//!
//! **Instruction-exact.** The program is the C's, slot for slot: the same
//! instructions in the same order, each label a slot offset in the slot
//! after its instruction, each charset in the eight slots after its
//! instruction (or its offset), the same peephole rewrites
//! (`docs/M6.6-ANALYSIS.md`, D2). The ceilings the backtrack stack puts on
//! a subject's nesting — the only bound on depth the C has — depend on that
//! code, so they come out as the C's. "Instruction-exact" holds up to the
//! order of a grammar's non-initial rules, which follows table iteration
//! order here as in the C (`collectrules`, `lpeg.c:2965`), and never changes
//! an answer or the stack a match uses.
//!
//! One departure, the C's bug: its peephole re-scans from the slot before a
//! jump it rewrote into a commit (`i--`, `lpeg.c:1846`). That slot is often
//! the last word of the previous instruction, an offset or charset bytes, so
//! the scan loses its alignment and follows "labels" read from bytes nothing
//! wrote, out of the program (`lpeg-codegen-jump-out-of-code`; `finaltarget`,
//! `:1508-1509`, is where ASan sees it). Here the rewrite is kept and the scan
//! goes on after it, which is what the re-scan meant to do whenever it stayed
//! aligned: the new label is already final, so re-scanning it changes nothing.
//!
//! **Iterative and pre-emptible.** The C's code generator recurses on the C
//! stack for every child but a sequence's second; here it is a loop over an
//! explicit stack of jobs ([`gen`]), so a pattern a million nodes deep
//! compiles without recursion (E2). Every job, analysis step and scan costs
//! a unit of budget, and [`Compiler::step`] returns [`Poll::Pending`] when
//! the budget is spent, its state intact, so the binding can return to the
//! VM between slices (D3). Each job makes sure of the analyses it needs
//! before it emits anything, so where the slices fall never changes the code.
//!
//! **Memoised analyses** ([`analysis`], E10). The C's `getfirst`, `headfail`,
//! `nullable`/`nofail` and `fixedlen` follow calls into rules and re-walk
//! shared sub-grammars, which takes time exponential in a grammar's depth.
//! Each is a pure function of a node (and, for `fixedlen`, of the calls
//! already followed), so here each node's answer is computed once.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "slot indices are below the program's length, which is kept below i32::MAX \
              (an offset is an int in the C), and node indices below MAX_TREE: the sum of \
              two cannot overflow usize; offsets are computed with checked conversions"
)]

use super::tree::{CapKind, Charset, Key, TreeError, CHARSET_SIZE};

pub(crate) mod analysis;
mod gen;

pub use gen::Compiler;

/// The matching machine's instructions (`Opcode`, `lpeg.c:274-297`), in the
/// C's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Op {
    /// If no byte is left, fail; else consume one.
    Any,
    /// If the next byte is not `aux`, fail.
    Char,
    /// If the next byte is not in the charset, fail.
    Set,
    /// If no byte is left, jump.
    TestAny,
    /// If the next byte is not `aux`, jump.
    TestChar,
    /// If the next byte is not in the charset, jump.
    TestSet,
    /// Consume bytes while they are in the charset.
    Span,
    /// Move back `aux` bytes; fail if there are not that many.
    Behind,
    /// Return from a rule.
    Ret,
    /// The pattern matched.
    End,
    /// Push a choice: the next failure goes to the label.
    Choice,
    /// Go to the label.
    Jmp,
    /// Call the rule at the label.
    Call,
    /// Call rule number `key`; compilation turns each into a `Call` or a
    /// `Jmp`, and none is ever run.
    OpenCall,
    /// Pop the choice and go to the label.
    Commit,
    /// Move the top choice to here, and go to the label.
    PartialCommit,
    /// Pop the choice, going back to its position, and go to the label.
    BackCommit,
    /// Pop whatever is on top, then fail.
    FailTwice,
    /// Go back to the last choice.
    Fail,
    /// The bottom of the backtrack stack: no match. Never in a program.
    Giveup,
    /// A capture of the last `off` bytes: `aux` is `kind | off << 4`.
    FullCapture,
    /// Open a capture of kind `aux`.
    OpenCapture,
    /// Close the last open capture.
    CloseCapture,
    /// Close a match-time capture: call its function (step d).
    CloseRunTime,
}

impl Op {
    /// `names` in `printinst` (`lpeg.c:1940`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Op::Any => "any",
            Op::Char => "char",
            Op::Set => "set",
            Op::TestAny => "testany",
            Op::TestChar => "testchar",
            Op::TestSet => "testset",
            Op::Span => "span",
            Op::Behind => "behind",
            Op::Ret => "ret",
            Op::End => "end",
            Op::Choice => "choice",
            Op::Jmp => "jmp",
            Op::Call => "call",
            Op::OpenCall => "open_call",
            Op::Commit => "commit",
            Op::PartialCommit => "partial_commit",
            Op::BackCommit => "back_commit",
            Op::FailTwice => "failtwice",
            Op::Fail => "fail",
            Op::Giveup => "giveup",
            Op::FullCapture => "fullcapture",
            Op::OpenCapture => "opencapture",
            Op::CloseCapture => "closecapture",
            Op::CloseRunTime => "closeruntime",
        }
    }

    /// `sizei` (`lpeg.c:1318`): the slots an instruction takes, its label
    /// and its charset included.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Op::Set | Op::Span => SET_INST_SLOTS,
            Op::TestSet => SET_INST_SLOTS + 1,
            Op::TestChar
            | Op::TestAny
            | Op::Choice
            | Op::Jmp
            | Op::Call
            | Op::OpenCall
            | Op::Commit
            | Op::PartialCommit
            | Op::BackCommit => 2,
            _ => 1,
        }
    }

    /// Whether the slot after the instruction is a label.
    #[must_use]
    pub const fn has_label(self) -> bool {
        matches!(
            self,
            Op::TestChar
                | Op::TestAny
                | Op::TestSet
                | Op::Choice
                | Op::Jmp
                | Op::Call
                | Op::OpenCall
                | Op::Commit
                | Op::PartialCommit
                | Op::BackCommit
        )
    }
}

/// `CHARSETINSTSIZE` (`lpeg.c:130`, `instsize(CHARSETSIZE)`): an instruction
/// and the eight 4-byte slots of its charset.
pub const SET_INST_SLOTS: usize = 1 + CHARSET_SIZE / 4;

/// `MAXOFF` (`lpeg.c:117`): the longest full capture.
pub const MAXOFF: i64 = 15;

/// One slot of a program (`Instruction`, `lpeg.c:303-311`, a 4-byte union):
/// an instruction, the label after one, or four bytes of a charset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// `{code, aux, key}`. `key` is 32 bits wide where the C's is a `short`
    /// (`lpeg-ktable-key-16bit`, D4).
    Inst { op: Op, aux: u8, key: Key },
    /// A label: the offset of its target from its instruction.
    Offset(i32),
    /// Four bytes of a charset.
    Bytes([u8; 4]),
}

/// A compiled pattern: its slots, never changed once made. A match runs a
/// handle to it taken when the match starts, never the pattern's cache again
/// (E3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    slots: Vec<Slot>,
    /// Whether it holds a capture that calls Lua (`Cmt`, `/f`, `/table`,
    /// `Cf`): step d's.
    calls_lua: bool,
}

/// Why a pattern could not be compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// `finalfix` refused the tree (an open call outside a grammar), or the
    /// tree was malformed.
    Tree(TreeError),
    /// The code outgrew the memory budget, or an `int` (`reallocprog`'s "not
    /// enough memory", `lpeg.c:1356`).
    NotEnoughMemory,
    /// `getfirst` re-entered the rule with this key on its own walk, where
    /// the C's recursion would never end (`lpeg-getfirst-unbounded-recursion`):
    /// a left call through `lpeg.B`.
    LeftRecursive(Key),
}

impl From<TreeError> for CodeError {
    fn from(e: TreeError) -> Self {
        match e {
            TreeError::NotEnoughMemory => CodeError::NotEnoughMemory,
            TreeError::LeftRecursive(k) => CodeError::LeftRecursive(k),
            e => CodeError::Tree(e),
        }
    }
}

impl Program {
    /// The slots.
    #[must_use]
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Its length in slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Never true: every program ends with `End`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Whether it holds a capture that calls Lua.
    #[must_use]
    pub fn calls_lua(&self) -> bool {
        self.calls_lua
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.slots
            .capacity()
            .saturating_mul(std::mem::size_of::<Slot>())
    }

    /// The instruction at slot `i`, if `i` holds one.
    #[must_use]
    pub fn inst(&self, i: usize) -> Option<(Op, u8, Key)> {
        inst_at(&self.slots, i)
    }

    /// The label of the instruction at `i` (`target(code, i)`).
    #[must_use]
    pub fn target(&self, i: usize) -> Option<usize> {
        target_at(&self.slots, i)
    }

    /// The charset in the eight slots from `i`.
    #[must_use]
    pub fn charset(&self, i: usize) -> Option<Charset> {
        charset_at(&self.slots, i)
    }

    /// The program as `lpeg.pcode` prints it in a debug build of LPeg
    /// (`printpatt`, `lpeg.c:1931-1990`), one instruction a line: what the
    /// tests compare with the C's output.
    #[must_use]
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let mut i = 0;
        while i < self.slots.len() {
            let Some((op, aux, key)) = self.inst(i) else {
                out.push_str(&format!("{i:02}: ?\n"));
                i += 1;
                continue;
            };
            out.push_str(&format!("{i:02}: {} ", op.name()));
            let jmp = |i: usize| match self.slots.get(i + 1) {
                Some(Slot::Offset(o)) => {
                    format!("-> {}", i64::try_from(i).unwrap_or(0) + i64::from(*o))
                }
                _ => "-> ?".to_string(),
            };
            match op {
                Op::Char => out.push_str(&format!("'{}'", char::from(aux))),
                Op::TestChar => {
                    out.push_str(&format!("'{}'", char::from(aux)));
                    out.push_str(&jmp(i));
                }
                Op::FullCapture => out.push_str(&format!(
                    "{} (size = {})  (idx = {})",
                    cap_name(aux & 0xf),
                    aux >> 4,
                    key
                )),
                Op::OpenCapture => out.push_str(&format!("{} (idx = {key})", cap_name(aux & 0xf))),
                Op::Set | Op::Span => {
                    out.push_str(&charset_text(
                        &self.charset(i + 1).unwrap_or(Charset::empty()),
                    ));
                }
                Op::TestSet => {
                    out.push_str(&charset_text(
                        &self.charset(i + 2).unwrap_or(Charset::empty()),
                    ));
                    out.push_str(&jmp(i));
                }
                Op::OpenCall => match self.slots.get(i + 1) {
                    Some(Slot::Offset(o)) => out.push_str(&format!("-> {o}")),
                    _ => out.push_str("-> ?"),
                },
                Op::Behind => out.push_str(&format!("{aux}")),
                Op::Jmp
                | Op::Call
                | Op::Commit
                | Op::Choice
                | Op::PartialCommit
                | Op::BackCommit
                | Op::TestAny => out.push_str(&jmp(i)),
                _ => {}
            }
            out.push('\n');
            i += op.size();
        }
        out
    }
}

/// `printcapkind`.
fn cap_name(kind: u8) -> &'static str {
    const MODES: [&str; 15] = [
        "close",
        "position",
        "constant",
        "backref",
        "argument",
        "simple",
        "table",
        "function",
        "query",
        "string",
        "num",
        "substitution",
        "fold",
        "runtime",
        "group",
    ];
    MODES.get(usize::from(kind)).copied().unwrap_or("?")
}

/// `printcharset`: the set as ranges of hex bytes.
fn charset_text(cs: &Charset) -> String {
    let mut out = String::from("[");
    let mut i = 0usize;
    while i <= 255 {
        let first = i;
        while i <= 255 && cs.has(u8::try_from(i).unwrap_or(0)) {
            i += 1;
        }
        if i == first + 1 {
            out.push_str(&format!("({first:02x})"));
        } else if i > first + 1 {
            out.push_str(&format!("({first:02x}-{:02x})", i - 1));
        }
        i += 1;
    }
    out.push(']');
    out
}

/// The instruction at slot `i`.
pub(crate) fn inst_at(slots: &[Slot], i: usize) -> Option<(Op, u8, Key)> {
    match slots.get(i)? {
        Slot::Inst { op, aux, key } => Some((*op, *aux, *key)),
        _ => None,
    }
}

/// `target(code, i)` (`lpeg.c:1410`): `i` plus the offset in slot `i + 1`.
pub(crate) fn target_at(slots: &[Slot], i: usize) -> Option<usize> {
    match slots.get(i.checked_add(1)?)? {
        Slot::Offset(o) => i.checked_add_signed(isize::try_from(*o).ok()?),
        _ => None,
    }
}

/// The charset in the eight slots from `i`.
pub(crate) fn charset_at(slots: &[Slot], i: usize) -> Option<Charset> {
    let mut cs = Charset::empty();
    for k in 0..CHARSET_SIZE / 4 {
        match slots.get(i.checked_add(k)?)? {
            Slot::Bytes(b) => cs.0[k * 4..k * 4 + 4].copy_from_slice(b),
            _ => return None,
        }
    }
    Some(cs)
}

/// `charsettype` (`lpeg.c:955`): what a charset compiles to — exactly a
/// classification by the number of its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetKind {
    /// No member: `IFail`.
    Fail,
    /// One member: `IChar`.
    Char(u8),
    /// All 256: `IAny`.
    Any,
    /// Anything else: `ISet`.
    Set,
}

pub(crate) fn set_kind(cs: &Charset) -> SetKind {
    let count: u32 = cs.0.iter().map(|b| b.count_ones()).sum();
    match count {
        0 => SetKind::Fail,
        1 => {
            let c = (0..=255u8).find(|&c| cs.has(c)).unwrap_or(0);
            SetKind::Char(c)
        }
        256 => SetKind::Any,
        _ => SetKind::Set,
    }
}

/// Whether a capture kind calls Lua when it is evaluated or matched.
pub(crate) fn kind_calls_lua(kind: u8) -> bool {
    kind == CapKind::Function as u8
        || kind == CapKind::Query as u8
        || kind == CapKind::Fold as u8
        || kind == CapKind::Runtime as u8
}

#[cfg(test)]
mod tests;
