//! Capture evaluation (`lpcap.c`, `lpeg.c:388-930`), as a resumable cursor.
//!
//! The C walks the capture list with mutually recursive functions —
//! `pushcapture`, `pushnestedvalues`, `tablecap`, `backrefcap`, `numcap`,
//! `stringcap`, `substcap`, `addonestring` — that push values on the Lua
//! stack. Here each activation is a frame on an explicit stack, recording
//! where it resumes and its locals, so evaluation recurses on no Rust stack
//! however deep the captures nest (E2), and stops at any point when its
//! budget is spent (D3: a chain of back-references re-evaluates its groups
//! at each reference, which takes time exponential in its depth with no Lua
//! call at all, `docs/M6.6-ANALYSIS.md` §1.1).
//!
//! **Values.** The cursor is pure: values are [`CapVal`]s — subject slices,
//! strings it built, integers, and references to the pattern's constants
//! and the match's extra arguments, which a [`CapEnv`] shows it — and
//! tables are lists of assignments, in the C's order, that the binding
//! makes into Lua tables. `vs` mirrors the Lua stack the C would use, slot
//! for slot, so the C's one check of it — `luaL_checkstack(L, 4, …)` at
//! every entry to `pushcapture`, against `LUAI_MAXSTACK` — fails exactly
//! where the C's does, given what was on the stack below (`u0`): "stack
//! overflow (too many captures)". The C's later pushes, which it does not
//! check (`lpeg-nested-capture-lua-stack-overflow`: 300 nested `C` write
//! past the stack), just succeed here.
//!
//! **Laziness**, as the C's: a capture nothing reaches is never evaluated,
//! and its errors never raised — a named group outside `Ct` and `Cb`, a
//! `/0`, a `/string` slot past 9 or never referenced.
//!
//! **Fuel.** A frame step is a unit of the budget, and so is each
//! [`BYTES_PER_FUEL`] bytes a step copies into a buffer, moves or compares: a
//! copy goes on from where it stopped in the next slice (`Frame::Copy`),
//! as does the move of a `C`'s whole match below its nested values. A
//! growth that takes the heap past the memory budget ends the slice
//! (`lpeg::grow`).
//!
//! Captures that call Lua (`/f`, `/table`, `Cf`, match-time captures) are
//! step d's: [`CapError::CallsLua`] until then.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "positions are indices into the capture list and the subject, and counts of \
              values on a stack that the memory budget bounds: none reaches usize::MAX, and \
              each step moves an index by one"
)]

use std::borrow::Cow;

use super::Capture;
use crate::nse::lpeg::tree::{CapKind, Key};
use crate::nse::lpeg::{did_bytes, did_steps, grow as grow_by, Grown, BYTES_PER_FUEL};

/// `LUAI_MAXSTACK` (`luaconf.h`): the most slots a Lua stack may use.
pub const LUAI_MAXSTACK: usize = 1_000_000;

/// `MAXSTRCAPS` (`lpeg.c:705`): the captures `/string` can refer to,
/// `%0` to `%9`; further nested captures are skipped silently.
pub const MAXSTRCAPS: usize = 10;

/// `FIXEDARGS` (`lpeg.c:69`): `match`'s arguments before the extra ones
/// `Carg` reads.
pub const FIXEDARGS: usize = 3;

/// Assignments in one chunk of a table capture's list: a list grows a chunk
/// at a time, so the binding gives it back a chunk at a time as it fills
/// the table ([`CapCursor::give_back`]), with nothing moved.
pub const TABLE_CHUNK: usize = 4096;

/// One assignment a table capture makes.
pub type Entry = (TableKey, CapVal);

/// One slot of the mirrored Lua stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapVal {
    Nil,
    /// A position or a match's end, 1-based.
    Int(i64),
    /// The subject from the first index to the second.
    Str(usize, usize),
    /// A string the cursor built, by its index ([`CapCursor::string`]).
    Bytes(u32),
    /// The pattern's constant at this key (never 0: that is `Nil`).
    K(Key),
    /// `match`'s extra argument with this number (`Carg`).
    Arg(u32),
    /// A table, by its index ([`CapCursor::table`]).
    Table(u32),
    /// `luaL_Buffer`'s slot while a string capture is being built.
    Buf,
}

/// A key a table capture sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKey {
    /// A positional value (`lua_rawseti`).
    Int(i64),
    /// A named group: the constant naming it (`lua_settable`).
    K(Key),
}

/// A Lua value as capture evaluation needs to see it: its type, and its
/// text where `lua_tolstring` gives one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View<'a> {
    Nil,
    /// A string.
    Str(Cow<'a, [u8]>),
    /// A number, and its text as `lua_tolstring` writes it (`%.14g`, an
    /// integer as `%d`).
    Num(Cow<'a, [u8]>),
    /// Anything else, by `luaL_typename`: `boolean`, `table`, `userdata`,
    /// `function`, `thread`.
    Other(&'static str),
}

/// The constants and extra arguments of a match, as the cursor sees them.
pub trait CapEnv {
    /// The constant at key `k` (`k > 0`).
    fn constant(&self, k: Key) -> View<'_>;
    /// `match`'s `n`-th extra argument (`n >= 1`, present).
    fn argument(&self, n: u32) -> View<'_>;
    /// Whether the constants at `a` and `b` are raw-equal (group names, which
    /// are always strings), and how many bytes deciding it compared. Key 0 is
    /// `nil`.
    fn same_constant(&self, a: Key, b: Key) -> (bool, usize);
}

/// Why evaluation failed. The binding words each as the C does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// "stack overflow (too many captures)".
    StackOverflow,
    /// "back reference '%s' not found", naming the constant.
    BackrefNotFound(Key),
    /// "reference to absent argument #%d".
    AbsentArgument(u32),
    /// "no capture '%d'".
    NoCapture(u32),
    /// "invalid capture index (%d)".
    InvalidCaptureIndex(u32),
    /// "no values in capture index %d".
    NoValues(u32),
    /// "invalid %s value (a %s)".
    InvalidValue {
        what: &'static str,
        type_name: &'static str,
    },
    /// "buffer too large" (`luaL_addlstring` of a negative length, which a
    /// substitution's captures out of order make).
    BufferTooLarge,
    /// The memory budget refused a buffer or a table.
    NotEnoughMemory,
    /// A capture that calls Lua: step d's.
    CallsLua,
    /// A list this machine cannot have made.
    Malformed,
}

/// A slot of `/string`'s capture array (`StrAux`).
#[derive(Debug, Clone, Copy)]
enum StrAux {
    /// The subject from the first index to the second.
    Str(usize, usize),
    /// The nested capture at this index, evaluated where it is used.
    Capture(usize),
}

/// One activation of one of the C's functions, and where it resumes.
#[derive(Debug, Clone, Copy)]
enum Frame {
    /// `getcaptures`' loop: the values so far.
    Top { n: usize, started: bool },
    /// `pushcapture`, about to start at `pos`.
    Push,
    /// `pushnestedvalues`: the open entry, the values so far.
    Nested {
        co: usize,
        n: usize,
        addextra: bool,
        started: bool,
    },
    /// `Csimple` after `pushnestedvalues(1)`: the whole match, pushed last,
    /// goes first (`lua_insert`), moved down a chunk a step: `k` values, the
    /// whole match now at `cur`.
    SimpleEnd { k: usize, cur: usize, started: bool },
    /// A string or substitution capture after `stringcap`/`substcap`: its
    /// buffer becomes its value.
    BufEnd,
    /// `backrefcap`: the reference, and the step it is at.
    Backref { curr: usize, stage: u8 },
    /// `findback`, scanning back from `cap`; `skip` while `findopen` skips
    /// a closed capture (the closes still to match).
    FindBack {
        name: Key,
        cap: usize,
        skip: Option<usize>,
    },
    /// `tablecap`: the table, its positional count, and what it waits for.
    Table { t: u32, n: i64, wait: TableWait },
    /// `numcap`, after the nested values.
    Num { idx: Key },
    /// `nextcap`, scanning forward from `cap`; `None` before it starts.
    NextCap { cap: usize, depth: Option<usize> },
    /// `getstrcaps` into the array at `base`: the next slot, the open
    /// simple captures (`ks`, at most [`MAXSTRCAPS`]), and whether the
    /// nested capture being skipped takes a slot.
    StrCaps {
        base: usize,
        n: usize,
        ks: [u8; MAXSTRCAPS],
        nks: u8,
        skipping: Option<bool>,
    },
    /// `stringcap`'s format loop: the format's key, the array at `base`
    /// with `n + 1` slots, the format byte `i`, and while a slot is being
    /// added, its number and where to come back.
    StringCap {
        fmt: Key,
        base: usize,
        n: usize,
        i: usize,
        adding: Option<(u32, usize)>,
        stage: StrStage,
    },
    /// `substcap`: the position text resumes at, and where it is.
    Subst { curr: usize, stage: SubstStage },
    /// `addonestring`; `n`, the values the capture had, once known.
    AddOne {
        what: &'static str,
        stage: u8,
        n: usize,
    },
    /// `luaL_addlstring` of `src[at..end]` into the buffer being built, as
    /// much a step as the budget pays for.
    Copy { src: Src, at: usize, end: usize },
}

/// Where a [`Frame::Copy`] copies from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    Subject,
    /// A string the cursor built.
    String(u32),
    /// A constant's text (a string's, or a number's as `lua_tolstring`
    /// writes it).
    Const(Key),
    /// An extra argument's text.
    Arg(u32),
}

/// Where `substcap` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubstStage {
    /// About to start at `pos`.
    Start,
    /// The text before the nested capture at `next` is in: its value next.
    Replace { next: usize },
    /// Back from the nested capture at `next`.
    Replaced { next: usize },
    /// The last text is in: done.
    End,
}

/// Where `stringcap` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrStage {
    /// About to collect the slots.
    Start,
    /// Back from `getstrcaps`, with the slot count in `ret`.
    Collected,
    /// In the format.
    Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableWait {
    Start,
    /// A named group's value, its name below it.
    Named,
    /// A positional capture's values.
    Positional,
}

/// Capture evaluation of one match (`getcaptures`, `lpeg.c:902`).
#[derive(Debug, Clone)]
pub struct CapCursor {
    pos: usize,
    frames: Vec<Frame>,
    /// The mirrored Lua stack.
    vs: Vec<CapVal>,
    /// The buffers of the string captures being built, innermost last.
    bufs: Vec<Vec<u8>>,
    /// The strings built.
    strings: Vec<Vec<u8>>,
    /// The tables made, as their assignments in order, in chunks of
    /// [`TABLE_CHUNK`].
    tables: Vec<Vec<Vec<Entry>>>,
    /// `/string`'s capture arrays, [`MAXSTRCAPS`] slots each.
    strcaps: Vec<StrAux>,
    /// The last returned count.
    ret: usize,
    /// The match's end, for a match with no values.
    end: usize,
    /// Stack slots in use below the values.
    u0: usize,
    /// `match`'s argument count (`ptop`).
    ptop: usize,
    done: bool,
    steps: u64,
    /// A growth took the heap past the memory budget: end the slice.
    stop: bool,
    /// Units a step took past the budget, on work it could not stop
    /// part-way ([`CapCursor::take_over`]).
    over: u64,
}

impl CapCursor {
    /// Evaluation of a match that ended at `end`, with `u0` stack slots in
    /// use when it starts and `ptop` arguments to `match`.
    #[must_use]
    pub fn new(end: usize, u0: usize, ptop: usize) -> CapCursor {
        CapCursor {
            pos: 0,
            frames: vec![Frame::Top {
                n: 0,
                started: false,
            }],
            vs: Vec::new(),
            bufs: Vec::new(),
            strings: Vec::new(),
            tables: Vec::new(),
            strcaps: Vec::new(),
            ret: 0,
            end,
            u0,
            ptop,
            done: false,
            steps: 0,
            stop: false,
            over: 0,
        }
    }

    /// Units of budget a step took past the budget it was given, on work
    /// that cannot stop part-way (comparing two group names whose hashes are
    /// equal), since this was last asked: the binding charges them to the
    /// slice's fuel.
    pub fn take_over(&mut self) -> u64 {
        std::mem::take(&mut self.over)
    }

    /// The values, once done: what `match` returns.
    #[must_use]
    pub fn values(&self) -> &[CapVal] {
        &self.vs
    }

    /// The string a [`CapVal::Bytes`] refers to.
    #[must_use]
    pub fn string(&self, i: u32) -> &[u8] {
        self.strings
            .get(usize::try_from(i).unwrap_or(usize::MAX))
            .map_or(&[], Vec::as_slice)
    }

    /// The assignments of the table a [`CapVal::Table`] refers to, in order
    /// (a copy, for the tests).
    #[must_use]
    pub fn table(&self, i: u32) -> Vec<Entry> {
        self.tables
            .get(usize::try_from(i).unwrap_or(usize::MAX))
            .map_or(Vec::new(), |chunks| chunks.concat())
    }

    /// Assignment `e` of table `i`, in order; `None` past the last (or in a
    /// chunk given back).
    #[must_use]
    pub fn table_entry(&self, i: u32, e: usize) -> Option<Entry> {
        self.tables
            .get(usize::try_from(i).ok()?)?
            .get(e / TABLE_CHUNK)?
            .get(e % TABLE_CHUNK)
            .copied()
    }

    /// How many tables were made: [`CapVal::Table`] indices are below this,
    /// and a table is made before any it holds.
    #[must_use]
    pub fn tables(&self) -> usize {
        self.tables.len()
    }

    /// Give back the assignments of table `i`, once they are made: it reads
    /// as empty from then on.
    pub fn free_table(&mut self, i: u32) {
        if let Some(t) = self
            .tables
            .get_mut(usize::try_from(i).unwrap_or(usize::MAX))
        {
            *t = Vec::new();
        }
    }

    /// Give back the chunks of table `i` whose assignments are all below
    /// `e`, once they are made.
    pub fn give_back(&mut self, i: u32, e: usize) {
        if let Some(chunks) = self
            .tables
            .get_mut(usize::try_from(i).unwrap_or(usize::MAX))
        {
            for chunk in chunks.iter_mut().take(e / TABLE_CHUNK) {
                *chunk = Vec::new();
            }
        }
    }

    /// Frame steps taken, for the tests.
    #[must_use]
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// The bytes it holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        fn b<T>(v: &Vec<T>) -> usize {
            v.capacity().saturating_mul(std::mem::size_of::<T>())
        }
        [
            b(&self.frames),
            b(&self.vs),
            b(&self.strcaps),
            self.bufs
                .iter()
                .map(Vec::capacity)
                .fold(0, usize::saturating_add),
            self.strings
                .iter()
                .map(Vec::capacity)
                .fold(0, usize::saturating_add),
            self.tables
                .iter()
                .map(|chunks| chunks.iter().map(b).fold(b(chunks), usize::saturating_add))
                .fold(0, usize::saturating_add),
            b(&self.bufs),
            b(&self.strings),
            b(&self.tables),
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }

    /// Evaluate until done (`Some`) or `budget` is spent (`None`). `caps` is
    /// the match's capture list, its closing `Cclose` included, and `subj`
    /// its subject, the same at every step.
    pub fn step(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
        budget: &mut u32,
    ) -> Result<Option<()>, CapError> {
        let start = self.steps;
        let r = self.run(caps, subj, env, budget);
        did_steps(self.steps - start);
        r
    }

    fn run(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
        budget: &mut u32,
    ) -> Result<Option<()>, CapError> {
        while !self.done {
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
            self.steps += 1;
            let Some(&frame) = self.frames.last() else {
                self.done = true;
                break;
            };
            self.frame(frame, caps, subj, env, budget)?;
            if std::mem::take(&mut self.stop) {
                *budget = 0;
            }
        }
        Ok(Some(()))
    }

    // ------------------------------------------------------------ helpers

    fn cap<'c>(&self, caps: &'c [Capture], i: usize) -> Result<&'c Capture, CapError> {
        caps.get(i).ok_or(CapError::Malformed)
    }

    fn push(&mut self, v: CapVal) -> Result<(), CapError> {
        grow(&mut self.vs, 1, &mut self.stop)?;
        self.vs.push(v);
        Ok(())
    }

    fn pop(&mut self) -> Result<CapVal, CapError> {
        self.vs.pop().ok_or(CapError::Malformed)
    }

    fn call(&mut self, f: Frame) -> Result<(), CapError> {
        grow(&mut self.frames, 1, &mut self.stop)?;
        self.frames.push(f);
        Ok(())
    }

    /// Replace the running frame (a tail call, or a change of stage).
    fn set(&mut self, f: Frame) {
        if let Some(top) = self.frames.last_mut() {
            *top = f;
        }
    }

    /// Return `n` values to the caller.
    fn ret(&mut self, n: usize) {
        self.frames.pop();
        self.ret = n;
    }

    /// The buffer being built.
    fn buf(&mut self) -> Result<&mut Vec<u8>, CapError> {
        self.bufs.last_mut().ok_or(CapError::Malformed)
    }

    /// Append a few bytes — a format's escaped byte, a number's text — to
    /// the buffer being built (`luaL_addlstring`); the step's unit pays.
    fn add(&mut self, bytes: &[u8]) -> Result<(), CapError> {
        let buf = self.bufs.last_mut().ok_or(CapError::Malformed)?;
        grow(buf, bytes.len(), &mut self.stop)?;
        buf.extend_from_slice(bytes);
        did_bytes(bytes.len());
        Ok(())
    }

    /// `luaL_addlstring(b, curr, next - curr)`: the subject between two
    /// positions, through a [`Frame::Copy`]. Out of order — a capture an
    /// and-predicate kept from a called rule can start before the last one
    /// ended — the C's length is a huge `size_t`, and `newbuffsize` raises
    /// "buffer too large" when the buffer holds at least the difference, or
    /// else asks for that much memory and is refused (`lua_error`, "not
    /// enough memory").
    fn add_range(&mut self, subj: &[u8], curr: usize, next: usize) -> Result<(), CapError> {
        if next < curr {
            return if self.buf()?.len() >= curr - next {
                Err(CapError::BufferTooLarge)
            } else {
                Err(CapError::NotEnoughMemory)
            };
        }
        if next > subj.len() {
            return Err(CapError::Malformed);
        }
        self.copy(Src::Subject, curr, next)
    }

    /// Copy `src[at..end]` into the buffer being built: a [`Frame::Copy`]
    /// called, unless there is nothing to copy.
    fn copy(&mut self, src: Src, at: usize, end: usize) -> Result<(), CapError> {
        if end > at {
            self.call(Frame::Copy { src, at, end })
        } else {
            Ok(())
        }
    }

    /// `luaL_typename` of a value.
    fn type_name(v: CapVal, env: &dyn CapEnv) -> &'static str {
        let view = |w: View<'_>| match w {
            View::Nil => "nil",
            View::Str(_) => "string",
            View::Num(_) => "number",
            View::Other(t) => t,
        };
        match v {
            CapVal::Nil => "nil",
            CapVal::Int(_) => "number",
            CapVal::Str(..) | CapVal::Bytes(_) => "string",
            CapVal::Table(_) => "table",
            CapVal::K(k) => view(seen(env.constant(k))),
            CapVal::Arg(n) => view(seen(env.argument(n))),
            CapVal::Buf => "userdata",
        }
    }

    /// The constant at `k` as a value: key 0 is `nil` (`Cc(nil)` adds no
    /// constant, and the C reads entry 0 of a table it may not have:
    /// `lpeg-cc-nil-without-ktable`).
    fn constant(k: Key) -> CapVal {
        if k == 0 {
            CapVal::Nil
        } else {
            CapVal::K(k)
        }
    }

    // ------------------------------------------------------------ frames

    fn frame(
        &mut self,
        frame: Frame,
        caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        match frame {
            // `getcaptures`.
            Frame::Top { n, started } => {
                let n = if started { n + self.ret } else { n };
                if self.cap(caps, self.pos)?.is_close() {
                    if n == 0 {
                        self.push(CapVal::Int(
                            i64::try_from(self.end)
                                .unwrap_or(i64::MAX)
                                .saturating_add(1),
                        ))?;
                    }
                    self.frames.pop();
                    self.done = true;
                    return Ok(());
                }
                self.set(Frame::Top { n, started: true });
                self.call(Frame::Push)
            }
            Frame::Push => self.push_capture(caps, subj, env),
            Frame::Nested {
                co,
                n,
                addextra,
                started,
            } => {
                if !started {
                    let c = *self.cap(caps, self.pos)?;
                    let co = self.pos;
                    self.pos += 1;
                    if c.is_full() {
                        self.push(CapVal::Str(c.s, c.s + usize::from(c.siz) - 1))?;
                        self.ret(1);
                        return Ok(());
                    }
                    self.set(Frame::Nested {
                        co,
                        n: 0,
                        addextra,
                        started: true,
                    });
                    return self.nested_loop(caps, co, 0, addextra);
                }
                self.nested_loop(caps, co, n + self.ret, addextra)
            }
            Frame::SimpleEnd { k, cur, started } => self.simple_end(k, cur, started, budget),
            // `luaL_pushresult`: the string replaces the buffer's slot.
            Frame::BufEnd => {
                let s = self.bufs.pop().ok_or(CapError::Malformed)?;
                let id =
                    u32::try_from(self.strings.len()).map_err(|_| CapError::NotEnoughMemory)?;
                grow(&mut self.strings, 1, &mut self.stop)?;
                self.strings.push(s);
                match self.vs.last_mut() {
                    Some(v @ CapVal::Buf) => *v = CapVal::Bytes(id),
                    _ => return Err(CapError::Malformed),
                }
                self.ret(1);
                Ok(())
            }
            Frame::Backref { curr, stage } => self.backref(caps, curr, stage),
            Frame::FindBack { name, cap, skip } => {
                self.find_back(caps, env, name, cap, skip, budget)
            }
            Frame::Table { t, n, wait } => self.table_cap(caps, t, n, wait),
            // `numcap`, after the nested values: keep the `idx`-th.
            Frame::Num { idx } => {
                let n = self.ret;
                let want = usize::try_from(idx).map_err(|_| CapError::Malformed)?;
                if n < want {
                    return Err(CapError::NoCapture(idx));
                }
                let base = self.vs.len() - n;
                let v = self.vs[base + want - 1];
                self.vs.truncate(base);
                self.push(v)?;
                self.ret(1);
                Ok(())
            }
            Frame::NextCap { cap, depth } => self.next_cap(caps, cap, depth, budget),
            Frame::StrCaps {
                base,
                n,
                ks,
                nks,
                skipping,
            } => self.str_caps(caps, base, n, ks, nks, skipping),
            Frame::StringCap {
                fmt,
                base,
                n,
                i,
                adding,
                stage,
            } => self.string_cap(caps, subj, env, fmt, base, n, i, adding, stage, budget),
            Frame::Subst { curr, stage } => self.subst_cap(caps, subj, curr, stage),
            Frame::AddOne { what, stage, n } => self.add_one(caps, env, what, stage, n, budget),
            Frame::Copy { src, at, end } => self.copy_step(subj, env, src, at, end, budget),
        }
    }

    /// `lua_insert(L, -k)` after a simple capture's nested values: the whole
    /// match, pushed last, goes below them, moved down a chunk of values a
    /// step — the bytes the step's unit and the budget pay for,
    /// [`BYTES_PER_FUEL`] a unit, two values at least — so `C` nested `d`
    /// deep, `d²/2` values moved, takes slices in proportion.
    fn simple_end(
        &mut self,
        k: usize,
        cur: usize,
        started: bool,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        let (k, cur) = if started {
            (k, cur)
        } else {
            let last = self.vs.len().checked_sub(1).ok_or(CapError::Malformed)?;
            (self.ret, last)
        };
        let at = self.vs.len().checked_sub(k).ok_or(CapError::Malformed)?;
        let size = std::mem::size_of::<CapVal>();
        let room = (BYTES_PER_FUEL.saturating_mul(
            usize::try_from(*budget)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        ) / size)
            .max(2);
        let lo = (cur + 1).saturating_sub(room).max(at);
        self.vs
            .get_mut(lo..=cur)
            .ok_or(CapError::Malformed)?
            .rotate_right(1);
        let bytes = (cur - lo + 1).saturating_mul(size);
        did_bytes(bytes);
        let units = bytes.div_ceil(BYTES_PER_FUEL).saturating_sub(1);
        *budget = budget.saturating_sub(u32::try_from(units).unwrap_or(u32::MAX));
        if lo == at {
            self.ret(k);
        } else {
            self.set(Frame::SimpleEnd {
                k,
                cur: lo,
                started: true,
            });
        }
        Ok(())
    }

    /// A step of a [`Frame::Copy`]: as many bytes as the step's unit and the
    /// budget pay for, [`BYTES_PER_FUEL`] a unit. The first step makes room
    /// for all of them, as `luaL_addlstring` does.
    fn copy_step(
        &mut self,
        subj: &[u8],
        env: &dyn CapEnv,
        src: Src,
        at: usize,
        end: usize,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        let remaining = end.checked_sub(at).ok_or(CapError::Malformed)?;
        let room = BYTES_PER_FUEL.saturating_mul(
            usize::try_from(*budget)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        let n = remaining.min(room);
        let buf = self.bufs.last_mut().ok_or(CapError::Malformed)?;
        grow(buf, remaining, &mut self.stop)?;
        let view;
        let from: &[u8] = match src {
            Src::Subject => subj,
            Src::String(i) => self
                .strings
                .get(usize::try_from(i).unwrap_or(usize::MAX))
                .ok_or(CapError::Malformed)?,
            Src::Const(_) | Src::Arg(_) => {
                view = match src {
                    Src::Const(k) => seen(env.constant(k)),
                    Src::Arg(m) => seen(env.argument(m)),
                    _ => View::Nil,
                };
                match &view {
                    View::Str(s) | View::Num(s) => s,
                    _ => return Err(CapError::Malformed),
                }
            }
        };
        let part = from.get(at..at + n).ok_or(CapError::Malformed)?;
        buf.extend_from_slice(part);
        did_bytes(n);
        let units = n.div_ceil(BYTES_PER_FUEL).saturating_sub(1);
        *budget = budget.saturating_sub(u32::try_from(units).unwrap_or(u32::MAX));
        if n == remaining {
            self.frames.pop();
        } else {
            self.set(Frame::Copy {
                src,
                at: at + n,
                end,
            });
        }
        Ok(())
    }

    /// `pushcapture` (`lpeg.c:831`) of the capture at `pos`.
    fn push_capture(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
    ) -> Result<(), CapError> {
        let _ = (subj, env);
        // `luaL_checkstack(L, 4, "too many captures")`: the stack's whole
        // height, plus four, within `LUAI_MAXSTACK`.
        if self.u0.saturating_add(self.vs.len()).saturating_add(4) > LUAI_MAXSTACK {
            return Err(CapError::StackOverflow);
        }
        let c = *self.cap(caps, self.pos)?;
        let kind = c.kind;
        match kind {
            k if k == CapKind::Position as u8 => {
                self.push(CapVal::Int(
                    i64::try_from(c.s).unwrap_or(i64::MAX).saturating_add(1),
                ))?;
                self.pos += 1;
                self.ret(1);
            }
            k if k == CapKind::Const as u8 => {
                self.push(Self::constant(c.idx))?;
                self.pos += 1;
                self.ret(1);
            }
            k if k == CapKind::Arg as u8 => {
                self.pos += 1;
                let arg = usize::try_from(c.idx).unwrap_or(usize::MAX);
                if arg.saturating_add(FIXEDARGS) > self.ptop {
                    return Err(CapError::AbsentArgument(c.idx));
                }
                self.push(CapVal::Arg(c.idx))?;
                self.ret(1);
            }
            k if k == CapKind::Simple as u8 => {
                self.set(Frame::SimpleEnd {
                    k: 0,
                    cur: 0,
                    started: false,
                });
                self.call(nested(true))?;
            }
            k if k == CapKind::String as u8 || k == CapKind::Subst as u8 => {
                // `luaL_buffinit`'s slot.
                self.push(CapVal::Buf)?;
                grow(&mut self.bufs, 1, &mut self.stop)?;
                self.bufs.push(Vec::new());
                self.set(Frame::BufEnd);
                if k == CapKind::String as u8 {
                    self.call(string_cap(c.idx))?;
                } else {
                    self.call(subst())?;
                }
            }
            // An anonymous group gives its values; a named one gives none,
            // and is not evaluated.
            k if k == CapKind::Group as u8 => {
                if c.idx == 0 {
                    self.set(nested(false));
                } else {
                    self.set(Frame::NextCap {
                        cap: 0,
                        depth: None,
                    });
                }
            }
            k if k == CapKind::Backref as u8 => self.set(Frame::Backref {
                curr: self.pos,
                stage: 0,
            }),
            k if k == CapKind::Table as u8 => self.set(Frame::Table {
                t: 0,
                n: 0,
                wait: TableWait::Start,
            }),
            k if k == CapKind::Num as u8 => {
                if c.idx == 0 {
                    // `p / 0`: nothing, and nothing evaluated.
                    self.set(Frame::NextCap {
                        cap: 0,
                        depth: None,
                    });
                } else {
                    self.set(Frame::Num { idx: c.idx });
                    self.call(nested(false))?;
                }
            }
            k if super::super::code::kind_calls_lua(k) => return Err(CapError::CallsLua),
            _ => return Err(CapError::Malformed),
        }
        Ok(())
    }

    /// `pushnestedvalues`' loop, at entry `pos`: the next nested capture,
    /// or the close.
    fn nested_loop(
        &mut self,
        caps: &[Capture],
        co: usize,
        n: usize,
        addextra: bool,
    ) -> Result<(), CapError> {
        let c = *self.cap(caps, self.pos)?;
        if !c.is_close() {
            self.set(Frame::Nested {
                co,
                n,
                addextra,
                started: true,
            });
            return self.call(Frame::Push);
        }
        let mut n = n;
        if addextra || n == 0 {
            // A capture's close is never before its open: no pattern moves
            // back past where it started.
            let open = self.cap(caps, co)?.s;
            if c.s < open {
                return Err(CapError::Malformed);
            }
            self.push(CapVal::Str(open, c.s))?;
            n += 1;
        }
        self.pos += 1;
        self.ret(n);
        Ok(())
    }

    /// `backrefcap` (`lpeg.c:527`): find the group, and push all its
    /// values, evaluated again where they are.
    fn backref(&mut self, caps: &[Capture], curr: usize, stage: u8) -> Result<(), CapError> {
        match stage {
            0 => {
                let name = self.cap(caps, curr)?.idx;
                self.push(Self::constant(name))?;
                self.set(Frame::Backref { curr, stage: 1 });
                self.call(Frame::FindBack {
                    name,
                    cap: curr,
                    skip: None,
                })
            }
            1 => {
                // `ret` is where the group is.
                self.pos = self.ret;
                self.set(Frame::Backref { curr, stage: 2 });
                self.call(nested(false))
            }
            _ => {
                let n = self.ret;
                self.pos = curr + 1;
                self.ret(n);
                Ok(())
            }
        }
    }

    /// `findback` (`lpeg.c:503`): back from `cap`, the nearest named group
    /// of this name that is not an enclosing capture; a closed capture is
    /// skipped whole (`findopen`), its own open entry tested. A unit an
    /// entry. Returns the group's index in `ret`.
    fn find_back(
        &mut self,
        caps: &[Capture],
        env: &dyn CapEnv,
        name: Key,
        mut cap: usize,
        mut skip: Option<usize>,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        let mut first = true;
        loop {
            // An entry a unit, the frame's step paying for the first.
            if !first {
                if *budget == 0 {
                    self.set(Frame::FindBack { name, cap, skip });
                    return Ok(());
                }
                *budget -= 1;
            }
            first = false;
            if let Some(n) = skip {
                // `findopen`: back to the open entry this close ends.
                cap = cap.checked_sub(1).ok_or(CapError::Malformed)?;
                let c = self.cap(caps, cap)?;
                if c.is_close() {
                    skip = Some(n + 1);
                    continue;
                }
                if c.is_full() {
                    continue;
                }
                if n > 0 {
                    skip = Some(n - 1);
                    continue;
                }
                skip = None;
            } else {
                if cap == 0 {
                    return Err(CapError::BackrefNotFound(name));
                }
                cap -= 1;
                let c = self.cap(caps, cap)?;
                if c.is_close() {
                    skip = Some(0);
                    continue;
                }
                // An open entry here encloses the reference: invisible.
                if !c.is_full() {
                    continue;
                }
            }
            let c = self.cap(caps, cap)?;
            if c.kind == CapKind::Group as u8 && c.idx != 0 {
                // Names whose hashes differ compare in no time; equal ones
                // byte by byte, [`BYTES_PER_FUEL`] a unit, all at once: what
                // the budget cannot pay is charged past it.
                let (same, compared) = env.same_constant(c.idx, name);
                did_bytes(compared);
                let units = u32::try_from(compared / BYTES_PER_FUEL).unwrap_or(u32::MAX);
                let paid = units.min(*budget);
                *budget -= paid;
                self.over = self.over.saturating_add(u64::from(units - paid));
                if same {
                    // The reference's name off the stack.
                    self.pop()?;
                    self.ret(cap);
                    return Ok(());
                }
            }
        }
    }

    /// `tablecap` (`lpeg.c:542`): a table of the nested captures' values,
    /// positional, and each named group's first value under its name.
    fn table_cap(
        &mut self,
        caps: &[Capture],
        t: u32,
        mut n: i64,
        wait: TableWait,
    ) -> Result<(), CapError> {
        let mut t = t;
        match wait {
            TableWait::Start => {
                t = u32::try_from(self.tables.len()).map_err(|_| CapError::NotEnoughMemory)?;
                grow(&mut self.tables, 1, &mut self.stop)?;
                self.tables.push(Vec::new());
                self.push(CapVal::Table(t))?;
                let full = self.cap(caps, self.pos)?.is_full();
                self.pos += 1;
                if full {
                    // An empty table.
                    self.ret(1);
                    return Ok(());
                }
            }
            // `pushonenestedvalue`, then `lua_settable(L, -3)`: on a fresh
            // table, a `nil` value removes the name.
            TableWait::Named => {
                let k = self.ret;
                let keep = self
                    .vs
                    .len()
                    .checked_sub(k.saturating_sub(1))
                    .ok_or(CapError::Malformed)?;
                self.vs.truncate(keep);
                let v = self.pop()?;
                let name = match self.pop()? {
                    CapVal::K(k) => k,
                    _ => return Err(CapError::Malformed),
                };
                self.assign(t, TableKey::K(name), v)?;
            }
            // `lua_rawseti(L, -(i + 1), n + i)` for i from k down to 1.
            TableWait::Positional => {
                let k = self.ret;
                for i in (1..=k).rev() {
                    let v = self.pop()?;
                    let key = n.saturating_add(i64::try_from(i).unwrap_or(i64::MAX));
                    self.assign(t, TableKey::Int(key), v)?;
                }
                n = n.saturating_add(i64::try_from(k).unwrap_or(i64::MAX));
            }
        }
        let c = *self.cap(caps, self.pos)?;
        if c.is_close() {
            self.pos += 1;
            self.ret(1);
            return Ok(());
        }
        if c.kind == CapKind::Group as u8 && c.idx != 0 {
            self.push(CapVal::K(c.idx))?;
            self.set(Frame::Table {
                t,
                n,
                wait: TableWait::Named,
            });
            self.call(nested(false))
        } else {
            self.set(Frame::Table {
                t,
                n,
                wait: TableWait::Positional,
            });
            self.call(Frame::Push)
        }
    }

    fn assign(&mut self, t: u32, k: TableKey, v: CapVal) -> Result<(), CapError> {
        let chunks = self
            .tables
            .get_mut(usize::try_from(t).unwrap_or(usize::MAX))
            .ok_or(CapError::Malformed)?;
        if chunks.last().is_none_or(|c| c.len() == TABLE_CHUNK) {
            // The first chunk grows as a list does; the others are made
            // whole, so no chunk is ever moved.
            let mut chunk = Vec::new();
            if !chunks.is_empty() {
                grow(&mut chunk, TABLE_CHUNK, &mut self.stop)?;
            }
            grow(chunks, 1, &mut self.stop)?;
            chunks.push(chunk);
        }
        let chunk = chunks.last_mut().ok_or(CapError::Malformed)?;
        grow(chunk, 1, &mut self.stop)?;
        chunk.push((k, v));
        Ok(())
    }

    /// `nextcap` (`lpeg.c:446`): past the capture at `pos`, its nested
    /// captures and its close. A unit an entry. Returns nothing.
    fn next_cap(
        &mut self,
        caps: &[Capture],
        cap: usize,
        depth: Option<usize>,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        let (mut cap, mut n) = match depth {
            Some(n) => (cap, n),
            None => {
                let c = self.cap(caps, self.pos)?;
                if c.is_full() {
                    self.pos += 1;
                    self.ret(0);
                    return Ok(());
                }
                (self.pos, 0)
            }
        };
        // An entry a unit, the frame's step paying for the first: each call
        // makes progress.
        loop {
            cap += 1;
            let c = self.cap(caps, cap)?;
            if c.is_close() {
                if n == 0 {
                    self.pos = cap + 1;
                    self.ret(0);
                    return Ok(());
                }
                n -= 1;
            } else if !c.is_full() {
                n += 1;
            }
            if *budget == 0 {
                self.set(Frame::NextCap {
                    cap,
                    depth: Some(n),
                });
                return Ok(());
            }
            *budget -= 1;
        }
    }

    /// `getstrcaps` (`lpeg.c:713`), from the string capture at `pos`: the
    /// whole match in slot 0, then nested simple captures in pre-order (each
    /// a slot, descended into), any other nested capture a slot of its own,
    /// not descended into, and past [`MAXSTRCAPS`] slots, nested captures
    /// skipped. Returns the slots filled.
    fn str_caps(
        &mut self,
        caps: &[Capture],
        base: usize,
        mut n: usize,
        mut ks: [u8; MAXSTRCAPS],
        mut nks: u8,
        skipping: Option<bool>,
    ) -> Result<(), CapError> {
        let slot = |n: usize| base + n;
        // Back from `nextcap`: a non-string capture took slot `n`.
        if let Some(took) = skipping {
            if took {
                n += 1;
            }
        } else if nks == 0 && n == 0 {
            // Entering the string capture itself.
            self.enter_str(caps, base, &mut n, &mut ks, &mut nks)?;
        }
        loop {
            if nks == 0 {
                self.ret(n);
                return Ok(());
            }
            let c = *self.cap(caps, self.pos)?;
            if c.is_close() {
                self.pos += 1;
                nks -= 1;
                let k = usize::from(ks[usize::from(nks)]);
                if let Some(StrAux::Str(_, e)) = self.strcaps.get_mut(slot(k)) {
                    *e = c.s;
                }
                continue;
            }
            if n >= MAXSTRCAPS {
                // Skipped, and never evaluated.
                self.set(Frame::StrCaps {
                    base,
                    n,
                    ks,
                    nks,
                    skipping: Some(false),
                });
                return self.call(Frame::NextCap {
                    cap: 0,
                    depth: None,
                });
            }
            if c.kind == CapKind::Simple as u8 {
                self.enter_str(caps, base, &mut n, &mut ks, &mut nks)?;
                continue;
            }
            *self.strcaps.get_mut(slot(n)).ok_or(CapError::Malformed)? = StrAux::Capture(self.pos);
            self.set(Frame::StrCaps {
                base,
                n,
                ks,
                nks,
                skipping: Some(true),
            });
            return self.call(Frame::NextCap {
                cap: 0,
                depth: None,
            });
        }
    }

    /// `getstrcaps`' entry for the capture at `pos`: slot `n` from its
    /// start; a full capture ends there, an open one when its close comes.
    fn enter_str(
        &mut self,
        caps: &[Capture],
        base: usize,
        n: &mut usize,
        ks: &mut [u8; MAXSTRCAPS],
        nks: &mut u8,
    ) -> Result<(), CapError> {
        let c = *self.cap(caps, self.pos)?;
        let k = *n;
        *n += 1;
        self.pos += 1;
        let e = if c.is_full() { c.close_addr() } else { c.s };
        *self.strcaps.get_mut(base + k).ok_or(CapError::Malformed)? = StrAux::Str(c.s, e);
        if !c.is_full() {
            // At most MAXSTRCAPS slots, so at most that many open.
            *ks.get_mut(usize::from(*nks)).ok_or(CapError::Malformed)? =
                u8::try_from(k).map_err(|_| CapError::Malformed)?;
            *nks += 1;
        }
        Ok(())
    }

    /// `stringcap` (`lpeg.c:747`): the format with `%0`-`%9` replaced by
    /// the capture slots, into the buffer being built. A digit names one
    /// slot (`%10` is `%1` then `0`); a `%` before anything else gives that
    /// byte, and a trailing `%` the format's terminating NUL.
    #[allow(clippy::too_many_arguments, reason = "one frame's locals, unpacked")]
    fn string_cap(
        &mut self,
        _caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
        fmt: Key,
        base: usize,
        n: usize,
        mut i: usize,
        adding: Option<(u32, usize)>,
        stage: StrStage,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        let frame = |n, i, adding| Frame::StringCap {
            fmt,
            base,
            n,
            i,
            adding,
            stage: StrStage::Format,
        };
        let n = match stage {
            StrStage::Start => {
                // The capture array, then the slots.
                let base = self.strcaps.len();
                for _ in 0..MAXSTRCAPS {
                    grow(&mut self.strcaps, 1, &mut self.stop)?;
                    self.strcaps.push(StrAux::Str(0, 0));
                }
                self.set(Frame::StringCap {
                    fmt,
                    base,
                    n: 0,
                    i: 0,
                    adding: None,
                    stage: StrStage::Collected,
                });
                return self.call(Frame::StrCaps {
                    base,
                    n: 0,
                    ks: [0; MAXSTRCAPS],
                    nks: 0,
                    skipping: None,
                });
            }
            // The slots after the whole match.
            StrStage::Collected => self.ret.checked_sub(1).ok_or(CapError::Malformed)?,
            StrStage::Format => n,
        };
        if let Some((l, saved)) = adding {
            // Back from `addonestring` of slot `l`.
            if self.ret == 0 {
                return Err(CapError::NoValues(l));
            }
            self.pos = saved;
            i += 1;
        }
        // The format's own bytes: a string constant's are borrowed, so
        // reading it again each time the frame resumes costs nothing.
        let view = seen(env.constant(fmt));
        let fmt_bytes: &[u8] = match &view {
            View::Str(s) | View::Num(s) => s,
            _ => &[],
        };
        let len = fmt_bytes.len();
        let mut credit = Credit(BYTES_PER_FUEL);
        while i < len {
            if credit.room(*budget) == 0 {
                self.set(frame(n, i, None));
                return Ok(());
            }
            let c = fmt_bytes[i];
            if c != b'%' {
                // Text, up to the next `%` or as far as the budget pays.
                let stop_at = len.min(i.saturating_add(credit.room(*budget)));
                let end = fmt_bytes
                    .get(i..stop_at)
                    .and_then(|run| memchr::memchr(b'%', run))
                    .map_or(stop_at, |p| i + p);
                self.add(fmt_bytes.get(i..end).ok_or(CapError::Malformed)?)?;
                credit.spend(budget, end - i);
                i = end;
                continue;
            }
            credit.spend(budget, 1);
            i += 1;
            let d = fmt_bytes.get(i).copied().unwrap_or(0);
            if !d.is_ascii_digit() {
                credit.spend(budget, 1);
                self.add(&[d])?;
                i += 1;
                continue;
            }
            let l = usize::from(d - b'0');
            if l > n {
                return Err(CapError::InvalidCaptureIndex(u32::from(d - b'0')));
            }
            match self
                .strcaps
                .get(base + l)
                .copied()
                .ok_or(CapError::Malformed)?
            {
                StrAux::Str(s, e) => {
                    if e < s || e > subj.len() {
                        return Err(CapError::Malformed);
                    }
                    self.set(frame(n, i + 1, None));
                    return self.copy(Src::Subject, s, e);
                }
                StrAux::Capture(cp) => {
                    let saved = self.pos;
                    self.pos = cp;
                    self.set(frame(n, i, Some((u32::from(d - b'0'), saved))));
                    return self.call(add_one("capture"));
                }
            }
        }
        // Done: its capture array goes.
        self.strcaps.truncate(base);
        self.ret(1);
        Ok(())
    }

    /// `substcap` (`lpeg.c:780`): the match, each nested capture's value in
    /// place of what it matched (or the text, if it has none). The text
    /// between goes in through [`Frame::Copy`]s.
    fn subst_cap(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        curr: usize,
        stage: SubstStage,
    ) -> Result<(), CapError> {
        let mut curr = curr;
        match stage {
            SubstStage::Start => {
                let c = *self.cap(caps, self.pos)?;
                if c.is_full() {
                    self.set(Frame::Subst {
                        curr: c.s,
                        stage: SubstStage::End,
                    });
                    return self.add_range(subj, c.s, c.close_addr());
                }
                curr = c.s;
                self.pos += 1;
            }
            SubstStage::Replace { next } => {
                self.set(Frame::Subst {
                    curr,
                    stage: SubstStage::Replaced { next },
                });
                return self.call(add_one("replacement"));
            }
            SubstStage::Replaced { next } => {
                curr = if self.ret > 0 {
                    self.cap(caps, self.pos.checked_sub(1).ok_or(CapError::Malformed)?)?
                        .close_addr()
                } else {
                    next
                };
            }
            SubstStage::End => {
                self.pos += 1;
                self.ret(1);
                return Ok(());
            }
        }
        let c = *self.cap(caps, self.pos)?;
        let (next, stage) = if c.is_close() {
            (c.s, SubstStage::End)
        } else {
            (c.s, SubstStage::Replace { next: c.s })
        };
        self.set(Frame::Subst { curr, stage });
        self.add_range(subj, curr, next)
    }

    /// `addonestring` (`lpeg.c:804`): the capture's first value into the
    /// buffer — a string or substitution capture straight in, anything else
    /// through the stack, a string or a number. Returns the values it had.
    fn add_one(
        &mut self,
        caps: &[Capture],
        env: &dyn CapEnv,
        what: &'static str,
        stage: u8,
        n: usize,
        budget: &mut u32,
    ) -> Result<(), CapError> {
        match stage {
            0 => {
                let c = *self.cap(caps, self.pos)?;
                if c.kind == CapKind::String as u8 {
                    self.set(Frame::AddOne { what, stage: 1, n });
                    self.call(string_cap(c.idx))
                } else if c.kind == CapKind::Subst as u8 {
                    self.set(Frame::AddOne { what, stage: 1, n });
                    self.call(subst())
                } else {
                    self.set(Frame::AddOne { what, stage: 2, n });
                    self.call(Frame::Push)
                }
            }
            1 => {
                self.ret(1);
                Ok(())
            }
            // The values are on the stack: the first, if any, into the
            // buffer (`luaL_addvalue`), a string or a number's text.
            2 => {
                let n = self.ret;
                if n == 0 {
                    self.ret(0);
                    return Ok(());
                }
                let keep = self
                    .vs
                    .len()
                    .checked_sub(n - 1)
                    .ok_or(CapError::Malformed)?;
                self.vs.truncate(keep);
                let v = *self.vs.last().ok_or(CapError::Malformed)?;
                let invalid = || CapError::InvalidValue {
                    what,
                    type_name: Self::type_name(v, env),
                };
                let text_len = |w: View<'_>| match w {
                    View::Str(s) | View::Num(s) => Ok(s.len()),
                    _ => Err(invalid()),
                };
                self.set(Frame::AddOne { what, stage: 3, n });
                match v {
                    CapVal::Int(i) => {
                        let text = i.to_string();
                        Credit(BYTES_PER_FUEL).spend(budget, text.len());
                        self.add(text.as_bytes())
                    }
                    CapVal::Str(a, b) => self.copy(Src::Subject, a, b),
                    CapVal::Bytes(i) => {
                        let len = self.string(i).len();
                        self.copy(Src::String(i), 0, len)
                    }
                    CapVal::K(k) => {
                        let len = text_len(seen(env.constant(k)))?;
                        self.copy(Src::Const(k), 0, len)
                    }
                    CapVal::Arg(m) => {
                        let len = text_len(seen(env.argument(m)))?;
                        self.copy(Src::Arg(m), 0, len)
                    }
                    CapVal::Nil | CapVal::Table(_) => Err(invalid()),
                    CapVal::Buf => Err(CapError::Malformed),
                }
            }
            // The value is in: off the stack.
            _ => {
                self.pop()?;
                self.ret(n);
                Ok(())
            }
        }
    }
}

/// `pushnestedvalues(addextra)`, about to start.
const fn nested(addextra: bool) -> Frame {
    Frame::Nested {
        co: 0,
        n: 0,
        addextra,
        started: false,
    }
}

/// `substcap`, about to start.
const fn subst() -> Frame {
    Frame::Subst {
        curr: 0,
        stage: SubstStage::Start,
    }
}

/// `addonestring`, about to start.
const fn add_one(what: &'static str) -> Frame {
    Frame::AddOne {
        what,
        stage: 0,
        n: 0,
    }
}

/// Bytes a step may still spend: what its unit paid for, then the budget's
/// units, [`BYTES_PER_FUEL`] each.
struct Credit(usize);

impl Credit {
    fn room(&self, budget: u32) -> usize {
        BYTES_PER_FUEL
            .saturating_mul(usize::try_from(budget).unwrap_or(usize::MAX))
            .saturating_add(self.0)
    }

    /// Spend `k` bytes of [`Credit::room`], taking the units from `budget`.
    fn spend(&mut self, budget: &mut u32, k: usize) {
        if k <= self.0 {
            self.0 -= k;
            return;
        }
        let rest = k - self.0;
        let units = rest.div_ceil(BYTES_PER_FUEL);
        *budget = budget.saturating_sub(u32::try_from(units).unwrap_or(u32::MAX));
        self.0 = units.saturating_mul(BYTES_PER_FUEL) - rest;
    }
}

/// `stringcap` of the format at key `fmt`, about to start.
const fn string_cap(fmt: Key) -> Frame {
    Frame::StringCap {
        fmt,
        base: 0,
        n: 0,
        i: 0,
        adding: None,
        stage: StrStage::Start,
    }
}

/// A view the environment gave: a text it copied to give it (where a string
/// is not borrowed) counted as work, for `lpeg::take_work`.
fn seen(v: View<'_>) -> View<'_> {
    if let View::Str(Cow::Owned(b)) | View::Num(Cow::Owned(b)) = &v {
        did_bytes(b.len());
    }
    v
}

/// Room for `n` more, through the memory budget and accounted to the heap
/// at once; `stop` set when the heap is then past the budget.
fn grow<T>(v: &mut Vec<T>, n: usize, stop: &mut bool) -> Result<(), CapError> {
    match grow_by(v, n) {
        Grown::Ok => Ok(()),
        Grown::PastBudget => {
            *stop = true;
            Ok(())
        }
        Grown::Refused => Err(CapError::NotEnoughMemory),
    }
}
