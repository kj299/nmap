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
use crate::nse::stdlib::reserve;

/// `LUAI_MAXSTACK` (`luaconf.h`): the most slots a Lua stack may use.
pub const LUAI_MAXSTACK: usize = 1_000_000;

/// `MAXSTRCAPS` (`lpeg.c:705`): the captures `/string` can refer to,
/// `%0` to `%9`; further nested captures are skipped silently.
pub const MAXSTRCAPS: usize = 10;

/// `FIXEDARGS` (`lpeg.c:69`): `match`'s arguments before the extra ones
/// `Carg` reads.
pub const FIXEDARGS: usize = 3;

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
    /// are always strings). Key 0 is `nil`.
    fn same_constant(&self, a: Key, b: Key) -> bool;
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
    /// `Csimple` after `pushnestedvalues(1)`: the whole match goes first.
    SimpleEnd,
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
    /// `substcap`: the position text resumes at, and while a nested
    /// capture is being added, where it starts.
    Subst {
        curr: usize,
        next: Option<usize>,
        started: bool,
    },
    /// `addonestring`.
    AddOne { what: &'static str, stage: u8 },
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
    /// The tables made, as their assignments in order.
    tables: Vec<Vec<(TableKey, CapVal)>>,
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
        }
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

    /// The assignments of the table a [`CapVal::Table`] refers to, in order.
    #[must_use]
    pub fn table(&self, i: u32) -> &[(TableKey, CapVal)] {
        self.tables
            .get(usize::try_from(i).unwrap_or(usize::MAX))
            .map_or(&[], Vec::as_slice)
    }

    /// How many tables were made: [`CapVal::Table`] indices are below this,
    /// and a table is made before any it holds.
    #[must_use]
    pub fn tables(&self) -> usize {
        self.tables.len()
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
            self.tables.iter().map(b).fold(0, usize::saturating_add),
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
        }
        Ok(Some(()))
    }

    // ------------------------------------------------------------ helpers

    fn cap<'c>(&self, caps: &'c [Capture], i: usize) -> Result<&'c Capture, CapError> {
        caps.get(i).ok_or(CapError::Malformed)
    }

    fn push(&mut self, v: CapVal) -> Result<(), CapError> {
        grow(&mut self.vs)?;
        self.vs.push(v);
        Ok(())
    }

    fn pop(&mut self) -> Result<CapVal, CapError> {
        self.vs.pop().ok_or(CapError::Malformed)
    }

    fn call(&mut self, f: Frame) -> Result<(), CapError> {
        grow(&mut self.frames)?;
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

    /// Append bytes to the buffer being built (`luaL_addlstring`).
    fn add(&mut self, bytes: &[u8]) -> Result<(), CapError> {
        let buf = self.buf()?;
        if !reserve(buf, bytes.len()) {
            return Err(CapError::NotEnoughMemory);
        }
        buf.extend_from_slice(bytes);
        Ok(())
    }

    /// `luaL_addlstring(b, curr, next - curr)`: the subject between two
    /// positions. Out of order — a capture an and-predicate kept from a
    /// called rule can start before the last one ended — the C's length is
    /// a huge `size_t`, and `newbuffsize` raises "buffer too large" when the
    /// buffer holds at least the difference, or else asks for that much
    /// memory and is refused (`lua_error`, "not enough memory").
    fn add_range(&mut self, subj: &[u8], curr: usize, next: usize) -> Result<(), CapError> {
        match subj.get(curr..next) {
            Some(part) => self.add(part),
            None if next < curr => {
                if self.buf()?.len() >= curr - next {
                    Err(CapError::BufferTooLarge)
                } else {
                    Err(CapError::NotEnoughMemory)
                }
            }
            None => Err(CapError::Malformed),
        }
    }

    /// What `lua_tolstring` gives for a value, if it is a string or a
    /// number (`lua_isstring`).
    fn text<'a>(
        &'a self,
        v: CapVal,
        subj: &'a [u8],
        env: &'a dyn CapEnv,
    ) -> Result<Option<Cow<'a, [u8]>>, CapError> {
        Ok(match v {
            CapVal::Int(i) => Some(Cow::Owned(i.to_string().into_bytes())),
            CapVal::Str(a, b) => Some(Cow::Borrowed(subj.get(a..b).ok_or(CapError::Malformed)?)),
            CapVal::Bytes(i) => Some(Cow::Borrowed(self.string(i))),
            CapVal::K(k) => match env.constant(k) {
                View::Str(s) | View::Num(s) => Some(s),
                _ => None,
            },
            CapVal::Arg(n) => match env.argument(n) {
                View::Str(s) | View::Num(s) => Some(s),
                _ => None,
            },
            CapVal::Nil | CapVal::Table(_) => None,
            CapVal::Buf => return Err(CapError::Malformed),
        })
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
            CapVal::K(k) => view(env.constant(k)),
            CapVal::Arg(n) => view(env.argument(n)),
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
            // `lua_insert(L, -k)`: the whole match, pushed last, goes first.
            Frame::SimpleEnd => {
                let k = self.ret;
                let at = self.vs.len().checked_sub(k).ok_or(CapError::Malformed)?;
                let v = self.pop()?;
                self.vs.insert(at, v);
                *budget = budget.saturating_sub(u32::try_from(k / 64).unwrap_or(u32::MAX));
                self.ret(k);
                Ok(())
            }
            // `luaL_pushresult`: the string replaces the buffer's slot.
            Frame::BufEnd => {
                let s = self.bufs.pop().ok_or(CapError::Malformed)?;
                let id =
                    u32::try_from(self.strings.len()).map_err(|_| CapError::NotEnoughMemory)?;
                grow(&mut self.strings)?;
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
            Frame::Subst {
                curr,
                next,
                started,
            } => self.subst_cap(caps, subj, curr, next, started),
            Frame::AddOne { what, stage } => self.add_one(caps, subj, env, what, stage),
        }
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
                self.set(Frame::SimpleEnd);
                self.call(nested(true))?;
            }
            k if k == CapKind::String as u8 || k == CapKind::Subst as u8 => {
                // `luaL_buffinit`'s slot.
                self.push(CapVal::Buf)?;
                grow(&mut self.bufs)?;
                self.bufs.push(Vec::new());
                self.set(Frame::BufEnd);
                if k == CapKind::String as u8 {
                    self.call(string_cap(c.idx))?;
                } else {
                    self.call(Frame::Subst {
                        curr: 0,
                        next: None,
                        started: false,
                    })?;
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
            if c.kind == CapKind::Group as u8 && c.idx != 0 && env.same_constant(c.idx, name) {
                // The reference's name off the stack.
                self.pop()?;
                self.ret(cap);
                return Ok(());
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
                grow(&mut self.tables)?;
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
        let entries = self
            .tables
            .get_mut(usize::try_from(t).unwrap_or(usize::MAX))
            .ok_or(CapError::Malformed)?;
        grow(entries)?;
        entries.push((k, v));
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
                    grow(&mut self.strcaps)?;
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
        let fmt_bytes = match env.constant(fmt) {
            View::Str(s) | View::Num(s) => s,
            _ => Cow::Borrowed(&[][..]),
        };
        let len = fmt_bytes.len();
        let mut first = true;
        while i < len {
            // A format byte a unit, the frame's step paying for the first.
            if !first {
                if *budget == 0 {
                    self.set(frame(n, i, None));
                    return Ok(());
                }
                *budget -= 1;
            }
            first = false;
            let c = fmt_bytes[i];
            if c != b'%' {
                self.add(&[c])?;
                i += 1;
                continue;
            }
            i += 1;
            let d = fmt_bytes.get(i).copied().unwrap_or(0);
            if !d.is_ascii_digit() {
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
                    let part = subj.get(s..e).ok_or(CapError::Malformed)?;
                    self.add(part)?;
                    i += 1;
                }
                StrAux::Capture(cp) => {
                    let saved = self.pos;
                    self.pos = cp;
                    self.set(frame(n, i, Some((u32::from(d - b'0'), saved))));
                    return self.call(Frame::AddOne {
                        what: "capture",
                        stage: 0,
                    });
                }
            }
        }
        // Done: its capture array goes.
        self.strcaps.truncate(base);
        self.ret(1);
        Ok(())
    }

    /// `substcap` (`lpeg.c:780`): the match, each nested capture's value in
    /// place of what it matched (or the text, if it has none).
    fn subst_cap(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        curr: usize,
        next: Option<usize>,
        started: bool,
    ) -> Result<(), CapError> {
        let mut curr = curr;
        if !started {
            let c = *self.cap(caps, self.pos)?;
            curr = c.s;
            if c.is_full() {
                self.add_range(subj, curr, c.close_addr())?;
                self.pos += 1;
                self.ret(1);
                return Ok(());
            }
            self.pos += 1;
        } else if let Some(next) = next {
            curr = if self.ret > 0 {
                self.cap(caps, self.pos.checked_sub(1).ok_or(CapError::Malformed)?)?
                    .close_addr()
            } else {
                next
            };
        }
        let c = *self.cap(caps, self.pos)?;
        if c.is_close() {
            self.add_range(subj, curr, c.s)?;
            self.pos += 1;
            self.ret(1);
            return Ok(());
        }
        let next = c.s;
        self.add_range(subj, curr, next)?;
        self.set(Frame::Subst {
            curr,
            next: Some(next),
            started: true,
        });
        self.call(Frame::AddOne {
            what: "replacement",
            stage: 0,
        })
    }

    /// `addonestring` (`lpeg.c:804`): the capture's first value into the
    /// buffer — a string or substitution capture straight in, anything else
    /// through the stack, a string or a number. Returns the values it had.
    fn add_one(
        &mut self,
        caps: &[Capture],
        subj: &[u8],
        env: &dyn CapEnv,
        what: &'static str,
        stage: u8,
    ) -> Result<(), CapError> {
        match stage {
            0 => {
                let c = *self.cap(caps, self.pos)?;
                if c.kind == CapKind::String as u8 {
                    self.set(Frame::AddOne { what, stage: 1 });
                    self.call(string_cap(c.idx))
                } else if c.kind == CapKind::Subst as u8 {
                    self.set(Frame::AddOne { what, stage: 1 });
                    self.call(Frame::Subst {
                        curr: 0,
                        next: None,
                        started: false,
                    })
                } else {
                    self.set(Frame::AddOne { what, stage: 2 });
                    self.call(Frame::Push)
                }
            }
            1 => {
                self.ret(1);
                Ok(())
            }
            _ => {
                let n = self.ret;
                if n > 0 {
                    let keep = self
                        .vs
                        .len()
                        .checked_sub(n - 1)
                        .ok_or(CapError::Malformed)?;
                    self.vs.truncate(keep);
                    let v = *self.vs.last().ok_or(CapError::Malformed)?;
                    let text = match self.text(v, subj, env)? {
                        Some(t) => t.into_owned(),
                        None => {
                            return Err(CapError::InvalidValue {
                                what,
                                type_name: Self::type_name(v, env),
                            });
                        }
                    };
                    self.add(&text)?;
                    self.pop()?;
                }
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

/// Room for one more, through the memory budget.
fn grow<T>(v: &mut Vec<T>) -> Result<(), CapError> {
    if v.len() == v.capacity() && !reserve(v, 1) {
        return Err(CapError::NotEnoughMemory);
    }
    Ok(())
}
