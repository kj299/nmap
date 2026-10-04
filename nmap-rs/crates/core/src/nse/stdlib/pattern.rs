//! Lua patterns — the matcher behind `string.find`, `string.match`,
//! `string.gmatch` and `string.gsub` — ported from `liblua/lstrlib.c:347-947`.
//!
//! This is the most-used piece of Lua's standard library in the shipped NSE
//! corpus (2,040 call sites in 421 files), and the subject it runs over is,
//! routinely, a banner, a header or a packet a remote host chose. So it is
//! written here — in `core`, under `#![forbid(unsafe_code)]`, with no dependency
//! on the interpreter — where the differential, fuzz and Miri gates reach it.
//!
//! # What is ported, and what is deliberately not
//!
//! Every observable behaviour of the C is kept, including the ones that look
//! like accidents, because NSE scripts were written against them:
//!
//! * pattern errors are **lazy**: a malformed piece is only diagnosed when the
//!   matcher reaches it, so `("a"):find("b[")` returns `nil` rather than
//!   raising, because `b` fails before `[` is ever parsed;
//! * the subject is read as if it carried C's hidden NUL one past its end, so a
//!   frontier at the very end sees `\0` as the next character (`%f[%z]` matches
//!   there) and `%b` with a NUL opener behaves as it does in C;
//! * a back-reference to a **position** capture never matches (the C compares
//!   against a length of `(size_t)-2`), and is not an error;
//! * `^` anchors `find`, `match` and `gsub` but is an ordinary character to
//!   `gmatch`;
//! * the character classes are the C locale's, which is the locale nmap runs
//!   in — it never calls `setlocale(LC_CTYPE, "")` — so `%a` and friends are
//!   ASCII-only and every byte at or above `0x80` is in none of them;
//! * the recursion limit is `MAXCCALLS` (200), and exceeding it is the same
//!   catchable "pattern too complex" error.
//!
//! What is **not** reproduced is one defect. `gmatch` keeps its `MatchState` —
//! and with it the recursion budget — alive between calls of the iterator, and
//! the budget is decremented on the way into `match` but only restored on a
//! normal return. An error raised mid-match (`pcall`-caught, so the iterator can
//! be called again) leaves it permanently lowered, and after "pattern too
//! complex" it is left at `-1`, where the `== 0` test can never fire again: the
//! next call recurses as deep as the pattern allows, which is the C stack
//! overflow the limit exists to prevent. Here every call starts from a fresh
//! state, so the limit holds on every call. Ledgered as
//! `pattern-gmatch-depth-budget-leaks`.
//!
//! # Layering
//!
//! Nothing here touches a Lua value. `gsub` is offered as a step-wise driver,
//! [`Gsub`], rather than a function, because a function or table replacement
//! means calling back into the VM between one match and the next, and in a
//! stackless VM that call cannot be made from inside a Rust function: the
//! binding in [`super`] polls the driver, makes the call, and hands the result
//! back.

use std::fmt;

use super::strpack::posrelat_i;

/// `LUA_MAXCAPTURES` (`lstrlib.c:35`).
pub const MAXCAPTURES: usize = 32;

/// `MAXCCALLS` (`lstrlib.c:378`): how deep `match` may recurse.
const MAXCCALLS: u32 = 200;

/// `L_ESC` (`lstrlib.c:382`).
const L_ESC: u8 = b'%';

/// `SPECIALS` (`lstrlib.c:383`): a pattern with none of these is searched for
/// literally by `find`.
const SPECIALS: &[u8] = b"^$*+?.([%-";

/// A Lua error raised by the matcher: `luaL_error`, which names no argument,
/// with the message as the C words it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    /// The message, exactly as the C formats it.
    pub msg: String,
}

impl PatternError {
    fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }

    fn capture_index(l: i32) -> Self {
        Self::new(format!("invalid capture index %{l}"))
    }

    fn out_of_memory() -> Self {
        Self::new("not enough memory")
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for PatternError {}

/// One value a match produces, as `push_onecapture` pushes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capture<'a> {
    /// A string capture, or the whole match: a sub-slice of the subject.
    Bytes(&'a [u8]),
    /// A position capture, `()`: the 1-based subject position it stood at.
    Position(i64),
}

/// `capture[i].len` (`lstrlib.c:367`), with the two sentinels the C stores in
/// the same `ptrdiff_t` made into variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapLen {
    /// `CAP_UNFINISHED`: opened by `(`, not yet closed.
    Unfinished,
    /// `CAP_POSITION`: `()`.
    Position,
    /// A closed string capture of this many bytes.
    Closed(usize),
}

#[derive(Debug, Clone, Copy)]
struct Cap {
    init: usize,
    len: CapLen,
}

const NO_CAP: Cap = Cap {
    init: 0,
    len: CapLen::Unfinished,
};

/// A 1-based Lua position for the 0-based subject offset `i`.
fn lua_pos(i: usize) -> i64 {
    i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1)
}

/// The 0-based offset an `init` argument selects, as `str_find_aux` and
/// `gmatch` compute it: `posrelatI(init, len) - 1`, which may lie past the end.
fn start_offset(init: i64, len: usize) -> u64 {
    // `posrelat_i` never returns 0.
    posrelat_i(init, len).saturating_sub(1)
}

/// `isspace` in the C locale. Not `u8::is_ascii_whitespace`, which leaves out
/// the vertical tab.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t'..=b'\r')
}

/// `match_class` (`lstrlib.c:421`): does byte `c` belong to class letter `cl`?
fn match_class(c: u8, cl: u8) -> bool {
    let res = match cl.to_ascii_lowercase() {
        b'a' => c.is_ascii_alphabetic(),
        b'c' => c.is_ascii_control(),
        b'd' => c.is_ascii_digit(),
        b'g' => c.is_ascii_graphic(),
        b'l' => c.is_ascii_lowercase(),
        b'p' => c.is_ascii_punctuation(),
        b's' => is_c_space(c),
        b'u' => c.is_ascii_uppercase(),
        b'w' => c.is_ascii_alphanumeric(),
        b'x' => c.is_ascii_hexdigit(),
        b'z' => c == 0, // deprecated, still accepted
        _ => return cl == c,
    };
    if cl.is_ascii_lowercase() {
        res
    } else {
        !res
    }
}

/// `MatchState` (`lstrlib.c:358`), minus the `lua_State`: errors are returned,
/// not thrown.
///
/// # Arithmetic
///
/// Every `s` is an offset into `src` and every `p` an offset into `pat`, and
/// the matcher keeps both within `0 ..= len` — it never steps `s` past the end
/// (`singlematch` refuses at `src.len()`, and every other advance follows a
/// successful single match or a `%b` that found its closer) and every advance
/// of `p` is past bytes `classend` has already proven present. The additions
/// and subtractions below are therefore by small constants on values at most a
/// slice length, and cannot overflow; the fuzz target is what holds that
/// argument to account (`overflow-checks` is on in every profile, so a wrong
/// argument would be a caught panic, not a wrong answer).
struct MatchState<'a> {
    src: &'a [u8],
    pat: &'a [u8],
    matchdepth: u32,
    level: usize,
    cap: [Cap; MAXCAPTURES],
    /// Failed computations, when memoisation applies. See [`Memo`].
    memo: Option<Memo>,
    /// Computations entered so far; the memo starts recording past a threshold.
    steps: u64,
    /// The deepest frame entered since the current computation began.
    peak: u32,
    /// The computations each active frame has run through, innermost last:
    /// `(s, p, deepest frame entered while it was the current one)`.
    chain: Vec<(usize, usize, u32)>,
    /// The deepest frame entered under each child an expansion loop has tried.
    tried: Vec<u32>,
    /// Where the innermost frame's computations start in `chain`.
    frame_base: usize,
}

/// Failed matcher computations, keyed by `(subject offset, pattern offset)`.
///
/// # Why this is exact
///
/// The C matcher is a backtracking search whose worst case is exponential in
/// the number of quantified items; the subject is what a remote host controls.
/// Recording which states have already *failed* turns that into work roughly
/// linear in `subject × pattern`, and can be made to change nothing a script
/// can observe:
///
/// * **A failure depends only on `(s, p)`.** Captures open and close at fixed
///   pattern offsets (quantifiers apply to single characters, and there is no
///   alternation), so the capture structure at `p` is the same on every path
///   that reaches it. What differs between paths is *where* captures started,
///   and that is read only on success — or by a back-reference, which is why a
///   pattern containing `%0`-`%9` is never memoised.
/// * **A failed computation saw no success and raised no error.** Any success
///   inside it returns straight up the stack, and any error aborts the whole
///   call. So repeating it would repeat the same failure — except for the one
///   error whose outcome depends on *where* it runs: the recursion limit.
/// * **The recursion limit is replayed, not skipped.** With each failure the
///   memo records how many frames deeper than its own it went. Reused in a
///   frame at depth `d`, a failure of height `h` is a failure if `d + h` is
///   within `MAXCCALLS`, and "pattern too complex" otherwise — which is exactly
///   what re-running it would have raised, since the re-run is the same search
///   shifted by `d`.
///
/// The two expansion loops (`*`/`+` and `-`) extend this: a failed loop proves
/// that every later start in the same run of matching characters fails too,
/// and records those with their heights, so a long run is walked once rather
/// than once per start.
struct Memo {
    failed: std::collections::HashMap<(usize, usize), u8, BuildFx>,
}

/// Recording starts after this many computations plus [`MEMO_PER_BYTE`] per
/// subject byte. A scan that never backtracks does a few computations per
/// starting position and so never pays for a table; a search that is going
/// super-linear crosses it while the work done is still linear.
const MEMO_AFTER: u64 = 1 << 12;

/// See [`MEMO_AFTER`].
const MEMO_PER_BYTE: u64 = 16;

/// The memo stops growing past this many entries (each failure is still
/// correct without it; it is only slower).
const MEMO_MAX: usize = 1 << 22;

thread_local! {
    /// Test and fuzz override for [`MEMO_AFTER`]: `Some(0)` memoises from the
    /// first computation, `Some(u64::MAX)` never.
    static MEMO_AFTER_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Set (or with `None`, clear) the memoisation threshold for this thread.
/// For the equivalence tests and the fuzz target, which run every input both
/// ways; nothing else should call it.
#[doc(hidden)]
pub fn set_memo_after(after: Option<u64>) {
    MEMO_AFTER_OVERRIDE.with(|c| c.set(after));
}

fn memo_after(subject_len: usize) -> u64 {
    MEMO_AFTER_OVERRIDE
        .with(std::cell::Cell::get)
        .unwrap_or_else(|| {
            let len = u64::try_from(subject_len).unwrap_or(u64::MAX);
            MEMO_AFTER.saturating_add(len.saturating_mul(MEMO_PER_BYTE))
        })
}

/// A multiply-rotate hash for `(usize, usize)` keys. The keys are offsets the
/// matcher derives, not values an attacker chooses, so a keyed hash buys
/// nothing here.
#[derive(Default, Clone, Copy)]
struct Fx(u64);

impl std::hash::Hasher for Fx {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

type BuildFx = std::hash::BuildHasherDefault<Fx>;

/// Whether a pattern may be memoised: it has no back-reference. Any `%`
/// followed by a digit counts, even one that turns out to be inside a set,
/// which only ever errs on the side of not memoising.
fn memoisable(pat: &[u8]) -> bool {
    !pat.windows(2)
        .any(|w| w[0] == L_ESC && w[1].is_ascii_digit())
}

#[allow(clippy::arithmetic_side_effects)] // see "Arithmetic" on `MatchState`
impl<'a> MatchState<'a> {
    /// `prepstate` (`lstrlib.c:757`) followed by `reprepstate`.
    fn new(src: &'a [u8], pat: &'a [u8]) -> Self {
        Self {
            src,
            pat,
            matchdepth: MAXCCALLS,
            level: 0,
            cap: [NO_CAP; MAXCAPTURES],
            memo: None,
            steps: 0,
            peak: 0,
            chain: Vec::new(),
            tried: Vec::new(),
            frame_base: 0,
        }
    }

    /// The depth of the innermost active frame (the top-level call is 1).
    fn depth(&self) -> u32 {
        MAXCCALLS - self.matchdepth
    }

    /// Count one computation, and start the memo once there have been enough.
    fn tick(&mut self) {
        self.steps = self.steps.saturating_add(1);
        if self.memo.is_none() && self.steps > memo_after(self.src.len()) && memoisable(self.pat) {
            self.memo = Some(Memo {
                failed: std::collections::HashMap::default(),
            });
        }
    }

    /// The recorded failure of computation `(s, p)`, if any: its height.
    fn known_failure(&self, s: usize, p: usize) -> Option<u32> {
        self.memo
            .as_ref()?
            .failed
            .get(&(s, p))
            .map(|&h| u32::from(h))
    }

    /// Record that computation `(s, p)` fails, reaching `height` frames below
    /// the frame it runs in.
    fn record_failure(&mut self, s: usize, p: usize, height: u32) {
        let Some(memo) = self.memo.as_mut() else {
            return;
        };
        if memo.failed.len() < MEMO_MAX && memo.failed.try_reserve(1).is_ok() {
            // A height is at most MAXCCALLS (200).
            memo.failed
                .insert((s, p), u8::try_from(height).unwrap_or(u8::MAX));
        }
    }

    /// Reuse a recorded failure of height `h` in the current frame: a plain
    /// failure if it fits under the recursion limit here, and the limit's own
    /// error if it does not — which is what running it again would raise.
    fn replay_failure(&mut self, h: u32) -> Result<Option<usize>, PatternError> {
        let reach = self.depth() + h;
        if reach > MAXCCALLS {
            return Err(PatternError::new("pattern too complex"));
        }
        self.peak = self.peak.max(reach);
        Ok(None)
    }

    /// Begin computation `(s, p)` in the current frame (the C's `init:`).
    /// Returns the replayed outcome if it is already known to fail.
    fn enter(&mut self, s: usize, p: usize) -> Option<Result<Option<usize>, PatternError>> {
        self.tick();
        if let Some(h) = self.known_failure(s, p) {
            return Some(self.replay_failure(h));
        }
        // Close the previous computation's segment — of this frame only.
        if self.chain.len() > self.frame_base {
            if let Some(last) = self.chain.last_mut() {
                last.2 = self.peak;
            }
        }
        let d = self.depth();
        self.peak = d;
        self.chain.push((s, p, u32::MAX));
        None
    }

    /// Run `f` as a child call and report the deepest frame it entered.
    fn child(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<Option<usize>, PatternError>,
    ) -> (Result<Option<usize>, PatternError>, u32) {
        let saved = self.peak;
        self.peak = self.depth();
        let res = f(self);
        let reached = self.peak;
        self.peak = saved.max(reached);
        (res, reached)
    }

    /// `reprepstate` (`lstrlib.c:767`).
    fn reprep(&mut self) {
        self.level = 0;
        debug_assert_eq!(self.matchdepth, MAXCCALLS);
    }

    /// The pattern byte at `p`, or the NUL the C would read one past its end.
    fn pc(&self, p: usize) -> u8 {
        self.pat.get(p).copied().unwrap_or(0)
    }

    /// The subject byte at `s`, or the NUL the C would read one past its end.
    fn sc(&self, s: usize) -> u8 {
        self.src.get(s).copied().unwrap_or(0)
    }

    /// `check_capture` (`lstrlib.c:386`): `l` is the digit byte after `%`.
    fn check_capture(&self, l: u8) -> Result<usize, PatternError> {
        let l = i32::from(l) - i32::from(b'1');
        match usize::try_from(l) {
            Ok(i) if i < self.level && self.cap[i].len != CapLen::Unfinished => Ok(i),
            _ => Err(PatternError::capture_index(l + 1)),
        }
    }

    /// `capture_to_close` (`lstrlib.c:395`).
    fn capture_to_close(&self) -> Result<usize, PatternError> {
        (0..self.level)
            .rev()
            .find(|&l| self.cap[l].len == CapLen::Unfinished)
            .ok_or_else(|| PatternError::new("invalid pattern capture"))
    }

    /// `classend` (`lstrlib.c:403`): the offset just past the single-character
    /// class starting at `p`.
    fn classend(&self, mut p: usize) -> Result<usize, PatternError> {
        let c = self.pc(p);
        p += 1;
        match c {
            L_ESC => {
                if p == self.pat.len() {
                    return Err(PatternError::new("malformed pattern (ends with '%')"));
                }
                Ok(p + 1)
            }
            b'[' => {
                if self.pc(p) == b'^' {
                    p += 1;
                }
                // A `do ... while`: the first byte after `[` or `[^` is part of
                // the set even if it is `]`.
                loop {
                    if p == self.pat.len() {
                        return Err(PatternError::new("malformed pattern (missing ']')"));
                    }
                    let c = self.pc(p);
                    p += 1;
                    if c == L_ESC && p < self.pat.len() {
                        p += 1; // skip escapes (e.g. '%]')
                    }
                    if self.pc(p) == b']' {
                        break;
                    }
                }
                Ok(p + 1)
            }
            _ => Ok(p),
        }
    }

    /// `matchbracketclass` (`lstrlib.c:441`): `p` is the `[`, `ec` the `]`.
    fn matchbracketclass(&self, c: u8, mut p: usize, ec: usize) -> bool {
        let mut sig = true;
        if self.pc(p + 1) == b'^' {
            sig = false;
            p += 1;
        }
        loop {
            p += 1;
            if p >= ec {
                break;
            }
            if self.pc(p) == L_ESC {
                p += 1;
                if match_class(c, self.pc(p)) {
                    return sig;
                }
            } else if self.pc(p + 1) == b'-' && p + 2 < ec {
                p += 2;
                if self.pc(p - 2) <= c && c <= self.pc(p) {
                    return sig;
                }
            } else if self.pc(p) == c {
                return sig;
            }
        }
        !sig
    }

    /// `singlematch` (`lstrlib.c:468`).
    fn singlematch(&self, s: usize, p: usize, ep: usize) -> bool {
        let Some(&c) = self.src.get(s) else {
            return false;
        };
        match self.pc(p) {
            b'.' => true,
            L_ESC => match_class(c, self.pc(p + 1)),
            b'[' => self.matchbracketclass(c, p, ep - 1),
            pb => pb == c,
        }
    }

    /// `matchbalance` (`lstrlib.c:484`): `%bxy` with `p` at `x`.
    fn matchbalance(&self, mut s: usize, p: usize) -> Result<Option<usize>, PatternError> {
        if p + 1 >= self.pat.len() {
            return Err(PatternError::new(
                "malformed pattern (missing arguments to '%b')",
            ));
        }
        if self.sc(s) != self.pc(p) {
            return Ok(None);
        }
        let (b, e) = (self.pc(p), self.pc(p + 1));
        let mut cont: usize = 1;
        loop {
            s += 1;
            let Some(&c) = self.src.get(s) else {
                return Ok(None); // string ends out of balance
            };
            if c == e {
                cont -= 1;
                if cont == 0 {
                    return Ok(Some(s + 1));
                }
            } else if c == b {
                cont += 1;
            }
        }
    }

    /// `max_expand` (`lstrlib.c:504`) for the item at `p`..`ep` that computation
    /// `(s0, p)` matched once at `s0`; `off` is 1 for `+` (that match is
    /// consumed) and 0 for `*`. The C tries every repetition count from the
    /// most down, each as a child call of the continuation at `ep + 1`.
    fn max_expand(
        &mut self,
        s0: usize,
        off: usize,
        p: usize,
        ep: usize,
    ) -> Result<Option<usize>, PatternError> {
        let base = s0 + off;
        // If the computation one byte on is known to fail, so is every child
        // it tried — all of ours but the last — and only that one is left.
        if self.singlematch(s0 + 1, p, ep) {
            if let Some(h) = self.known_failure(s0 + 1, p) {
                self.replay_failure(h)?;
                return self.child(|m| m.do_match(base, ep + 1)).0;
            }
        }
        let mut end = base;
        while self.singlematch(end, p, ep) {
            end += 1;
        }
        let mark = self.tried.len();
        // Keep trying with the maximum repetitions, then one fewer.
        let mut i = end;
        loop {
            let (res, reached) = self.child(|m| m.do_match(i, ep + 1));
            if let Some(found) = res? {
                self.tried.truncate(mark);
                return Ok(Some(found));
            }
            self.tried.push(reached);
            if i == base {
                break;
            }
            i -= 1;
        }
        // All failed. Every start `x` strictly inside the run tries the
        // children from `end` down to `x + off`: the first `end - x - off + 1`
        // tried here.
        let d = self.depth();
        let mut deepest = d;
        for k in 0..self.tried.len() - mark {
            deepest = deepest.max(self.tried[mark + k]);
            let child_pos = end - k;
            if let Some(x) = child_pos.checked_sub(off).filter(|&x| x > s0 && x < end) {
                self.record_failure(x, p, deepest - d);
            }
        }
        self.tried.truncate(mark);
        Ok(None)
    }

    /// `min_expand` (`lstrlib.c:519`) for the item at `p`..`ep` that computation
    /// `(s0, p)` matched once at `s0`.
    fn min_expand(
        &mut self,
        s0: usize,
        p: usize,
        ep: usize,
    ) -> Result<Option<usize>, PatternError> {
        let mark = self.tried.len();
        let mut s = s0;
        let outcome = loop {
            // The rest of this loop is exactly computation `(s, p)`'s own.
            if s > s0 && self.singlematch(s, p, ep) {
                if let Some(h) = self.known_failure(s, p) {
                    let r = self.replay_failure(h);
                    if r.is_err() {
                        self.tried.truncate(mark);
                        return r;
                    }
                    self.tried.push(self.depth() + h);
                    break None;
                }
            }
            let (res, reached) = self.child(|m| m.do_match(s, ep + 1));
            if let Some(found) = res? {
                self.tried.truncate(mark);
                return Ok(Some(found));
            }
            self.tried.push(reached);
            if self.singlematch(s, p, ep) {
                s += 1; // try with one more repetition
            } else {
                break None;
            }
        };
        // All failed: every start after `s0` that still matched the item ran
        // the tail of this loop from there.
        let d = self.depth();
        let mut deepest = d;
        let tried = self.tried.len() - mark;
        for k in (0..tried).rev() {
            deepest = deepest.max(self.tried[mark + k]);
            let x = s0 + k;
            if k > 0 && self.singlematch(x, p, ep) {
                self.record_failure(x, p, deepest - d);
            }
        }
        self.tried.truncate(mark);
        Ok(outcome)
    }

    /// `start_capture` (`lstrlib.c:532`).
    fn start_capture(
        &mut self,
        s: usize,
        p: usize,
        what: CapLen,
    ) -> Result<Option<usize>, PatternError> {
        let level = self.level;
        if level >= MAXCAPTURES {
            return Err(PatternError::new("too many captures"));
        }
        self.cap[level] = Cap { init: s, len: what };
        self.level = level + 1;
        let res = self.do_match(s, p)?;
        if res.is_none() {
            self.level -= 1; // undo capture
        }
        Ok(res)
    }

    /// `end_capture` (`lstrlib.c:547`).
    fn end_capture(&mut self, s: usize, p: usize) -> Result<Option<usize>, PatternError> {
        let l = self.capture_to_close()?;
        // `s` never moves backwards along one match path, and the capture was
        // opened earlier on this one.
        self.cap[l].len = CapLen::Closed(s - self.cap[l].init);
        let res = self.do_match(s, p)?;
        if res.is_none() {
            self.cap[l].len = CapLen::Unfinished; // undo capture
        }
        Ok(res)
    }

    /// `match_capture` (`lstrlib.c:559`): a back-reference `%1`-`%9`.
    fn match_capture(&self, s: usize, l: u8) -> Result<Option<usize>, PatternError> {
        let l = self.check_capture(l)?;
        let Cap { init, len } = self.cap[l];
        // A position capture's length is `CAP_POSITION`, which the C compares
        // as `(size_t)-2` — longer than any subject — so it never matches.
        let CapLen::Closed(len) = len else {
            return Ok(None);
        };
        if self.src.len() - s >= len && self.src[init..init + len] == self.src[s..s + len] {
            Ok(Some(s + len))
        } else {
            Ok(None)
        }
    }

    /// `match` (`lstrlib.c:571`). The C's `goto init` tail calls are the
    /// `continue`s; its recursive calls are the calls to `do_match`.
    fn do_match(&mut self, s: usize, p: usize) -> Result<Option<usize>, PatternError> {
        if self.matchdepth == 0 {
            return Err(PatternError::new("pattern too complex"));
        }
        self.matchdepth -= 1;
        let d = self.depth();
        let saved_peak = self.peak;
        self.peak = d;
        let base = self.chain.len();
        let saved_base = std::mem::replace(&mut self.frame_base, base);
        let res = self.match_body(s, p);
        self.frame_base = saved_base;
        // Close the frame's last segment, then walk its computations back to
        // front: each one's height is the deepest any later one reached.
        if self.chain.len() > base {
            if let Some(last) = self.chain.last_mut() {
                last.2 = self.peak;
            }
        }
        let mut deepest = self.peak.max(d);
        for i in (base..self.chain.len()).rev() {
            let (cs, cp, seg) = self.chain[i];
            deepest = deepest.max(seg);
            if matches!(res, Ok(None)) {
                self.record_failure(cs, cp, deepest - d);
            }
        }
        self.chain.truncate(base);
        self.peak = saved_peak.max(deepest);
        // The C restores the budget only on a normal return; it is restored
        // here on an error too. See the module documentation.
        self.matchdepth += 1;
        res
    }

    fn match_body(&mut self, mut s: usize, mut p: usize) -> Result<Option<usize>, PatternError> {
        loop {
            if let Some(known) = self.enter(s, p) {
                return known;
            }
            if p == self.pat.len() {
                return Ok(Some(s)); // end of pattern
            }
            match self.pc(p) {
                b'(' => {
                    return if self.pc(p + 1) == b')' {
                        self.start_capture(s, p + 2, CapLen::Position)
                    } else {
                        self.start_capture(s, p + 1, CapLen::Unfinished)
                    };
                }
                b')' => return self.end_capture(s, p + 1),
                b'$' if p + 1 == self.pat.len() => {
                    return Ok((s == self.src.len()).then_some(s));
                }
                L_ESC if self.pc(p + 1) == b'b' => match self.matchbalance(s, p + 2)? {
                    Some(next) => {
                        s = next;
                        p += 4;
                    }
                    None => return Ok(None),
                },
                L_ESC if self.pc(p + 1) == b'f' => {
                    p += 2;
                    if self.pc(p) != b'[' {
                        return Err(PatternError::new("missing '[' after '%f' in pattern"));
                    }
                    let ep = self.classend(p)?;
                    let previous = if s == 0 { 0 } else { self.src[s - 1] };
                    if !self.matchbracketclass(previous, p, ep - 1)
                        && self.matchbracketclass(self.sc(s), p, ep - 1)
                    {
                        p = ep;
                    } else {
                        return Ok(None);
                    }
                }
                L_ESC if self.pc(p + 1).is_ascii_digit() => {
                    match self.match_capture(s, self.pc(p + 1))? {
                        Some(next) => {
                            s = next;
                            p += 2;
                        }
                        None => return Ok(None),
                    }
                }
                // `dflt`: a single-character class plus an optional suffix.
                _ => {
                    let ep = self.classend(p)?;
                    let suffix = self.pc(ep);
                    if !self.singlematch(s, p, ep) {
                        if matches!(suffix, b'*' | b'?' | b'-') {
                            p = ep + 1; // accept empty
                        } else {
                            return Ok(None); // '+' or no suffix
                        }
                    } else {
                        match suffix {
                            b'?' => {
                                if let Some(res) = self.do_match(s + 1, ep + 1)? {
                                    return Ok(Some(res));
                                }
                                p = ep + 1;
                            }
                            b'+' => return self.max_expand(s, 1, p, ep),
                            b'*' => return self.max_expand(s, 0, p, ep),
                            b'-' => return self.min_expand(s, p, ep),
                            _ => {
                                s += 1;
                                p = ep;
                            }
                        }
                    }
                }
            }
        }
    }

    /// The state `match` left behind, kept as the result of a successful match.
    fn matched(&self, start: usize, end: usize) -> Match {
        Match {
            start,
            end,
            level: self.level,
            cap: self.cap,
        }
    }
}

/// One successful match: where it lies in the subject, and its captures.
///
/// The captures are offsets, not slices, so that a `Match` can be held while
/// the binding calls back into the VM; the subject is passed back in to read
/// them.
#[derive(Debug, Clone)]
pub struct Match {
    start: usize,
    end: usize,
    level: usize,
    cap: [Cap; MAXCAPTURES],
}

impl Match {
    /// `get_onecapture` (`lstrlib.c:704`) for capture `i` (0-based); capture 0
    /// of a pattern with none is the whole match.
    pub fn capture<'a>(&self, src: &'a [u8], i: usize) -> Result<Capture<'a>, PatternError> {
        if i >= self.level {
            if i != 0 {
                return Err(PatternError::capture_index(
                    i32::try_from(i).unwrap_or(i32::MAX).saturating_add(1),
                ));
            }
            return Ok(Capture::Bytes(&src[self.start..self.end]));
        }
        let Cap { init, len } = self.cap[i];
        match len {
            CapLen::Unfinished => Err(PatternError::new("unfinished capture")),
            CapLen::Position => Ok(Capture::Position(lua_pos(init))),
            #[allow(clippy::arithmetic_side_effects)] // a closed capture lies within `src`
            CapLen::Closed(n) => Ok(Capture::Bytes(&src[init..init + n])),
        }
    }

    /// `push_captures` (`lstrlib.c:734`). With `whole` (the C passes a
    /// non-NULL `s`), a pattern with no captures yields the whole match;
    /// without it (`find`), it yields nothing.
    pub fn captures<'a>(
        &self,
        src: &'a [u8],
        whole: bool,
    ) -> Result<Vec<Capture<'a>>, PatternError> {
        let n = if self.level == 0 && whole {
            1
        } else {
            self.level
        };
        (0..n).map(|i| self.capture(src, i)).collect()
    }
}

/// `nospecials` (`lstrlib.c:745`). The C walks the pattern a NUL-terminated
/// chunk at a time so that bytes after an embedded NUL are checked too; that is
/// every byte.
fn nospecials(p: &[u8]) -> bool {
    !p.iter().any(|b| SPECIALS.contains(b))
}

/// `lmemfind` (`lstrlib.c:668`): the offset of the first occurrence of `needle`
/// in `hay`. An empty needle is found at 0.
///
/// The C finds candidate positions with `memchr` and compares only there; a
/// window comparison at every offset gave the same answers 57 times slower on
/// a 10 MB body searched for `"\r\n\r\n"`, which is how NSE's HTTP code uses
/// it. `memmem::find` is a vectorised substring search with the same contract.
fn lmemfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(hay, needle)
}

/// Strip the anchor `find`, `match` and `gsub` honour.
fn split_anchor(p: &[u8]) -> (bool, &[u8]) {
    match p.split_first() {
        Some((b'^', rest)) => (true, rest),
        _ => (false, p),
    }
}

/// What `string.find` returns on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<'a> {
    /// The 1-based position of the first byte of the match.
    pub start: i64,
    /// The 1-based position of its last byte (`start - 1` for an empty match).
    pub end: i64,
    /// The pattern's captures; empty for a pattern with none, and for a plain
    /// search.
    pub captures: Vec<Capture<'a>>,
}

/// The pattern-matching loop of `str_find_aux` (`lstrlib.c:776`), shared by
/// `find` and `match`: the first match at or after `init`, as `(start, end)`
/// offsets plus its state.
fn first_match(s: &[u8], p: &[u8], init: usize) -> Result<Option<Match>, PatternError> {
    let (anchor, pat) = split_anchor(p);
    let mut ms = MatchState::new(s, pat);
    let mut s1 = init;
    loop {
        ms.reprep();
        if let Some(end) = ms.do_match(s1, 0)? {
            return Ok(Some(ms.matched(s1, end)));
        }
        // `while (s1++ < ms.src_end && !anchor)`
        if s1 >= s.len() || anchor {
            return Ok(None);
        }
        s1 = s1.saturating_add(1);
    }
}

/// `string.find(s, pattern [, init [, plain]])` (`str_find_aux` with `find`
/// set). `None` is Lua's `fail`.
pub fn find<'a>(
    s: &'a [u8],
    p: &[u8],
    init: i64,
    plain: bool,
) -> Result<Option<Found<'a>>, PatternError> {
    let init = start_offset(init, s.len());
    let Some(init) = usize::try_from(init).ok().filter(|&i| i <= s.len()) else {
        return Ok(None); // start after the subject's end: cannot find anything
    };
    if plain || nospecials(p) {
        return Ok(lmemfind(&s[init..], p).map(|off| {
            let at = init.saturating_add(off);
            Found {
                start: lua_pos(at),
                end: lua_pos(at.saturating_add(p.len())).saturating_sub(1),
                captures: Vec::new(),
            }
        }));
    }
    let Some(m) = first_match(s, p, init)? else {
        return Ok(None);
    };
    Ok(Some(Found {
        start: lua_pos(m.start),
        end: lua_pos(m.end).saturating_sub(1),
        captures: m.captures(s, false)?,
    }))
}

/// `string.match(s, pattern [, init])` (`str_find_aux` with `find` clear):
/// the captures, or the whole match for a pattern with none. `None` is `fail`.
pub fn str_match<'a>(
    s: &'a [u8],
    p: &[u8],
    init: i64,
) -> Result<Option<Vec<Capture<'a>>>, PatternError> {
    let init = start_offset(init, s.len());
    let Some(init) = usize::try_from(init).ok().filter(|&i| i <= s.len()) else {
        return Ok(None);
    };
    match first_match(s, p, init)? {
        Some(m) => Ok(Some(m.captures(s, true)?)),
        None => Ok(None),
    }
}

/// The state `string.gmatch` keeps between calls of its iterator
/// (`GMatchState`, `lstrlib.c:819`) — only the two positions. The C also keeps
/// the `MatchState`, and with it a recursion budget an error can leave
/// lowered; see the module documentation for why that is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gmatch {
    src: usize,
    lastmatch: Option<usize>,
}

impl Gmatch {
    /// `gmatch` (`lstrlib.c:844`) for a subject of `len` bytes.
    pub fn new(len: usize, init: i64) -> Self {
        let init = start_offset(init, len);
        let src = match usize::try_from(init) {
            Ok(i) if i <= len => i,
            // start after the subject's end: one past it, so nothing is found
            _ => len.saturating_add(1),
        };
        Self {
            src,
            lastmatch: None,
        }
    }

    /// `gmatch_aux` (`lstrlib.c:827`): the next match's captures, or `None`
    /// when there are no more. `s` and `p` must be the subject and pattern
    /// this iterator was created for. The pattern is used whole: `^` is not an
    /// anchor here.
    pub fn next<'a>(
        &mut self,
        s: &'a [u8],
        p: &[u8],
    ) -> Result<Option<Vec<Capture<'a>>>, PatternError> {
        let mut ms = MatchState::new(s, p);
        let mut src = self.src;
        while src <= s.len() {
            ms.reprep();
            if let Some(e) = ms.do_match(src, 0)? {
                if Some(e) != self.lastmatch {
                    // Advanced before the captures are read, as in the C: an
                    // "unfinished capture" error still consumes the match.
                    self.src = e;
                    self.lastmatch = Some(e);
                    return Ok(Some(ms.matched(src, e).captures(s, true)?));
                }
            }
            src = src.saturating_add(1);
        }
        Ok(None)
    }
}

/// Append `bytes` to a `gsub` result, failing as `luaL_Buffer` does — with a
/// catchable error — if the allocation is refused, rather than aborting.
fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PatternError> {
    if !super::reserve(out, bytes.len()) {
        return Err(PatternError::out_of_memory());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// `string.gsub` (`str_gsub`, `lstrlib.c:928`) as a driver the binding polls.
///
/// [`Gsub::next`] finds the next match and returns it. The caller then
/// decides the replacement and calls exactly one of [`Gsub::add_template`]
/// (a string replacement, with `%n` escapes), [`Gsub::add_value`] (the string
/// a function or table produced) or [`Gsub::keep`] (it produced `nil` or
/// `false`) before calling `next` again. [`Gsub::finish`] yields the result.
#[derive(Debug, Clone)]
pub struct Gsub {
    src: usize,
    lastmatch: Option<usize>,
    n: i64,
    max_s: i64,
    anchor: bool,
    changed: bool,
    done: bool,
    out: Vec<u8>,
}

impl Gsub {
    /// Start a substitution of `p` with at most `max_s` replacements.
    pub fn new(p: &[u8], max_s: i64) -> Self {
        Self {
            src: 0,
            lastmatch: None,
            n: 0,
            max_s,
            anchor: split_anchor(p).0,
            changed: false,
            done: false,
            out: Vec::new(),
        }
    }

    /// The next match to replace, or `None` when the substitution is over.
    /// Unmatched bytes are copied to the result as the scan passes them.
    pub fn next(&mut self, s: &[u8], p: &[u8]) -> Result<Option<Match>, PatternError> {
        let pat = split_anchor(p).1;
        let mut ms = MatchState::new(s, pat);
        while !self.done && self.n < self.max_s {
            ms.reprep();
            match ms.do_match(self.src, 0)? {
                Some(e) if Some(e) != self.lastmatch => {
                    // `n < max_s`, so this cannot overflow.
                    self.n = self.n.saturating_add(1);
                    return Ok(Some(ms.matched(self.src, e)));
                }
                _ => match s.get(self.src) {
                    Some(&c) => {
                        put(&mut self.out, &[c])?; // skip one character
                        self.src = self.src.saturating_add(1);
                    }
                    None => self.done = true, // end of subject
                },
            }
            if self.anchor {
                self.done = true;
            }
        }
        Ok(None)
    }

    /// After a match has been replaced: continue from its end.
    fn advance(&mut self, m: &Match) {
        self.src = m.end;
        self.lastmatch = Some(m.end);
        if self.anchor {
            self.done = true;
        }
    }

    /// `add_s` (`lstrlib.c:870`): replace `m` with the string `repl`, in which
    /// `%0`-`%9` stand for captures and `%%` for a `%`.
    pub fn add_template(&mut self, s: &[u8], m: &Match, repl: &[u8]) -> Result<(), PatternError> {
        let mut news = repl;
        while let Some(i) = news.iter().position(|&b| b == L_ESC) {
            put(&mut self.out, &news[..i])?;
            // The byte after the escape; at the end, the NUL the C would read.
            let c = news.get(i.saturating_add(1)).copied().unwrap_or(0);
            if c == L_ESC {
                put(&mut self.out, &[L_ESC])?;
            } else if c == b'0' {
                put(&mut self.out, &s[m.start..m.end])?;
            } else if c.is_ascii_digit() {
                match m.capture(s, usize::from(c.saturating_sub(b'1')))? {
                    Capture::Bytes(b) => put(&mut self.out, b)?,
                    Capture::Position(n) => put(&mut self.out, n.to_string().as_bytes())?,
                }
            } else {
                return Err(PatternError::new(
                    "invalid use of '%' in replacement string",
                ));
            }
            // `c` was a real byte, so `i + 2 <= news.len()`.
            news = news.get(i.saturating_add(2)..).unwrap_or_default();
        }
        put(&mut self.out, news)?;
        self.changed = true;
        self.advance(m);
        Ok(())
    }

    /// Replace `m` with `value`, the string a replacement function or table
    /// produced (`luaL_addvalue`).
    pub fn add_value(&mut self, m: &Match, value: &[u8]) -> Result<(), PatternError> {
        put(&mut self.out, value)?;
        self.changed = true;
        self.advance(m);
        Ok(())
    }

    /// Keep `m`'s original text: the replacement function or table produced
    /// `nil` or `false`.
    pub fn keep(&mut self, s: &[u8], m: &Match) -> Result<(), PatternError> {
        put(&mut self.out, &s[m.start..m.end])?;
        self.advance(m);
        Ok(())
    }

    /// The result and the number of matches. `None` means nothing was
    /// replaced and the subject itself is the result — the C returns the
    /// original string object in that case.
    ///
    /// The driver is spent afterwards: its buffer has been handed over.
    pub fn finish(&mut self, s: &[u8]) -> Result<(Option<Vec<u8>>, i64), PatternError> {
        self.done = true;
        if !self.changed {
            return Ok((None, self.n));
        }
        put(&mut self.out, s.get(self.src..).unwrap_or_default())?;
        Ok((Some(std::mem::take(&mut self.out)), self.n))
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for decisions the differential corpus cannot isolate; the
    //! corpus (`tests/differential/m6/m6_pattern_*`) is the real gate.
    use super::*;

    fn b(s: &str) -> Capture<'_> {
        Capture::Bytes(s.as_bytes())
    }

    fn find_s<'a>(s: &'a str, p: &str) -> Option<(i64, i64, Vec<Capture<'a>>)> {
        find(s.as_bytes(), p.as_bytes(), 1, false)
            .unwrap()
            .map(|f| (f.start, f.end, f.captures))
    }

    fn match_s<'a>(s: &'a str, p: &str) -> Result<Option<Vec<Capture<'a>>>, String> {
        str_match(s.as_bytes(), p.as_bytes(), 1).map_err(|e| e.msg)
    }

    fn gsub_s(s: &str, p: &str, repl: &str) -> Result<(String, i64), String> {
        let (s, p) = (s.as_bytes(), p.as_bytes());
        let mut g = Gsub::new(p, i64::try_from(s.len()).unwrap().saturating_add(1));
        while let Some(m) = g.next(s, p).map_err(|e| e.msg)? {
            g.add_template(s, &m, repl.as_bytes()).map_err(|e| e.msg)?;
        }
        let (out, n) = g.finish(s).map_err(|e| e.msg)?;
        Ok((
            String::from_utf8(out.unwrap_or_else(|| s.to_vec())).unwrap(),
            n,
        ))
    }

    #[test]
    fn find_reports_positions_and_captures() {
        assert_eq!(find_s("hello world", "o w"), Some((5, 7, vec![])));
        assert_eq!(
            find_s("hello world", "(o)%s(w)"),
            Some((5, 7, vec![b("o"), b("w")]))
        );
        assert_eq!(find_s("hello", "l+"), Some((3, 4, vec![])));
        assert_eq!(find_s("hello", "xyz"), None);
        // An empty match at the start is `start, start - 1`.
        assert_eq!(find_s("abc", ""), Some((1, 0, vec![])));
        assert_eq!(
            find_s("abc", "()"),
            Some((1, 0, vec![Capture::Position(1)]))
        );
    }

    #[test]
    fn init_selects_the_start_and_past_the_end_is_fail() {
        let at = |init| find(b"abcabc", b"b", init, false).unwrap().map(|f| f.start);
        assert_eq!(at(1), Some(2));
        assert_eq!(at(3), Some(5));
        assert_eq!(at(-2), Some(5));
        assert_eq!(at(-100), Some(2)); // clipped to 1
        assert_eq!(at(7), None);
        assert_eq!(at(i64::MAX), None);
        // An empty pattern is found one past the end, but not two past.
        assert_eq!(
            find(b"abc", b"", 4, false).unwrap().map(|f| f.start),
            Some(4)
        );
        assert_eq!(find(b"abc", b"", 5, false).unwrap(), None);
    }

    #[test]
    fn match_returns_the_whole_match_without_captures() {
        assert_eq!(
            match_s("key=value", "(%w+)=(%w+)"),
            Ok(Some(vec![b("key"), b("value")]))
        );
        assert_eq!(match_s("key=value", "%w+"), Ok(Some(vec![b("key")])));
        assert_eq!(
            match_s("  x", "^%s*()"),
            Ok(Some(vec![Capture::Position(3)]))
        );
    }

    #[test]
    fn character_classes_are_the_c_locales() {
        // `\v` is a space in C, and not in `is_ascii_whitespace`.
        assert_eq!(match_s("\x0b", "%s"), Ok(Some(vec![b("\x0b")])));
        // Nothing at or above 0x80 is a letter in the C locale.
        assert_eq!(str_match(b"\xe9", b"%a", 1).unwrap(), None);
        assert_eq!(
            str_match(b"\xe9", b"%A", 1).unwrap(),
            Some(vec![Capture::Bytes(b"\xe9")])
        );
        // The deprecated `%z` still matches NUL.
        assert_eq!(
            str_match(b"a\0b", b"%z", 1).unwrap(),
            Some(vec![Capture::Bytes(b"\0")])
        );
    }

    #[test]
    fn errors_are_lazy() {
        // `b` fails before `[` is ever parsed, so this is a plain miss.
        assert_eq!(match_s("a", "b["), Ok(None));
        assert_eq!(
            match_s("b", "b[").unwrap_err(),
            "malformed pattern (missing ']')"
        );
        assert_eq!(
            match_s("a", "%").unwrap_err(),
            "malformed pattern (ends with '%')"
        );
        assert_eq!(
            match_s("a", "%b(").unwrap_err(),
            "malformed pattern (missing arguments to '%b')"
        );
        assert_eq!(
            match_s("a", "%fa").unwrap_err(),
            "missing '[' after '%f' in pattern"
        );
        assert_eq!(
            match_s("a", "(a)%2").unwrap_err(),
            "invalid capture index %2"
        );
        assert_eq!(match_s("a", "%0").unwrap_err(), "invalid capture index %0");
        assert_eq!(match_s("a", "a)").unwrap_err(), "invalid pattern capture");
        assert_eq!(match_s("a", "(a").unwrap_err(), "unfinished capture");
        assert_eq!(
            match_s("a", &"()".repeat(33)).unwrap_err(),
            "too many captures"
        );
    }

    #[test]
    fn the_subject_reads_as_nul_terminated() {
        // A frontier at the end sees the C's hidden NUL as the next byte.
        assert_eq!(find_s("abc", "%f[%z]"), Some((4, 3, vec![])));
        assert_eq!(find_s("abc", "%f[%a]"), Some((1, 0, vec![])));
        assert_eq!(find_s("abc", "%f[%A]"), Some((4, 3, vec![])));
    }

    #[test]
    fn balance_and_back_references() {
        assert_eq!(match_s("x(a(b)c)y", "%b()"), Ok(Some(vec![b("(a(b)c)")])));
        assert_eq!(match_s("x(a(b", "%b()"), Ok(None));
        assert_eq!(
            match_s("say 'hi' now", "(['\"])(.-)%1"),
            Ok(Some(vec![b("'"), b("hi")]))
        );
        // A back-reference to a position capture never matches, and is not an error.
        assert_eq!(match_s("aa", "()%1"), Ok(None));
    }

    #[test]
    fn gmatch_treats_the_caret_as_a_literal() {
        let (s, p) = (b"a^b^c", b"^%a");
        let mut g = Gmatch::new(s.len(), 1);
        let mut got = vec![];
        while let Some(c) = g.next(s, p).unwrap() {
            got.push(c);
        }
        assert_eq!(
            got,
            vec![vec![Capture::Bytes(b"^b")], vec![Capture::Bytes(b"^c")]]
        );
    }

    #[test]
    fn gmatch_does_not_repeat_an_empty_match_at_the_previous_end() {
        let (s, p) = (b"abc", b"%a*");
        let mut g = Gmatch::new(s.len(), 1);
        let mut got = vec![];
        while let Some(c) = g.next(s, p).unwrap() {
            got.push(c);
        }
        // "abc" then, at 4, an empty match at the previous end is skipped.
        assert_eq!(got, vec![vec![Capture::Bytes(b"abc")]]);
    }

    #[test]
    fn gsub_templates() {
        assert_eq!(
            gsub_s("hello world", "o", "0"),
            Ok(("hell0 w0rld".into(), 2))
        );
        assert_eq!(
            gsub_s("hello", "(l)(l)", "%2%1%0%%"),
            Ok(("hellll%o".into(), 1))
        );
        assert_eq!(gsub_s("abc", "", "-"), Ok(("-a-b-c-".into(), 4)));
        assert_eq!(gsub_s("abc", "^", ">"), Ok((">abc".into(), 1)));
        assert_eq!(gsub_s("abc", "b()", "%1"), Ok(("a3c".into(), 1)));
        assert_eq!(
            gsub_s("abc", "b", "%").unwrap_err(),
            "invalid use of '%' in replacement string"
        );
        assert_eq!(
            gsub_s("abc", "b", "%x").unwrap_err(),
            "invalid use of '%' in replacement string"
        );
        assert_eq!(
            gsub_s("abc", "b", "%2").unwrap_err(),
            "invalid capture index %2"
        );
        // An unfinished capture is only an error if the template reads it.
        assert_eq!(gsub_s("abc", "(b", "x"), Ok(("axc".into(), 1)));
        assert_eq!(gsub_s("abc", "(b", "%1").unwrap_err(), "unfinished capture");
    }

    #[test]
    fn gsub_respects_max_and_reports_unchanged() {
        let s = b"aaa";
        let mut g = Gsub::new(b"a", 2);
        while let Some(m) = g.next(s, b"a").unwrap() {
            g.add_template(s, &m, b"b").unwrap();
        }
        assert_eq!(g.finish(s).unwrap(), (Some(b"bba".to_vec()), 2));

        let mut g = Gsub::new(b"a", 10);
        while let Some(m) = g.next(s, b"a").unwrap() {
            g.keep(s, &m).unwrap();
        }
        assert_eq!(g.finish(s).unwrap(), (None, 3));
    }

    #[test]
    fn the_recursion_limit_is_an_error_not_a_crash() {
        // Each `a?` that matches recurses once; 200 is the C's budget.
        let s = "a".repeat(250);
        let ok = "a?".repeat(199);
        assert!(match_s(&s, &ok).unwrap().is_some());
        let deep = "a?".repeat(201);
        assert_eq!(match_s(&s, &deep).unwrap_err(), "pattern too complex");
    }

    #[test]
    fn a_gmatch_error_does_not_lower_the_next_calls_budget() {
        // The C leaves `matchdepth` at -1 after this error, and its next call
        // then recurses without limit. Here the second call raises the same
        // error, because the budget starts from 200 every time.
        let s = "a".repeat(250);
        let p = "a?".repeat(201);
        let mut g = Gmatch::new(s.len(), 1);
        for _ in 0..2 {
            assert_eq!(
                g.next(s.as_bytes(), p.as_bytes()).unwrap_err().msg,
                "pattern too complex"
            );
        }
    }

    /// The memo's one non-trivial claim: a failure reused at a different
    /// recursion depth is still a failure where the C's search would fit under
    /// MAXCCALLS, and "pattern too complex" where it would not.
    ///
    /// The first loop is a broad sweep: `a?a*` pairs reach the same `(s, p)`
    /// along different paths. The second is the case that matters, built so
    /// that a failure is first met shallow and then reused one frame deeper,
    /// where only the reuse crosses the limit: `.*` tries its longest
    /// repetition first, so `(j + 1, X)` is reached with `a?` unmatched and
    /// then again, one frame deeper, with `a?` matched at `j`; `X` nests one
    /// frame per `a*` that matches. A replay that ignored the depth, or a
    /// height recorded one frame short, fails it.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "hundreds of thousands of matcher steps; the fuzz target and CI cover it natively"
    )]
    fn the_memo_replays_the_recursion_limit_exactly() {
        for pairs in 197usize..=201 {
            for tail in ["b", "(b)"] {
                for subject in ["", "aab"] {
                    let pat = format!("{}{tail}", "a?a*".repeat(pairs));
                    let run = |after| {
                        set_memo_after(Some(after));
                        let f = find(subject.as_bytes(), pat.as_bytes(), 1, false)
                            .map(|o| o.map(|f| (f.start, f.end)));
                        let m = str_match(subject.as_bytes(), pat.as_bytes(), 1)
                            .map(|o| o.map(|c| format!("{c:?}")));
                        let (s, p) = (subject.as_bytes(), pat.as_bytes());
                        let mut g = Gsub::new(p, 100);
                        let r = (|| {
                            while let Some(m) = g.next(s, p)? {
                                g.add_template(s, &m, b"<%0>")?;
                            }
                            g.finish(s)
                        })();
                        set_memo_after(None);
                        (format!("{f:?}"), format!("{m:?}"), format!("{r:?}"))
                    };
                    assert_eq!(
                        run(0),
                        run(u64::MAX),
                        "{pairs} pairs, tail {tail:?}, subject {subject:?}"
                    );
                }
            }
        }

        let (mut crossed, mut tried) = (0, 0);
        for stars in 195..=200 {
            for subject in ["ab", "aab"] {
                let pat = format!(".*a?{}c", "a*".repeat(stars));
                let run = |after| {
                    set_memo_after(Some(after));
                    let r = format!("{:?}", find(subject.as_bytes(), pat.as_bytes(), 1, false));
                    set_memo_after(None);
                    r
                };
                let (with, without) = (run(0), run(u64::MAX));
                assert_eq!(with, without, "{stars} stars, subject {subject:?}");
                crossed += usize::from(with.contains("too complex"));
                tried += 1;
            }
        }
        // Both sides of the limit were reached.
        assert!(
            crossed > 0 && crossed < tried,
            "{crossed} of {tried} raised"
        );
    }

    /// The memo's tables and bookkeeping, small enough for Miri: a handful of
    /// backtracking cases, memo always on against memo never on.
    #[test]
    fn memo_on_and_off_agree_on_small_backtracking_cases() {
        let cases: [(&str, &str); 6] = [
            ("aaaaab", "a?a?a?a?aaaaa"),
            ("xaxbxc", "(.-)a(.-)b(.-)c"),
            ("<p>hi</p>", "(.*)</html>"),
            ("aaab", ".*.*b"),
            ("ab ab", "%f[%w]%w+ (%w*)$"),
            ("aaa", "a*a*a*$"),
        ];
        for (subject, pat) in cases {
            let run = |after| {
                set_memo_after(Some(after));
                let r = format!(
                    "{:?} {:?}",
                    find(subject.as_bytes(), pat.as_bytes(), 1, false),
                    str_match(subject.as_bytes(), pat.as_bytes(), 1)
                );
                set_memo_after(None);
                r
            };
            assert_eq!(run(0), run(u64::MAX), "{pat:?} on {subject:?}");
        }
    }
}
