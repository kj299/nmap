//! The `--script` selection grammar (M6.2).
//!
//! This decides, for one script and one `--script` rule, whether the script is
//! selected and whether it was selected *by name*. It is a pure function over
//! `&[u8]`: no Lua, no filesystem, no allocation beyond the parse tree.
//!
//! # What the C does
//!
//! `get_chosen_scripts` (`nse_main.lua:717`) builds an LPeg grammar and matches
//! each rule against it once per script in the index. Three things about that
//! implementation are load-bearing, and none of them is obvious from reading
//! the grammar:
//!
//! 1. **It is a PEG, so backtracking is limited.** An ordered choice commits to
//!    the first alternative that succeeds. If the *continuation* then fails,
//!    the choice is not reconsidered — the failure propagates outward. This is
//!    what makes `a and b or c` parse as `a and (b or c)` rather than the
//!    conventional `(a and b) or c`, because the right operand of `and` is a
//!    full `expression` that greedily takes `b or c` and is never asked to give
//!    any of it back. See [`matches`] and the `grouping_*` corpus cases.
//! 2. **Repetition is possessive.** `path` is `R(...)^1`, which consumes as far
//!    as the character class allows and never yields characters to help a later
//!    part of the pattern match.
//! 3. **Capture functions run only after the whole match succeeds**, in
//!    left-to-right order over the surviving parse tree. `match_script` — which
//!    sets `selected_by_name` — is such a capture. So a glob that is evaluated
//!    but contributes nothing to the result still sets the flag (`safe and not
//!    http-*` reports "selected by name" while returning false), whereas a glob
//!    in an alternative that was backtracked away never runs at all.
//!
//! Each of those was measured against nmap's own LPeg rather than assumed; the
//! differential corpus in `tests/differential/m6` pins all three.
//!
//! # Two asymmetries worth knowing
//!
//! Keywords and category names are matched **case-insensitively**, but path
//! globs are matched **case-sensitively** — `--script SAFE` works and
//! `--script HTTP-TITLE` does not. And `*` is the *only* wildcard: `?`, `.`,
//! `[`, `]`, `+`, `-`, `^`, `$` and `%` are all escaped into literals before
//! matching, so `http-titl?` does not match `http-title`.
//!
//! Both follow from the C and are reproduced here deliberately.

use std::rc::Rc;

/// Longest rule this module will parse.
///
/// The C has no explicit bound; a rule arrives from `argv` and is limited only
/// by the operating system's argument size. This cap keeps parse cost linear in
/// a hostile input without rejecting anything a person would type.
pub const MAX_RULE_LEN: usize = 64 * 1024;

/// Deepest nesting this module will parse, counting parentheses and operator
/// chains alike.
///
/// The C's own ceiling is far lower and is not a designed limit: LPeg keeps
/// pending choices on a fixed 100-slot backtrack stack (`lpeg.c`: `MAXBACK`),
/// so the effective maximum depends on how many slots each construct happens to
/// cost — measured at 15 nested parentheses, 19 chained `and`s and 31 chained
/// `or`s. Reproducing those three numbers would mean emulating LPeg's stack
/// accounting, which is an implementation detail rather than a grammar
/// property. This port picks one uniform, generous bound instead: every rule
/// the C accepts is accepted here with the same verdict, and the divergence is
/// ledgered as `nse-selection-depth-ceiling`.
///
/// The budget is spent by grammar recursion rather than by source characters,
/// and a parenthesis costs two levels (`expression` then `value`), so this
/// admits roughly 127 nested parentheses or 127 chained operators — an order of
/// magnitude past anything the C will parse, and far past anything a person
/// would type. It exists to keep a hostile rule from recursing without limit,
/// not to express a grammar rule.
pub const MAX_NESTING: usize = 256;

/// Why a rule could not be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// The rule is not a well-formed selection expression.
    ///
    /// This is the C's `nil` return from `T:match(rule)`, and it is not a
    /// failure: `get_chosen_scripts` falls back to treating such a rule as a
    /// filename or directory, and only errors if that lookup also fails.
    NotAnExpression,
    /// Nesting exceeded [`MAX_NESTING`].
    TooDeep,
    /// The rule exceeded [`MAX_RULE_LEN`].
    TooLong,
}

/// A `--script` rule after normalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule<'a> {
    /// The rule text, with surrounding whitespace and any `+` prefix removed.
    pub text: &'a [u8],
    /// Whether the rule was prefixed with `+`, forcing the script to run even
    /// when its rule would decline.
    pub forced: bool,
}

/// The script being tested, as the selection grammar sees it.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The script's basename with any `.nse` extension removed — the C's
    /// `escaped_basename`. Build it with [`Entry::from_filename`] rather than
    /// setting it by hand from an index entry.
    pub basename: &'a [u8],
    /// The script's categories, in index order.
    pub categories: &'a [&'a [u8]],
}

/// Reduce an index entry's `filename` to the name globs are matched against,
/// reproducing `nse_main.lua:765`:
///
/// ```lua
/// match(filename, "([^/\\]-)%.nse$") or match(filename, "([^/\\]-)$")
/// ```
///
/// Both patterns are anchored at the end and neither may cross a `/` or `\`,
/// so together they mean: take the final path segment, and drop a `.nse`
/// extension if it has one. A filename that is exactly `.nse` reduces to the
/// empty string, which is a name no glob but `*` can match.
pub fn basename_of(filename: &[u8]) -> &[u8] {
    let start = filename
        .iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map_or(0, |i| i.saturating_add(1));
    let segment = &filename[start..];
    match segment.strip_suffix(b".nse") {
        Some(stripped) => stripped,
        None => segment,
    }
}

impl<'a> Entry<'a> {
    /// Build an entry from an index entry's `filename` and categories, applying
    /// [`basename_of`].
    pub fn from_filename(filename: &'a [u8], categories: &'a [&'a [u8]]) -> Self {
        Entry {
            basename: basename_of(filename),
            categories,
        }
    }
}

/// The outcome of matching one rule against one script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// Whether the rule selects this script.
    pub matched: bool,
    /// Whether any path glob in the surviving parse tree matched the script's
    /// basename.
    ///
    /// This drives the C's `script_params.selection` ("name" vs "category") and
    /// its `verbosity` flag. It is set by evaluation, not by the result: a glob
    /// that matches inside a negated or short-circuited branch still sets it.
    pub by_name: bool,
}

/// Split a `--script` argument into rules, the way `NmapOps::chooseScripts`
/// (`NmapOps.cc:628`) does.
///
/// Every comma splits, unconditionally — there is no quoting and no awareness
/// of parentheses, so a rule can never itself contain a comma. An empty
/// argument yields one empty rule, which [`normalize`] then skips.
pub fn split_arg(arg: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = arg;
    loop {
        match rest.iter().position(|&b| b == b',') {
            Some(i) => {
                out.push(&rest[..i]);
                rest = &rest[i.saturating_add(1)..];
            }
            None => {
                out.push(rest);
                return out;
            }
        }
    }
}

/// True for the bytes LPeg's `locale().space` accepts, which is C `isspace` in
/// the default locale: tab, newline, vertical tab, form feed, carriage return
/// and space.
#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

/// Strip surrounding whitespace and peel a leading `+`, as the rule loop in
/// `get_chosen_scripts` (`nse_main.lua:724-732`) does with
/// `match(rule, "^%s*(%+?)%s*(.-)%s*$")`.
///
/// Returns `None` when nothing remains — the C leaves such a rule out of
/// `used_rules` entirely, so it selects nothing and is never reported as
/// unmatched. A bare `"+"` normalises to nothing and is skipped this way.
pub fn normalize(raw: &[u8]) -> Option<Rule<'_>> {
    let mut i = 0;
    while i < raw.len() && is_space(raw[i]) {
        i = i.saturating_add(1);
    }
    let forced = i < raw.len() && raw[i] == b'+';
    if forced {
        i = i.saturating_add(1);
    }
    while i < raw.len() && is_space(raw[i]) {
        i = i.saturating_add(1);
    }
    let mut end = raw.len();
    while end > i && is_space(raw[end.saturating_sub(1)]) {
        end = end.saturating_sub(1);
    }
    if i == end {
        return None;
    }
    Some(Rule {
        text: &raw[i..end],
        forced,
    })
}

/// The `path` character class: `R("\033\039", "\042\126")`.
///
/// Lua's `\ddd` escapes are decimal, so this is 33..=39 and 42..=126 — every
/// graphical ASCII character except `(` and `)`. Note that it *includes* the
/// comma, even though the C's comma-splitting means no rule reaching the
/// grammar can contain one.
#[inline]
fn is_path_byte(b: u8) -> bool {
    (33..=39).contains(&b) || (42..=126).contains(&b)
}

/// The follow-set `K` requires after a keyword: `#(V"space" + S"()," + P(-1))`.
///
/// This is what stops `not` from matching the start of `nota`.
#[inline]
fn is_keyword_follow(next: Option<u8>) -> bool {
    match next {
        None => true,
        Some(b) => is_space(b) || b == b'(' || b == b')' || b == b',',
    }
}

#[inline]
fn eq_ignore_ascii_case(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

/// The parse tree. `Path` carries a range into the rule rather than a slice so
/// the node stays borrow-free.
///
/// Children are `Rc` rather than `Box` so that a memoised sub-parse can be
/// handed to more than one caller without being rebuilt. Only one of those
/// callers can survive into the final tree — two parents cannot both consume
/// the same span — so evaluation still visits every node exactly once, which is
/// what `Selection::by_name` depends on.
#[derive(Debug)]
enum Node {
    Or(Rc<Node>, Rc<Node>),
    And(Rc<Node>, Rc<Node>),
    Not(Rc<Node>),
    Const(bool),
    /// A category the entry has, or the pseudo-category `all`. Always true.
    Category,
    /// A glob, as a `start..end` range of the rule.
    Path(usize, usize),
}

/// One packrat memo entry: the outcome of `expression` at a position.
///
/// `None` records a failure; `Some((node, end))` records a success and where it
/// ended. The enclosing `Option` in the memo table distinguishes both of those
/// from "not tried yet".
type MemoEntry = Option<(Rc<Node>, usize)>;

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    entry: &'a Entry<'a>,
    too_deep: bool,
    /// The packrat memo: for each start position, the result of `expression`
    /// there — `None` for "not tried yet", `Some(None)` for a failure, and
    /// `Some(Some((node, end)))` for a success and where it ended.
    ///
    /// PEG parsing is a function of the position alone, so re-deriving a result
    /// at a position already visited is pure waste — and this grammar does that
    /// enormously. Two separate blowups were measured, both by the fuzzer:
    ///
    /// * On failing input, `disjunct_tail` rewinds and leaves an `or`
    ///   unconsumed, so the enclosing level re-tries the very same suffix and
    ///   each `and`/`or` alternation doubles the work. A 653-byte rule took
    ///   **328 seconds**.
    /// * On input with unclosed parentheses, `value` throws away a *successful*
    ///   inner `expression` when the `)` never arrives, and that inner parse is
    ///   redone every time the position is reached again. A 1,135-byte rule
    ///   drove 12.3 million `expression` calls over 1,135 possible positions.
    ///
    /// Memoising failures alone fixes only the first. Both inputs are kept as
    /// fuzz seeds.
    memo: Vec<Option<MemoEntry>>,
    /// How many times the depth guard has fired.
    ///
    /// A result reached while the guard was firing depends on where we are in
    /// the recursion rather than on the position, so it must not be memoised:
    /// the same position may be reachable at a shallower depth and parse fine
    /// there. Comparing this counter before and after a sub-parse is what
    /// distinguishes the two cases.
    deep_hits: u64,
}

impl<'a> Parser<'a> {
    fn skip_space(&mut self) {
        while self.pos < self.src.len() && is_space(self.src[self.pos]) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// `K(word)`: a caseless literal followed by the keyword follow-set.
    fn keyword(&mut self, word: &[u8]) -> bool {
        let end = self.pos.saturating_add(word.len());
        if end > self.src.len() {
            return false;
        }
        if !self.src[self.pos..end]
            .iter()
            .zip(word)
            .all(|(&a, &b)| eq_ignore_ascii_case(a, b))
        {
            return false;
        }
        if !is_keyword_follow(self.src.get(end).copied()) {
            return false;
        }
        self.pos = end;
        true
    }

    /// ```text
    /// expression <- disjunct / conjunct / value
    /// disjunct   <- (conjunct / value) space* K"or"  space* expression
    /// conjunct   <- value              space* K"and" space* expression
    /// ```
    ///
    /// Written as one function rather than three, because all three
    /// alternatives begin by parsing the same `value` at the same position, and
    /// `value` is deterministic. Transcribing the three rules literally makes
    /// the parse **exponential**: `value` is re-parsed up to four times per
    /// level, so a nested-parenthesis rule costs `4^depth` — measured at 160ms
    /// for eight parentheses before this was folded into one pass. The C's
    /// grammar has exactly that shape and is saved from it only by LPeg's
    /// backtrack stack giving out at fifteen levels; this port deliberately
    /// accepts far deeper rules, so it has to be linear on its own merits.
    ///
    /// The fold preserves PEG's commit semantics exactly. In particular, once
    /// the `conjunct` branch succeeds, a missing `or` does not cause the left
    /// side to be retried as a bare `value`: the enclosing choice falls through
    /// to the `conjunct` alternative of `expression`, which yields the very
    /// same node. That is what makes `a and b or c` mean `a and (b or c)`.
    fn expression(&mut self, depth: usize) -> Option<Rc<Node>> {
        // Once the depth guard has fired the whole parse is over, so unwind
        // instead of trying alternatives. Continuing would not only be wasted
        // work: it is the state in which nothing can be memoised (a result
        // reached under the guard is not a property of the position), so the
        // parse would fall back to its exponential behaviour precisely when the
        // input is most hostile. The fuzzer found both halves of that.
        //
        // The matching check in `value` is the one that actually does the
        // unwinding, since every path into `expression` reaches `value` first —
        // deleting this one changes no measured timing, so no test can tell the
        // difference. It is kept as a cheap second net at the other recursion
        // entry point, not because it is load-bearing today.
        if self.too_deep {
            return None;
        }
        if depth > MAX_NESTING {
            self.too_deep = true;
            self.deep_hits = self.deep_hits.saturating_add(1);
            return None;
        }
        let start = self.pos;
        if let Some(cached) = &self.memo[start] {
            return match cached {
                Some((node, end)) => {
                    let node = Rc::clone(node);
                    self.pos = *end;
                    Some(node)
                }
                None => {
                    self.pos = start;
                    None
                }
            };
        }

        let hits_before = self.deep_hits;
        let result = self.expression_uncached(depth);
        if result.is_none() {
            self.pos = start;
        }
        if self.deep_hits == hits_before {
            self.memo[start] = Some(result.as_ref().map(|n| (Rc::clone(n), self.pos)));
        }
        result
    }

    fn expression_uncached(&mut self, depth: usize) -> Option<Rc<Node>> {
        let lhs = self.value(depth.saturating_add(1))?;
        let after_value = self.pos;

        // conjunct: `value space* K"and" space* expression`
        self.skip_space();
        if self.keyword(b"and") {
            self.skip_space();
            if let Some(rhs) = self.expression(depth.saturating_add(1)) {
                let conj = Rc::new(Node::And(lhs, rhs));
                // disjunct, with that conjunct as its committed left operand.
                let after_conj = self.pos;
                self.skip_space();
                if self.keyword(b"or") {
                    self.skip_space();
                    if let Some(rest) = self.expression(depth.saturating_add(1)) {
                        return Some(Rc::new(Node::Or(conj, rest)));
                    }
                }
                self.pos = after_conj;
                return Some(conj);
            }
            // The conjunct's right operand failed, so `conjunct` fails and the
            // left operand is reused as a bare `value` — exactly what the
            // `(conjunct / value)` choice inside `disjunct` does next.
            return self.disjunct_tail(lhs, after_value, depth);
        }
        self.disjunct_tail(lhs, after_value, depth)
    }

    /// The tail shared by `disjunct` with a bare `value` on the left and by the
    /// bare-`value` alternative of `expression`.
    fn disjunct_tail(
        &mut self,
        lhs: Rc<Node>,
        after_value: usize,
        depth: usize,
    ) -> Option<Rc<Node>> {
        self.pos = after_value;
        self.skip_space();
        if self.keyword(b"or") {
            self.skip_space();
            if let Some(rhs) = self.expression(depth.saturating_add(1)) {
                return Some(Rc::new(Node::Or(lhs, rhs)));
            }
        }
        self.pos = after_value;
        Some(lhs)
    }

    /// ```text
    /// value <- K"not" space* value
    ///        / "(" space* expression space* ")"
    ///        / K"true" / K"false"
    ///        / category
    ///        / path
    /// ```
    fn value(&mut self, depth: usize) -> Option<Rc<Node>> {
        if self.too_deep {
            return None;
        }
        if depth > MAX_NESTING {
            self.too_deep = true;
            self.deep_hits = self.deep_hits.saturating_add(1);
            return None;
        }
        let save = self.pos;

        if self.keyword(b"not") {
            self.skip_space();
            if let Some(inner) = self.value(depth.saturating_add(1)) {
                return Some(Rc::new(Node::Not(inner)));
            }
            if self.too_deep {
                return None;
            }
            self.pos = save;
        }

        if self.src.get(self.pos) == Some(&b'(') {
            self.pos = self.pos.saturating_add(1);
            self.skip_space();
            if let Some(inner) = self.expression(depth.saturating_add(1)) {
                self.skip_space();
                if self.src.get(self.pos) == Some(&b')') {
                    self.pos = self.pos.saturating_add(1);
                    return Some(inner);
                }
            }
            if self.too_deep {
                return None;
            }
            self.pos = save;
        }

        if self.keyword(b"true") {
            return Some(Rc::new(Node::Const(true)));
        }
        self.pos = save;
        if self.keyword(b"false") {
            return Some(Rc::new(Node::Const(false)));
        }
        self.pos = save;

        // `category`: the pseudo-category `all` first, then the entry's own, in
        // index order. Each is a `K`, so a category only matches a whole word.
        if self.keyword(b"all") {
            return Some(Rc::new(Node::Category));
        }
        self.pos = save;
        for cat in self.entry.categories {
            if self.keyword(cat) {
                return Some(Rc::new(Node::Category));
            }
            self.pos = save;
        }

        // `path`: possessive, so it takes every byte the class allows.
        let start = self.pos;
        while self.pos < self.src.len() && is_path_byte(self.src[self.pos]) {
            self.pos = self.pos.saturating_add(1);
        }
        if self.pos > start {
            return Some(Rc::new(Node::Path(start, self.pos)));
        }
        self.pos = save;
        None
    }
}

/// Match a glob against a basename, reproducing the C's `globs` metatable
/// (`nse_main.lua:748-758`) followed by `find(escaped_basename, glob)`.
///
/// The C builds a Lua pattern in three steps: strip one trailing `.nse`, escape
/// `^ $ ( ) % . [ ] + - ?` into literals, then turn `*` into `.*` and anchor the
/// result. `*` is conspicuously absent from the escape set, which is what makes
/// it the *only* metacharacter — `?` is a literal question mark here, not a
/// single-character wildcard. Since the compiled pattern's only construct is
/// `.*`, this is plain anchored glob matching, done directly on bytes.
fn glob_matches(pattern: &[u8], name: &[u8]) -> bool {
    // `gsub(path, "%.nse$", "")` — anchored, so at most one suffix goes.
    let pattern = match pattern.strip_suffix(b".nse") {
        Some(stripped) => stripped,
        None => pattern,
    };

    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while n < name.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p = p.saturating_add(1);
            resume = n;
        } else if p < pattern.len() && pattern[p] == name[n] {
            p = p.saturating_add(1);
            n = n.saturating_add(1);
        } else if let Some(s) = star {
            // The last `*` absorbs one more byte and we retry from there.
            p = s.saturating_add(1);
            resume = resume.saturating_add(1);
            n = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p = p.saturating_add(1);
    }
    p == pattern.len()
}

/// Evaluate the surviving parse tree left to right.
///
/// Neither operator short-circuits. In the C the operands are LPeg captures
/// that have already been reduced to booleans by the time
/// `function (a, b) return a or b end` runs, so both sides always execute — and
/// `match_script`'s side effect on `selected_by_name` always happens. Using
/// Rust's `||` here would silently drop that side effect and change
/// `Selection::by_name` for rules like `http-* or safe`.
fn eval(node: &Node, rule: &[u8], entry: &Entry<'_>, by_name: &mut bool) -> bool {
    match node {
        Node::Or(a, b) => {
            let left = eval(a, rule, entry, by_name);
            let right = eval(b, rule, entry, by_name);
            left || right
        }
        Node::And(a, b) => {
            let left = eval(a, rule, entry, by_name);
            let right = eval(b, rule, entry, by_name);
            left && right
        }
        Node::Not(a) => !eval(a, rule, entry, by_name),
        Node::Const(v) => *v,
        Node::Category => true,
        Node::Path(start, end) => {
            let found = glob_matches(&rule[*start..*end], entry.basename);
            *by_name = *by_name || found;
            found
        }
    }
}

/// Decide whether `rule` selects `entry`.
///
/// `rule` should already have been through [`normalize`]. Returns
/// [`SelectionError::NotAnExpression`] when the rule is not a selection
/// expression at all — which the C treats not as an error but as a signal to
/// try the rule as a filename or directory instead.
///
/// # Examples
///
/// ```
/// use nmap_core::nse::selection::{matches, Entry};
///
/// let entry = Entry {
///     basename: b"http-title",
///     categories: &[b"default", b"safe"],
/// };
///
/// // Selected by category.
/// assert!(matches(b"safe", &entry).unwrap().matched);
///
/// // Selected by name, which the C reports differently.
/// let by_name = matches(b"http-*", &entry).unwrap();
/// assert!(by_name.matched && by_name.by_name);
///
/// // Grouping is right-greedy: this is `default and (safe or zzz)`, not
/// // `(default and safe) or zzz`.
/// assert!(matches(b"default and safe or zzz", &entry).unwrap().matched);
/// ```
pub fn matches(rule: &[u8], entry: &Entry<'_>) -> Result<Selection, SelectionError> {
    if rule.len() > MAX_RULE_LEN {
        return Err(SelectionError::TooLong);
    }
    let mut parser = Parser {
        src: rule,
        pos: 0,
        entry,
        too_deep: false,
        memo: vec![None; rule.len().saturating_add(1)],
        deep_hits: 0,
    };
    parser.skip_space();
    let tree = parser.expression(0);
    let tree = match tree {
        Some(t) => t,
        None => {
            return Err(if parser.too_deep {
                SelectionError::TooDeep
            } else {
                SelectionError::NotAnExpression
            })
        }
    };
    parser.skip_space();
    if parser.pos != rule.len() {
        // `P(-1)`: anything left over means the rule is not an expression.
        return Err(if parser.too_deep {
            SelectionError::TooDeep
        } else {
            SelectionError::NotAnExpression
        });
    }
    let mut by_name = false;
    let matched = eval(&tree, rule, entry, &mut by_name);
    Ok(Selection { matched, by_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("../../../../tests/differential/m6/m62_fixtures.rs");

    /// Build an entry the way the corpus does: from a FILENAME, so the tests
    /// exercise the basename derivation too.
    fn entry<'a>(filename: &'a [u8], categories: &'a [&'a [u8]]) -> Entry<'a> {
        Entry::from_filename(filename, categories)
    }

    /// Render a verdict in the golden file's vocabulary so the fixtures can be
    /// compared as strings.
    fn verdict(rule: &[u8], e: &Entry<'_>) -> String {
        match matches(rule, e) {
            Ok(s) => format!("ACCEPT:{}:{}", s.matched, s.by_name),
            Err(SelectionError::NotAnExpression) => "REJECT".to_owned(),
            Err(SelectionError::TooDeep) => "ERROR:depth".to_owned(),
            Err(SelectionError::TooLong) => "ERROR:length".to_owned(),
        }
    }

    #[test]
    fn every_corpus_case_matches_the_oracle() {
        for (name, rule, filename, cats, expected) in SELECTION_CASES {
            let e = entry(filename, cats);
            assert_eq!(&verdict(rule, &e), expected, "case {name}");
        }
    }

    #[test]
    fn every_normalisation_case_matches_the_oracle() {
        for (name, raw, expected) in NORM_CASES {
            let got = match normalize(raw) {
                Some(r) => format!(
                    "RULE:{}:{}",
                    r.forced,
                    core::str::from_utf8(r.text).unwrap_or("<binary>")
                ),
                // The C leaves `rules[i]` at its ORIGINAL text when the rule
                // normalises away, so the golden records the raw input here.
                None => format!("SKIP:{}", core::str::from_utf8(raw).unwrap_or("<binary>")),
            };
            assert_eq!(&got, expected, "case {name}");
        }
    }

    // ---- the three LPeg behaviours the grammar depends on -------------------

    #[test]
    fn grouping_is_right_greedy_not_conventional_precedence() {
        // a=false, b=false, c=true. Conventional precedence would give
        // `(a and b) or c` = true; this grammar gives `a and (b or c)` = false.
        let e = entry(b"c", &[]);
        assert!(!matches(b"a and b or c", &e).unwrap().matched);
        // Parentheses restore the conventional reading.
        assert!(matches(b"(a and b) or c", &e).unwrap().matched);
    }

    #[test]
    fn a_committed_choice_is_never_reconsidered() {
        // With `x` as a category, `value` commits to the category branch after
        // consuming `x`; the leftover `,y` then fails `P(-1)` and the parse is
        // abandoned rather than retried as the glob `x,y`.
        let with_cat = entry(b"x", &[b"x"]);
        assert_eq!(
            matches(b"x,y", &with_cat),
            Err(SelectionError::NotAnExpression)
        );
        // Without the category there is nothing to commit to, so the same rule
        // parses as a single glob.
        let without = entry(b"x,y", &[]);
        assert!(matches(b"x,y", &without).unwrap().matched);
    }

    #[test]
    fn an_evaluated_glob_sets_by_name_even_when_it_loses() {
        let e = entry(b"http-title", &[b"safe"]);
        // Matched by name, then negated away: false overall, but still "by name".
        let s = matches(b"safe and not http-*", &e).unwrap();
        assert!(!s.matched && s.by_name);
        // A glob that is evaluated but misses leaves the flag alone.
        let s = matches(b"zzz-* or safe", &e).unwrap();
        assert!(s.matched && !s.by_name);
    }

    #[test]
    fn neither_operator_short_circuits() {
        // `safe` is true, so a short-circuiting `or` would skip the glob and
        // leave by_name false.
        let e = entry(b"http-title", &[b"safe"]);
        assert!(matches(b"safe or http-*", &e).unwrap().by_name);
        // `zzz` is false, so a short-circuiting `and` would skip the glob.
        let s = matches(b"zzz and http-*", &e).unwrap();
        assert!(!s.matched && s.by_name);
    }

    // ---- the two asymmetries ------------------------------------------------

    #[test]
    fn keywords_fold_case_but_globs_do_not() {
        let e = entry(b"http-title", &[b"safe"]);
        assert!(matches(b"SAFE", &e).unwrap().matched);
        assert!(matches(b"SaFe", &e).unwrap().matched);
        assert!(matches(b"NOT zzz", &e).unwrap().matched);
        assert!(matches(b"safe AND safe", &e).unwrap().matched);
        // ... but the glob is compared byte for byte.
        assert!(!matches(b"HTTP-TITLE", &e).unwrap().matched);
    }

    #[test]
    fn star_is_the_only_wildcard() {
        let e = entry(b"http-title", &[]);
        assert!(matches(b"http-*", &e).unwrap().matched);
        assert!(matches(b"*-title", &e).unwrap().matched);
        assert!(matches(b"ht*le", &e).unwrap().matched);
        // Everything else is escaped into a literal.
        for pattern in [
            &b"http-titl?"[..],
            b"http.title",
            b"http[-]title",
            b"http-title+",
        ] {
            assert!(
                !matches(pattern, &e).unwrap().matched,
                "{} should be literal",
                core::str::from_utf8(pattern).unwrap()
            );
        }
    }

    #[test]
    fn globs_are_anchored_at_both_ends() {
        let e = entry(b"http-title", &[]);
        assert!(!matches(b"ttp-titl", &e).unwrap().matched);
        assert!(!matches(b"http", &e).unwrap().matched);
        assert!(matches(b"http-title", &e).unwrap().matched);
    }

    #[test]
    fn one_trailing_nse_suffix_is_stripped() {
        // The suffix is dropped from BOTH sides — the rule's glob and the
        // entry's filename — and only once, and only at the end.
        assert!(matches(b"x.nse", &entry(b"x.nse", &[])).unwrap().matched);
        assert!(matches(b"x", &entry(b"x.nse", &[])).unwrap().matched);
        assert!(
            matches(b"x.nse.nse", &entry(b"x.nse.nse", &[]))
                .unwrap()
                .matched
        );
        assert!(
            matches(b"a.nse.b", &entry(b"a.nse.b", &[]))
                .unwrap()
                .matched
        );
        // Stripping can empty the pattern entirely.
        assert!(matches(b".nse", &entry(b".nse", &[])).unwrap().matched);
        assert!(!matches(b".nse", &entry(b"x", &[])).unwrap().matched);
    }

    #[test]
    fn the_basename_is_the_last_segment_without_its_extension() {
        assert_eq!(basename_of(b"http-title.nse"), b"http-title");
        assert_eq!(basename_of(b"scripts/http-title.nse"), b"http-title");
        assert_eq!(basename_of(b"scripts\\http-title.nse"), b"http-title");
        assert_eq!(basename_of(b"readme"), b"readme");
        // Only one extension goes.
        assert_eq!(basename_of(b"x.nse.nse"), b"x.nse");
        // A `.nse` that is not the extension is left alone.
        assert_eq!(basename_of(b"a.nse/b"), b"b");
        // And a filename that is nothing but the extension reduces to nothing.
        assert_eq!(basename_of(b".nse"), b"");
        assert_eq!(basename_of(b""), b"");
    }

    // ---- the keyword follow-set --------------------------------------------

    #[test]
    fn a_keyword_only_matches_a_whole_word() {
        // `not` must not split `nota`.
        assert!(matches(b"nota", &entry(b"nota", &[])).unwrap().matched);
        assert!(matches(b"anda", &entry(b"anda", &[])).unwrap().matched);
        assert!(matches(b"ora", &entry(b"ora", &[])).unwrap().matched);
        assert!(matches(b"allx", &entry(b"allx", &[])).unwrap().matched);
        assert!(matches(b"truex", &entry(b"truex", &[])).unwrap().matched);
        // A category is a keyword too, so a prefix does not match it.
        let e = entry(b"safex", &[b"safe"]);
        assert!(matches(b"safex", &e).unwrap().by_name);
    }

    #[test]
    fn a_bare_not_falls_through_to_a_glob() {
        // `not` with no operand is not a parse error: the `not` branch fails,
        // and `not` is a perfectly good glob.
        let s = matches(b"not", &entry(b"not", &[])).unwrap();
        assert!(s.matched && s.by_name);
        assert!(!matches(b"not", &entry(b"other", &[])).unwrap().matched);
    }

    #[test]
    fn a_paren_closes_a_keyword() {
        // `(` is in the follow-set, so `not(safe)` is `not (safe)`.
        let e = entry(b"http-title", &[b"safe"]);
        assert!(!matches(b"not(safe)", &e).unwrap().matched);
    }

    // ---- structure ----------------------------------------------------------

    #[test]
    fn malformed_rules_are_not_expressions() {
        let e = entry(b"http-title", &[b"safe"]);
        for rule in [
            &b""[..],
            b"   ",
            b"safe(",
            b"safe)",
            b"()",
            b"safe and",
            b"and safe",
            b"a or or b",
        ] {
            assert_eq!(
                matches(rule, &e),
                Err(SelectionError::NotAnExpression),
                "{:?} should not parse",
                core::str::from_utf8(rule)
            );
        }
    }

    #[test]
    fn bytes_outside_the_path_class_end_the_rule() {
        // Space splits, and with no operator between the halves the rule fails.
        assert_eq!(
            matches(b"a\nb", &entry(b"a\nb", &[])),
            Err(SelectionError::NotAnExpression)
        );
        // Non-ASCII and control bytes are outside the class entirely.
        for rule in [&b"\xc3\xa9"[..], b"\x7f", b"a\x00b", b"\t"] {
            assert_eq!(
                matches(rule, &entry(rule, &[])),
                Err(SelectionError::NotAnExpression),
                "{rule:?} should not parse"
            );
        }
    }

    #[test]
    fn the_path_class_edges_are_exact() {
        // 33..=39 and 42..=126 are in; 32, 40, 41, and 127 are out.
        for b in [33u8, 39, 42, 126] {
            let raw = [b];
            assert!(
                matches(&raw, &entry(&raw, &[])).is_ok(),
                "byte {b} should be a path byte"
            );
        }
        for b in [32u8, 40, 41, 127] {
            let raw = [b];
            assert!(
                matches(&raw, &entry(&raw, &[])).is_err(),
                "byte {b} should not be a path byte"
            );
        }
    }

    #[test]
    fn nesting_is_bounded_rather_than_recursing_without_limit() {
        let e = entry(b"http-title", &[b"safe"]);
        let deep = |n: usize| {
            let mut v = vec![b'('; n];
            v.extend_from_slice(b"safe");
            v.extend(core::iter::repeat_n(b')', n));
            v
        };
        // Far past the C's 15-parenthesis ceiling, still fine here.
        assert!(matches(&deep(64), &e).unwrap().matched);
        // And bounded rather than overflowing the stack.
        assert_eq!(matches(&deep(4096), &e), Err(SelectionError::TooDeep));
    }

    #[test]
    fn operator_chains_are_bounded_too() {
        let e = entry(b"http-title", &[b"safe"]);
        let mut chain = Vec::new();
        for i in 0..4096 {
            if i > 0 {
                chain.extend_from_slice(b" or ");
            }
            chain.extend_from_slice(b"zz");
        }
        assert_eq!(matches(&chain, &e), Err(SelectionError::TooDeep));
    }

    /// Parsing stays fast on the shapes that made it exponential twice.
    ///
    /// These are the exact inputs the fuzzer produced, `include_bytes!`d from
    /// the committed seed corpus rather than reconstructed — synthetic
    /// look-alikes turned out not to reproduce the blowup, so a mutation that
    /// disabled the memo survived a test built on them. The real inputs are
    /// what the guarantee rests on, so they are what the test uses.
    ///
    /// Measured on this machine: 10-40µs each with the memo, versus 328s and
    /// 408ms without it. The threshold below therefore has four orders of
    /// magnitude of headroom against a slow CI runner while still failing
    /// loudly if the memo or the depth abort is removed.
    ///
    /// Skipped under Miri, where a 100x interpretation penalty makes wall-clock
    /// assertions meaningless.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn pathological_rules_stay_fast() {
        /// Alternating `and`/`or` with a suffix that cannot parse: each
        /// alternation used to double the work. 653 bytes, 328 seconds.
        const RETRY_BLOWUP: &[u8] =
            include_bytes!("../../../../fuzz/seeds/nse_selection/seed20-fuzzer-found-exponential");
        /// Unclosed parentheses: every level threw away a *successful* inner
        /// parse when its `)` never arrived. 1,135 bytes, 12.3 million
        /// `expression` calls over 1,135 possible positions.
        const DISCARD_BLOWUP: &[u8] = include_bytes!(
            "../../../../fuzz/seeds/nse_selection/seed21-fuzzer-found-unclosed-parens"
        );
        /// The same shape, deeper: this one also needs the depth overrun to
        /// abort the parse rather than let it keep trying alternatives.
        const DEEP_BLOWUP: &[u8] = include_bytes!(
            "../../../../fuzz/seeds/nse_selection/seed22-fuzzer-found-deep-alternation"
        );

        let e = entry(b"http-title.nse", &[b"safe"]);
        for raw in [RETRY_BLOWUP, DISCARD_BLOWUP, DEEP_BLOWUP] {
            // The seeds are NUL-separated fields; the rule is the first.
            let rule = raw.split(|&b| b == 0).next().unwrap_or(raw);
            let start = std::time::Instant::now();
            let _ = matches(rule, &e);
            let elapsed = start.elapsed();
            assert!(
                elapsed < core::time::Duration::from_millis(50),
                "parsing {} bytes took {elapsed:?}; the packrat memo or the \
                 depth abort is not doing its job",
                rule.len()
            );
        }
    }

    #[test]
    fn an_overlong_rule_is_refused_before_parsing() {
        let rule = vec![b'a'; MAX_RULE_LEN + 1];
        assert_eq!(
            matches(&rule, &entry(b"a", &[])),
            Err(SelectionError::TooLong)
        );
    }

    // ---- argument splitting and normalisation --------------------------------

    #[test]
    fn every_comma_splits_unconditionally() {
        assert_eq!(split_arg(b"a,b,c"), vec![&b"a"[..], b"b", b"c"]);
        // No quoting, no paren awareness — a rule can never contain a comma.
        assert_eq!(split_arg(b"(a,b)"), vec![&b"(a"[..], b"b)"]);
        assert_eq!(split_arg(b""), vec![&b""[..]]);
        assert_eq!(split_arg(b","), vec![&b""[..], b""]);
        assert_eq!(split_arg(b"a,"), vec![&b"a"[..], b""]);
    }

    #[test]
    fn normalisation_peels_one_plus_and_trims() {
        assert_eq!(
            normalize(b"safe"),
            Some(Rule {
                text: b"safe",
                forced: false
            })
        );
        assert_eq!(
            normalize(b"+safe"),
            Some(Rule {
                text: b"safe",
                forced: true
            })
        );
        assert_eq!(
            normalize(b"  +  safe  "),
            Some(Rule {
                text: b"safe",
                forced: true
            })
        );
        // Only one `+` is a prefix; the second is part of the rule.
        assert_eq!(
            normalize(b"++safe"),
            Some(Rule {
                text: b"+safe",
                forced: true
            })
        );
        // Inner whitespace survives.
        assert_eq!(
            normalize(b"  a and b  "),
            Some(Rule {
                text: b"a and b",
                forced: false
            })
        );
        // Nothing left means the C never records the rule at all.
        assert_eq!(normalize(b""), None);
        assert_eq!(normalize(b"   "), None);
        assert_eq!(normalize(b"+"), None);
        assert_eq!(normalize(b"  +  "), None);
    }
}
