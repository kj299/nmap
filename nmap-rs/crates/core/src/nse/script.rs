//! `script.db` and `.nse` metadata — read, never executed (M6.1).
//!
//! # What the C does, and why this does not do it
//!
//! nmap reads both of these inputs by *running them as Lua*.
//!
//! `script.db` is handed to `loadfile(path, "t", script_database)`
//! (`nse_main.lua:1310`) — an arbitrary Lua chunk, executed, whose `Entry`
//! calls happen to append rows. Its environment is narrow (`Entry` and
//! `chunk`, nothing else), so it is not the open door it first looks like, but
//! it is still a program: loops, conditionals and non-termination are all
//! inside the grammar the C accepts.
//!
//! `.nse` metadata is worse. `Script.new` (`nse_main.lua:601`) wraps the script
//! in `return function (_ENV) return function (...)`, loads it, and *resumes a
//! coroutine over the whole top level* with `setmetatable(env, {__index = _G})`
//! — the complete standard library, `io` and `os` included. Reading a script's
//! `categories` therefore executes that script. And `--script-updatedb` does
//! this to **every** `.nse` in the scripts directory; nmap triggers that update
//! by itself whenever `script.db` is missing (`nse_main.lua:1305-1307`). A file
//! dropped into the scripts directory is executed, usually as root.
//!
//! This module reads both formats instead. Nothing here evaluates, so the
//! metadata of a hostile script is as inert as the metadata of a friendly one.
//! The two behaviour changes that follow are ledgered in `DIVERGENCES.md` as
//! `nse-scriptdb-not-evaluated` and `nse-metadata-not-executed`.
//!
//! # What is accepted
//!
//! The **literal subset of Lua**: string literals in every form the language
//! has (both quotes, every escape, long brackets), integer literals, `nil`,
//! `true`, `false`, and table constructors over those. No operators, no calls,
//! no variables, no control flow. That subset is a data format — it is what
//! `--script-updatedb` emits — and it is total: every input either parses to a
//! value or is rejected with a reason.
//!
//! Measured against the shipped corpus, the subset is not a compromise:
//! all 611 `scripts/*.nse` declare `categories` literally, and re-deriving
//! `script.db` from them with this parser reproduces the committed file byte for
//! byte. `tests/nse_corpus.rs` is that check.
//!
//! # Determinacy is per field, because one shipped script needs it to be
//!
//! `scripts/clock-skew.nse` builds its `description` by concatenating its own
//! `dependencies` list, so its description is not a literal and cannot be read
//! out statically. Fields that gate execution — `categories`, `dependencies`,
//! and which rule functions exist — must be literal or the script is refused.
//! Presentational fields carry [`Field::Indeterminate`] instead, which costs
//! nothing: they feed `--script-help`, not selection.

/// Largest `script.db` accepted, in bytes. The shipped index is 52 KiB for 611
/// scripts; this is three orders of magnitude of headroom and still bounds the
/// work a hostile file can ask for.
pub const MAX_DB_LEN: usize = 4 * 1024 * 1024;

/// Largest `.nse` source accepted, in bytes. The largest shipped script is
/// well under 200 KiB.
pub const MAX_SCRIPT_LEN: usize = 1024 * 1024;

/// Largest number of records in a `script.db`.
pub const MAX_ENTRIES: usize = 65_536;

/// Largest number of categories on one record. nmap defines 15.
pub const MAX_CATEGORIES: usize = 256;

/// Largest number of dependencies on one script.
pub const MAX_DEPENDENCIES: usize = 256;

/// Largest decoded string literal, in bytes.
pub const MAX_STRING_LEN: usize = 64 * 1024;

/// Deepest table nesting accepted. The formats need one level; anything deeper
/// is refused rather than recursed into, so the parser cannot be driven to
/// exhaust the stack.
pub const MAX_NESTING: usize = 4;

/// Why an input was refused.
///
/// Every variant names something the caller can act on. There is no catch-all
/// "parse error": an operator who is told `UnterminatedString` can find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input exceeds [`MAX_DB_LEN`] or [`MAX_SCRIPT_LEN`].
    TooLarge,
    /// A string literal ran to end of input.
    UnterminatedString,
    /// A long-bracket comment ran to end of input.
    UnterminatedComment,
    /// A `\` escape that Lua does not define.
    BadEscape,
    /// A `\ddd`, `\xXX` or `\u{...}` escape outside its legal range.
    EscapeOutOfRange,
    /// A decoded string exceeds [`MAX_STRING_LEN`].
    StringTooLong,
    /// A byte that cannot begin any token.
    BadByte,
    /// The input ended in the middle of a construct.
    UnexpectedEof,
    /// A token appeared where the grammar does not allow it.
    Unexpected,
    /// Table nesting exceeded [`MAX_NESTING`].
    TooDeep,
    /// More than [`MAX_ENTRIES`] records.
    TooManyEntries,
    /// More than [`MAX_CATEGORIES`] categories on one record.
    TooManyCategories,
    /// More than [`MAX_DEPENDENCIES`] dependencies.
    TooManyDependencies,
    /// A statement that is not an `Entry` record. **Divergence:** the C accepts
    /// any Lua here and simply produces no entry for it.
    NotAnEntry,
    /// A record with no `filename`, or one that is not a string.
    BadFilename,
    /// A record with no `categories`, or one that is not a table.
    BadCategories,
    /// A category that is not a string.
    BadCategory,
    /// A dependency that is not a string.
    BadDependency,
    /// A required field (`action`) is absent.
    MissingField,
    /// A required field is present with a literal of the wrong type.
    BadFieldType,
    /// No rule function (`prerule`/`hostrule`/`portrule`/`postrule`) is defined.
    MissingRule,
    /// A rule is present with a literal that is not a function.
    BadRuleType,
    /// `categories` or `dependencies` could not be read as a literal, or is
    /// passed to a statement-level call that may mutate it.
    Indeterminate,
}

// ---------------------------------------------------------------------------
// Lexer over the literal subset of Lua
// ---------------------------------------------------------------------------

/// One token of the literal subset.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An identifier or keyword.
    Name(Vec<u8>),
    /// A decoded string literal.
    Str(Vec<u8>),
    /// A numeric literal, kept only as its source bytes: the formats use
    /// numbers solely as table keys, so no value is ever needed.
    Num(Vec<u8>),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Assign,
    Comma,
    Semi,
    /// Any other operator or punctuation. The literal subset has no use for
    /// these, but the `.nse` scanner must still step over them to find the next
    /// top-level statement.
    Other,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos.checked_add(off)?).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Skip whitespace and both comment forms. Returns an error only for an
    /// unterminated long comment.
    fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            match self.peek_at(0) {
                Some(b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c) => self.bump(),
                Some(b'-') if self.peek_at(1) == Some(b'-') => {
                    self.pos = self.pos.saturating_add(2);
                    if self.peek_at(0) == Some(b'[') {
                        if let Some(level) = self.long_bracket_level() {
                            self.read_long_bracket(level)?;
                            continue;
                        }
                    }
                    while !matches!(self.peek_at(0), None | Some(b'\n')) {
                        self.bump();
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// At a `[`, return `Some(level)` if this opens a long bracket `[==[`.
    fn long_bracket_level(&self) -> Option<usize> {
        if self.peek_at(0) != Some(b'[') {
            return None;
        }
        let mut level = 0usize;
        while self.peek_at(level.checked_add(1)?) == Some(b'=') {
            level = level.checked_add(1)?;
        }
        if self.peek_at(level.checked_add(1)?) == Some(b'[') {
            Some(level)
        } else {
            None
        }
    }

    /// Consume a long bracket whose opener is at the cursor, returning its body.
    fn read_long_bracket(&mut self, level: usize) -> Result<Vec<u8>, ParseError> {
        // Step over `[` + level `=` + `[`.
        self.pos = self
            .pos
            .checked_add(level.checked_add(2).ok_or(ParseError::TooLarge)?)
            .ok_or(ParseError::TooLarge)?;
        // Lua drops one immediately-following newline.
        if self.peek_at(0) == Some(b'\r') && self.peek_at(1) == Some(b'\n') {
            self.pos = self.pos.saturating_add(2);
        } else if matches!(self.peek_at(0), Some(b'\n' | b'\r')) {
            self.bump();
        }
        let start = self.pos;
        loop {
            match self.peek_at(0) {
                None => return Err(ParseError::UnterminatedComment),
                Some(b']') => {
                    let mut eqs = 0usize;
                    while self.peek_at(eqs.checked_add(1).ok_or(ParseError::TooLarge)?)
                        == Some(b'=')
                    {
                        eqs = eqs.checked_add(1).ok_or(ParseError::TooLarge)?;
                    }
                    if eqs == level
                        && self.peek_at(eqs.checked_add(1).ok_or(ParseError::TooLarge)?)
                            == Some(b']')
                    {
                        let body = self.src.get(start..self.pos).unwrap_or_default().to_vec();
                        self.pos = self
                            .pos
                            .checked_add(eqs.checked_add(2).ok_or(ParseError::TooLarge)?)
                            .ok_or(ParseError::TooLarge)?;
                        if body.len() > MAX_STRING_LEN {
                            return Err(ParseError::StringTooLong);
                        }
                        return Ok(body);
                    }
                    self.bump();
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// Decode a quoted string literal whose opening quote is at the cursor.
    fn read_quoted(&mut self, quote: u8) -> Result<Vec<u8>, ParseError> {
        self.bump();
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.peek_at(0).ok_or(ParseError::UnterminatedString)?;
            if out.len() >= MAX_STRING_LEN {
                return Err(ParseError::StringTooLong);
            }
            match b {
                b if b == quote => {
                    self.bump();
                    return Ok(out);
                }
                b'\n' => return Err(ParseError::UnterminatedString),
                b'\\' => {
                    self.bump();
                    self.read_escape(&mut out)?;
                }
                _ => {
                    out.push(b);
                    self.bump();
                }
            }
        }
    }

    /// Decode one escape sequence, the backslash already consumed.
    fn read_escape(&mut self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        let b = self.peek_at(0).ok_or(ParseError::UnterminatedString)?;
        match b {
            b'a' => {
                out.push(0x07);
                self.bump();
            }
            b'b' => {
                out.push(0x08);
                self.bump();
            }
            b'f' => {
                out.push(0x0c);
                self.bump();
            }
            b'n' => {
                out.push(b'\n');
                self.bump();
            }
            b'r' => {
                out.push(b'\r');
                self.bump();
            }
            b't' => {
                out.push(b'\t');
                self.bump();
            }
            b'v' => {
                out.push(0x0b);
                self.bump();
            }
            b'\\' | b'"' | b'\'' => {
                out.push(b);
                self.bump();
            }
            // A backslash before a real newline embeds a newline.
            b'\n' | b'\r' => {
                let first = b;
                self.bump();
                if matches!(self.peek_at(0), Some(n) if (n == b'\n' || n == b'\r') && n != first) {
                    self.bump();
                }
                out.push(b'\n');
            }
            // `\z` swallows the following whitespace run.
            b'z' => {
                self.bump();
                while matches!(
                    self.peek_at(0),
                    Some(b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
                ) {
                    self.bump();
                }
            }
            b'x' => {
                self.bump();
                let hi = hex_val(self.peek_at(0).ok_or(ParseError::UnterminatedString)?)
                    .ok_or(ParseError::BadEscape)?;
                self.bump();
                let lo = hex_val(self.peek_at(0).ok_or(ParseError::UnterminatedString)?)
                    .ok_or(ParseError::BadEscape)?;
                self.bump();
                out.push(hi.wrapping_mul(16).wrapping_add(lo));
            }
            b'u' => {
                self.bump();
                if self.peek_at(0) != Some(b'{') {
                    return Err(ParseError::BadEscape);
                }
                self.bump();
                let mut cp: u32 = 0;
                let mut digits = 0usize;
                while let Some(d) = self.peek_at(0).and_then(hex_val) {
                    cp = cp
                        .checked_mul(16)
                        .and_then(|v| v.checked_add(u32::from(d)))
                        .ok_or(ParseError::EscapeOutOfRange)?;
                    digits = digits.saturating_add(1);
                    if cp > 0x7FFF_FFFF {
                        return Err(ParseError::EscapeOutOfRange);
                    }
                    self.bump();
                }
                if digits == 0 || self.peek_at(0) != Some(b'}') {
                    return Err(ParseError::BadEscape);
                }
                self.bump();
                push_utf8(out, cp)?;
            }
            b'0'..=b'9' => {
                let mut val: u32 = 0;
                let mut digits = 0usize;
                while digits < 3 {
                    match self.peek_at(0) {
                        Some(d @ b'0'..=b'9') => {
                            val = val
                                .saturating_mul(10)
                                .saturating_add(u32::from(d.wrapping_sub(b'0')));
                            digits = digits.saturating_add(1);
                            self.bump();
                        }
                        _ => break,
                    }
                }
                let byte = u8::try_from(val).map_err(|_| ParseError::EscapeOutOfRange)?;
                out.push(byte);
            }
            _ => return Err(ParseError::BadEscape),
        }
        Ok(())
    }

    /// Produce the next token, or `None` at end of input.
    fn next_token(&mut self) -> Result<Option<Tok>, ParseError> {
        self.skip_trivia()?;
        let Some(b) = self.peek_at(0) else {
            return Ok(None);
        };
        let tok = match b {
            b'{' => {
                self.bump();
                Tok::LBrace
            }
            b'}' => {
                self.bump();
                Tok::RBrace
            }
            b'(' => {
                self.bump();
                Tok::LParen
            }
            b')' => {
                self.bump();
                Tok::RParen
            }
            b',' => {
                self.bump();
                Tok::Comma
            }
            b';' => {
                self.bump();
                Tok::Semi
            }
            b'=' if self.peek_at(1) != Some(b'=') => {
                self.bump();
                Tok::Assign
            }
            b'[' => {
                if let Some(level) = self.long_bracket_level() {
                    Tok::Str(self.read_long_bracket(level)?)
                } else {
                    self.bump();
                    Tok::LBracket
                }
            }
            b']' => {
                self.bump();
                Tok::RBracket
            }
            b'"' | b'\'' => Tok::Str(self.read_quoted(b)?),
            b'0'..=b'9' => {
                let start = self.pos;
                while matches!(self.peek_at(0),
                    Some(c) if c.is_ascii_alphanumeric() || c == b'.' )
                {
                    self.bump();
                }
                Tok::Num(self.src.get(start..self.pos).unwrap_or_default().to_vec())
            }
            b'_' | b'A'..=b'Z' | b'a'..=b'z' => {
                let start = self.pos;
                while matches!(self.peek_at(0), Some(c) if c == b'_' || c.is_ascii_alphanumeric()) {
                    self.bump();
                }
                Tok::Name(self.src.get(start..self.pos).unwrap_or_default().to_vec())
            }
            b if b.is_ascii_graphic() => {
                self.bump();
                Tok::Other
            }
            _ => return Err(ParseError::BadByte),
        };
        Ok(Some(tok))
    }
}

/// The value of a numeric literal when it is a plain non-negative integer.
/// Floats, hex and exponent forms cannot be the next array index, so they are
/// reported as `None` rather than approximated.
fn plain_integer(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: u64 = 0;
    for d in digits {
        n = n
            .checked_mul(10)?
            .checked_add(u64::from(d.wrapping_sub(b'0')))?;
    }
    Some(n)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Append `cp` as Lua encodes it in `\u{...}`: UTF-8, extended to 6 bytes for
/// the code points above the Unicode range that Lua still accepts.
fn push_utf8(out: &mut Vec<u8>, cp: u32) -> Result<(), ParseError> {
    let mut buf = [0u8; 6];
    let n = match cp {
        0x0000_0000..=0x0000_007F => {
            buf[0] = u8::try_from(cp).map_err(|_| ParseError::EscapeOutOfRange)?;
            1
        }
        0x0000_0080..=0x0000_07FF => {
            buf[0] = 0xC0 | u8::try_from(cp >> 6).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[1] = 0x80 | u8::try_from(cp & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            2
        }
        0x0000_0800..=0x0000_FFFF => {
            buf[0] = 0xE0 | u8::try_from(cp >> 12).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[1] =
                0x80 | u8::try_from((cp >> 6) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[2] = 0x80 | u8::try_from(cp & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            3
        }
        0x0001_0000..=0x001F_FFFF => {
            buf[0] = 0xF0 | u8::try_from(cp >> 18).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[1] =
                0x80 | u8::try_from((cp >> 12) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[2] =
                0x80 | u8::try_from((cp >> 6) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[3] = 0x80 | u8::try_from(cp & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            4
        }
        0x0020_0000..=0x03FF_FFFF => {
            buf[0] = 0xF8 | u8::try_from(cp >> 24).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[1] =
                0x80 | u8::try_from((cp >> 18) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[2] =
                0x80 | u8::try_from((cp >> 12) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[3] =
                0x80 | u8::try_from((cp >> 6) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[4] = 0x80 | u8::try_from(cp & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            5
        }
        _ => {
            buf[0] = 0xFC | u8::try_from(cp >> 30).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[1] =
                0x80 | u8::try_from((cp >> 24) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[2] =
                0x80 | u8::try_from((cp >> 18) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[3] =
                0x80 | u8::try_from((cp >> 12) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[4] =
                0x80 | u8::try_from((cp >> 6) & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            buf[5] = 0x80 | u8::try_from(cp & 0x3F).map_err(|_| ParseError::EscapeOutOfRange)?;
            6
        }
    };
    if out.len().saturating_add(n) > MAX_STRING_LEN {
        return Err(ParseError::StringTooLong);
    }
    out.extend_from_slice(buf.get(..n).unwrap_or_default());
    Ok(())
}

// ---------------------------------------------------------------------------
// Literal values
// ---------------------------------------------------------------------------

/// A value of the literal subset. Anything richer than this is not data, and is
/// where the C would start executing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Nil,
    Bool(bool),
    /// A numeric literal. `Some(n)` for a plain non-negative integer — the only
    /// shape that can be an array index — and `None` for anything else.
    Num(Option<u64>),
    Str(Vec<u8>),
    /// A table's array part, in `ipairs` order: the contiguous run from index 1.
    /// Keyed and out-of-order entries are held only insofar as they extend that
    /// run, because `ipairs` is all either format ever looks at.
    Table(Vec<Value>),
    /// A `function ... end` literal. Its body is skipped, never analysed.
    Function,
}

impl Value {
    fn as_str(&self) -> Option<&[u8]> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// A parser over a token stream, used for both formats.
struct Parser<'a> {
    lex: Lexer<'a>,
    /// One token of lookahead.
    ahead: Option<Tok>,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Result<Self, ParseError> {
        let mut lex = Lexer::new(src);
        let ahead = lex.next_token()?;
        Ok(Self { lex, ahead })
    }

    fn peek(&self) -> Option<&Tok> {
        self.ahead.as_ref()
    }

    fn next(&mut self) -> Result<Option<Tok>, ParseError> {
        let cur = self.ahead.take();
        self.ahead = self.lex.next_token()?;
        Ok(cur)
    }

    fn eat(&mut self, want: &Tok) -> Result<bool, ParseError> {
        if self.peek() == Some(want) {
            self.next()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Parse one literal value. Returns `Ok(None)` when the next token cannot
    /// begin a literal — the caller decides whether that is fatal.
    fn value(&mut self, depth: usize) -> Result<Option<Value>, ParseError> {
        match self.peek() {
            Some(Tok::Str(_)) => {
                let Some(Tok::Str(s)) = self.next()? else {
                    return Err(ParseError::Unexpected);
                };
                Ok(Some(Value::Str(s)))
            }
            Some(Tok::Num(_)) => {
                let Some(Tok::Num(digits)) = self.next()? else {
                    return Err(ParseError::Unexpected);
                };
                Ok(Some(Value::Num(plain_integer(&digits))))
            }
            Some(Tok::Name(n)) => {
                let v = match n.as_slice() {
                    b"nil" => Value::Nil,
                    b"true" => Value::Bool(true),
                    b"false" => Value::Bool(false),
                    b"function" => {
                        self.next()?;
                        self.skip_function_body()?;
                        return Ok(Some(Value::Function));
                    }
                    _ => return Ok(None),
                };
                self.next()?;
                Ok(Some(v))
            }
            Some(Tok::LBrace) => Ok(Some(self.table(depth)?)),
            _ => Ok(None),
        }
    }

    /// Parse a table constructor. Only the `ipairs` view is retained: a value
    /// with no key extends the array part, `[n] = v` is honoured when `n` is the
    /// next index, and named fields are collected by the caller via
    /// [`Self::table_fields`].
    fn table(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth >= MAX_NESTING {
            return Err(ParseError::TooDeep);
        }
        let inner = depth.saturating_add(1);
        if !self.eat(&Tok::LBrace)? {
            return Err(ParseError::Unexpected);
        }
        let mut array: Vec<Value> = Vec::new();
        loop {
            if self.eat(&Tok::RBrace)? {
                return Ok(Value::Table(array));
            }
            if self.peek().is_none() {
                return Err(ParseError::UnexpectedEof);
            }
            // `[key] = value`
            if self.eat(&Tok::LBracket)? {
                let key = self.value(inner)?.ok_or(ParseError::Unexpected)?;
                if !self.eat(&Tok::RBracket)? || !self.eat(&Tok::Assign)? {
                    return Err(ParseError::Unexpected);
                }
                let val = self.value(inner)?.ok_or(ParseError::Unexpected)?;
                // A numeric key extends the array part only when it is the very
                // next index. `{[2] = "x"}` therefore leaves `ipairs` empty,
                // exactly as it does in Lua, and the entry is dropped.
                if let Value::Num(Some(n)) = key {
                    if u64::try_from(array.len())
                        .ok()
                        .and_then(|len| len.checked_add(1))
                        == Some(n)
                    {
                        if array.len() >= MAX_CATEGORIES {
                            return Err(ParseError::TooManyCategories);
                        }
                        array.push(val);
                    }
                }
            } else if matches!(self.peek(), Some(Tok::Name(_))) && self.name_is_field_key() {
                // `name = value`: a named field, not part of `ipairs`.
                self.next()?;
                self.next()?;
                self.value(inner)?.ok_or(ParseError::Unexpected)?;
            } else {
                let val = self.value(inner)?.ok_or(ParseError::Unexpected)?;
                if array.len() >= MAX_CATEGORIES {
                    return Err(ParseError::TooManyCategories);
                }
                array.push(val);
            }
            if !self.eat(&Tok::Comma)? && !self.eat(&Tok::Semi)? {
                if self.eat(&Tok::RBrace)? {
                    return Ok(Value::Table(array));
                }
                return Err(ParseError::Unexpected);
            }
        }
    }

    /// True when the lookahead `Name` is followed by `=` — a named field rather
    /// than a bare value. Requires two tokens of lookahead, which the lexer does
    /// not buffer, so this is answered by cloning the cursor.
    fn name_is_field_key(&self) -> bool {
        let mut probe = Lexer {
            src: self.lex.src,
            pos: self.lex.pos,
        };
        matches!(probe.next_token(), Ok(Some(Tok::Assign)))
    }

    /// True when the next token can only continue an expression — a binary or
    /// unary operator, a call, or an index. Used to tell a complete literal from
    /// the first term of a larger expression.
    fn at_expression_continuation(&self) -> bool {
        match self.peek() {
            Some(Tok::Other | Tok::LParen | Tok::LBracket) => true,
            Some(Tok::Name(n)) => matches!(n.as_slice(), b"and" | b"or"),
            // A string or table directly after a value is Lua's call sugar,
            // `f"x"` and `f{…}`.
            Some(Tok::Str(_) | Tok::LBrace) => true,
            _ => false,
        }
    }

    /// True when the lookahead sits inside a Lua multiple assignment — a
    /// comma-separated name list terminated by `=`. `scripts/ms-sql-info.nse`
    /// and seven siblings declare their entry points as
    /// `action, portrule, hostrule = mssql.Helper.InitScript(...)`, so a parser
    /// that only understands `name =` cannot see their `action` at all.
    fn in_assignment_name_list(&self) -> bool {
        let mut probe = Lexer {
            src: self.lex.src,
            pos: self.lex.pos,
        };
        // The cursor is just past a `Name`; the caller has established that the
        // token after it is a comma.
        let mut budget = 64usize;
        loop {
            budget = match budget.checked_sub(1) {
                Some(b) => b,
                None => return false,
            };
            match probe.next_token() {
                Ok(Some(Tok::Comma | Tok::Name(_))) => {}
                Ok(Some(Tok::Assign)) => return true,
                _ => return false,
            }
        }
    }

    /// Consume `function`'s parameter list and body, balancing `do`/`if`/
    /// `while`/`for`/`function` against `end`. Nothing inside is interpreted.
    fn skip_function_body(&mut self) -> Result<(), ParseError> {
        let mut depth: usize = 1;
        loop {
            let Some(tok) = self.next()? else {
                return Err(ParseError::UnexpectedEof);
            };
            if let Tok::Name(n) = tok {
                match n.as_slice() {
                    b"function" | b"do" | b"if" => depth = depth.saturating_add(1),
                    b"end" => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// script.db
// ---------------------------------------------------------------------------

/// One record of the script index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbEntry {
    filename: Vec<u8>,
    categories: Vec<Vec<u8>>,
}

impl DbEntry {
    /// The script's basename, as the index records it. Raw bytes: nmap writes
    /// whatever the filesystem gave it, which need not be UTF-8.
    #[must_use]
    pub fn filename(&self) -> &[u8] {
        &self.filename
    }

    /// The categories the script declares, in the order the index lists them.
    #[must_use]
    pub fn categories(&self) -> &[Vec<u8>] {
        &self.categories
    }
}

/// A parsed script index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptDb {
    entries: Vec<DbEntry>,
}

impl ScriptDb {
    /// The records, in file order.
    #[must_use]
    pub fn entries(&self) -> &[DbEntry] {
        &self.entries
    }
}

/// Read a `script.db`.
///
/// Accepts a sequence of `Entry { filename = <string>, categories = { <string>… } }`
/// records and nothing else. Unknown fields inside a record are ignored, exactly
/// as the C ignores them; a statement that is not an `Entry` record is refused,
/// where the C would run it.
///
/// # Errors
///
/// Returns [`ParseError`] naming what was wrong. Never panics, for any input.
pub fn parse_script_db(bytes: &[u8]) -> Result<ScriptDb, ParseError> {
    if bytes.len() > MAX_DB_LEN {
        return Err(ParseError::TooLarge);
    }
    let mut p = Parser::new(bytes)?;
    let mut entries: Vec<DbEntry> = Vec::new();
    loop {
        match p.next()? {
            None => return Ok(ScriptDb { entries }),
            Some(Tok::Semi) => {}
            Some(Tok::Name(n)) if n.as_slice() == b"Entry" => {
                if entries.len() >= MAX_ENTRIES {
                    return Err(ParseError::TooManyEntries);
                }
                entries.push(parse_entry(&mut p)?);
            }
            Some(_) => return Err(ParseError::NotAnEntry),
        }
    }
}

/// Parse the table argument of one `Entry` call.
fn parse_entry(p: &mut Parser<'_>) -> Result<DbEntry, ParseError> {
    // `Entry { … }` and `Entry({ … })` are the same call in Lua.
    let parenthesised = p.eat(&Tok::LParen)?;
    if p.peek() != Some(&Tok::LBrace) {
        return Err(ParseError::NotAnEntry);
    }
    let fields = table_fields(p, 0)?;
    if parenthesised && !p.eat(&Tok::RParen)? {
        return Err(ParseError::Unexpected);
    }

    let filename = fields
        .iter()
        .rev()
        .find(|(k, _)| k.as_slice() == b"filename")
        .map(|(_, v)| v)
        .and_then(Value::as_str)
        .ok_or(ParseError::BadFilename)?
        .to_vec();

    let cats = fields
        .iter()
        .rev()
        .find(|(k, _)| k.as_slice() == b"categories")
        .map(|(_, v)| v)
        .ok_or(ParseError::BadCategories)?;
    let Value::Table(items) = cats else {
        return Err(ParseError::BadCategories);
    };
    let mut categories: Vec<Vec<u8>> = Vec::new();
    for item in items {
        categories.push(item.as_str().ok_or(ParseError::BadCategory)?.to_vec());
    }
    Ok(DbEntry {
        filename,
        categories,
    })
}

/// Parse a table constructor, returning its **named** fields in source order
/// (later duplicates included, so the caller can take the last, as Lua does).
fn table_fields(p: &mut Parser<'_>, depth: usize) -> Result<Vec<(Vec<u8>, Value)>, ParseError> {
    if depth >= MAX_NESTING {
        return Err(ParseError::TooDeep);
    }
    let inner = depth.saturating_add(1);
    if !p.eat(&Tok::LBrace)? {
        return Err(ParseError::Unexpected);
    }
    let mut out: Vec<(Vec<u8>, Value)> = Vec::new();
    loop {
        if p.eat(&Tok::RBrace)? {
            return Ok(out);
        }
        if p.peek().is_none() {
            return Err(ParseError::UnexpectedEof);
        }
        if p.eat(&Tok::LBracket)? {
            let key = p.value(inner)?.ok_or(ParseError::Unexpected)?;
            if !p.eat(&Tok::RBracket)? || !p.eat(&Tok::Assign)? {
                return Err(ParseError::Unexpected);
            }
            let val = p.value(inner)?.ok_or(ParseError::Unexpected)?;
            if let Value::Str(k) = key {
                out.push((k, val));
            }
        } else if matches!(p.peek(), Some(Tok::Name(_))) && p.name_is_field_key() {
            let Some(Tok::Name(k)) = p.next()? else {
                return Err(ParseError::Unexpected);
            };
            p.next()?; // `=`
            let val = p.value(inner)?.ok_or(ParseError::Unexpected)?;
            if out.len() >= MAX_CATEGORIES {
                return Err(ParseError::TooManyCategories);
            }
            out.push((k, val));
        } else {
            // A positional value. The C ignores these; so do we, but the value
            // must still be a literal or we are looking at code.
            p.value(inner)?.ok_or(ParseError::Unexpected)?;
        }
        if !p.eat(&Tok::Comma)? && !p.eat(&Tok::Semi)? {
            if p.eat(&Tok::RBrace)? {
                return Ok(out);
            }
            return Err(ParseError::Unexpected);
        }
    }
}

// ---------------------------------------------------------------------------
// `.nse` metadata
// ---------------------------------------------------------------------------

/// A metadata field that may or may not be readable without running the script.
///
/// Nothing here guesses. A field the C would compute at load time is reported as
/// [`Indeterminate`](Field::Indeterminate) rather than silently defaulted, so a
/// caller can never mistake "not stated literally" for "not set".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field<T> {
    /// The script states this value literally.
    Literal(T),
    /// The script computes this value, or names it somewhere this parser cannot
    /// prove is only a read. Determining it needs an interpreter.
    Indeterminate,
}

impl<T> Field<T> {
    /// The literal value, if there is one.
    pub const fn literal(&self) -> Option<&T> {
        match self {
            Self::Literal(v) => Some(v),
            Self::Indeterminate => None,
        }
    }

    /// Whether the value was readable without evaluation.
    #[must_use]
    pub const fn is_literal(&self) -> bool {
        matches!(self, Self::Literal(_))
    }
}

/// The four rule functions a script may define.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rules {
    /// `prerule` — runs before any host is scanned.
    pub prerule: bool,
    /// `hostrule` — runs per host.
    pub hostrule: bool,
    /// `portrule` — runs per port.
    pub portrule: bool,
    /// `postrule` — runs after the scan.
    pub postrule: bool,
}

impl Rules {
    /// Whether the script defines any rule at all. `Script.new` requires one.
    #[must_use]
    pub const fn any(self) -> bool {
        self.prerule || self.hostrule || self.portrule || self.postrule
    }
}

/// Everything M6.1 can learn about a script without running it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptMetadata {
    categories: Field<Vec<Vec<u8>>>,
    dependencies: Field<Vec<Vec<u8>>>,
    description: Field<Vec<u8>>,
    author: Field<Vec<u8>>,
    license: Field<Vec<u8>>,
    rules: Rules,
}

impl ScriptMetadata {
    /// The declared categories. Undeclared means the empty list, matching the
    /// `categories = {}` default `Script.new` puts in the environment.
    #[must_use]
    pub const fn categories(&self) -> &Field<Vec<Vec<u8>>> {
        &self.categories
    }

    /// The declared dependencies, with the same default.
    #[must_use]
    pub const fn dependencies(&self) -> &Field<Vec<Vec<u8>>> {
        &self.dependencies
    }

    /// The `description` field, for `--script-help`.
    #[must_use]
    pub const fn description(&self) -> &Field<Vec<u8>> {
        &self.description
    }

    /// The `author` field.
    #[must_use]
    pub const fn author(&self) -> &Field<Vec<u8>> {
        &self.author
    }

    /// The `license` field.
    #[must_use]
    pub const fn license(&self) -> &Field<Vec<u8>> {
        &self.license
    }

    /// Which rule functions the script defines.
    #[must_use]
    pub const fn rules(&self) -> Rules {
        self.rules
    }
}

/// The metadata names this parser tracks. Everything else in a script is skipped.
const META_NAMES: [&[u8]; 10] = [
    b"categories",
    b"dependencies",
    b"description",
    b"author",
    b"license",
    b"action",
    b"prerule",
    b"hostrule",
    b"portrule",
    b"postrule",
];

/// Names whose value gates whether and when a script runs, so an indeterminate
/// one is reported rather than defaulted.
const GATING_NAMES: [&[u8]; 2] = [b"categories", b"dependencies"];

/// Read the metadata header of a `.nse` script **without executing it**.
///
/// Recognises top-level assignments to the ten names `Script.new` reads. A
/// `local` declaration is ignored, because it never reaches the script's
/// environment. Values that are not literals make their field
/// [`Field::Indeterminate`]; they do not fail the parse, because
/// `scripts/clock-skew.nse` legitimately computes its `description`.
///
/// # Errors
///
/// Returns [`ParseError::MissingField`] when `action` is absent,
/// [`ParseError::BadFieldType`] or [`ParseError::BadRuleType`] when a field
/// holds a literal of the wrong type, and [`ParseError::MissingRule`] when no
/// rule function is defined — the three conditions `Script.new` itself raises
/// on. Lexical errors are returned as they are found. Never panics.
pub fn parse_nse_metadata(bytes: &[u8]) -> Result<ScriptMetadata, ParseError> {
    if bytes.len() > MAX_SCRIPT_LEN {
        return Err(ParseError::TooLarge);
    }

    // `(name, literal value, was it inside a block?)`. A global assignment is
    // still a global assignment inside an `if` — `scripts/banner.nse` picks its
    // `portrule` that way — so nesting does not hide it. What nesting does mean
    // is that the value is conditional, and so not statically determinate.
    let mut assigned: Vec<(Vec<u8>, Option<Value>, bool)> = Vec::new();
    let mut referenced: Vec<Vec<u8>> = Vec::new();
    // Names a `local` declaration shadows. A `local categories = {…}` never
    // reaches the script's environment, so the environment keeps the empty
    // default `Script.new` seeded — and every later assignment to that name
    // lands on the local, not the global.
    let mut shadowed: Vec<Vec<u8>> = Vec::new();
    let mut action_seen: Option<Value> = None;
    let mut p = Parser::new(bytes)?;

    // Bracket nesting distinguishes a statement from a table field; block
    // nesting records whether an assignment is conditional.
    let mut brackets: usize = 0;
    let mut blocks: usize = 0;
    let mut prev_was_local = false;

    while let Some(tok) = p.next()? {
        match &tok {
            Tok::LBrace | Tok::LParen | Tok::LBracket => brackets = brackets.saturating_add(1),
            Tok::RBrace | Tok::RParen | Tok::RBracket => brackets = brackets.saturating_sub(1),
            Tok::Name(n) => {
                match n.as_slice() {
                    b"do" | b"if" | b"function" | b"repeat" => blocks = blocks.saturating_add(1),
                    b"end" | b"until" => blocks = blocks.saturating_sub(1),
                    _ => {}
                }
                if prev_was_local && META_NAMES.contains(&n.as_slice()) {
                    shadowed.push(n.clone());
                }
                let is_meta = META_NAMES.contains(&n.as_slice())
                    && !shadowed.iter().any(|sh| sh.as_slice() == n.as_slice());
                let assignment = p.peek() == Some(&Tok::Assign);

                // `function action() … end` is Lua's sugar for
                // `action = function() … end`, and 21 shipped scripts use it.
                if n.as_slice() == b"function" && brackets == 0 && !prev_was_local {
                    if let Some(Tok::Name(f)) = p.peek() {
                        if META_NAMES.contains(&f.as_slice()) {
                            let f = f.clone();
                            p.next()?;
                            // Only the plain form declares a global of this
                            // name; `function action.helper()` declares a field.
                            if p.peek() == Some(&Tok::LParen) {
                                if f.as_slice() == b"action" {
                                    action_seen = Some(Value::Function);
                                }
                                assigned.push((f, Some(Value::Function), blocks > 1));
                            }
                            prev_was_local = false;
                            continue;
                        }
                    }
                }

                if is_meta
                    && p.peek() == Some(&Tok::Comma)
                    && !prev_was_local
                    && brackets == 0
                    && p.in_assignment_name_list()
                {
                    // One target of a multiple assignment. The values are a
                    // separate expression list this parser does not evaluate, so
                    // the name is recorded as present with an unknown value.
                    if n.as_slice() == b"action" {
                        action_seen = Some(Value::Function);
                    }
                    assigned.push((n.clone(), None, blocks > 0));
                } else if is_meta && assignment && !prev_was_local && brackets == 0 {
                    p.next()?; // `=`
                               // `function` opens a block that `skip_function_body` closes,
                               // so `blocks` is left untouched by a function-literal value.
                               // A value that *starts* with a literal but continues into
                               // an expression (`description = [[…]] .. table.concat(…)`,
                               // which `scripts/clock-skew.nse` really does) is not that
                               // literal. Truncating it to the prefix would be a confident
                               // wrong answer, so it becomes indeterminate instead.
                    let val = match p.value(0)? {
                        Some(v) if p.at_expression_continuation() => {
                            let _ = v;
                            None
                        }
                        other => other,
                    };
                    if n.as_slice() == b"action" {
                        action_seen = Some(val.clone().unwrap_or(Value::Function));
                    }
                    assigned.push((n.clone(), val, blocks > 0));
                } else if is_meta && GATING_NAMES.contains(&n.as_slice()) {
                    // Any other mention of a gating name: it may be mutated, and
                    // proving otherwise needs dataflow this parser does not do.
                    referenced.push(n.clone());
                }
            }
            _ => {}
        }
        prev_was_local = matches!(&tok, Tok::Name(n) if n.as_slice() == b"local");
    }

    // `action` is required, and must be a function if it is a literal at all.
    match action_seen {
        None => return Err(ParseError::MissingField),
        Some(Value::Function) => {}
        Some(Value::Nil) => return Err(ParseError::MissingField),
        Some(_) => return Err(ParseError::BadFieldType),
    }

    let mut rules = Rules::default();
    for (name, val, _conditional) in &assigned {
        let slot = match name.as_slice() {
            b"prerule" => &mut rules.prerule,
            b"hostrule" => &mut rules.hostrule,
            b"portrule" => &mut rules.portrule,
            b"postrule" => &mut rules.postrule,
            _ => continue,
        };
        match val {
            // `portrule = nil` un-sets it, exactly as it does in the C.
            Some(Value::Nil) => *slot = false,
            Some(Value::Function) | None => *slot = true,
            Some(_) => return Err(ParseError::BadRuleType),
        }
    }
    if !rules.any() {
        return Err(ParseError::MissingRule);
    }

    let categories = string_list_field(
        &assigned,
        &referenced,
        b"categories",
        ParseError::BadCategory,
    )?;
    let dependencies = string_list_field(
        &assigned,
        &referenced,
        b"dependencies",
        ParseError::BadDependency,
    )?;

    Ok(ScriptMetadata {
        categories,
        dependencies,
        description: string_field(&assigned, b"description"),
        author: string_field(&assigned, b"author"),
        license: string_field(&assigned, b"license"),
        rules,
    })
}

/// The last literal assignment to `name`, as a string. Lua's last-write-wins.
fn string_field(assigned: &[(Vec<u8>, Option<Value>, bool)], name: &[u8]) -> Field<Vec<u8>> {
    match assigned.iter().rev().find(|(k, _, _)| k.as_slice() == name) {
        None => Field::Literal(Vec::new()),
        Some((_, Some(Value::Str(s)), false)) => Field::Literal(s.clone()),
        Some(_) => Field::Indeterminate,
    }
}

/// The last literal assignment to `name`, as a list of strings.
fn string_list_field(
    assigned: &[(Vec<u8>, Option<Value>, bool)],
    referenced: &[Vec<u8>],
    name: &[u8],
    bad: ParseError,
) -> Result<Field<Vec<Vec<u8>>>, ParseError> {
    if referenced.iter().any(|r| r.as_slice() == name) {
        return Ok(Field::Indeterminate);
    }
    match assigned.iter().rev().find(|(k, _, _)| k.as_slice() == name) {
        // Undeclared: `Script.new` seeds the environment with an empty table.
        None => Ok(Field::Literal(Vec::new())),
        // Assigned inside a block: which branch ran is not knowable statically.
        Some((_, _, true)) => Ok(Field::Indeterminate),
        Some((_, Some(Value::Table(items)), false)) => {
            let limit = if name == b"categories" {
                MAX_CATEGORIES
            } else {
                MAX_DEPENDENCIES
            };
            if items.len() > limit {
                return Err(if name == b"categories" {
                    ParseError::TooManyCategories
                } else {
                    ParseError::TooManyDependencies
                });
            }
            let mut out: Vec<Vec<u8>> = Vec::new();
            for item in items {
                out.push(item.as_str().ok_or(bad)?.to_vec());
            }
            Ok(Field::Literal(out))
        }
        // A literal of the wrong type is what `Script.new` rejects as
        // "field is of improper type".
        Some((_, Some(_), false)) => Err(ParseError::BadFieldType),
        Some((_, None, false)) => Ok(Field::Indeterminate),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The differential corpus as Rust consts, so the same inputs are exercised
    /// under Miri — which has no filesystem to read the corpus from.
    /// `tests/differential/m6/regen_m6.sh --check` keeps this in step with the
    /// oracle, and CI runs that check.
    mod fixtures {
        include!("../../../../tests/differential/m6/m6_fixtures.rs");
    }

    /// The oracle's `esc()`, so a fixture's expected string can be rebuilt here.
    fn esc(bytes: &[u8]) -> String {
        let mut out = String::new();
        for &b in bytes {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b' ') {
                out.push(char::from(b));
            } else {
                out.push_str(&alloc_format(b));
            }
        }
        out
    }

    fn alloc_format(b: u8) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let hi = char::from(HEX[usize::from(b >> 4)]);
        let lo = char::from(HEX[usize::from(b & 0x0f)]);
        let mut s = String::from("%");
        s.push(hi);
        s.push(lo);
        s
    }

    fn db_verdict(input: &[u8]) -> String {
        match parse_script_db(input) {
            Err(_) => "REJECT".to_owned(),
            Ok(db) => {
                let mut body = String::from("ACCEPT:");
                for (i, e) in db.entries().iter().enumerate() {
                    if i > 0 {
                        body.push('|');
                    }
                    body.push_str(&esc(e.filename()));
                    body.push('=');
                    for (j, c) in e.categories().iter().enumerate() {
                        if j > 0 {
                            body.push(',');
                        }
                        body.push_str(&esc(c));
                    }
                }
                body
            }
        }
    }

    fn nse_verdict(input: &[u8]) -> String {
        let Ok(m) = parse_nse_metadata(input) else {
            return "REJECT".to_owned();
        };
        let (Field::Literal(cats), Field::Literal(deps)) = (m.categories(), m.dependencies())
        else {
            return "REJECT".to_owned();
        };
        let (Field::Literal(desc), Field::Literal(author), Field::Literal(license)) =
            (m.description(), m.author(), m.license())
        else {
            return "REJECT".to_owned();
        };
        let join = |v: &[Vec<u8>]| {
            let mut s = String::new();
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&esc(x));
            }
            s
        };
        let r = m.rules();
        let mut names = String::new();
        for (on, n) in [
            (r.prerule, "prerule"),
            (r.hostrule, "hostrule"),
            (r.portrule, "portrule"),
            (r.postrule, "postrule"),
        ] {
            if on {
                if !names.is_empty() {
                    names.push(',');
                }
                names.push_str(n);
            }
        }
        let mut out = String::from("ACCEPT:cats=");
        out.push_str(&join(cats));
        out.push_str(";deps=");
        out.push_str(&join(deps));
        out.push_str(";rules=");
        out.push_str(&names);
        out.push_str(";desc=");
        out.push_str(&esc(desc));
        out.push_str(";author=");
        out.push_str(&esc(author));
        out.push_str(";license=");
        out.push_str(&esc(license));
        out
    }

    #[test]
    fn script_db_fixtures_agree_with_the_oracle_corpus() {
        assert!(fixtures::SCRIPTDB_CASES.len() > 20);
        for (name, input, expected) in fixtures::SCRIPTDB_CASES {
            assert_eq!(&db_verdict(input), expected, "case {name}");
        }
    }

    #[test]
    fn nse_fixtures_agree_with_the_oracle_corpus() {
        assert!(fixtures::NSE_CASES.len() > 20);
        for (name, input, expected) in fixtures::NSE_CASES {
            assert_eq!(&nse_verdict(input), expected, "case {name}");
        }
    }

    #[test]
    fn the_generated_form_round_trips() {
        let db = parse_script_db(
            b"Entry { filename = \"a.nse\", categories = { \"discovery\", \"safe\", } }\n",
        )
        .expect("parses");
        assert_eq!(db.entries().len(), 1);
        assert_eq!(db.entries()[0].filename(), b"a.nse");
        assert_eq!(
            db.entries()[0].categories(),
            [b"discovery".to_vec(), b"safe".to_vec()]
        );
    }

    #[test]
    fn nesting_is_bounded_rather_than_recursed_into() {
        let deep = format!(
            "Entry {{ filename = \"a.nse\", categories = {} }}\n",
            "{".repeat(64)
        );
        assert_eq!(parse_script_db(deep.as_bytes()), Err(ParseError::TooDeep));
    }

    #[test]
    fn an_oversized_input_is_refused_before_it_is_parsed() {
        let big = vec![b' '; MAX_DB_LEN.saturating_add(1)];
        assert_eq!(parse_script_db(&big), Err(ParseError::TooLarge));
        let big = vec![b' '; MAX_SCRIPT_LEN.saturating_add(1)];
        assert_eq!(parse_nse_metadata(&big), Err(ParseError::TooLarge));
    }

    #[test]
    fn a_string_literal_may_not_grow_without_bound() {
        let mut src = Vec::from(b"Entry { filename = \"".as_slice());
        src.extend(core::iter::repeat_n(b'a', MAX_STRING_LEN.saturating_add(1)));
        src.extend_from_slice(b"\", categories = {} }\n");
        assert_eq!(parse_script_db(&src), Err(ParseError::StringTooLong));
    }

    #[test]
    fn every_prefix_of_the_generated_form_is_handled_without_panicking() {
        let full = b"Entry { filename = \"a.nse\", categories = { \"safe\", } }\n";
        for n in 0..=full.len() {
            let _ = parse_script_db(full.get(..n).unwrap_or_default());
        }
    }

    #[test]
    fn every_prefix_of_a_script_is_handled_without_panicking() {
        let full = b"description = \"d\"\ncategories = {\"safe\"}\nportrule = function() end\naction = function() end\n";
        for n in 0..=full.len() {
            let _ = parse_nse_metadata(full.get(..n).unwrap_or_default());
        }
    }

    #[test]
    fn a_local_declaration_never_reaches_the_environment() {
        let m = parse_nse_metadata(
            b"local categories = {\"intrusive\"}\ncategories = {\"vuln\"}\nportrule = function() end\naction = function() end\n",
        )
        .expect("parses");
        // Both assignments land on the local; the environment keeps its default.
        assert_eq!(m.categories(), &Field::Literal(Vec::new()));
    }

    #[test]
    fn a_conditional_rule_counts_as_defined() {
        // The shape `scripts/banner.nse` uses.
        let m = parse_nse_metadata(
            b"if x then\n  portrule = f(1)\nelse\n  portrule = function() end\nend\naction = function() end\n",
        )
        .expect("parses");
        assert!(m.rules().portrule);
    }

    #[test]
    fn a_conditional_category_list_is_not_claimed_to_be_known() {
        let m = parse_nse_metadata(
            b"if x then\n  categories = {\"safe\"}\nend\nportrule = function() end\naction = function() end\n",
        )
        .expect("parses");
        assert_eq!(m.categories(), &Field::Indeterminate);
    }

    #[test]
    fn the_function_statement_form_defines_the_global() {
        // The shape 32 shipped scripts use.
        let m = parse_nse_metadata(
            b"categories = {\"safe\"}\nfunction portrule() end\nfunction action() end\n",
        )
        .expect("parses");
        assert!(m.rules().portrule);
    }

    #[test]
    fn a_multiple_assignment_defines_every_target() {
        // The shape `scripts/ms-sql-info.nse` uses.
        let m = parse_nse_metadata(
            b"categories = {\"safe\"}\naction, portrule, hostrule = helper.init(x)\n",
        )
        .expect("parses");
        assert!(m.rules().portrule && m.rules().hostrule);
    }

    #[test]
    fn a_name_mentioned_outside_its_assignment_is_not_claimed_to_be_known() {
        // The shape `scripts/clock-skew.nse` uses for `dependencies`.
        let m = parse_nse_metadata(
            b"dependencies = {\"a\"}\ndescription = \"x\" .. table.concat(dependencies, \",\")\nportrule = function() end\naction = function() end\n",
        )
        .expect("parses");
        assert_eq!(m.dependencies(), &Field::Indeterminate);
        assert_eq!(m.description(), &Field::Indeterminate);
    }

    #[test]
    fn ipairs_semantics_govern_a_keyed_category_list() {
        let one =
            parse_script_db(b"Entry { filename = \"a.nse\", categories = { [1] = \"safe\" } }")
                .expect("parses");
        assert_eq!(one.entries()[0].categories(), [b"safe".to_vec()]);
        let two =
            parse_script_db(b"Entry { filename = \"a.nse\", categories = { [2] = \"safe\" } }")
                .expect("parses");
        assert!(two.entries()[0].categories().is_empty());
    }
}
