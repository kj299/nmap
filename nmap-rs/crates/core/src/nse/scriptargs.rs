//! `--script-args` and `--script-args-file`: the text that becomes
//! `nmap.registry.args`.
//!
//! A port of `nse_main.lua:1245-1291`. nmap joins the file's contents (trailing
//! commas stripped) and the command line's string with `,`, wraps the result in
//! braces, and matches it against an LPeg grammar of nested tables:
//!
//! ```text
//! top      <- space* table space*            -- no end anchor
//! table    <- '{' space* fieldlst? space* '}'
//! fieldlst <- field (hws* [\n,] space* field)*
//! field    <- kv / av
//! kv       <- string hws* '=' hws* value     -- t[string] = value
//! av       <- value                          -- table.insert(t, value)
//! value    <- table / string
//! string   <- qstring / uqstring
//! qstring  <- escaped_quote('"') / escaped_quote("'")
//! uqstring <- hws* { (!(hws* [\n,{}=]) .)* } hws*
//! ```
//!
//! This is script input from the operator's command line, so it is parsed here
//! — a pure, total function over bytes — and the binding only builds Lua tables
//! from the result. Every consequence of the grammar is the C's, deliberately:
//!
//! * text after the closing brace is ignored (`a=1},junk` is `{a="1"}`): the
//!   pattern has no end anchor;
//! * an unquoted string may be empty, so `{}` is `{""}`, `a,,b` has three
//!   elements, and a blank argument string is `{""}`;
//! * an unquoted string keeps its inner spaces and drops its outer ones;
//! * inside quotes, a backslash escapes only a backslash or the quote — any
//!   other backslash is kept, with the byte after it;
//! * a repeated key keeps its last value.
//!
//! The one departure is depth. LPeg keeps pending calls and choices on a
//! 100-slot stack (`lpeg.c`: `MAXBACK`), so nmap refuses nesting past 10 to 14
//! levels depending on the path; this module accepts up to [`MAX_DEPTH`]
//! (`nse-script-args-depth-ceiling`, as for M6.2's selection grammar).

/// Deepest table nesting this module parses, counting the outer braces nmap
/// adds. The C gives out at 11 to 15 for reasons of LPeg's stack accounting;
/// this bound exists only to keep recursion finite on hostile input.
pub const MAX_DEPTH: usize = 128;

/// One value in the arguments: a string, or a table of further values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    /// A quoted or unquoted string, with escapes already resolved.
    Str(Vec<u8>),
    /// A nested `{...}`.
    Table(ArgTable),
}

/// A parsed table: positional values in order, and keyed values with the last
/// assignment to each key winning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgTable {
    /// `av` fields, in order: Lua indices 1, 2, ...
    pub array: Vec<ArgValue>,
    /// `kv` fields, each key once, in order of first assignment.
    pub fields: Vec<(Vec<u8>, ArgValue)>,
}

impl ArgTable {
    fn set(&mut self, key: Vec<u8>, value: ArgValue) {
        match self.fields.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value, // `rawset` replaces
            None => self.fields.push((key, value)),
        }
    }

    /// The value at `key`, if the table has one.
    pub fn get(&self, key: &[u8]) -> Option<&ArgValue> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

/// Why the arguments could not be parsed. Both abort NSE's start-up in nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgsError {
    /// The grammar did not match: nmap's "arguments did not parse!".
    NoMatch,
    /// Nested past [`MAX_DEPTH`].
    TooDeep,
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgsError::NoMatch => f.write_str("arguments did not parse!"),
            ArgsError::TooDeep => write!(f, "arguments nested deeper than {MAX_DEPTH} levels"),
        }
    }
}

impl std::error::Error for ArgsError {}

/// `nmap.registry.args` for a `--script-args-file` whose contents are `file`
/// and a `--script-args` of `cli`. Without the option nmap's `cli` is the
/// empty string (`NmapOps.cc:536`), and it still takes part in the join — so a
/// file alone gets a trailing empty element, as in the C.
pub fn registry_args(file: Option<&[u8]>, cli: &[u8]) -> Result<ArgTable, ArgsError> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2);
    if let Some(file) = file {
        // `:gsub(",*$", "")`: trailing commas only.
        let end = file
            .iter()
            .rposition(|&b| b != b',')
            .map_or(0, |i| i.saturating_add(1));
        parts.push(&file[..end]);
    }
    parts.push(cli);
    let args = parts.join(&b","[..]);
    if args.is_empty() {
        return Ok(ArgTable::default()); // `if #args > 0`
    }
    parse(&args)
}

/// Match `{args}` against the grammar.
pub fn parse(args: &[u8]) -> Result<ArgTable, ArgsError> {
    let mut input = Vec::with_capacity(args.len().saturating_add(2));
    input.push(b'{');
    input.extend_from_slice(args);
    input.push(b'}');
    let mut p = Parser {
        s: &input,
        too_deep: false,
    };
    let pos = p.space(0);
    let result = p.table(pos, 1);
    if p.too_deep {
        return Err(ArgsError::TooDeep);
    }
    // `V "space"^0` after the table always matches; nothing else is required.
    result.map(|(t, _)| t).ok_or(ArgsError::NoMatch)
}

/// `isspace` in the C locale: what `lpeg.locale().space` matches.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `space - "\n"`.
fn is_hws(b: u8) -> bool {
    is_space(b) && b != b'\n'
}

struct Parser<'a> {
    s: &'a [u8],
    /// Set once the depth bound fires; the parse is then over.
    too_deep: bool,
}

impl Parser<'_> {
    fn at(&self, pos: usize) -> Option<u8> {
        self.s.get(pos).copied()
    }

    fn skip(&self, mut pos: usize, pred: fn(u8) -> bool) -> usize {
        while self.at(pos).is_some_and(pred) {
            pos = pos.saturating_add(1);
        }
        pos
    }

    fn space(&self, pos: usize) -> usize {
        self.skip(pos, is_space)
    }

    fn hws(&self, pos: usize) -> usize {
        self.skip(pos, is_hws)
    }

    /// `'{' space* fieldlst? space* '}'`, folding fields into a table.
    fn table(&mut self, pos: usize, depth: usize) -> Option<(ArgTable, usize)> {
        if self.at(pos) != Some(b'{') {
            return None;
        }
        if depth > MAX_DEPTH {
            self.too_deep = true;
            return None;
        }
        let mut t = ArgTable::default();
        let mut pos = self.space(pos.saturating_add(1));
        // `fieldlst^-1`; a field always matches, so so does the list.
        pos = self.fieldlst(pos, depth, &mut t)?;
        pos = self.space(pos);
        if self.at(pos) != Some(b'}') {
            return None;
        }
        Some((t, pos.saturating_add(1)))
    }

    /// `field (hws* [\n,] space* field)*`. Returns `None` only when the
    /// depth bound has fired.
    fn fieldlst(&mut self, pos: usize, depth: usize, t: &mut ArgTable) -> Option<usize> {
        let mut pos = self.field(pos, depth, t)?;
        loop {
            let sep = self.hws(pos);
            if !matches!(self.at(sep), Some(b'\n' | b',')) {
                return Some(pos);
            }
            let next = self.space(sep.saturating_add(1));
            // The repetition's body: a field always matches, so the iteration
            // never backtracks past the separator.
            pos = self.field(next, depth, t)?;
        }
    }

    /// `kv / av`. Always matches unless the depth bound fires.
    fn field(&mut self, pos: usize, depth: usize, t: &mut ArgTable) -> Option<usize> {
        // kv <- string hws* '=' hws* value
        let (key, after_key) = self.string(pos);
        let eq = self.hws(after_key);
        if self.at(eq) == Some(b'=') {
            let vpos = self.hws(eq.saturating_add(1));
            let (value, end) = self.value(vpos, depth)?;
            t.set(key, value);
            return Some(end);
        }
        // av <- value
        let (value, end) = self.value(pos, depth)?;
        t.array.push(value);
        Some(end)
    }

    /// `table / string`. Always matches unless the depth bound fires.
    fn value(&mut self, pos: usize, depth: usize) -> Option<(ArgValue, usize)> {
        if let Some((t, end)) = self.table(pos, depth.saturating_add(1)) {
            return Some((ArgValue::Table(t), end));
        }
        if self.too_deep {
            return None;
        }
        let (s, end) = self.string(pos);
        Some((ArgValue::Str(s), end))
    }

    /// `qstring / uqstring`. Always matches.
    fn string(&self, pos: usize) -> (Vec<u8>, usize) {
        self.quoted(pos, b'"')
            .or_else(|| self.quoted(pos, b'\''))
            .unwrap_or_else(|| self.unquoted(pos))
    }

    /// `escaped_quote(q)` (`nselib/lpeg-utility.lua:85`): `q`, then any mix of
    /// plain bytes, `\` + `\` or `\` + `q` (the backslash dropped), and `\` +
    /// any other plain byte (both kept), then `q`.
    fn quoted(&self, pos: usize, q: u8) -> Option<(Vec<u8>, usize)> {
        if self.at(pos) != Some(q) {
            return None;
        }
        let mut out = Vec::new();
        let mut i = pos.saturating_add(1);
        loop {
            match self.at(i)? {
                c if c == q => return Some((out, i.saturating_add(1))),
                b'\\' => match self.at(i.saturating_add(1)) {
                    // unesc
                    Some(c) if c == b'\\' || c == q => {
                        out.push(c);
                        i = i.saturating_add(2);
                    }
                    // noesc: the escape and a simple char, kept as written
                    Some(c) => {
                        out.extend_from_slice(&[b'\\', c]);
                        i = i.saturating_add(2);
                    }
                    // a lone backslash at the end: nothing more can match
                    None => return None,
                },
                c => {
                    out.push(c);
                    i = i.saturating_add(1);
                }
            }
        }
    }

    /// `hws* { (!(hws* [\n,{}=]) .)* } hws*`.
    fn unquoted(&self, pos: usize) -> (Vec<u8>, usize) {
        let start = self.hws(pos);
        let mut i = start;
        while self.at(i).is_some() {
            // The predicate: hws* followed by a delimiter stops the string.
            let after = self.hws(i);
            if matches!(self.at(after), Some(b'\n' | b',' | b'{' | b'}' | b'=')) {
                break;
            }
            // A run of whitespace not followed by a delimiter is consumed
            // whole: every position inside it would reach the same verdict.
            // Stepping one byte at a time instead is quadratic in the run.
            i = if after > i {
                after
            } else {
                i.saturating_add(1)
            };
        }
        (self.s[start..i].to_vec(), self.hws(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> ArgValue {
        ArgValue::Str(v.as_bytes().to_vec())
    }

    fn arr(vs: Vec<ArgValue>) -> ArgTable {
        ArgTable {
            array: vs,
            fields: vec![],
        }
    }

    #[test]
    fn the_grammars_corners_are_the_cs() {
        // Each of these was checked against nmap 7.94 itself.
        assert_eq!(parse(b"a,,b").unwrap(), arr(vec![s("a"), s(""), s("b")]));
        assert_eq!(parse(b" ").unwrap(), arr(vec![s("")]));
        assert_eq!(parse(b",").unwrap(), arr(vec![s(""), s("")]));
        assert_eq!(
            parse(b"a={}").unwrap().get(b"a"),
            Some(&ArgValue::Table(arr(vec![s("")])))
        );
        let t = parse(b"a=1},junk").unwrap();
        assert_eq!(t.get(b"a"), Some(&s("1")));
        assert_eq!(t.fields.len(), 1);
        let t = parse(b"x = y z  ,w").unwrap();
        assert_eq!(t.get(b"x"), Some(&s("y z")));
        assert_eq!(t.array, vec![s("w")]);
        assert_eq!(parse(br#""a\"b"=c"#).unwrap().get(br#"a"b"#), Some(&s("c")));
        assert_eq!(parse(br#""a\\b""#).unwrap().array, vec![s(r"a\b")]);
        assert_eq!(parse(br#""a\xb""#).unwrap().array, vec![s(r"a\xb")]);
        assert_eq!(parse(br#"a="}"#).unwrap().get(b"a"), Some(&s("\"")));
        assert_eq!(parse(b"a={"), Err(ArgsError::NoMatch));
        assert_eq!(parse(b"k=v=w"), Err(ArgsError::NoMatch));
        assert_eq!(parse(b"a=1,a=2").unwrap().get(b"a"), Some(&s("2")));
        assert_eq!(parse(b"=x").unwrap().get(b""), Some(&s("x")));
        assert_eq!(parse(b"a\tb = c\t").unwrap().get(b"a\tb"), Some(&s("c")));
    }

    #[test]
    fn the_file_and_the_command_line_join_as_in_the_c() {
        assert_eq!(registry_args(None, b""), Ok(ArgTable::default()));
        // The empty command-line string still joins: a trailing "" element.
        let t = registry_args(Some(b"a=1,,"), b"").unwrap();
        assert_eq!(t.get(b"a"), Some(&s("1")));
        assert_eq!(t.array, vec![s("")]);
        let t = registry_args(Some(b""), b"b=2").unwrap();
        assert_eq!(t.array, vec![s("")]);
        assert_eq!(t.get(b"b"), Some(&s("2")));
    }

    #[test]
    fn depth_is_bounded_not_recursed_without_limit() {
        let ok = format!(
            "{}x{}",
            "{".repeat(MAX_DEPTH - 1),
            "}".repeat(MAX_DEPTH - 1)
        );
        assert!(parse(ok.as_bytes()).is_ok());
        let deep = format!("{}x{}", "{".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH));
        assert_eq!(parse(deep.as_bytes()), Err(ArgsError::TooDeep));
        let huge = "{".repeat(100_000);
        assert_eq!(parse(huge.as_bytes()), Err(ArgsError::TooDeep));
    }
}
