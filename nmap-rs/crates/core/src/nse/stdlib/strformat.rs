//! `string.format`, ported from `liblua/lstrlib.c:990-1376`.
//!
//! The C is a thin layer over the C library's `printf`: it validates each
//! conversion specification (`getformat`, `checkformat`), adds a length
//! modifier and hands the specification to `snprintf`. So porting it means
//! porting two things — Lua's validation exactly, and the `printf` behaviour
//! for every specification that validation lets through. The second half is
//! glibc's, because the oracle is nmap's own `liblua/` built on Linux.
//!
//! # What is ported, and what is deliberately not
//!
//! Kept, because scripts can observe them:
//!
//! * the validation is Lua's, not `printf`'s: flags may repeat in any order,
//!   width and precision are at most two digits, a specification longer than
//!   21 bytes is "invalid format (too long)", and each conversion accepts only
//!   its own flags (`%5.2c` and `%#d` are errors);
//! * the order in which each conversion checks its argument and its
//!   specification, which decides which error a doubly-wrong call reports;
//! * `%s` without modifiers keeps the whole string, NUL bytes included, and
//!   with modifiers rejects NUL bytes ("string contains zeros") and keeps a
//!   string of 100 bytes or more whole unless a precision is given;
//! * `%q` writes floats as hexadecimal (`0x1p+1` for `2.0`), `math.mininteger`
//!   as `0x8000000000000000`, and escapes control bytes as `\ddd` only when a
//!   digit follows;
//! * `%a` is glibc's: a subnormal prints as `0x0.<13 digits>p-1022`.
//!
//! Not reproduced: `printf` is called with a fixed-size buffer whose bounds
//! the C argues from the specification (`MAX_ITEM`, `MAX_ITEMF`). Here the
//! output is a `Vec` grown with `try_reserve`, so there is no bound to argue.
//!
//! # Layering
//!
//! Arguments come in through [`FormatArgs`], one method per `luaL_check*` the
//! C calls. `%s` needs `luaL_tolstring`, which may call a `__tostring`
//! metamethod — a call back into the VM that cannot be made from here. So
//! [`FormatArgs::tostring`] may answer "not yet", in which case [`format_step`]
//! stops *before* that specification, the binding makes the call, and the step
//! is run again from the same place. Every check the C makes before
//! `luaL_tolstring` is free of side effects, so running it twice is
//! unobservable.

use std::borrow::Cow;

use super::strpack::PackError;

/// `MAX_FORMAT` (`lstrlib.c:1119`).
const MAX_FORMAT: usize = 32;

/// Flags for `a A e E f g G` (`L_FMTFLAGSF`).
const FLAGS_F: &[u8] = b"-+#0 ";
/// Flags for `o x X` (`L_FMTFLAGSX`).
const FLAGS_X: &[u8] = b"-#0";
/// Flags for `d i` (`L_FMTFLAGSI`).
const FLAGS_I: &[u8] = b"-+0 ";
/// Flags for `u` (`L_FMTFLAGSU`).
const FLAGS_U: &[u8] = b"-0";
/// Flags for `c p s` (`L_FMTFLAGSC`).
const FLAGS_C: &[u8] = b"-";

/// A value `%q` can write as a literal (`addliteral`).
#[derive(Debug, Clone, PartialEq)]
pub enum Literal<'a> {
    Str(Cow<'a, [u8]>),
    Integer(i64),
    Float(f64),
    /// `nil`, `true` or `false`, already rendered by `luaL_tolstring`.
    Text(&'static str),
}

/// The Lua arguments of one `string.format` call, by 1-based number. The
/// format itself is argument 1.
pub trait FormatArgs {
    /// `lua_gettop`: how many arguments the call has.
    fn count(&self) -> usize;
    /// `luaL_checkinteger`.
    fn integer(&mut self, arg: usize) -> Result<i64, PackError>;
    /// `luaL_checknumber`.
    fn number(&mut self, arg: usize) -> Result<f64, PackError>;
    /// `luaL_tolstring`, or `Ok(None)` if producing it needs a call into the
    /// VM that has not been made yet.
    fn tostring(&mut self, arg: usize) -> Result<Option<Cow<'_, [u8]>>, PackError>;
    /// The argument as `addliteral` sees it, or the "value has no literal
    /// form" argument error.
    fn literal(&mut self, arg: usize) -> Result<Literal<'_>, PackError>;
    /// `lua_topointer`: `None` for a value that has no address.
    fn pointer(&mut self, arg: usize) -> Option<usize>;
}

/// Where a formatting run stands. Create with [`Formatter::default`] and
/// drive with [`format_step`].
#[derive(Debug, Clone, Default)]
pub struct Formatter {
    pos: usize,
    arg: usize,
    out: Vec<u8>,
}

/// What [`format_step`] stopped for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The whole format is done; this is the result.
    Done(Vec<u8>),
    /// `%s` needs argument `arg` converted by a call into the VM. Make it,
    /// arrange for [`FormatArgs::tostring`] to answer, and step again.
    NeedsToString(usize),
}

/// A Lua error raised by `string.format`. Unlike the other modules' errors
/// its message is **bytes**: two of the C's messages quote the offending
/// specification, `'%s'`, byte for byte, and a format is a byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError {
    /// The 1-based Lua argument number, for an argument error.
    pub arg: Option<usize>,
    /// The message, exactly as the C formats it.
    pub msg: Vec<u8>,
}

impl FormatError {
    /// The whole message as `luaL_argerror` would build it, given the name the
    /// function was called by.
    pub fn lua_message(&self, fname: &str) -> Vec<u8> {
        match self.arg {
            Some(n) => {
                let mut m = format!("bad argument #{n} to '{fname}' (").into_bytes();
                m.extend_from_slice(&self.msg);
                m.push(b')');
                m
            }
            None => self.msg.clone(),
        }
    }
}

/// The argument conversions are shared with the other modules, and report in
/// their type.
impl From<PackError> for FormatError {
    fn from(e: PackError) -> Self {
        Self {
            arg: e.arg,
            msg: e.msg.into_bytes(),
        }
    }
}

fn err(msg: impl Into<Vec<u8>>) -> FormatError {
    FormatError {
        arg: None,
        msg: msg.into(),
    }
}

fn arg_err(arg: usize, msg: impl Into<Vec<u8>>) -> FormatError {
    FormatError {
        arg: Some(arg),
        msg: msg.into(),
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FormatError> {
    out.try_reserve(bytes.len())
        .map_err(|_| err("not enough memory"))?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// `string.format(fmt, ...)` for an argument source that never needs the VM:
/// every `%s` must be answerable at once.
pub fn format(fmt: &[u8], args: &mut impl FormatArgs) -> Result<Vec<u8>, FormatError> {
    let mut f = Formatter::default();
    match format_step(fmt, &mut f, args)? {
        Step::Done(out) => Ok(out),
        Step::NeedsToString(arg) => Err(arg_err(arg, "needs a __tostring call")),
    }
}

/// `str_format` (`lstrlib.c:1273`), run until it finishes or needs the VM.
pub fn format_step(
    fmt: &[u8],
    f: &mut Formatter,
    args: &mut impl FormatArgs,
) -> Result<Step, FormatError> {
    while let Some(&c) = fmt.get(f.pos) {
        let after = f.pos.saturating_add(1);
        if c != b'%' {
            put(&mut f.out, &[c])?;
            f.pos = after;
            continue;
        }
        if fmt.get(after) == Some(&b'%') {
            put(&mut f.out, b"%")?;
            f.pos = after.saturating_add(1);
            continue;
        }
        // A format item. `arg` is only committed once the item is written, so
        // that a step stopped for `__tostring` resumes on the same item.
        let arg = f.arg.saturating_add(2);
        if arg > args.count() {
            return Err(arg_err(arg, "no value"));
        }
        let spec = getformat(fmt, after)?;
        let mut item = Vec::new();
        if !convert(&spec, arg, args, &mut item)? {
            return Ok(Step::NeedsToString(arg));
        }
        put(&mut f.out, &item)?;
        f.arg = f.arg.saturating_add(1);
        f.pos = spec.next;
    }
    Ok(Step::Done(std::mem::take(&mut f.out)))
}

/// One conversion specification as `getformat` copies it.
struct Spec<'a> {
    /// The flags, width and precision bytes between `%` and the conversion.
    body: &'a [u8],
    /// The conversion byte; 0 if the format ended first.
    conv: u8,
    /// Where the format continues.
    next: usize,
}

impl Spec<'_> {
    /// `form` as the C's messages print it: `%`, the body, the conversion,
    /// cut at a NUL as `%s` cuts a C string.
    fn form(&self) -> Vec<u8> {
        let mut b = vec![b'%'];
        b.extend_from_slice(self.body);
        b.push(self.conv);
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        b.truncate(end);
        b
    }

    /// A message quoting this specification: `before` + `'form'` + `after`.
    fn quoted(&self, before: &str, after: &str) -> FormatError {
        let mut m = before.as_bytes().to_vec();
        m.push(b'\'');
        m.extend_from_slice(&self.form());
        m.push(b'\'');
        m.extend_from_slice(after.as_bytes());
        err(m)
    }

    /// `form[2] != '\0'`: is there anything between `%` and the conversion?
    fn has_modifiers(&self) -> bool {
        !self.body.is_empty()
    }
}

/// `getformat` (`lstrlib.c:1245`).
fn getformat(fmt: &[u8], start: usize) -> Result<Spec<'_>, FormatError> {
    let rest = fmt.get(start..).unwrap_or_default();
    let span = rest
        .iter()
        .take_while(|b| b"-+#0 123456789.".contains(b))
        .count();
    // The span, plus the conversion byte (which may be the C's terminator).
    if span.saturating_add(1) >= MAX_FORMAT - 10 {
        return Err(err("invalid format (too long)"));
    }
    Ok(Spec {
        body: &rest[..span],
        conv: rest.get(span).copied().unwrap_or(0),
        next: start.saturating_add(span).saturating_add(1),
    })
}

/// A validated specification, parsed for formatting.
#[derive(Debug, Default)]
struct Parsed {
    minus: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
}

/// `checkformat` (`lstrlib.c:1225`) — and, since what it accepts is exactly
/// `flags* width? (. precision?)?`, the parse of what it accepted.
///
/// Indices stay within the body, at most 21 bytes (`getformat` refused anything
/// longer), and a two-digit number is at most 99: none of this can overflow.
#[allow(clippy::arithmetic_side_effects)]
fn checkformat(spec: &Spec<'_>, flags: &[u8], precision: bool) -> Result<Parsed, FormatError> {
    let b = spec.body;
    let at = |i: usize| b.get(i).copied().unwrap_or(spec.conv);
    let mut p = Parsed::default();
    let mut i = 0;
    while i < b.len() && flags.contains(&b[i]) {
        match b[i] {
            b'-' => p.minus = true,
            b'+' => p.plus = true,
            b' ' => p.space = true,
            b'#' => p.alt = true,
            _ => p.zero = true,
        }
        i += 1;
    }
    let digits = |i: &mut usize| {
        let mut n = 0usize;
        for _ in 0..2 {
            if *i < b.len() && b[*i].is_ascii_digit() {
                n = n * 10 + usize::from(b[*i] - b'0');
                *i += 1;
            }
        }
        n
    };
    if at(i) != b'0' {
        p.width = digits(&mut i);
        if at(i) == b'.' && precision {
            i += 1;
            p.precision = Some(digits(&mut i));
        }
    }
    if i != b.len() || !spec.conv.is_ascii_alphabetic() {
        return Err(spec.quoted("invalid conversion specification: ", ""));
    }
    Ok(p)
}

/// Pad `body` (sign and prefix first, then digits) to the width, as `printf`
/// does: right-justified with spaces, left with `-`, or with zeros between the
/// prefix and the digits when `zero` applies.
fn pad(
    p: &Parsed,
    prefix: &[u8],
    digits: &[u8],
    zero_ok: bool,
    out: &mut Vec<u8>,
) -> Result<(), FormatError> {
    let len = prefix.len().saturating_add(digits.len());
    let fill = p.width.saturating_sub(len);
    if p.minus {
        put(out, prefix)?;
        put(out, digits)?;
        put(out, &vec![b' '; fill])?;
    } else if p.zero && zero_ok {
        put(out, prefix)?;
        put(out, &vec![b'0'; fill])?;
        put(out, digits)?;
    } else {
        put(out, &vec![b' '; fill])?;
        put(out, prefix)?;
        put(out, digits)?;
    }
    Ok(())
}

/// Format one item into `out`. `Ok(false)` means `%s` needs the VM first.
fn convert(
    spec: &Spec<'_>,
    arg: usize,
    args: &mut impl FormatArgs,
    out: &mut Vec<u8>,
) -> Result<bool, FormatError> {
    match spec.conv {
        b'c' => {
            let p = checkformat(spec, FLAGS_C, false)?;
            let n = args.integer(arg)?;
            // `(int)n` then `printf`'s `unsigned char` conversion: the low byte.
            pad(&p, &[], &[n.to_le_bytes()[0]], false, out)?;
        }
        conv @ (b'd' | b'i' | b'u' | b'o' | b'x' | b'X') => {
            let n = args.integer(arg)?;
            let flags = match conv {
                b'd' | b'i' => FLAGS_I,
                b'u' => FLAGS_U,
                _ => FLAGS_X,
            };
            let p = checkformat(spec, flags, true)?;
            int_item(&p, conv, n, out)?;
        }
        conv @ (b'a' | b'A') => {
            let p = checkformat(spec, FLAGS_F, true)?;
            let x = args.number(arg)?;
            float_item(&p, conv, x, out)?;
        }
        conv @ (b'f' | b'e' | b'E' | b'g' | b'G') => {
            let x = args.number(arg)?;
            let p = checkformat(spec, FLAGS_F, true)?;
            float_item(&p, conv, x, out)?;
        }
        b'p' => {
            let ptr = args.pointer(arg);
            let p = checkformat(spec, FLAGS_C, false)?;
            match ptr {
                // `printf("%p", NULL)` is avoided by formatting "(null)" with `%s`.
                None => pad(&p, &[], b"(null)", false, out)?,
                Some(a) => pad(&p, &[], format!("{a:#x}").as_bytes(), false, out)?,
            }
        }
        b'q' => {
            if spec.has_modifiers() {
                return Err(err("specifier '%q' cannot have modifiers"));
            }
            add_literal(args.literal(arg)?, out)?;
        }
        b's' => {
            let Some(s) = args.tostring(arg)? else {
                return Ok(false);
            };
            if !spec.has_modifiers() {
                put(out, &s)?; // keep the entire string
            } else {
                if s.contains(&0) {
                    return Err(arg_err(arg, "string contains zeros"));
                }
                let p = checkformat(spec, FLAGS_C, true)?;
                if p.precision.is_none() && s.len() >= 100 {
                    put(out, &s)?; // too long to be formatted; kept whole
                } else {
                    let cut = p.precision.map_or(s.len(), |n| n.min(s.len()));
                    pad(&p, &[], &s[..cut], false, out)?;
                }
            }
        }
        _ => return Err(spec.quoted("invalid conversion ", " to 'format'")),
    }
    Ok(true)
}

/// `%d %i %u %o %x %X` with the `ll` length modifier.
fn int_item(p: &Parsed, conv: u8, n: i64, out: &mut Vec<u8>) -> Result<(), FormatError> {
    let u = if matches!(conv, b'd' | b'i') {
        n.unsigned_abs()
    } else {
        n as u64 // `%llu`/`%llo`/`%llx` read the bits as unsigned
    };
    let mut digits = match conv {
        b'o' => format!("{u:o}"),
        b'x' => format!("{u:x}"),
        b'X' => format!("{u:X}"),
        _ => u.to_string(),
    }
    .into_bytes();
    if let Some(prec) = p.precision {
        if prec == 0 && u == 0 {
            digits.clear();
        } else if digits.len() < prec {
            let mut z = vec![b'0'; prec.saturating_sub(digits.len())];
            z.extend_from_slice(&digits);
            digits = z;
        }
    }
    let mut prefix: Vec<u8> = Vec::new();
    match conv {
        b'd' | b'i' => {
            if n < 0 {
                prefix.push(b'-');
            } else if p.plus {
                prefix.push(b'+');
            } else if p.space {
                prefix.push(b' ');
            }
        }
        b'o' if p.alt && digits.first() != Some(&b'0') => digits.insert(0, b'0'),
        b'x' if p.alt && u != 0 => prefix.extend_from_slice(b"0x"),
        b'X' if p.alt && u != 0 => prefix.extend_from_slice(b"0X"),
        _ => {}
    }
    // A precision turns the `0` flag off for integers.
    pad(p, &prefix, &digits, p.precision.is_none(), out)
}

/// `%a %A %e %E %f %g %G` with no length modifier (a `double`).
fn float_item(p: &Parsed, conv: u8, x: f64, out: &mut Vec<u8>) -> Result<(), FormatError> {
    let upper = conv.is_ascii_uppercase();
    let mut sign: Vec<u8> = Vec::new();
    if x.is_sign_negative() {
        sign.push(b'-');
    } else if p.plus {
        sign.push(b'+');
    } else if p.space {
        sign.push(b' ');
    }
    if !x.is_finite() {
        let word = match (x.is_nan(), upper) {
            (true, false) => "nan",
            (true, true) => "NAN",
            (false, false) => "inf",
            (false, true) => "INF",
        };
        // glibc pads infinities and NaNs with spaces even under `0`.
        return pad(p, &sign, word.as_bytes(), false, out);
    }
    let ax = x.abs();
    let (prefix, body) = match conv.to_ascii_lowercase() {
        b'e' => (Vec::new(), exp_form(ax, p.precision.unwrap_or(6), p.alt)),
        b'f' => (Vec::new(), fixed_form(ax, p.precision.unwrap_or(6), p.alt)),
        b'g' => (
            Vec::new(),
            general_form(ax, p.precision.unwrap_or(6), p.alt),
        ),
        _ => (b"0x".to_vec(), hex_form(ax, p.precision, p.alt)),
    };
    let mut lead = sign;
    lead.extend_from_slice(&prefix);
    let (mut lead, mut body) = (lead, body.into_bytes());
    if upper {
        lead.make_ascii_uppercase();
        body.make_ascii_uppercase();
    }
    pad(p, &lead, &body, true, out)
}

/// `%.*e` of a non-negative finite `x`: `d.ddde±XX`.
fn exp_form(x: f64, prec: usize, alt: bool) -> String {
    let s = format!("{x:.prec$e}");
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let point = if alt && prec == 0 { "." } else { "" };
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mant}{point}e{sign}{:02}", exp.unsigned_abs())
}

/// `%.*f` of a non-negative finite `x`. Rust's fixed formatting is exact, as
/// glibc's is, and rounds the exact binary value half-to-even, as glibc does.
fn fixed_form(x: f64, prec: usize, alt: bool) -> String {
    let point = if alt && prec == 0 { "." } else { "" };
    format!("{x:.prec$}{point}")
}

/// `%.*g` of a non-negative finite `x` (C11 7.21.6.1).
fn general_form(x: f64, prec: usize, alt: bool) -> String {
    let p = prec.max(1);
    let e = exp_form(x, p.saturating_sub(1), false);
    let exp: i64 = e
        .rsplit_once('e')
        .and_then(|(_, x)| x.parse().ok())
        .unwrap_or(0);
    let p_i = i64::try_from(p).unwrap_or(i64::MAX);
    let s = if exp < p_i && exp >= -4 {
        let fprec = usize::try_from(p_i.saturating_sub(1).saturating_sub(exp)).unwrap_or(0);
        fixed_form(x, fprec, alt)
    } else {
        exp_form(x, p.saturating_sub(1), alt)
    };
    if alt {
        return s;
    }
    // Without `#`, trailing zeros go, and the point with them if nothing is left.
    let (mant, tail) = match s.find('e') {
        Some(i) => s.split_at(i),
        None => (s.as_str(), ""),
    };
    let mant = if mant.contains('.') {
        mant.trim_end_matches('0').trim_end_matches('.')
    } else {
        mant
    };
    format!("{mant}{tail}")
}

/// glibc's `%a` digits (after `0x`) of a non-negative finite `x`.
///
/// The arithmetic is on the 52-bit fraction and a precision below 13, so
/// every shift is by at most 52 bits and the sums fit in a `u64`; the casts
/// are of numbers below 64.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn hex_form(x: f64, prec: Option<usize>, alt: bool) -> String {
    let bits = x.to_bits();
    let biased = (bits >> 52) & 0x7ff;
    let mut frac = bits & ((1u64 << 52) - 1);
    let (mut lead, exp): (u64, i64) = if biased == 0 {
        // Zero prints with exponent 0; a subnormal keeps the fixed -1022.
        (0, if frac == 0 { 0 } else { -1022 })
    } else {
        (1, i64::try_from(biased).unwrap_or(0) - 1023)
    };
    let digits = match prec {
        None => {
            let mut d = format!("{frac:013x}");
            while d.ends_with('0') {
                d.pop();
            }
            d
        }
        Some(p) if p >= 13 => format!("{frac:013x}{}", "0".repeat(p - 13)),
        Some(p) => {
            // Round the 52-bit fraction to `4p` bits, half to even.
            let drop = 4 * (13 - p) as u32;
            let kept = frac >> drop;
            let rem = frac & ((1u64 << drop) - 1);
            let half = 1u64 << (drop - 1);
            // With no fraction digits kept, the leading digit is the last one.
            let last = if p == 0 { lead } else { kept };
            let up = rem > half || (rem == half && last & 1 == 1);
            frac = kept + u64::from(up);
            if p == 0 {
                lead += frac;
                String::new()
            } else if frac >> (4 * p as u32) != 0 {
                // The carry ran into the leading digit.
                lead += 1;
                format!("{:0w$x}", frac & ((1u64 << (4 * p as u32)) - 1), w = p)
            } else {
                format!("{frac:0w$x}", w = p)
            }
        }
    };
    let point = if !digits.is_empty() || alt { "." } else { "" };
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{lead:x}{point}{digits}p{sign}{}", exp.unsigned_abs())
}

/// `addliteral` (`lstrlib.c:1175`) for `%q`.
fn add_literal(lit: Literal<'_>, out: &mut Vec<u8>) -> Result<(), FormatError> {
    match lit {
        Literal::Str(s) => add_quoted(&s, out),
        Literal::Integer(n) if n == i64::MIN => put(out, b"0x8000000000000000"),
        Literal::Integer(n) => put(out, n.to_string().as_bytes()),
        Literal::Float(x) if x == f64::INFINITY => put(out, b"1e9999"),
        Literal::Float(x) if x == f64::NEG_INFINITY => put(out, b"-1e9999"),
        Literal::Float(x) if x.is_nan() => put(out, b"(0/0)"),
        Literal::Float(x) => {
            let mut s = if x.is_sign_negative() { "-0x" } else { "0x" }.to_string();
            s.push_str(&hex_form(x.abs(), None, false));
            put(out, s.as_bytes())
        }
        Literal::Text(t) => put(out, t.as_bytes()),
    }
}

/// `addquoted` (`lstrlib.c:1122`).
fn add_quoted(s: &[u8], out: &mut Vec<u8>) -> Result<(), FormatError> {
    put(out, b"\"")?;
    for (i, &c) in s.iter().enumerate() {
        if matches!(c, b'"' | b'\\' | b'\n') {
            put(out, &[b'\\', c])?;
        } else if c.is_ascii_control() {
            // The C reads one byte past the last for its terminator, a NUL.
            let next_is_digit = s.get(i.saturating_add(1)).is_some_and(u8::is_ascii_digit);
            let esc = if next_is_digit {
                format!("\\{c:03}")
            } else {
                format!("\\{c}")
            };
            put(out, esc.as_bytes())?;
        } else {
            put(out, &[c])?;
        }
    }
    put(out, b"\"")
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::approx_constant
)]
mod tests {
    use super::*;

    /// Arguments as plain values, converted the way the C converts them.
    #[derive(Clone, Debug)]
    enum A {
        I(i64),
        F(f64),
        S(&'static [u8]),
        Nil,
    }

    struct Args(Vec<A>);

    impl FormatArgs for Args {
        fn count(&self) -> usize {
            self.0.len() + 1
        }
        fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
            match self.0.get(arg - 2) {
                Some(A::I(n)) => Ok(*n),
                Some(A::F(f)) if f.fract() == 0.0 => Ok(*f as i64),
                Some(A::F(_)) => Err(PackError::bad_argument(
                    arg,
                    "number has no integer representation",
                )),
                _ => Err(PackError::bad_argument(arg, "number expected")),
            }
        }
        fn number(&mut self, arg: usize) -> Result<f64, PackError> {
            match self.0.get(arg - 2) {
                Some(A::I(n)) => Ok(*n as f64),
                Some(A::F(f)) => Ok(*f),
                _ => Err(PackError::bad_argument(arg, "number expected")),
            }
        }
        fn tostring(&mut self, arg: usize) -> Result<Option<Cow<'_, [u8]>>, PackError> {
            Ok(Some(match &self.0[arg - 2] {
                A::S(s) => Cow::Borrowed(*s),
                A::I(n) => Cow::Owned(n.to_string().into_bytes()),
                A::F(f) => Cow::Owned(f.to_string().into_bytes()),
                A::Nil => Cow::Borrowed(b"nil"),
            }))
        }
        fn literal(&mut self, arg: usize) -> Result<Literal<'_>, PackError> {
            Ok(match &self.0[arg - 2] {
                A::S(s) => Literal::Str(Cow::Borrowed(*s)),
                A::I(n) => Literal::Integer(*n),
                A::F(f) => Literal::Float(*f),
                A::Nil => Literal::Text("nil"),
            })
        }
        fn pointer(&mut self, _arg: usize) -> Option<usize> {
            None
        }
    }

    fn f(fmt: &str, args: Vec<A>) -> String {
        String::from_utf8(format(fmt.as_bytes(), &mut Args(args)).unwrap()).unwrap()
    }

    fn e(fmt: &str, args: Vec<A>) -> String {
        String::from_utf8(format(fmt.as_bytes(), &mut Args(args)).unwrap_err().msg).unwrap()
    }

    #[test]
    fn integers_follow_printf() {
        assert_eq!(
            f(
                "%d|%5d|%-5d|%05d|%+d|% d",
                vec![A::I(42), A::I(42), A::I(42), A::I(42), A::I(42), A::I(42)]
            ),
            "42|   42|42   |00042|+42| 42"
        );
        assert_eq!(
            f(
                "%.3d|%5.3d|%05.3d|%.0d",
                vec![A::I(7), A::I(-7), A::I(7), A::I(0)]
            ),
            "007| -007|  007|"
        );
        assert_eq!(
            f(
                "%x|%X|%#x|%#o|%o|%#x",
                vec![A::I(255), A::I(255), A::I(255), A::I(8), A::I(8), A::I(0)]
            ),
            "ff|FF|0xff|010|10|0"
        );
        assert_eq!(
            f("%x|%u", vec![A::I(-1), A::I(-1)]),
            "ffffffffffffffff|18446744073709551615"
        );
        assert_eq!(f("%d", vec![A::I(i64::MIN)]), "-9223372036854775808");
        assert_eq!(
            f("%c%c%3c", vec![A::I(65), A::I(256 + 66), A::I(67)]),
            "AB  C"
        );
    }

    #[test]
    fn floats_follow_glibc() {
        assert_eq!(
            f(
                "%f|%.2f|%8.3f|%-8.1f|%+.1f",
                vec![A::F(1.5), A::F(2.675), A::F(3.14159), A::F(2.0), A::F(1.0)]
            ),
            "1.500000|2.67|   3.142|2.0     |+1.0"
        );
        assert_eq!(
            f(
                "%e|%.2E|%.0e|%#.0e",
                vec![A::F(12345.678), A::F(0.000123), A::F(5.0), A::F(5.0)]
            ),
            "1.234568e+04|1.23E-04|5e+00|5.e+00"
        );
        assert_eq!(
            f(
                "%g|%g|%g|%g|%#g|%.3g",
                vec![
                    A::F(100000.0),
                    A::F(1e6),
                    A::F(1e-5),
                    A::F(0.0001),
                    A::F(1.5),
                    A::F(1234.0)
                ]
            ),
            "100000|1e+06|1e-05|0.0001|1.50000|1.23e+03"
        );
        assert_eq!(
            f(
                "%f|%5.1f|%05f|%-6f|%+f",
                vec![
                    A::F(f64::INFINITY),
                    A::F(f64::NEG_INFINITY),
                    A::F(f64::NAN),
                    A::F(f64::INFINITY),
                    A::F(f64::INFINITY)
                ]
            ),
            "inf| -inf|  nan|inf   |+inf"
        );
        assert_eq!(
            f("%.1f|%.0f|%.0f", vec![A::F(0.25), A::F(0.5), A::F(1.5)]),
            "0.2|0|2"
        );
        assert_eq!(f("%f", vec![A::F(-0.0)]), "-0.000000");
    }

    #[test]
    fn hex_floats_are_glibcs() {
        assert_eq!(
            f(
                "%a|%a|%a|%A",
                vec![A::F(1.0), A::F(3.0), A::F(0.0), A::F(-0.5)]
            ),
            "0x1p+0|0x1.8p+1|0x0p+0|-0X1P-1"
        );
        assert_eq!(
            f("%a", vec![A::F(f64::from_bits(1))]),
            "0x0.0000000000001p-1022"
        );
        assert_eq!(
            f("%.1a|%.0a|%#a", vec![A::F(1.96875), A::F(1.5), A::F(1.0)]),
            "0x2.0p+0|0x2p+0|0x1.p+0"
        );
    }

    #[test]
    fn strings_and_quoting() {
        assert_eq!(
            f(
                "[%s]|[%5s]|[%-5s]|[%.2s]",
                vec![A::S(b"abc"), A::S(b"abc"), A::S(b"abc"), A::S(b"abc")]
            ),
            "[abc]|[  abc]|[abc  ]|[ab]"
        );
        assert_eq!(f("%s", vec![A::S(b"a\0b")]), "a\0b");
        assert_eq!(e("%5s", vec![A::S(b"a\0b")]), "string contains zeros");
        assert_eq!(
            f("%q", vec![A::S(b"a\"b\\c\nd\re\x001")]),
            "\"a\\\"b\\\\c\\\nd\\13e\\0001\""
        );
        assert_eq!(
            f(
                "%q|%q|%q|%q",
                vec![A::I(i64::MIN), A::F(2.0), A::F(f64::NAN), A::Nil]
            ),
            "0x8000000000000000|0x1p+1|(0/0)|nil"
        );
        let long = Box::leak(vec![b'x'; 120].into_boxed_slice());
        assert_eq!(f("%5s", vec![A::S(long)]).len(), 120);
    }

    #[test]
    fn validation_is_luas() {
        assert_eq!(e("%", vec![]), "no value");
        assert_eq!(e("%", vec![A::I(1)]), "invalid conversion '%' to 'format'");
        assert_eq!(
            e("%y", vec![A::I(1)]),
            "invalid conversion '%y' to 'format'"
        );
        assert_eq!(
            e("%#d", vec![A::I(1)]),
            "invalid conversion specification: '%#d'"
        );
        assert_eq!(
            e("%100d", vec![A::I(1)]),
            "invalid conversion specification: '%100d'"
        );
        assert_eq!(
            e("%5.2c", vec![A::I(65)]),
            "invalid conversion specification: '%5.2c'"
        );
        assert_eq!(
            e("%05s", vec![A::S(b"a")]),
            "invalid conversion specification: '%05s'"
        );
        assert_eq!(
            e("%5q", vec![A::S(b"a")]),
            "specifier '%q' cannot have modifiers"
        );
        assert_eq!(
            e("%-----------------------d", vec![A::I(1)]),
            "invalid format (too long)"
        );
        assert_eq!(f("%--+ 5d", vec![A::I(1)]), "+1   ");
        // The integer is checked before the specification for `%d`, after it for `%c`.
        assert_eq!(
            e("%#d", vec![A::F(1.5)]),
            "number has no integer representation"
        );
        assert_eq!(
            e("%.1c", vec![A::F(1.5)]),
            "invalid conversion specification: '%.1c'"
        );
    }
}
