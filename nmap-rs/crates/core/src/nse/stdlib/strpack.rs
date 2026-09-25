//! `string.pack`, `string.unpack` and `string.packsize`, ported from
//! `liblua/lstrlib.c:1385-1830`.
//!
//! This is the function NSE's protocol libraries use to pull fields out of
//! packets: `unpack` appears at 1,087 call sites across 138 files of the shipped
//! corpus, and its `data` argument is, routinely, bytes a remote host chose. So
//! it is written here — in `core`, under `#![forbid(unsafe_code)]`, with no
//! dependency on the interpreter — rather than in the vendored VM, because this
//! is where the differential, fuzz and Miri gates can reach it.
//!
//! # What is ported, and what is deliberately not
//!
//! Every observable behaviour of the C is kept, including the ones that look
//! like accidents, because NSE scripts were written against them:
//!
//! * the format is a **C string**: it ends at the first NUL, so
//!   `pack("i4\0junk", 1)` packs one integer and ignores the rest;
//! * `X` **consumes** the option it takes its alignment from ("which is otherwise
//!   ignored", per the manual), so `Xi4` packs nothing;
//! * alignment is checked for being a power of two **after** it is clamped to
//!   `!`'s maximum, and not at all when it is 1;
//! * a count longer than ten digits stops being read part-way (`getnum`), and the
//!   digits left over are then parsed as the *next option* — so `c99999999999`
//!   is an "invalid format option '9'", not an overflow;
//! * native sizes and alignment are the host C ABI's, not constants: `l` is 8
//!   bytes on LP64 Linux and 4 on LLP64 Windows, exactly as it is for the C
//!   build on the same machine.
//!
//! What is **not** reproduced is anything that depends on C's memory model
//! rather than on Lua's semantics. `unpack`'s `z` uses `strlen`, which is safe in
//! C only because every Lua string carries a hidden NUL one past its end; here it
//! is a bounded search of the slice, with the same result. Every length and
//! offset is computed with checked arithmetic rather than by relying on the
//! argument that it cannot overflow. And the output buffer grows with
//! `try_reserve`, so an allocation the system refuses — `pack("c2000000000",
//! "")` asks for two gigabytes — becomes a catchable "not enough memory" error,
//! which is what the C raises, rather than a Rust out-of-memory abort, which is
//! what a plain `Vec` push would do.
//!
//! # Layering
//!
//! The functions here take their Lua arguments through [`PackArgs`], one method
//! per `luaL_check*` call in the C, and leave the conversion to the caller. That
//! is not abstraction for its own sake: string-to-number coercion, float-to-
//! integer conversion and number-to-string formatting are *interpreter*
//! semantics, each with its own differential corpus in the M6.0 suite, and
//! restating them here would create a second implementation to drift from the
//! first. The binding in [`super`] implements the trait with the VM's own
//! conversions; the tests and the fuzz target implement it over plain values.

use std::borrow::Cow;
use std::ffi::{c_int, c_long, c_short};
use std::fmt;
use std::mem::{offset_of, size_of};

/// `LUAL_PACKPADBYTE` (`lstrlib.c:1393`).
const PADBYTE: u8 = 0x00;

/// `MAXINTSIZE` (`lstrlib.c:1397`): the widest integer `i`/`I`/`s`/`!` accept.
const MAXINTSIZE: usize = 16;

/// `SZINT` (`lstrlib.c:1406`): `sizeof(lua_Integer)`.
const SZINT: usize = size_of::<i64>();

/// `MAXSIZE` (`lstrlib.c:49`). `size_t` is wider than `int` on every platform
/// this port targets, so it is `INT_MAX`.
const MAXSIZE: usize = i32::MAX as usize;

/// `LUAI_MAXSTACK` (`luaconf.h:749`). See [`unpack`] for how this is used and
/// why it is an approximation.
const MAX_RESULTS: usize = 1_000_000;

/// The native maximum alignment, computed the way `getoption` does rather than
/// assumed: `offsetof(struct cD, u)` for `struct cD { char c; union {
/// LUAI_MAXALIGN; } u; }` (`lstrlib.c:1490`), with `LUAI_MAXALIGN` spelled out
/// from `luaconf.h`. `repr(C)` gives this the C layout, so the answer is the
/// host ABI's — 8 on x86-64, but not something to hard-code.
///
/// The union is never read; it exists to be laid out. Declaring one needs no
/// `unsafe`, which is what lets this module stay `#![forbid(unsafe_code)]`.
#[allow(
    dead_code,
    reason = "a layout probe: its fields are measured, never read"
)]
#[repr(C)]
union MaxAlign {
    n: f64,
    u: f64,
    s: *const u8,
    i: i64,
    l: c_long,
}

#[allow(
    dead_code,
    reason = "a layout probe: its fields are measured, never read"
)]
#[repr(C)]
struct AlignProbe {
    c: u8,
    u: MaxAlign,
}

const NATIVE_MAXALIGN: usize = offset_of!(AlignProbe, u);

/// `nativeendian.little` (`lstrlib.c:1410`).
const NATIVE_LITTLE: bool = cfg!(target_endian = "little");

/// An error raised by `pack`, `unpack` or `packsize`.
///
/// The C raises two kinds: `luaL_argerror`, which names the offending argument,
/// and `luaL_error`, which does not. Both are ordinary Lua errors a script can
/// `pcall`. Which Lua function name goes in the message is the binding's
/// business, so it is left out here and supplied by [`PackError::lua_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError {
    /// The 1-based Lua argument number, for an argument error.
    pub arg: Option<usize>,
    /// The message, as the C words it.
    pub msg: String,
}

impl PackError {
    fn arg(arg: usize, msg: impl Into<String>) -> Self {
        Self {
            arg: Some(arg),
            msg: msg.into(),
        }
    }

    fn plain(msg: impl Into<String>) -> Self {
        Self {
            arg: None,
            msg: msg.into(),
        }
    }

    /// Argument error for a value that could not be converted, for use by
    /// [`PackArgs`] implementations. `msg` is the parenthesised part:
    /// `"number expected, got table"`.
    pub fn bad_argument(arg: usize, msg: impl Into<String>) -> Self {
        Self::arg(arg, msg)
    }

    /// The whole message as `luaL_argerror` would build it, given the name the
    /// function was called by.
    pub fn lua_message(&self, fname: &str) -> String {
        match self.arg {
            Some(n) => format!("bad argument #{n} to '{fname}' ({})", self.msg),
            None => self.msg.clone(),
        }
    }
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.arg {
            Some(n) => write!(f, "bad argument #{n} ({})", self.msg),
            None => f.write_str(&self.msg),
        }
    }
}

impl std::error::Error for PackError {}

/// The values `pack` consumes, fetched by 1-based Lua argument number — the
/// format string is argument 1, so the first value is argument 2.
///
/// One method per conversion the C performs. Each must behave as the named
/// `lauxlib` function does, errors included, which is why this is a trait: the
/// interpreter already implements those conversions, with their own corpora, and
/// the binding should use them rather than have this module restate them.
pub trait PackArgs {
    /// `luaL_checkinteger`: an integer, a float with an exact integer value, or a
    /// string that converts to one.
    fn integer(&mut self, arg: usize) -> Result<i64, PackError>;
    /// `luaL_checknumber`: a number, or a string that converts to one.
    fn number(&mut self, arg: usize) -> Result<f64, PackError>;
    /// `luaL_checklstring`: a string, or a number rendered as `tostring` would.
    fn bytes(&mut self, arg: usize) -> Result<Cow<'_, [u8]>, PackError>;
}

/// One value produced by [`unpack`], borrowing any bytes from the input.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Unpacked<'a> {
    Integer(i64),
    Float(f64),
    Bytes(&'a [u8]),
}

/// `KOption` (`lstrlib.c:1428`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KOption {
    Int,
    Uint,
    Float,
    Number,
    Double,
    Char,
    String,
    Zstr,
    Padding,
    Paddalign,
    Nop,
}

/// `Header` (`lstrlib.c:1418`), minus the `lua_State`.
struct Header {
    little: bool,
    maxalign: usize,
}

impl Header {
    /// `initheader` (`lstrlib.c:1478`).
    fn new() -> Self {
        Self {
            little: NATIVE_LITTLE,
            maxalign: 1,
        }
    }
}

/// A cursor over the format, with the C's end-of-string convention: the format
/// is cut at its first NUL up front, and reading past the end yields NUL.
///
/// Kept as the unread remainder rather than an index, so advancing it is a
/// re-slice and not an addition.
struct Fmt<'a> {
    rest: &'a [u8],
}

impl<'a> Fmt<'a> {
    fn new(s: &'a [u8]) -> Self {
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        Self { rest: &s[..end] }
    }

    fn peek(&self) -> u8 {
        self.rest.first().copied().unwrap_or(0)
    }

    fn at_end(&self) -> bool {
        self.rest.is_empty()
    }

    fn next(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((&c, rest)) => {
                self.rest = rest;
                c
            }
            None => 0,
        }
    }
}

/// `(MAXSIZE - 9) / 10`, the point past which `getnum` stops reading digits.
const GETNUM_LIMIT: i32 = 214_748_363;
const _: () = assert!(GETNUM_LIMIT as usize == (MAXSIZE - 9) / 10);

/// `getnum` (`lstrlib.c:1449`).
///
/// The loop stops reading once the value passes `(MAXSIZE - 9) / 10`, which
/// leaves any further digits in the format to be read as the next option. That
/// is kept: it is what makes `c99999999999` an invalid-option error.
fn getnum(f: &mut Fmt<'_>, df: i32) -> i32 {
    if !f.peek().is_ascii_digit() {
        return df;
    }
    let mut a: i32 = 0;
    loop {
        // The byte was just peeked as a digit, so this is its value.
        let d = i32::from(f.next().saturating_sub(b'0'));
        // Cannot overflow: the loop only continues while `a <= GETNUM_LIMIT`,
        // and `GETNUM_LIMIT * 10 + 9 < i32::MAX`. Saturating rather than plain
        // arithmetic anyway, so that if that bound were ever wrong the result
        // would be a wrong size — which every caller range-checks — not a panic.
        debug_assert!(a <= GETNUM_LIMIT);
        a = a.saturating_mul(10).saturating_add(d);
        if !(f.peek().is_ascii_digit() && a <= GETNUM_LIMIT) {
            return a;
        }
    }
}

/// `getnumlimit` (`lstrlib.c:1466`).
fn getnumlimit(f: &mut Fmt<'_>, df: usize) -> Result<usize, PackError> {
    // `df` is always a native size: at most 16.
    let sz = getnum(f, i32::try_from(df).unwrap_or(i32::MAX));
    match usize::try_from(sz) {
        Ok(sz) if (1..=MAXINTSIZE).contains(&sz) => Ok(sz),
        _ => Err(PackError::plain(format!(
            "integral size ({sz}) out of limits [1,{MAXINTSIZE}]"
        ))),
    }
}

/// `getoption` (`lstrlib.c:1488`).
fn getoption(h: &mut Header, f: &mut Fmt<'_>) -> Result<(KOption, usize), PackError> {
    let opt = f.next();
    Ok(match opt {
        b'b' => (KOption::Int, size_of::<u8>()),
        b'B' => (KOption::Uint, size_of::<u8>()),
        b'h' => (KOption::Int, size_of::<c_short>()),
        b'H' => (KOption::Uint, size_of::<c_short>()),
        b'l' => (KOption::Int, size_of::<c_long>()),
        b'L' => (KOption::Uint, size_of::<c_long>()),
        b'j' => (KOption::Int, SZINT),
        b'J' => (KOption::Uint, SZINT),
        b'T' => (KOption::Uint, size_of::<usize>()),
        b'f' => (KOption::Float, size_of::<f32>()),
        b'n' => (KOption::Number, size_of::<f64>()),
        b'd' => (KOption::Double, size_of::<f64>()),
        b'i' => (KOption::Int, getnumlimit(f, size_of::<c_int>())?),
        b'I' => (KOption::Uint, getnumlimit(f, size_of::<c_int>())?),
        b's' => (KOption::String, getnumlimit(f, size_of::<usize>())?),
        b'c' => {
            let size = getnum(f, -1);
            let Ok(size) = usize::try_from(size) else {
                return Err(PackError::plain("missing size for format option 'c'"));
            };
            (KOption::Char, size)
        }
        b'z' => (KOption::Zstr, 0),
        b'x' => (KOption::Padding, 1),
        b'X' => (KOption::Paddalign, 0),
        b' ' => (KOption::Nop, 0),
        b'<' => {
            h.little = true;
            (KOption::Nop, 0)
        }
        b'>' => {
            h.little = false;
            (KOption::Nop, 0)
        }
        b'=' => {
            h.little = NATIVE_LITTLE;
            (KOption::Nop, 0)
        }
        b'!' => {
            h.maxalign = getnumlimit(f, NATIVE_MAXALIGN)?;
            (KOption::Nop, 0)
        }
        // The C formats this with `%c`, so a NUL can never reach it: the format
        // was cut at the first NUL and the loop stops there.
        _ => {
            return Err(PackError::plain(format!(
                "invalid format option '{}'",
                char::from(opt)
            )))
        }
    })
}

/// `getdetails` (`lstrlib.c:1541`): the option, its size, and how many padding
/// bytes align it given `totalsize` bytes so far.
fn getdetails(
    h: &mut Header,
    totalsize: usize,
    f: &mut Fmt<'_>,
) -> Result<(KOption, usize, usize), PackError> {
    let (opt, size) = getoption(h, f)?;
    let mut align = size;
    if opt == KOption::Paddalign {
        // `**fmt == '\0' || getoption(...) == Kchar || align == 0`, short-circuit
        // order kept: an `X` at the end errors without reading anything, and an
        // invalid option after `X` reports itself before `X` does.
        let invalid = || PackError::arg(1, "invalid next option for option 'X'");
        if f.at_end() {
            return Err(invalid());
        }
        let (next, next_align) = getoption(h, f)?;
        align = next_align;
        if next == KOption::Char || align == 0 {
            return Err(invalid());
        }
    }
    let ntoalign = if align <= 1 || opt == KOption::Char {
        0
    } else {
        let align = align.min(h.maxalign);
        if !align.is_power_of_two() {
            return Err(PackError::arg(
                1,
                "format asks for alignment not power of 2",
            ));
        }
        // `(align - (totalsize & (align - 1))) & (align - 1)`. Both subtractions
        // are exact: `align` is at least 1 (`maxalign` is range-checked to
        // `1..=16`), and `totalsize & mask` is at most `mask`, below `align`.
        // `wrapping_` states that they are modular, as the C's `int` arithmetic
        // is not, without pretending they could wrap.
        let mask = align.wrapping_sub(1);
        align.wrapping_sub(totalsize & mask) & mask
    };
    Ok((opt, size, ntoalign))
}

/// Reserve `additional` bytes or report the failure as a Lua error. The C
/// raises "not enough memory" when `luaL_Buffer` cannot grow; a plain `Vec`
/// push would abort the process instead, and `pcall` cannot catch an abort.
fn grow(out: &mut Vec<u8>, additional: usize) -> Result<(), PackError> {
    out.try_reserve(additional)
        .map_err(|_| PackError::plain("not enough memory"))
}

/// Append `n` padding bytes.
fn pad(out: &mut Vec<u8>, n: usize) -> Result<(), PackError> {
    grow(out, n)?;
    out.extend(std::iter::repeat_n(PADBYTE, n));
    Ok(())
}

/// Widen up to eight little-endian bytes to a `u64`, sign-extending from the
/// top byte when `signed`, zero-extending otherwise.
///
/// This is `unpackint`'s `(res ^ mask) - mask` without the shift arithmetic,
/// and it is also how `pack`'s overflow checks are expressed: a value fits in
/// `size` bytes exactly when widening its low `size` bytes gives it back.
fn widen_le(low: &[u8], signed: bool) -> u64 {
    let negative = signed && low.last().is_some_and(|&b| b & 0x80 != 0);
    let mut w = [if negative { 0xff } else { 0 }; SZINT];
    let n = low.len().min(SZINT);
    w[..n].copy_from_slice(&low[..n]);
    u64::from_le_bytes(w)
}

/// `-(1 << (size*NB - 1)) <= v < 1 << (size*NB - 1)`, the C's signed range
/// check for `size < SZINT`. True for every value at eight bytes and above,
/// where the C does not check.
fn fits_signed(v: i64, size: usize) -> bool {
    let le = v.to_le_bytes();
    le.get(..size)
        .filter(|low| low.len() < SZINT)
        .is_none_or(|low| widen_le(low, true) as i64 == v)
}

/// `(lua_Unsigned)v < 1 << (size*NB)`, the C's unsigned range check for
/// `size < SZINT`: every byte above the low `size` is zero. True at eight bytes
/// and above, where the C does not check.
fn fits_unsigned(v: u64, size: usize) -> bool {
    v.to_le_bytes()
        .get(size..)
        .is_none_or(|high| high.iter().all(|&b| b == 0))
}

/// `packint` (`lstrlib.c:1568`). Bytes past the eighth are sign-extension:
/// `0xff` for a negative value, `0` otherwise.
fn packint(
    out: &mut Vec<u8>,
    n: u64,
    little: bool,
    size: usize,
    neg: bool,
) -> Result<(), PackError> {
    let mut buf = [if neg { 0xff } else { 0 }; MAXINTSIZE];
    let low = size.min(SZINT);
    buf[..low].copy_from_slice(&n.to_le_bytes()[..low]);
    // `size` comes from `getnumlimit` or a native width, so it is at most 16;
    // an error rather than a panic if that ever stopped being true.
    let field = buf
        .get_mut(..size)
        .ok_or_else(|| PackError::plain("integral size out of limits"))?;
    if !little {
        field.reverse();
    }
    grow(out, size)?;
    out.extend_from_slice(field);
    Ok(())
}

/// `str_pack` (`lstrlib.c:1601`).
pub fn pack(fmt: &[u8], args: &mut impl PackArgs) -> Result<Vec<u8>, PackError> {
    let mut h = Header::new();
    let mut f = Fmt::new(fmt);
    let mut out = Vec::new();
    let mut totalsize: usize = 0;
    // The Lua argument the next value comes from; the format is argument 1.
    let mut next_arg: usize = 2;
    let too_large = || PackError::plain("format result too large");

    while !f.at_end() {
        let (opt, size, ntoalign) = getdetails(&mut h, totalsize, &mut f)?;
        totalsize = totalsize
            .checked_add(ntoalign)
            .and_then(|t| t.checked_add(size))
            .ok_or_else(too_large)?;
        pad(&mut out, ntoalign)?;
        // The C increments `arg` for every option and decrements it again for
        // the three that consume no value; this only increments for the rest.
        // Saturating: it cannot pass the format's length, but a wrong argument
        // number is a wrong message, and a trap would be a dead process.
        let arg = next_arg;
        if !matches!(opt, KOption::Padding | KOption::Paddalign | KOption::Nop) {
            next_arg = next_arg.saturating_add(1);
        }
        match opt {
            KOption::Int => {
                let n = args.integer(arg)?;
                if !fits_signed(n, size) {
                    return Err(PackError::arg(arg, "integer overflow"));
                }
                packint(&mut out, n as u64, h.little, size, n < 0)?;
            }
            KOption::Uint => {
                let n = args.integer(arg)?;
                // A negative value is huge once reinterpreted as unsigned, and
                // so overflows every size below eight, as in the C.
                if !fits_unsigned(n as u64, size) {
                    return Err(PackError::arg(arg, "unsigned overflow"));
                }
                packint(&mut out, n as u64, h.little, size, false)?;
            }
            KOption::Float => {
                // `(float)luaL_checknumber(...)`. Out of `f32` range this is
                // undefined behaviour in ISO C and infinity on every IEEE target
                // nmap ships for; Rust's `as` defines it as infinity.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "the C's `(float)` conversion, narrowing on purpose"
                )]
                let v = args.number(arg)? as f32;
                let bytes = if h.little {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                grow(&mut out, bytes.len())?;
                out.extend_from_slice(&bytes);
            }
            KOption::Number | KOption::Double => {
                let v = args.number(arg)?;
                let bytes = if h.little {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                grow(&mut out, bytes.len())?;
                out.extend_from_slice(&bytes);
            }
            KOption::Char => {
                let s = args.bytes(arg)?;
                let Some(fill) = size.checked_sub(s.len()) else {
                    return Err(PackError::arg(arg, "string longer than given size"));
                };
                grow(&mut out, s.len())?;
                out.extend_from_slice(&s);
                pad(&mut out, fill)?;
            }
            KOption::String => {
                let s = args.bytes(arg)?;
                let len = s.len();
                if !(size >= size_of::<usize>() || fits_unsigned(len as u64, size)) {
                    return Err(PackError::arg(
                        arg,
                        "string length does not fit in given size",
                    ));
                }
                packint(&mut out, len as u64, h.little, size, false)?;
                grow(&mut out, len)?;
                out.extend_from_slice(&s);
                totalsize = totalsize.checked_add(len).ok_or_else(too_large)?;
            }
            KOption::Zstr => {
                let s = args.bytes(arg)?;
                // `strlen(s) == len`.
                if s.contains(&0) {
                    return Err(PackError::arg(arg, "string contains zeros"));
                }
                let with_nul = s.len().checked_add(1).ok_or_else(too_large)?;
                grow(&mut out, with_nul)?;
                out.extend_from_slice(&s);
                out.push(0);
                totalsize = totalsize.checked_add(with_nul).ok_or_else(too_large)?;
            }
            KOption::Padding => pad(&mut out, 1)?,
            KOption::Paddalign | KOption::Nop => {}
        }
    }
    Ok(out)
}

/// `str_packsize` (`lstrlib.c:1700`).
pub fn packsize(fmt: &[u8]) -> Result<i64, PackError> {
    let mut h = Header::new();
    let mut f = Fmt::new(fmt);
    let mut totalsize: usize = 0;
    let too_large = || PackError::arg(1, "format result too large");
    while !f.at_end() {
        let (opt, size, ntoalign) = getdetails(&mut h, totalsize, &mut f)?;
        if opt == KOption::String || opt == KOption::Zstr {
            return Err(PackError::arg(1, "variable-length format"));
        }
        let size = size.checked_add(ntoalign).ok_or_else(too_large)?;
        // `totalsize <= MAXSIZE - size`, with the subtraction checked: `size` is
        // at most `MAXSIZE - 8` today, but that is an argument, not a type.
        if MAXSIZE
            .checked_sub(size)
            .is_none_or(|room| totalsize > room)
        {
            return Err(too_large());
        }
        totalsize = totalsize.checked_add(size).ok_or_else(too_large)?;
    }
    // Bounded by `MAXSIZE` just above, so this always fits.
    Ok(i64::try_from(totalsize).unwrap_or(i64::MAX))
}

/// `unpackint` (`lstrlib.c:1728`), reading all of `field`.
fn unpackint(field: &[u8], little: bool, signed: bool) -> Result<i64, PackError> {
    let size = field.len();
    let mut le = [0u8; MAXINTSIZE];
    let dst = le
        .get_mut(..size)
        .ok_or_else(|| PackError::plain("integral size out of limits"))?;
    dst.copy_from_slice(field);
    if !little {
        dst.reverse();
    }
    let res = widen_le(&le[..size.min(SZINT)], signed);
    if let Some(high) = le.get(SZINT..size) {
        // Bytes past the eighth must be pure sign-extension, or the value does
        // not fit in a Lua integer.
        let mask = if !signed || (res as i64) >= 0 {
            0
        } else {
            0xff
        };
        if high.iter().any(|&b| b != mask) {
            return Err(PackError::plain(format!(
                "{size}-byte integer does not fit into Lua Integer"
            )));
        }
    }
    Ok(res as i64)
}

/// `posrelatI` (`lstrlib.c:71`): a 1-based, possibly negative position, clipped
/// to `1` below. Not clipped above — the caller checks that.
fn posrelat_i(pos: i64, len: usize) -> u64 {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    let magnitude = pos.unsigned_abs();
    if pos > 0 {
        magnitude
    } else if pos == 0 || magnitude > len {
        1
    } else {
        // `pos` is in `-len ..= -1`, so this is in `1 ..= len` and cannot fail.
        len.checked_sub(magnitude)
            .and_then(|p| p.checked_add(1))
            .unwrap_or(1)
    }
}

/// `str_unpack` (`lstrlib.c:1754`). Returns the values and the position one
/// past the last byte read, which Lua returns as a final extra value.
///
/// `init` is argument 3 after `luaL_optinteger(L, 3, 1)`.
///
/// # The result limit
///
/// The C calls `luaL_checkstack(L, 2, "too many results")` per option, which
/// fails once the Lua stack would pass `LUAI_MAXSTACK`: a million slots, less
/// whatever the caller already has on it. The exact point therefore depends on
/// call depth and cannot be reproduced by a function that does not see the
/// stack. This raises the same error at a fixed [`MAX_RESULTS`], which is the
/// C's ceiling taken at an empty stack. Every result consumes at least one
/// format byte, so without a limit the count would still be bounded by the
/// format's length — but a bound nobody wrote down is not one worth relying on.
pub fn unpack<'a>(
    fmt: &[u8],
    data: &'a [u8],
    init: i64,
) -> Result<(Vec<Unpacked<'a>>, i64), PackError> {
    let ld = data.len();
    let too_short = || PackError::arg(2, "data string too short");
    // Every position below is checked against the data's length before it is
    // used; the additions are checked as well so that a mistake in that
    // reasoning is an error rather than an overflow trap.
    let advance = |pos: usize, n: usize| pos.checked_add(n).ok_or_else(too_short);

    // `posrelatI(...) - 1`, with `posrelatI` never below 1.
    let mut pos = match posrelat_i(init, ld)
        .checked_sub(1)
        .and_then(|p| usize::try_from(p).ok())
    {
        Some(p) if p <= ld => p,
        _ => return Err(PackError::arg(3, "initial position out of string")),
    };
    let mut h = Header::new();
    let mut f = Fmt::new(fmt);
    let mut out = Vec::new();

    while !f.at_end() {
        let (opt, size, ntoalign) = getdetails(&mut h, pos, &mut f)?;
        // `(size_t)ntoalign + size <= ld - pos`.
        let remaining = ld.checked_sub(pos).ok_or_else(too_short)?;
        if ntoalign
            .checked_add(size)
            .is_none_or(|need| need > remaining)
        {
            return Err(too_short());
        }
        pos = advance(pos, ntoalign)?;
        // `luaL_checkstack(L, 2, ...)`: the item and the final position.
        if out.len().saturating_add(2) > MAX_RESULTS {
            return Err(PackError::plain("stack overflow (too many results)"));
        }
        let field_end = advance(pos, size)?;
        let field = data.get(pos..field_end).ok_or_else(too_short)?;
        match opt {
            KOption::Int | KOption::Uint => {
                out.push(Unpacked::Integer(unpackint(
                    field,
                    h.little,
                    opt == KOption::Int,
                )?));
            }
            KOption::Float => {
                let b: [u8; 4] = field.try_into().map_err(|_| too_short())?;
                let v = if h.little {
                    f32::from_le_bytes(b)
                } else {
                    f32::from_be_bytes(b)
                };
                out.push(Unpacked::Float(f64::from(v)));
            }
            KOption::Number | KOption::Double => {
                let b: [u8; 8] = field.try_into().map_err(|_| too_short())?;
                let v = if h.little {
                    f64::from_le_bytes(b)
                } else {
                    f64::from_be_bytes(b)
                };
                out.push(Unpacked::Float(v));
            }
            KOption::Char => out.push(Unpacked::Bytes(field)),
            KOption::String => {
                // `(size_t)unpackint(...)`: a negative length reinterprets as a
                // huge one and fails the bound below, as it does in the C.
                let claimed = unpackint(field, h.little, false)? as u64;
                // `len <= ld - pos - size`.
                let room = ld.checked_sub(field_end).ok_or_else(too_short)?;
                let len = usize::try_from(claimed)
                    .ok()
                    .filter(|&len| len <= room)
                    .ok_or_else(too_short)?;
                let end = advance(field_end, len)?;
                out.push(Unpacked::Bytes(
                    data.get(field_end..end).ok_or_else(too_short)?,
                ));
                pos = advance(pos, len)?;
            }
            KOption::Zstr => {
                // `strlen(data + pos)` followed by `pos + len < ld`. The C's
                // `strlen` is bounded only by the NUL every Lua string carries
                // one past its end; here the search is bounded by the slice, and
                // "no NUL before the end" is exactly the case the C rejects.
                let rest = data.get(pos..).ok_or_else(too_short)?;
                let Some(len) = rest.iter().position(|&b| b == 0) else {
                    return Err(PackError::arg(2, "unfinished string for format 'z'"));
                };
                out.push(Unpacked::Bytes(&rest[..len]));
                pos = advance(advance(pos, len)?, 1)?;
            }
            KOption::Paddalign | KOption::Padding | KOption::Nop => {}
        }
        pos = advance(pos, size)?;
    }
    // `pos <= ld`, and `ld` is the length of an allocation, so neither the
    // increment nor the conversion can fail.
    let next = pos
        .checked_add(1)
        .and_then(|n| i64::try_from(n).ok())
        .unwrap_or(i64::MAX);
    Ok((out, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`PackArgs`] over already-converted values, for tests: no coercion, so
    /// asking for the wrong kind is an error.
    #[derive(Debug, Clone)]
    enum V {
        I(i64),
        F(f64),
        S(Vec<u8>),
    }

    struct Args(Vec<V>);

    impl PackArgs for Args {
        fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
            match arg.checked_sub(2).and_then(|i| self.0.get(i)) {
                Some(V::I(i)) => Ok(*i),
                _ => Err(PackError::bad_argument(arg, "number expected")),
            }
        }
        fn number(&mut self, arg: usize) -> Result<f64, PackError> {
            match arg.checked_sub(2).and_then(|i| self.0.get(i)) {
                Some(V::I(i)) => Ok(*i as f64),
                Some(V::F(f)) => Ok(*f),
                _ => Err(PackError::bad_argument(arg, "number expected")),
            }
        }
        fn bytes(&mut self, arg: usize) -> Result<Cow<'_, [u8]>, PackError> {
            match arg.checked_sub(2).and_then(|i| self.0.get(i)) {
                Some(V::S(s)) => Ok(Cow::Borrowed(s)),
                _ => Err(PackError::bad_argument(arg, "string expected")),
            }
        }
    }

    fn p(fmt: &str, args: Vec<V>) -> Result<Vec<u8>, PackError> {
        pack(fmt.as_bytes(), &mut Args(args))
    }

    #[test]
    fn integers_in_both_byte_orders() {
        assert_eq!(p("<i4", vec![V::I(1)]).unwrap(), [1, 0, 0, 0]);
        assert_eq!(p(">i4", vec![V::I(1)]).unwrap(), [0, 0, 0, 1]);
        assert_eq!(p("<i2", vec![V::I(-2)]).unwrap(), [0xfe, 0xff]);
        assert_eq!(p(">I3", vec![V::I(0x010203)]).unwrap(), [1, 2, 3]);
    }

    #[test]
    fn wide_integers_sign_extend_past_the_eighth_byte() {
        let neg = p("<i16", vec![V::I(-1)]).unwrap();
        assert_eq!(neg, [0xff; 16]);
        let pos = p("<i16", vec![V::I(1)]).unwrap();
        assert_eq!(pos[0], 1);
        assert!(pos[1..].iter().all(|&b| b == 0));
        // Unsigned never sign-extends, even from a negative Lua integer.
        let u = p("<I16", vec![V::I(-1)]).unwrap();
        assert_eq!(&u[..8], [0xff; 8]);
        assert_eq!(&u[8..], [0; 8]);
    }

    #[test]
    fn overflow_is_an_argument_error_not_a_wrap() {
        assert_eq!(p("i1", vec![V::I(127)]).unwrap(), [127]);
        assert_eq!(p("i1", vec![V::I(128)]).unwrap_err().arg, Some(2));
        assert_eq!(p("i1", vec![V::I(-129)]).unwrap_err().arg, Some(2));
        assert_eq!(
            p("I1", vec![V::I(-1)]).unwrap_err().msg,
            "unsigned overflow"
        );
        assert_eq!(
            p("I1", vec![V::I(256)]).unwrap_err().msg,
            "unsigned overflow"
        );
        // No overflow check at eight bytes and above.
        assert!(p("I8", vec![V::I(-1)]).is_ok());
        assert!(p("i8", vec![V::I(i64::MIN)]).is_ok());
    }

    #[test]
    fn integral_size_limits() {
        for bad in ["i0", "i17", "I0", "s17", "!17", "!0"] {
            let e = p(bad, vec![V::I(0)]).unwrap_err();
            assert!(e.msg.starts_with("integral size"), "{bad}: {e:?}");
        }
    }

    #[test]
    fn the_format_is_a_c_string() {
        // Everything after the NUL is invisible, so the second argument is unused
        // and no error is raised for its type.
        assert_eq!(p("<i1\0zzz", vec![V::I(5)]).unwrap(), [5]);
    }

    #[test]
    fn x_consumes_the_option_it_aligns_to() {
        // `!4` makes alignment matter; `Xi4` pads to four and packs nothing.
        assert_eq!(p("!4 b Xi4", vec![V::I(1)]).unwrap(), [1, 0, 0, 0]);
        assert_eq!(
            p("X", vec![]).unwrap_err().msg,
            "invalid next option for option 'X'"
        );
        assert_eq!(
            p("Xc1", vec![]).unwrap_err().msg,
            "invalid next option for option 'X'"
        );
        // An invalid option after X reports itself, not X.
        assert!(p("Xq", vec![]).unwrap_err().msg.contains("'q'"));
    }

    #[test]
    fn alignment_is_power_of_two_checked_after_clamping() {
        // `!3` is a legal maxalign; an `i4` then clamps to 3 and fails the check.
        assert_eq!(
            p("!3 i4", vec![V::I(0)]).unwrap_err().msg,
            "format asks for alignment not power of 2"
        );
        // But `i3` alone never aligns: the default maxalign is 1.
        assert!(p("i3", vec![V::I(0)]).is_ok());
    }

    #[test]
    fn a_long_count_spills_into_the_next_option() {
        let e = p("c99999999999", vec![V::S(vec![])]).unwrap_err();
        assert_eq!(e.msg, "invalid format option '9'");
        assert_eq!(
            p("c", vec![]).unwrap_err().msg,
            "missing size for format option 'c'"
        );
    }

    #[test]
    fn strings() {
        assert_eq!(p("c3", vec![V::S(b"ab".to_vec())]).unwrap(), b"ab\0");
        assert!(p("c1", vec![V::S(b"ab".to_vec())]).is_err());
        assert_eq!(p("<s1", vec![V::S(b"hi".to_vec())]).unwrap(), b"\x02hi");
        assert_eq!(p("z", vec![V::S(b"hi".to_vec())]).unwrap(), b"hi\0");
        assert_eq!(
            p("z", vec![V::S(b"h\0i".to_vec())]).unwrap_err().msg,
            "string contains zeros"
        );
        let long = vec![b'x'; 256];
        assert_eq!(
            p("s1", vec![V::S(long)]).unwrap_err().msg,
            "string length does not fit in given size"
        );
    }

    #[test]
    fn packsize_rejects_variable_length() {
        assert_eq!(packsize(b"i4i8").unwrap(), 12);
        assert_eq!(packsize(b"!8 b i8").unwrap(), 16);
        assert_eq!(packsize(b"s").unwrap_err().msg, "variable-length format");
        assert_eq!(packsize(b"z").unwrap_err().msg, "variable-length format");
        // Each `c` stays under MAXSIZE; together they do not.
        assert_eq!(
            packsize(b"c2000000000c2000000000").unwrap_err().msg,
            "format result too large"
        );
    }

    #[test]
    fn unpack_round_trips_and_reports_the_next_position() {
        let (v, next) = unpack(b"<i2 >I2", &[0xfe, 0xff, 0x01, 0x02], 1).unwrap();
        assert_eq!(v, [Unpacked::Integer(-2), Unpacked::Integer(0x0102)]);
        assert_eq!(next, 5);
    }

    #[test]
    fn unpack_never_reads_past_the_data() {
        assert_eq!(
            unpack(b"i4", &[1, 2, 3], 1).unwrap_err().msg,
            "data string too short"
        );
        // `s1` whose length byte claims more than remains.
        assert_eq!(
            unpack(b"s1", &[9, b'a'], 1).unwrap_err().msg,
            "data string too short"
        );
        // `z` with no terminator: the C's `strlen` would stop at the hidden NUL.
        assert_eq!(
            unpack(b"z", b"abc", 1).unwrap_err().msg,
            "unfinished string for format 'z'"
        );
        let (v, next) = unpack(b"z", b"ab\0cd", 1).unwrap();
        assert_eq!(v, [Unpacked::Bytes(b"ab")]);
        assert_eq!(next, 4);
    }

    #[test]
    fn unpack_initial_position() {
        let d = [1u8, 2, 3];
        assert_eq!(unpack(b"B", &d, 2).unwrap().0, [Unpacked::Integer(2)]);
        assert_eq!(unpack(b"B", &d, -1).unwrap().0, [Unpacked::Integer(3)]);
        // Below the start clips to 1; zero means 1.
        assert_eq!(unpack(b"B", &d, -99).unwrap().0, [Unpacked::Integer(1)]);
        assert_eq!(unpack(b"B", &d, 0).unwrap().0, [Unpacked::Integer(1)]);
        // One past the end is a legal position with nothing left to read.
        assert_eq!(unpack(b"", &d, 4).unwrap(), (vec![], 4));
        assert_eq!(unpack(b"", &d, 5).unwrap_err().arg, Some(3));
        assert_eq!(unpack(b"", &d, i64::MAX).unwrap_err().arg, Some(3));
        assert_eq!(unpack(b"", &d, i64::MIN).unwrap(), (vec![], 1));
    }

    #[test]
    fn wide_unpack_checks_the_bytes_it_cannot_keep() {
        let mut ok = [0u8; 16];
        ok[0] = 7;
        assert_eq!(unpack(b"<i16", &ok, 1).unwrap().0, [Unpacked::Integer(7)]);
        let mut bad = ok;
        bad[15] = 1;
        assert_eq!(
            unpack(b"<i16", &bad, 1).unwrap_err().msg,
            "16-byte integer does not fit into Lua Integer"
        );
        // A negative value must be followed by 0xff, not 0.
        assert_eq!(
            unpack(b"<i16", &[0xff; 16], 1).unwrap().0,
            [Unpacked::Integer(-1)]
        );
    }

    #[test]
    fn floats_round_trip_through_their_width() {
        let b = p("<f", vec![V::F(1.5)]).unwrap();
        assert_eq!(unpack(b"<f", &b, 1).unwrap().0, [Unpacked::Float(1.5)]);
        let b = p(">d", vec![V::F(-0.1)]).unwrap();
        assert_eq!(unpack(b">d", &b, 1).unwrap().0, [Unpacked::Float(-0.1)]);
        // Out of f32 range is infinity, not undefined behaviour.
        let b = p("<f", vec![V::F(1e300)]).unwrap();
        assert_eq!(
            unpack(b"<f", &b, 1).unwrap().0,
            [Unpacked::Float(f64::INFINITY)]
        );
    }

    #[test]
    fn native_layout_matches_the_c_abi() {
        assert!(NATIVE_MAXALIGN.is_power_of_two());
        assert!(NATIVE_MAXALIGN >= align_of_i64_in_c());
    }

    fn align_of_i64_in_c() -> usize {
        #[allow(dead_code, reason = "a layout probe")]
        #[repr(C)]
        struct P {
            c: u8,
            i: i64,
        }
        offset_of!(P, i)
    }
}
