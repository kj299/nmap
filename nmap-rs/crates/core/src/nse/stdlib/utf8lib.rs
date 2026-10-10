//! The `utf8` library, ported from `lutf8lib.c`.
//!
//! Positions are 1-based byte offsets, as in the C. Where the C reads one
//! byte past the end of a string — `utf8_decode` reading a continuation byte
//! that is not there, `offset` stepping onto the terminator — it reads the
//! terminating NUL; here a byte past the end reads as 0, which is what the C
//! reads.
//!
//! Arithmetic: positions are checked against the string's length before they
//! move, and move one byte at a time toward a bound already checked, so none
//! of the sums and differences below can overflow; a decoded sequence is at
//! most seven bytes. The `utf8` fuzz target exercises every function with
//! overflow checks on.
#![allow(clippy::arithmetic_side_effects)]

use piccolo::{Callback, CallbackReturn, Context, Error, Stack, Table, Value};

use super::strpack::PackError;
use super::{lua_error, lua_error_bytes, LuaArgs};

/// `MAXUNICODE`.
const MAX_UNICODE: u32 = 0x10_FFFF;
/// `MAXUTF`.
const MAX_UTF: u32 = 0x7FFF_FFFF;
/// `MSGInvalid`.
const MSG_INVALID: &str = "invalid UTF-8 code";
/// `UTF8PATT`: one UTF-8 character, as a Lua pattern.
pub const CHARPATTERN: &[u8] = b"[\0-\x7F\xC2-\xFD][\x80-\xBF]*";

/// The byte at `i`, or the terminating NUL past the end.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `iscont`.
fn is_cont(c: u8) -> bool {
    c & 0xC0 == 0x80
}

/// `utf8_decode` at `pos`: the code point and the position after it, or
/// `None` for an invalid sequence (and, when `strict`, for a surrogate or a
/// value past `MAXUNICODE`).
pub fn decode(s: &[u8], pos: usize, strict: bool) -> Option<(u32, usize)> {
    const LIMITS: [u32; 6] = [u32::MAX, 0x80, 0x800, 0x1_0000, 0x20_0000, 0x400_0000];
    let mut c = u32::from(at(s, pos));
    let mut res: u32 = 0;
    let mut count = 0usize;
    if c < 0x80 {
        res = c;
    } else {
        while c & 0x40 != 0 {
            count += 1;
            let cc = at(s, pos + count);
            if !is_cont(cc) {
                return None;
            }
            // `utfint` arithmetic: unsigned, so a malformed lead byte that
            // asks for six or seven continuations wraps rather than traps.
            res = res.wrapping_shl(6) | u32::from(cc & 0x3F);
            c = c.wrapping_shl(1);
        }
        // `res |= (c & 0x7F) << (count * 5)`, in the C's unsigned int.
        let first = (c & 0x7F)
            .checked_shl(u32::try_from(count * 5).ok()?)
            .unwrap_or(0);
        res |= first;
        if count > 5 || res > MAX_UTF || res < LIMITS[count.min(5)] {
            return None;
        }
    }
    if strict && (res > MAX_UNICODE || (0xD800..=0xDFFF).contains(&res)) {
        return None;
    }
    Some((res, pos + count + 1))
}

/// The low eight bits of `x`, as C's `cast_char`.
fn low_byte(x: u32) -> u8 {
    x.to_le_bytes()[0]
}

/// `luaO_utf8esc`: `x` (at most `MAXUTF`) in UTF-8, extended to six bytes.
pub fn encode(mut x: u32) -> Vec<u8> {
    if x < 0x80 {
        return vec![low_byte(x)];
    }
    let mut rev = Vec::with_capacity(6);
    let mut mfb: u32 = 0x3f;
    loop {
        rev.push(0x80 | low_byte(x & 0x3f));
        x >>= 6;
        mfb >>= 1;
        if x <= mfb {
            break;
        }
    }
    rev.push(low_byte((!mfb << 1) | x));
    rev.reverse();
    rev
}

/// `u_posrelat`.
fn posrelat(pos: i64, len: usize) -> i64 {
    let len = i64::try_from(len).unwrap_or(i64::MAX);
    if pos >= 0 {
        pos
    } else if pos.unsigned_abs() > len.unsigned_abs() {
        0
    } else {
        len + pos + 1
    }
}

/// Installs `utf8` into `ctx`'s globals and returns it.
pub fn load_utf8<'gc>(ctx: Context<'gc>) -> Table<'gc> {
    let t = Table::new(&ctx);
    t.set_field(ctx, "offset", Callback::from_fn(&ctx, byteoffset));
    t.set_field(ctx, "codepoint", Callback::from_fn(&ctx, codepoint));
    t.set_field(ctx, "char", Callback::from_fn(&ctx, utfchar));
    t.set_field(ctx, "len", Callback::from_fn(&ctx, utflen));
    t.set_field(ctx, "codes", Callback::from_fn(&ctx, iter_codes));
    t.set_field(ctx, "charpattern", ctx.intern(CHARPATTERN));
    ctx.set_global("utf8", t);
    t
}

fn raise<'gc>(ctx: Context<'gc>, name: &str, e: PackError) -> Error<'gc> {
    lua_error_bytes(ctx, &e.lua_message(name))
}

/// `luaL_argcheck`.
fn arg_check(ok: bool, arg: usize, msg: &str) -> Result<(), PackError> {
    if ok {
        Ok(())
    } else {
        Err(PackError::bad_argument(arg, msg))
    }
}

fn opt_integer(args: &LuaArgs<'_, '_, '_>, arg: usize, def: i64) -> Result<i64, PackError> {
    match args.get(arg) {
        None | Some(Value::Nil) => Ok(def),
        Some(_) => args.check_integer(arg),
    }
}

/// `utf8.len(s [, i [, j [, lax]]])`.
fn utflen<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let result = {
        let args = LuaArgs { ctx, stack: &stack };
        let run = || -> Result<Result<i64, i64>, PackError> {
            let s = args.string(1)?;
            let len = s.len();
            let leni = i64::try_from(len).unwrap_or(i64::MAX);
            let mut posi = posrelat(opt_integer(&args, 2, 1)?, len);
            let mut posj = posrelat(opt_integer(&args, 3, -1)?, len);
            let lax = args.get(4).is_some_and(|v| v.to_bool());
            arg_check(
                1 <= posi && posi - 1 <= leni,
                2,
                "initial position out of bounds",
            )?;
            posi -= 1;
            posj -= 1;
            arg_check(posj < leni, 3, "final position out of bounds")?;
            let mut n = 0i64;
            while posi <= posj {
                let at = usize::try_from(posi).unwrap_or(usize::MAX);
                match decode(&s, at, !lax) {
                    None => return Ok(Err(posi + 1)),
                    Some((_, next)) => posi = i64::try_from(next).unwrap_or(i64::MAX),
                }
                n += 1;
            }
            Ok(Ok(n))
        };
        run().map_err(|e| raise(ctx, "len", e))?
    };
    match result {
        Ok(n) => stack.replace(ctx, n),
        Err(pos) => stack.replace(ctx, (Value::Nil, pos)),
    }
    Ok(CallbackReturn::Return)
}

/// `utf8.codepoint(s [, i [, j [, lax]]])`.
fn codepoint<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let codes = {
        let args = LuaArgs { ctx, stack: &stack };
        let s = args.string(1).map_err(|e| raise(ctx, "codepoint", e))?;
        let len = s.len();
        let leni = i64::try_from(len).unwrap_or(i64::MAX);
        let posi = posrelat(
            opt_integer(&args, 2, 1).map_err(|e| raise(ctx, "codepoint", e))?,
            len,
        );
        let pose = posrelat(
            opt_integer(&args, 3, posi).map_err(|e| raise(ctx, "codepoint", e))?,
            len,
        );
        let lax = args.get(4).is_some_and(|v| v.to_bool());
        arg_check(posi >= 1, 2, "out of bounds").map_err(|e| raise(ctx, "codepoint", e))?;
        arg_check(pose <= leni, 3, "out of bounds").map_err(|e| raise(ctx, "codepoint", e))?;
        if posi > pose {
            stack.clear();
            return Ok(CallbackReturn::Return);
        }
        if pose - posi >= i64::from(i32::MAX) {
            return Err(lua_error(ctx, "string slice too long"));
        }
        let n = usize::try_from(pose - posi + 1).unwrap_or(usize::MAX);
        if !stack.has_room(n) {
            return Err(lua_error(ctx, "stack overflow (string slice too long)"));
        }
        let mut codes = Vec::new();
        let mut at = usize::try_from(posi - 1).unwrap_or(0);
        let end = usize::try_from(pose).unwrap_or(0);
        while at < end {
            match decode(&s, at, !lax) {
                None => return Err(lua_error(ctx, MSG_INVALID)),
                Some((code, next)) => {
                    codes.push(Value::Integer(i64::from(code)));
                    at = next;
                }
            }
        }
        codes
    };
    stack.clear();
    stack.extend(codes);
    Ok(CallbackReturn::Return)
}

/// `pushutfchar`: argument `arg` as a UTF-8 sequence.
fn utf_char(args: &LuaArgs<'_, '_, '_>, arg: usize) -> Result<Vec<u8>, PackError> {
    let code = args.check_integer(arg)? as u64;
    arg_check(code <= u64::from(MAX_UTF), arg, "value out of range")?;
    Ok(encode(u32::try_from(code).unwrap_or(MAX_UTF)))
}

/// `utf8.char(...)`.
fn utfchar<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let out = {
        let args = LuaArgs { ctx, stack: &stack };
        let mut out = Vec::new();
        for arg in 1..=stack.len() {
            out.extend(utf_char(&args, arg).map_err(|e| raise(ctx, "char", e))?);
        }
        out
    };
    let s = ctx.intern(&out);
    stack.replace(ctx, s);
    Ok(CallbackReturn::Return)
}

/// `utf8.offset(s, n [, i])`.
fn byteoffset<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let result = {
        let args = LuaArgs { ctx, stack: &stack };
        let s = args.string(1).map_err(|e| raise(ctx, "offset", e))?;
        let len = s.len();
        let leni = i64::try_from(len).unwrap_or(i64::MAX);
        let mut n = args.check_integer(2).map_err(|e| raise(ctx, "offset", e))?;
        let def = if n >= 0 { 1 } else { leni + 1 };
        let mut posi = posrelat(
            opt_integer(&args, 3, def).map_err(|e| raise(ctx, "offset", e))?,
            len,
        );
        arg_check(1 <= posi && posi - 1 <= leni, 3, "position out of bounds")
            .map_err(|e| raise(ctx, "offset", e))?;
        posi -= 1;
        let cont = |p: i64| is_cont(at(&s, usize::try_from(p).unwrap_or(usize::MAX)));
        if n == 0 {
            while posi > 0 && cont(posi) {
                posi -= 1;
            }
        } else {
            if cont(posi) {
                return Err(lua_error(ctx, "initial position is a continuation byte"));
            }
            if n < 0 {
                while n < 0 && posi > 0 {
                    loop {
                        posi -= 1;
                        if !(posi > 0 && cont(posi)) {
                            break;
                        }
                    }
                    n += 1;
                }
            } else {
                n -= 1;
                while n > 0 && posi < leni {
                    loop {
                        posi += 1;
                        if !cont(posi) {
                            break;
                        }
                    }
                    n -= 1;
                }
            }
        }
        (n == 0).then_some(posi + 1)
    };
    match result {
        Some(p) => stack.replace(ctx, p),
        None => stack.replace(ctx, Value::Nil),
    }
    Ok(CallbackReturn::Return)
}

/// `utf8.codes(s [, lax])`: the iterator, `s` and `0`.
fn iter_codes<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let (s, lax) = {
        let args = LuaArgs { ctx, stack: &stack };
        let lax = args.get(2).is_some_and(|v| v.to_bool());
        let s = args.string(1).map_err(|e| raise(ctx, "codes", e))?;
        // `luaL_argcheck(L, !iscontp(s), 1, MSGInvalid)`.
        arg_check(!is_cont(at(&s, 0)), 1, MSG_INVALID).map_err(|e| raise(ctx, "codes", e))?;
        (stack.get(0), lax)
    };
    let s = match s {
        Value::String(_) => s,
        v => Value::String(v.into_string(ctx).expect("checked by args.string")),
    };
    let iter = Callback::from_fn_with(&ctx, lax, |&lax, ctx, _, mut stack| {
        iter_aux(ctx, &mut stack, !lax)
    });
    stack.replace(ctx, (iter, s, 0));
    Ok(CallbackReturn::Return)
}

/// `iter_aux`.
fn iter_aux<'gc>(
    ctx: Context<'gc>,
    stack: &mut Stack<'gc, '_>,
    strict: bool,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let next = {
        let args = LuaArgs { ctx, stack };
        let s = args.string(1).map_err(|e| raise(ctx, "for iterator", e))?;
        let len = s.len() as u64;
        // `lua_tointeger`, as an unsigned: a negative or absent index is huge.
        let mut n = stack.get(1).to_integer().unwrap_or(0) as u64;
        if n < len {
            while is_cont(at(&s, usize::try_from(n).unwrap_or(usize::MAX))) {
                n += 1;
            }
        }
        if n >= len {
            None
        } else {
            match decode(&s, usize::try_from(n).unwrap_or(usize::MAX), strict) {
                Some((code, next)) if !is_cont(at(&s, next)) => Some((n + 1, code)),
                _ => return Err(lua_error(ctx, MSG_INVALID)),
            }
        }
    };
    match next {
        None => stack.clear(),
        Some((pos, code)) => stack.replace(ctx, (pos as i64, i64::from(code))),
    }
    Ok(CallbackReturn::Return)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        for code in [
            0u32,
            0x7F,
            0x80,
            0x7FF,
            0x800,
            0xFFFF,
            0x1_0000,
            0x10_FFFF,
            0x7FFF_FFFF,
        ] {
            let bytes = encode(code);
            assert_eq!(
                decode(&bytes, 0, false),
                Some((code, bytes.len())),
                "{code:#x}"
            );
        }
        assert_eq!(decode(&encode(0x11_0000), 0, true), None);
        assert_eq!(decode(&encode(0xD800), 0, true), None);
        // Overlong, and truncated at the end of the string.
        assert_eq!(decode(b"\xC0\x80", 0, false), None);
        assert_eq!(decode(b"\xE2\x82", 0, false), None);
    }
}
