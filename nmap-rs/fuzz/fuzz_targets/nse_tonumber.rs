// cargo-fuzz target for `tonumber`'s two string parsers, the script-facing
// byte parsers of `core::nse::stdlib::base` (M6.6 retrospective: the module's
// fuzz mapping reached only `chunk_id` and `string.rep` through `nse_tail`).
//
//   * `tonumber(s, base)`: `nmap_core::nse::stdlib::base::str2int` agrees with
//     a direct transliteration of `lbaselib.c`'s `b_str2int`, run as
//     `luaB_tonumber` runs it -- over the string as a C string, accepted only
//     when the numeral ends exactly at the string's length -- for every base
//     from 2 to 36: the same integer, wrapped as `lua_Unsigned` wraps, or the
//     same refusal (`fail`).
//   * `tonumber(s)`: the VM's conversion (`piccolo::Constant::to_numeric`, what
//     `Value::to_numeric` and so `tonumber` use) agrees with `lobject.c`'s
//     `l_str2int`, run as `lua_stringtonumber(L, s) == l + 1` runs it: where
//     the C reads an integer the VM gives that integer, and where the C's
//     integer reader refuses, the VM gives no integer (the C then tries a
//     float; a float is not checked here beyond not being an integer).
//
// Neither may panic on any bytes. Input layout: byte 0 picks the base
// (2 + byte % 35), the rest is the string.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::base::str2int;
use piccolo::Constant;

/// `SPACECHARS` (`lbaselib.c`), and `lisspace` in Lua's own `lctype` table:
/// the same six bytes.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\x0c' | b'\n' | b'\r' | b'\t' | b'\x0b')
}

/// `isalnum`, `isdigit` and `toupper` in the C locale nmap runs in.
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// `b_str2int(s, base, &n) == s + l` over the C string `s` (its bytes, then
/// a NUL; `*s` past the end reads that NUL), as `luaB_tonumber` calls it.
fn reference_str2int(bytes: &[u8], base: u64) -> Option<i64> {
    let at = |i: usize| bytes.get(i).copied().unwrap_or(0);
    // `strspn` stops at the terminating NUL, and so does every loop below.
    let mut i = 0;
    while at(i) != 0 && is_space(at(i)) {
        i += 1;
    }
    let mut neg = false;
    if at(i) == b'-' {
        i += 1;
        neg = true;
    } else if at(i) == b'+' {
        i += 1;
    }
    if !is_alnum(at(i)) {
        return None;
    }
    let mut n: u64 = 0;
    loop {
        let c = at(i);
        let digit = if c.is_ascii_digit() {
            u64::from(c - b'0')
        } else {
            u64::from(c.to_ascii_uppercase() - b'A') + 10
        };
        if digit >= base {
            return None;
        }
        n = n.wrapping_mul(base).wrapping_add(digit);
        i += 1;
        if !is_alnum(at(i)) {
            break;
        }
    }
    while at(i) != 0 && is_space(at(i)) {
        i += 1;
    }
    let n = if neg { 0u64.wrapping_sub(n) } else { n };
    (i == bytes.len()).then_some(n as i64)
}

/// `l_str2int` (`lobject.c`) over the C string `s`, as `luaO_str2num` and
/// `lua_stringtonumber(L, s) == l + 1` use it: the integer, or `None` where
/// the C's integer reader refuses the whole string.
fn reference_l_str2int(bytes: &[u8]) -> Option<i64> {
    const MAXBY10: u64 = (i64::MAX / 10) as u64;
    const MAXLASTD: u64 = (i64::MAX % 10) as u64;
    let at = |i: usize| bytes.get(i).copied().unwrap_or(0);
    let mut i = 0;
    while is_space(at(i)) {
        i += 1;
    }
    let neg = if at(i) == b'-' {
        i += 1;
        true
    } else {
        if at(i) == b'+' {
            i += 1;
        }
        false
    };
    let mut a: u64 = 0;
    let mut empty = true;
    if at(i) == b'0' && (at(i + 1) == b'x' || at(i + 1) == b'X') {
        i += 2;
        while at(i).is_ascii_hexdigit() {
            let c = at(i);
            let d = if c.is_ascii_digit() {
                c - b'0'
            } else {
                (c | 0x20) - b'a' + 10
            };
            a = a.wrapping_mul(16).wrapping_add(u64::from(d));
            empty = false;
            i += 1;
        }
    } else {
        while at(i).is_ascii_digit() {
            let d = u64::from(at(i) - b'0');
            if a >= MAXBY10 && (a > MAXBY10 || d > MAXLASTD + u64::from(neg)) {
                return None; // overflow: not accepted as an integer
            }
            a = a * 10 + d;
            empty = false;
            i += 1;
        }
    }
    while is_space(at(i)) {
        i += 1;
    }
    // `*s != '\0'`, and then `lua_stringtonumber`'s size must be `l + 1`:
    // the numeral ends at the string's end, not at an embedded NUL.
    if empty || i != bytes.len() {
        return None;
    }
    Some((if neg { 0u64.wrapping_sub(a) } else { a }) as i64)
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, s)) = data.split_first() else {
        return;
    };
    let base = 2 + u64::from(sel % 35);
    assert_eq!(
        str2int(s, base as i64),
        reference_str2int(s, base),
        "tonumber({s:?}, {base})"
    );

    let vm = Constant::String(s).to_numeric();
    match reference_l_str2int(s) {
        Some(n) => assert!(
            matches!(vm, Some(Constant::Integer(v)) if v == n),
            "tonumber({s:?}): the C reads the integer {n}, the VM {vm:?}"
        ),
        None => assert!(
            !matches!(vm, Some(Constant::Integer(_))),
            "tonumber({s:?}): the C reads no integer, the VM {vm:?}"
        ),
    }
});
