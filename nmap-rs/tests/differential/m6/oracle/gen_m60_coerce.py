#!/usr/bin/env python3
"""Emit the string-to-number coercion corpus.

`'10' + 1` is integer `11` in Lua and was float `11.0` here. That one case was
ledgered, and it turned out to be the visible corner of four separate defects,
all in the same conversion:

  1. **Subtype.** The arithmetic operators decided between the integer and the
     float path *before* coercing, so any string operand fell to the float arm.
     Lua coerces first (`luaO_str2num` tries `l_str2int` before `l_str2d`) and
     then decides, so a string that parses as an integer keeps that subtype.
  2. **Which operators coerce at all.** `luaO_rawarith` (`lobject.c:89`) uses
     the *no-string* conversions throughout; strings re-enter arithmetic only
     through the metamethods `lstrlib.c` installs on the string metatable, and
     that list is `__add __sub __mul __mod __pow __div __idiv __unm` — no
     bitwise ones. So `'10' | 0` is an error in Lua, and answered 10 here.
  3. **The float-to-integer range.** `2^63` is exactly representable as a
     double and is not an `i64`; Rust's `as` saturates it to `i64::MAX` instead
     of refusing it, so `2^63 | 0` answered `maxinteger` where Lua raises.
  4. **What counts as a numeral.** `l_str2d` rejects `inf` and `nan` outright,
     and `l_str2int`'s hexadecimal branch wraps rather than overflowing, so
     `0xffffffffffffffff` is the integer `-1`.

Each of those is a different line of C, and no two of them are visible in the
same case, which is why this is a cross product rather than a list. Every
operand is run through every operator, plus `tonumber`, `math.type` and
`math.tointeger` — the three functions NSE actually uses to decide whether a
packet field is a number and which kind.

Each row is `name<TAB>chunk_hex<TAB>note`, hex-encoded because several operands
contain NUL, tabs and non-UTF-8 bytes on purpose.
"""
from __future__ import annotations

import sys

# (label, lua string literal). The label becomes part of the case name, so it
# has to survive as an identifier; the literal is what the chunk sees.
OPERANDS: list[tuple[str, str]] = [
    # --- decimal integers, including both sides of every range edge ---------
    ("zero", "'0'"), ("one", "'1'"), ("neg1", "'-1'"), ("plus1", "'+1'"),
    ("ten", "'10'"), ("leading_zeros", "'007'"),
    ("i64max", "'9223372036854775807'"),
    ("i64max_plus1", "'9223372036854775808'"),
    ("i64min", "'-9223372036854775808'"),
    ("i64min_minus1", "'-9223372036854775809'"),
    ("u64max", "'18446744073709551615'"),
    ("u64max_plus1", "'18446744073709551616'"),
    ("huge_decimal", "'1" + "0" * 40 + "'"),

    # --- hexadecimal integers: the branch with NO overflow check ------------
    ("hex_zero", "'0x0'"), ("hex_ten", "'0x10'"), ("hex_upper_x", "'0X10'"),
    ("hex_neg", "'-0x10'"), ("hex_plus", "'+0x10'"),
    ("hex_i64max", "'0x7fffffffffffffff'"),
    ("hex_i64min", "'0x8000000000000000'"),
    ("hex_u64max", "'0xffffffffffffffff'"),
    ("hex_wraps_to_zero", "'0x10000000000000000'"),
    ("hex_wraps_far", "'0xfffffffffffffffff'"),
    ("hex_mixed_case", "'0xAbCdEf'"),
    ("hex_empty", "'0x'"), ("hex_bad_digit", "'0xg'"), ("hex_trailing", "'0x10z'"),

    # --- floats -------------------------------------------------------------
    ("float_one", "'1.0'"), ("float_neg", "'-1.0'"),
    ("float_leading_dot", "'.5'"), ("float_trailing_dot", "'5.'"),
    ("float_exp", "'1e2'"), ("float_exp_upper", "'1E2'"),
    ("float_exp_neg", "'1e-2'"), ("float_exp_plus", "'1e+2'"),
    ("float_overflow", "'1e400'"), ("float_overflow_neg", "'-1e400'"),
    ("float_underflow", "'1e-400'"),
    ("float_tenth", "'0.1'"), ("float_small", "'1.5e-10'"),
    ("float_dot_only", "'.'"), ("float_exp_empty", "'1e'"),

    # --- hexadecimal floats -------------------------------------------------
    ("hexfloat", "'0x1p4'"), ("hexfloat_upper_p", "'0x1P4'"),
    ("hexfloat_frac", "'0x1.8p1'"), ("hexfloat_lead_dot", "'0x.8p1'"),
    ("hexfloat_neg_exp", "'-0x1p-4'"), ("hexfloat_no_exp", "'0x1.8'"),
    ("hexfloat_empty_exp", "'0x1p'"), ("hexfloat_dangling_sign", "'0x1p+'"),
    # Exponents past what an `int` holds. The C accumulates these into a plain
    # `int` and overflows it, which is undefined behaviour; this port saturates
    # instead, and the cases are here to pin that the observable answer -- inf
    # or zero -- is the same either way.
    ("hexfloat_huge_exp", "'0x1p99999999999999'"),
    ("hexfloat_tiny_exp", "'0x1p-99999999999999'"),
    ("hexfloat_exp_2p31", "'0x1p2147483648'"),
    ("float_huge_exp", "'1e99999999999999'"),

    # --- the words Lua refuses ---------------------------------------------
    ("word_inf", "'inf'"), ("word_inf_neg", "'-inf'"), ("word_inf_plus", "'+inf'"),
    ("word_inf_upper", "'INF'"), ("word_infinity", "'Infinity'"),
    ("word_nan", "'nan'"), ("word_nan_mixed", "'NaN'"), ("word_nan_neg", "'-nan'"),
    ("word_n_prefix", "'n1'"), ("word_n_suffix", "'1n'"),
    ("word_hex_inf", "'0xinf'"),

    # --- whitespace, which l_str2int and l_str2d both skip at BOTH ends -----
    ("space_both", "' 10 '"), ("space_tab_nl", "'\\t10\\n'"),
    ("space_inner", "'1 0'"), ("space_only", "'  '"),
    ("space_hex", "'  0x10  '"),

    # --- not numerals at all ------------------------------------------------
    ("empty", "''"), ("alpha", "'abc'"), ("alnum", "'10abc'"),
    ("double_neg", "'--1'"), ("nul_only", "'\\0'"), ("nul_after", "'10\\0'"),
    ("nul_before", "'\\0 10'"), ("high_byte", "'\\xff'"),
    ("fullwidth_digits", "'\\xef\\xbc\\x91\\xef\\xbc\\x90'"),
]

# (label, template). `%s` is the operand. Each must `return` one value, or
# raise; the driver records "error" without the message, because message text
# is implementation detail while "is this an error" is the property under test.
OPS: list[tuple[str, str]] = [
    # What NSE actually calls to decide whether a field is a number.
    ("tonumber", "return tonumber(%s)"),
    ("mathtype", "return math.type(tonumber(%s))"),
    ("tointeger", "return math.tointeger(%s)"),
    ("tonumber_base16", "return tonumber(%s, 16)"),

    # Arithmetic: the string metatable carries a metamethod for each of these.
    ("add", "return %s + 1"),
    ("add_reversed", "return 1 + %s"),
    ("sub", "return %s - 1"),
    ("mul", "return %s * 3"),
    ("idiv", "return %s // 3"),
    ("mod", "return %s %% 3"),
    ("div", "return %s / 2"),
    ("pow", "return %s ^ 2"),
    ("unm", "return -(%s)"),
    ("add_float", "return %s + 1.0"),
    ("add_string", "return %s + '2'"),

    # Bitwise: it does NOT, so every one of these is an error on a string.
    ("band", "return %s & 1"),
    ("bor", "return %s | 1"),
    ("bxor", "return %s ~ 1"),
    ("shl", "return %s << 1"),
    ("shr", "return %s >> 1"),
    ("bnot", "return ~(%s)"),

    # Neither comparison nor concatenation nor length coerces.
    ("lt", "return %s < 10"),
    ("eq", "return %s == 10"),
    ("concat", "return %s .. '!'"),
    ("len", "return #(%s)"),
]


def main() -> int:
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m60_coerce.py. Do not edit by hand.\n")
    seen: set[str] = set()
    for oplabel, template in OPS:
        for label, literal in OPERANDS:
            name = f"{oplabel}__{label}"
            if name in seen:
                raise SystemExit("duplicate case name: %s" % name)
            seen.add(name)
            chunk = template % literal
            note = "%s applied to %s" % (oplabel, literal)
            if "\t" in note or "\n" in note:
                raise SystemExit("note for %s contains a field separator" % name)
            out.write("%s\t%s\t%s\n" % (name, chunk.encode("utf-8").hex(), note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
