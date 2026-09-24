#!/usr/bin/env python3
"""Emit the M6.0 Lua-semantics corpus: the expressions any runtime this port
adopts must evaluate exactly as nmap's own Lua does.

M6.1 and M6.2 gated *parsers* (`script.db`, `.nse` metadata, `--script`
expressions) — pure functions over bytes, with nmap's Lua as the oracle. M6.0
gates the interpreter itself, so the corpus is different in kind: each case is a
Lua chunk, and the golden is what `liblua/` prints for it.

The cases are not a general Lua conformance suite. They are the places where a
re-implementation plausibly goes wrong AND the NSE corpus would notice:

  * integer arithmetic at the edges of the 64-bit range. NSE's binary protocol
    libraries do arithmetic on values lifted straight out of hostile packets, so
    `i64::MIN`-adjacent operands are attacker-reachable, not theoretical.
  * floor division and modulus sign rules, which Lua defines differently from
    Rust: Lua's `//` floors and its `%` takes the sign of the divisor, where
    Rust's `/` truncates and `%` takes the sign of the dividend.
  * bit shifts past the word size, which Lua defines (as 0) and Rust makes a
    panic or a rotate depending on the operator.
  * string method dispatch — `("x"):rep(3)` — which needs a string metatable,
    not merely a `string` table. 992 sites in the shipped corpus call a method
    on a string literal.
  * string-to-number coercion, which NSE uses to parse protocol fields.

Each row is `name<TAB>chunk_hex<TAB>note`. The chunk is hex-encoded for the same
reason the M6.1 corpus is: these are byte strings that contain tabs, newlines,
quotes and non-UTF-8, and the file is TSV.
"""
from __future__ import annotations

import sys

# (name, lua chunk, note). Each chunk must `return` exactly one value, or call
# error(); the driver prints the value's type and its tostring().
CASES: list[tuple[str, str, str]] = [
    # --- integer arithmetic at the range edges -------------------------------
    ("mod_min_by_neg1", "return math.mininteger % -1",
     "Rust's i64::MIN % -1 overflows; Lua defines this as 0"),
    ("mod_neg1_by_min", "return -1 % math.mininteger",
     "the (a%b)+b adjustment overflows even when a%b does not"),
    ("mod_max_by_neg1", "return math.maxinteger % -1", "neighbour of the overflow case"),
    ("mod_neg_by_pos", "return -7 % 2", "Lua's % takes the sign of the divisor: 1, not -1"),
    ("mod_pos_by_neg", "return 7 % -2", "mirror of the above: -1, not 1"),
    ("idiv_neg_by_pos", "return -7 // 2", "Lua's // floors: -4, where Rust's / truncates to -3"),
    ("idiv_pos_by_neg", "return 7 // -2", "floors to -4"),
    ("idiv_min_by_neg1", "return math.mininteger // -1", "wraps to mininteger, does not trap"),
    ("add_max_plus_1", "return math.maxinteger + 1", "wraps to mininteger"),
    ("sub_min_minus_1", "return math.mininteger - 1", "wraps to maxinteger"),
    ("mul_min_by_neg1", "return math.mininteger * -1", "wraps to mininteger"),
    ("unm_min", "return -math.mininteger", "unary minus wraps"),
    # These three keep only pcall's boolean: the message text is
    # implementation-specific, while "is this a catchable Lua error" is exactly
    # the property under test. A host-language panic fails these cases by
    # escaping pcall entirely rather than by returning false.
    ("mod_by_zero", "return (pcall(function() return 1 % 0 end))",
     "integer modulus by zero is a Lua *error*, catchable by pcall"),
    ("idiv_by_zero", "return (pcall(function() return 1 // 0 end))",
     "integer division by zero is a Lua error, catchable by pcall"),
    ("fmod_by_zero_float", "return 1.0 % 0.0", "float modulus by zero is nan, NOT an error"),

    # --- bit shifts past the word size ---------------------------------------
    ("shl_64", "return 1 << 64", "Lua defines shifts >= 64 as 0; Rust panics or rotates"),
    ("shl_63", "return 1 << 63", "the last shift that fits"),
    ("shl_neg", "return 1 << -1", "a negative shift reverses direction"),
    ("shr_64", "return -1 >> 64", "0, not -1: Lua's >> is logical, not arithmetic"),
    ("shr_1_of_neg1", "return -1 >> 1", "logical shift of a negative: maxinteger"),
    ("bnot_zero", "return ~0", "-1"),

    # --- integer / float boundary --------------------------------------------
    ("type_of_int", "return math.type(1)", "integer"),
    ("type_of_float", "return math.type(1.0)", "float"),
    ("type_of_idiv", "return math.type(7 // 2)", "integer // integer stays integer"),
    ("type_of_div", "return math.type(7 / 2)", "/ always produces a float"),
    ("int_eq_float", "return 3 == 3.0", "true: Lua compares across subtypes"),
    ("max_int_vs_float", "return math.maxinteger + 0.0 == math.maxinteger",
     "false: the float cannot represent maxinteger exactly"),
    ("float_to_int_concat", "return 1.0 .. ''", "1.0, not 1"),
    ("int_concat", "return 1 .. ''", "1"),
    ("nan_eq_self", "return 0/0 == 0/0", "false"),
    ("nan_lt", "return 0/0 < 1", "false"),
    ("nan_not_lt", "return not (0/0 < 1)", "true — the negation must also hold"),
    # EVERY NaN comparison, in both operand orders. All six are false in Lua,
    # which is the whole point: NaN is unordered, so a compiler that lowers
    # `a > b` to `not (a <= b)` instead of to `b < a` inverts exactly these and
    # nothing else. That is a silent wrong answer, not a crash, and it is
    # invisible unless `>` and `>=` are tested SEPARATELY from `<` and `<=`.
    ("nan_gt", "return 0/0 > 1", "false"),
    ("nan_ge", "return 0/0 >= 1", "false"),
    ("nan_le", "return 0/0 <= 1", "false"),
    ("gt_nan", "return 1 > 0/0", "false"),
    ("ge_nan", "return 1 >= 0/0", "false"),
    ("lt_nan", "return 1 < 0/0", "false"),
    ("le_nan", "return 1 <= 0/0", "false"),
    ("nan_gt_nan", "return 0/0 > 0/0", "false"),
    ("nan_ge_nan", "return 0/0 >= 0/0", "false"),
    # and the ordinary orderings, so a wholesale inversion cannot hide behind
    # the NaN rows alone
    ("gt_true", "return 2 > 1", "true"),
    ("ge_eq", "return 1 >= 1", "true"),
    ("gt_false", "return 1 > 2", "false"),
    ("gt_mixed", "return 2 > 1.5", "true — integer vs float ordering"),
    ("inf_pos", "return 1/0", "inf"),
    ("inf_neg", "return -1/0", "-inf"),

    # --- string method dispatch (needs a string metatable) -------------------
    ("method_rep_literal", "return ('ab'):rep(3)", "992 corpus sites call a method on a literal"),
    ("method_len_literal", "return ('xyz'):len()", "method form of #"),
    ("method_sub_literal", "return ('hello'):sub(2, 3)", "method form of string.sub"),
    ("method_upper_var", "local s = 'ab' return s:upper()", "method on a variable, not a literal"),
    ("method_on_number", "return (pcall(function() return (1):rep(2) end))",
     "numbers have NO metatable in Lua: this is an error, not a coercion"),
    ("getmetatable_string", "return getmetatable('') ~= nil",
     "true: strings have a metatable and it is reachable"),
    ("string_meta_index_is_lib", "return getmetatable('').__index == string",
     "the metatable's __index IS the string library"),

    # --- string <-> number coercion ------------------------------------------
    ("coerce_add", "return '10' + 1", "arithmetic coerces numeric strings"),
    ("coerce_hex", "return '0x10' + 0", "hex literals coerce too"),

    # --- float-to-integer conversion at the range edge -----------------------
    # `lua_numbertointeger` (luaconf.h:432) tests `n >= -2^63 && n < 2^63`. The
    # upper bound is STRICT and the lower is not, which looks like a typo and is
    # not: `-2^63` has an exact double representation and `2^63` is one past
    # `i64::MAX`. Rust's `as` saturates rather than refusing, so a round-trip
    # check accepts `2^63` -- these are the cases that catch it. The systematic
    # corpus for string coercion is m60_coerce_cases.txt; these reach the same
    # conversion through a FLOAT, which that corpus does not.
    ("f2i_2p63_bor", "return (pcall(function() return 2^63 | 0 end))",
     "2^63 is not an integer: a Lua error, catchable"),
    ("f2i_neg_2p63_bor", "return -(2^63) | 0",
     "-2^63 IS an integer -- exactly mininteger -- and must convert"),
    ("f2i_2p62_bor", "return 2^62 | 0", "well inside the range"),
    ("f2i_maxint_as_float_bor",
     "return (pcall(function() return (math.maxinteger + 0.0) | 0 end))",
     "maxinteger has no exact double, so its float rounds up to 2^63"),
    ("f2i_fractional_bor", "return (pcall(function() return 2.5 | 0 end))",
     "F2Ieq: a float converts only if it is integral"),
    ("f2i_integral_float_bor", "return 2.0 | 0", "2.0 is integral, so it converts"),
    ("f2i_nan_bor", "return (pcall(function() return (0/0) | 0 end))", "NaN never converts"),
    ("f2i_inf_bor", "return (pcall(function() return (1/0) | 0 end))", "inf never converts"),
    ("f2i_2p63_shl", "return (pcall(function() return 2^63 << 1 end))", "same test, via a shift"),
    ("f2i_tointeger_2p63", "return math.tointeger(2^63)", "nil, not maxinteger"),
    ("f2i_tointeger_neg_2p63", "return math.tointeger(-(2^63))", "mininteger"),

    # --- string coercion: which operators do it, and to which subtype --------
    ("coerce_bor_string", "return (pcall(function() return '10' | 0 end))",
     "lstrlib.c installs no __bor: a string is a Lua ERROR for bitwise ops"),
    ("coerce_unm_string", "return -'10'", "integer -10, not float -10.0"),
    ("coerce_inf_word", "return tonumber('inf')", "nil: l_str2d rejects 'inf' and 'nan'"),
    ("coerce_hex_wraps", "return tonumber('0xffffffffffffffff')",
     "integer -1: the hex branch of l_str2int has no overflow check"),
    ("coerce_dec_overflows_to_float", "return tonumber('9223372036854775808')",
     "float: the DECIMAL branch does have one"),
    ("coerce_tonumber_base_empty", "return tonumber('', 16)", "nil, not 0"),

    # --- error() adds position information to a string message ---------------
    # Found by running upstream piccolo's own test suite under nmap's Lua:
    # tests/scripts/pcall.lua and coroutine.lua both assert the message comes
    # back unchanged, which PUC-Lua does not do. `luaB_error` (lbaselib.c:39)
    # calls luaL_where and prepends "chunk:LINE: " for a STRING message at
    # level > 0. Level 0, and any non-string message, are left alone.
    ("error_string_gets_position",
     "return select(2, pcall(function() error('boom') end)) == 'boom'",
     "false in Lua: the message comes back as 'chunk:1: boom'"),
    ("error_level_zero_verbatim",
     "return select(2, pcall(function() error('boom', 0) end)) == 'boom'",
     "true: level 0 suppresses the position prefix"),
    ("error_table_verbatim",
     "return type(select(2, pcall(function() error({code = 1}) end)))",
     "table: a non-string error value is never decorated"),
    ("error_no_argument",
     "return select(2, pcall(function() error() end))",
     "nil"),
    ("tonumber_hex", "return tonumber('0x1f')", "31"),
    ("tonumber_exp", "return tonumber('1e2')", "100.0, a float"),
    ("tonumber_ws", "return tonumber('  12  ')", "surrounding whitespace is allowed"),
    ("tonumber_bad", "return tonumber('12x')", "nil"),
    ("tonumber_base", "return tonumber('ff', 16)", "255"),
    ("tonumber_huge", "return tonumber('1e400')", "inf, not nil and not an error"),
    ("tostring_int", "return tostring(1)", "1"),
    ("tostring_float", "return tostring(1.0)", "1.0"),

    # --- float formatting ----------------------------------------------------
    # Lua's is printf("%.14g") plus a ".0" when the result would read back as an
    # integer. Rust's Display for f64 is shortest-round-trip and never uses an
    # exponent, so it agrees with Lua on almost nothing. The exhaustive gate is
    # m60_floatfmt_cases.txt; these are the end-to-end paths -- through the
    # lexer, the VM and the concatenation opcodes -- that the bit-pattern corpus
    # deliberately bypasses.
    ("tostring_float_third", "return tostring(1/3)",
     "0.33333333333333: fourteen significant digits, not Rust's sixteen"),
    ("tostring_float_exp", "return tostring(1e100)",
     "1e+100, not a hundred-and-one-digit numeral"),
    ("tostring_float_style_f", "return tostring(1e13)",
     "10000000000000.0: 14 digits still fits %g's fixed style"),
    ("tostring_float_style_e", "return tostring(1e14)",
     "1e+14: one digit more and %g switches styles"),
    ("tostring_float_negzero", "return tostring(-0.0)",
     "-0.0: the sign survives, and the .0 is appended after it"),
    ("tostring_float_inf", "return tostring(1/0) .. ',' .. tostring(-1/0)",
     "inf,-inf -- and NOT inf.0: the strspn test excludes them"),
    ("concat_float_many", "return 1.0 .. '|' .. 2.5 .. '|' .. 1e100",
     "three-operand concat is a different opcode from two-operand"),
    ("table_concat_floats", "return table.concat({1.0, 2.5, 1e100}, ',')",
     "table.concat has its own coercion path again"),
    ("concat_min_integer", "return math.mininteger .. '' .. ''",
     "i64::MIN.abs() overflows; the length estimate used to abort the process"),
    ("concat_min_integer_pair", "return math.mininteger .. ''",
     "the two-operand path, which does not take the length estimate"),

    # --- byte strings, not UTF-8 ---------------------------------------------
    ("len_embedded_nul", "return #'a\\0b'", "3: Lua strings are byte strings"),
    ("byte_high", "return ('\\xff'):byte(1)", "255 — a byte, not a replacement char"),
    ("char_roundtrip", "return (string.char(0, 255, 128)):byte(2)", "255"),
    ("concat_nul", "return #('a\\0' .. '\\0b')", "4"),
]


def main() -> int:
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m60_cases.py. Do not edit by hand.\n")
    seen = set()
    for name, chunk, note in CASES:
        if name in seen:
            raise SystemExit("duplicate case name: %s" % name)
        seen.add(name)
        if "\t" in note or "\n" in note:
            raise SystemExit("note for %s contains a field separator" % name)
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("utf-8").hex(), note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
