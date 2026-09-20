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
    ("tonumber_hex", "return tonumber('0x1f')", "31"),
    ("tonumber_exp", "return tonumber('1e2')", "100.0, a float"),
    ("tonumber_ws", "return tonumber('  12  ')", "surrounding whitespace is allowed"),
    ("tonumber_bad", "return tonumber('12x')", "nil"),
    ("tonumber_base", "return tonumber('ff', 16)", "255"),
    ("tonumber_huge", "return tonumber('1e400')", "inf, not nil and not an error"),
    ("tostring_int", "return tostring(1)", "1"),
    ("tostring_float", "return tostring(1.0)", "1.0"),

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
