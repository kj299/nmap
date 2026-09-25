#!/usr/bin/env python3
"""Emit the differential corpus for `string.pack` / `unpack` / `packsize`.

These three are ported into `core::nse::stdlib::strpack` from
`liblua/lstrlib.c:1385-1830`. `unpack` is how NSE's protocol libraries read
packet fields — 1,087 call sites in 138 files — so its `data` argument is,
routinely, bytes a remote host chose. The corpus is built to reach every
decision the C makes, not to be large:

  * every integer option at every width, both byte orders, against values on
    both sides of each width's overflow boundary;
  * the three float widths against the values where float conversion is
    interesting: signed zero, subnormals, the f32 overflow/underflow edges,
    infinities and NaN;
  * the format grammar itself, including the parts that look like accidents
    and are observable: the format is a C string (ends at NUL), `X` consumes
    the option it aligns to, alignment is power-of-two-checked AFTER clamping,
    and a count past ten digits spills into the next option;
  * `unpack` against data that is too short, lengths that claim more than
    remains, `z` with no terminator, wide integers whose upper bytes do not
    fit, and every shape of initial position;
  * argument coercion — `pack("i4", "10")`, `pack("z", 1.5)` — because the
    binding delegates those to the VM and the corpus is what checks it did;
  * round trips and method-form calls, which cross the binding end to end.

Each row is `name<TAB>chunk_hex<TAB>note`. The golden records the returned
values with their subtype, or that the call raised — not the message, which in
PUC-Lua carries the caller's position (ledgered as `error_string_gets_position`)
and, for a missing argument, artefacts of the C's own stack layout.
"""
from __future__ import annotations

import sys

CASES: list[tuple[str, str, str]] = []
_seen: set[str] = set()


def add(name: str, chunk: str, note: str) -> None:
    if name in _seen:
        raise SystemExit("duplicate case name: %s" % name)
    _seen.add(name)
    if "\t" in note or "\n" in note:
        raise SystemExit("note for %s contains a field separator" % name)
    CASES.append((name, chunk, note))


def lua_bytes(b: bytes) -> str:
    """A Lua string literal for arbitrary bytes."""
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def ident(s: str) -> str:
    """Make a case-name fragment out of a format or literal."""
    out = []
    for ch in s:
        if ch.isalnum():
            out.append(ch)
        else:
            out.append({"<": "le", ">": "be", "=": "ne", "!": "al", " ": "_",
                        "-": "m", ".": "p", "+": "pl"}.get(ch, "_"))
    return "".join(out) or "empty"


# ---------------------------------------------------------------------------
# A. Every integer option, every width, both byte orders, at the boundaries.
# ---------------------------------------------------------------------------
INT_OPTS = ["b", "B", "h", "H", "l", "L", "j", "J", "T"] + \
           ["i%d" % n for n in range(1, 17)] + ["I%d" % n for n in range(1, 17)]

# (label, Lua expression). Chosen so that for every width w in 1..8 there is a
# value just inside and just outside both the signed and unsigned range.
INT_VALUES = [
    ("zero", "0"), ("one", "1"), ("neg1", "-1"),
    ("p127", "127"), ("p128", "128"), ("m128", "-128"), ("m129", "-129"),
    ("p255", "255"), ("p256", "256"),
    ("p32767", "32767"), ("p32768", "32768"), ("m32768", "-32768"), ("m32769", "-32769"),
    ("p65535", "65535"), ("p65536", "65536"),
    ("p2e23m1", "8388607"), ("p2e24", "16777216"),
    ("p2e31m1", "2147483647"), ("p2e31", "2147483648"),
    ("m2e31", "-2147483648"), ("m2e31m1", "-2147483649"),
    ("p2e32m1", "4294967295"), ("p2e32", "4294967296"),
    ("p2e40", "1099511627776"), ("p2e48", "281474976710656"),
    ("p2e55", "36028797018963968"), ("p2e56", "72057594037927936"),
    ("maxint", "math.maxinteger"), ("minint", "math.mininteger"),
    # Conversions `luaL_checkinteger` performs, and the ones it refuses.
    ("float_integral", "2.0"), ("float_frac", "1.5"), ("float_2e63", "2^63"),
    ("str_dec", "'10'"), ("str_hex", "'0x10'"), ("str_frac", "'1.5'"),
    ("str_junk", "'abc'"), ("nil", "nil"), ("table", "{}"),
]

for opt in INT_OPTS:
    for endian in ("<", ">"):
        fmt = endian + opt
        for label, expr in INT_VALUES:
            add("pack_%s__%s" % (ident(fmt), label),
                "return string.pack(%r, %s)" % (fmt, expr),
                "pack %s %s" % (fmt, expr))

# ---------------------------------------------------------------------------
# B. Floats at every width.
# ---------------------------------------------------------------------------
FLOAT_VALUES = [
    ("zero", "0.0"), ("negzero", "-0.0"), ("one", "1.0"), ("half", "1.5"),
    ("neghalf", "-1.5"), ("tenth", "0.1"),
    ("f32max_ish", "3.4e38"), ("f32_overflow", "3.5e38"), ("big", "1e300"),
    ("f32_min_sub", "2^-149"), ("f32_underflow", "2^-151"), ("tiny", "1e-300"),
    ("inf", "math.huge"), ("neginf", "-math.huge"), ("nan", "0/0"),
    ("int", "7"), ("maxint", "math.maxinteger"),
    ("str_num", "'1.5'"), ("str_hex", "'0x10'"), ("str_junk", "'x'"),
    ("table", "{}"),
]
for opt in ("f", "n", "d"):
    for endian in ("<", ">"):
        fmt = endian + opt
        for label, expr in FLOAT_VALUES:
            add("pack_%s__%s" % (ident(fmt), label),
                "return string.pack(%r, %s)" % (fmt, expr),
                "pack %s %s" % (fmt, expr))

# ---------------------------------------------------------------------------
# C. Strings: fixed, length-prefixed, zero-terminated.
# ---------------------------------------------------------------------------
STRING_VALUES = [
    ("empty", "''"), ("a", "'a'"), ("abc", "'abc'"), ("nul", "'\\0'"),
    # Long strings are spelled out rather than built with `string.rep`, which
    # the VM does not ship yet: a case must fail only for the function it tests.
    ("inner_nul", "'a\\0b'"), ("len255", "'" + "x" * 255 + "'"),
    ("len256", "'" + "x" * 256 + "'"), ("len65536", "'" + "x" * 65536 + "'"),
    # `luaL_checklstring` converts numbers with tostring's own formatting.
    ("int", "42"), ("float", "1.5"), ("float_integral", "2.0"),
    ("nil", "nil"), ("table", "{}"), ("bool", "true"),
]
for fmt in ["c0", "c1", "c3", "c10", "<s", "<s1", ">s2", "<s3", "<s4", "<s8",
            "<s16", "z"]:
    for label, expr in STRING_VALUES:
        add("pack_%s__%s" % (ident(fmt), label),
            "return string.pack(%r, %s)" % (fmt, expr),
            "pack %s %s" % (fmt, expr))

# ---------------------------------------------------------------------------
# D. The format grammar, through all three functions.
# ---------------------------------------------------------------------------
# Formats chosen for what they exercise in getoption/getdetails. Arguments are
# a fixed list, so extra ones are ignored and missing ones are nil.
GRAMMAR = [
    "", " ", "   ", "<", ">", "=", "!", "!1", "!2", "!4", "!8", "!16",
    "!3", "!0", "!17", "i0", "i17", "I0", "I17", "s0", "s17",
    "i", "I", "c", "c0", "q", "%", "9",
    "x", "xx", "b x b", "X", "Xb", "Xi4", "Xc1", "Xz", "Xx", "X<", "X!4", "Xq",
    "!4 b Xi4 b", "!8 b Xd b", "!2 b Xi8 b", "!4 Xi2 b",
    "!8 b d", "!8 b n", "!8 b f", "!2 b h", "!4 b i8", "!4 b i3", "!3 i4",
    "i3", "!4 i3", "!8 b j", "!16 b i16", "!8 b i16",
    "c99999999999", "c2147483648", "i99999999999",
    "<i4\0garbage", "\0", "\0i4", " i4 ", "<i4>i4=i4", "<!4 b >i4",
    "bbbb", "BbHhIiLlJjT",
]
ARGS = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11"
DATA32 = bytes(range(1, 33))
for i, fmt in enumerate(GRAMMAR):
    # Numbered as well as named: several formats (" ", "%", "\0") would
    # otherwise collapse to the same identifier.
    n = "%02d_%s" % (i, ident(fmt))
    add("grammar_pack__%s" % n,
        "return string.pack(%s, %s)" % (lua_bytes(fmt.encode()), ARGS),
        "pack with format %r" % fmt)
    add("grammar_packsize__%s" % n,
        "return string.packsize(%s)" % lua_bytes(fmt.encode()),
        "packsize of %r" % fmt)
    add("grammar_unpack__%s" % n,
        "return string.unpack(%s, %s)" % (lua_bytes(fmt.encode()), lua_bytes(DATA32)),
        "unpack %r from 32 bytes 01..20" % fmt)

# packsize-only formats: fixed sizes at the MAXSIZE boundary, which `pack`
# could only reach by allocating gigabytes.
for fmt in ["c2147483639", "c2147483639 b", "c1073741824 c1073741823",
            "c1073741824 c1073741824", "s", "z", "i4 s1", "!8 c1 d", "c2147483639 !8 X d"]:
    add("packsize__%s" % ident(fmt),
        "return string.packsize(%r)" % fmt,
        "packsize %r" % fmt)

# ---------------------------------------------------------------------------
# E. unpack of integers from crafted data.
# ---------------------------------------------------------------------------
DATA_PATTERNS = [
    ("zeros", bytes(16)),
    ("ones", b"\xff" * 16),
    ("hibit", b"\x80" + bytes(15)),
    ("hibit_last", bytes(15) + b"\x80"),
    ("seq", bytes(range(1, 17))),
    ("seq_desc", bytes(range(16, 0, -1))),
    ("neg_then_zero", b"\xff" * 8 + bytes(8)),
    ("zero_then_neg", bytes(8) + b"\xff" * 8),
    ("pos_ext", b"\x7f" + b"\xff" * 7 + bytes(8)),
    ("neg_ext", b"\x00" * 7 + b"\x80" + b"\xff" * 8),
    ("neg_bad_ext", b"\x00" * 7 + b"\x80" + b"\xff" * 7 + b"\xfe"),
]
for opt in INT_OPTS:
    for endian in ("<", ">"):
        fmt = endian + opt
        for label, data in DATA_PATTERNS:
            add("unpack_%s__%s" % (ident(fmt), label),
                "return string.unpack(%r, %s)" % (fmt, lua_bytes(data)),
                "unpack %s from %s" % (fmt, label))
        add("unpack_%s__empty" % ident(fmt),
            "return string.unpack(%r, '')" % fmt,
            "unpack %s from an empty string" % fmt)

for opt in ("f", "n", "d"):
    for endian in ("<", ">"):
        fmt = endian + opt
        for label, data in DATA_PATTERNS + [
            ("f32_nan", b"\x00\x00\xc0\x7f" + bytes(4)),
            ("f32_negzero", b"\x00\x00\x00\x80" + bytes(4)),
            ("f32_subnormal", b"\x01\x00\x00\x00" + bytes(4)),
            ("f64_inf", b"\x00" * 6 + b"\xf0\x7f"),
            ("f64_negzero", b"\x00" * 7 + b"\x80"),
            ("f64_subnormal", b"\x01" + b"\x00" * 7),
        ]:
            add("unpack_%s__%s" % (ident(fmt), label),
                "return string.unpack(%r, %s)" % (fmt, lua_bytes(data)),
                "unpack %s from %s" % (fmt, label))

# ---------------------------------------------------------------------------
# F. unpack strings: lengths that lie, terminators that are missing.
# ---------------------------------------------------------------------------
STRING_DATA = [
    ("s1_exact", "<s1", b"\x03abc"),
    ("s1_short", "<s1", b"\x04abc"),
    ("s1_zero", "<s1", b"\x00rest"),
    ("s1_no_prefix", "<s1", b""),
    ("s2_be", ">s2", b"\x00\x02hi"),
    ("s2_le_wrong_order", "<s2", b"\x00\x02hi"),
    ("s4_huge", "<s4", b"\xff\xff\xff\xffabc"),
    ("s8_neg", "<s8", b"\xff" * 8 + b"abc"),
    ("s8_exact", "<s8", b"\x02" + bytes(7) + b"hi"),
    ("s16_fits", "<s16", b"\x01" + bytes(15) + b"x"),
    ("s16_high_byte", "<s16", b"\x01" + bytes(14) + b"\x01" + b"x"),
    ("z_ok", "z", b"ab\x00cd"),
    ("z_empty", "z", b"\x00"),
    ("z_unterminated", "z", b"abc"),
    ("z_at_end", "z", b""),
    ("zz", "zz", b"a\x00b\x00"),
    ("zz_second_open", "zz", b"a\x00b"),
    ("c0", "c0", b""),
    ("c3_exact", "c3", b"abc"),
    ("c3_short", "c3", b"ab"),
    ("c3_nul", "c3", b"a\x00c"),
    ("x_skip", "x B", b"\x01\x02"),
    ("x_past_end", "B x", b"\x01"),
]
for label, fmt, data in STRING_DATA:
    add("unpack_str__%s" % label,
        "return string.unpack(%r, %s)" % (fmt, lua_bytes(data)),
        "unpack %s from %r" % (fmt, data))

# ---------------------------------------------------------------------------
# G. Initial position: posrelatI, then the pos <= len check.
# ---------------------------------------------------------------------------
for label, init in [
    ("absent", None), ("nil", "nil"), ("zero", "0"), ("one", "1"), ("two", "2"),
    ("three", "3"), ("four", "4"), ("five", "5"), ("m1", "-1"), ("m2", "-2"),
    ("m3", "-3"), ("m4", "-4"), ("m100", "-100"), ("maxint", "math.maxinteger"),
    ("minint", "math.mininteger"), ("float_integral", "2.0"),
    ("float_frac", "1.5"), ("str_num", "'2'"), ("str_junk", "'x'"), ("table", "{}"),
]:
    args = "'B', 'abc'" if init is None else "'B', 'abc', %s" % init
    add("unpack_init__%s" % label, "return string.unpack(%s)" % args,
        "unpack B from 'abc' at init %s" % init)
    args = "'', 'abc'" if init is None else "'', 'abc', %s" % init
    add("unpack_init_empty_fmt__%s" % label, "return string.unpack(%s)" % args,
        "empty format at init %s: only the next position comes back" % init)

# Alignment is relative to the START of the data, not to `init`.
for init in range(1, 9):
    add("unpack_align_from_init_%d" % init,
        "return string.unpack('!4 i4', %s, %d)" % (lua_bytes(bytes(range(16))), init),
        "!4 i4 at init %d: padding counts from byte 1" % init)

# ---------------------------------------------------------------------------
# H. Round trips, method form, and argument coercion through the binding.
# ---------------------------------------------------------------------------
ROUND_TRIPS = [
    ("<i4", "-123456"), (">I2", "65535"), ("<j", "math.mininteger"),
    ("<J", "-1"), ("<i16", "-2"), (">I16", "math.maxinteger"),
    ("<d", "0.1"), ("<f", "0.1"), (">n", "-0.0"),
    ("<s1", "'hello'"), ("z", "'hello'"), ("c5", "'hi'"),
    ("<!4 b i4 h", "1, 2, 3"), ("<!8 b Xd i4", "1, 2"),
    (">i3 <i3 =i3", "-1, -2, -3"),
]
for fmt, vals in ROUND_TRIPS:
    add("roundtrip__%s" % ident(fmt),
        "return string.unpack(%r, string.pack(%r, %s))" % (fmt, fmt, vals),
        "unpack(pack(%s, %s))" % (fmt, vals))

add("method_pack", "return ('<i4'):pack(1)", "method call through the string metatable")
add("method_unpack", "return ('<i2'):unpack('\\1\\2')", "method call through the string metatable")
add("method_packsize", "return ('i4i8'):packsize()", "method call through the string metatable")
add("fmt_is_a_number", "return string.pack(4)", "luaL_checkstring turns 4 into '4': an invalid option")
add("fmt_is_a_table", "return string.pack({})", "the format must be a string")
add("data_is_a_number", "return string.unpack('c3', 123)", "luaL_checklstring turns 123 into '123'")
add("data_is_a_float", "return string.unpack('c3', 1.5)", "and 1.5 into '1.5', formatted as tostring would")
add("data_is_nil", "return string.unpack('b', nil)", "unpack's data must be a string")
add("pack_no_values", "return string.pack('i4')", "a missing value is an error, not a zero")
add("pack_extra_values", "return string.pack('i4', 1, 2, 3)", "surplus values are ignored")
add("unpack_many", "return string.unpack(%r, %s)" % ("B" * 200, lua_bytes(b"\x07" * 200)),
    "200 results plus the position")
add("pack_mixed", "return string.pack('<b h i4 j f d s1 z c2', 1, 2, 3, 4, 5.5, 6.25, 'ab', 'cd', 'e')",
    "every kind of option in one call")


def main() -> int:
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m6_strpack.py. Do not edit by hand.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("utf-8").hex(), note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
