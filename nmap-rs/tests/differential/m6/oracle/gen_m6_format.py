#!/usr/bin/env python3
"""Emit the differential corpus for `string.format`.

`core::nse::stdlib::strformat` ports `liblua/lstrlib.c:990-1376`, which is
Lua's validation of each conversion specification in front of the C
library's `printf`. The oracle is nmap's own `liblua/` built on Linux, so the
`printf` being matched is glibc's. The corpus is built to reach every decision
in both halves:

  A. every integer conversion (d i u o x X) under every flag set, width and
     precision shape, against the values where printf's rules interact
     (zero, signs, the 64-bit edges, precision 0 with value 0);
  B. every float conversion (a A e E f g G) the same way, against values that
     exercise rounding ties, the %g switch-over, subnormals, the extremes,
     infinities and both NaN signs;
  C. %c over all 256 byte values, with width and justification;
  D. %s with and without modifiers: lengths around the 100-byte rule, NUL
     bytes, precision truncation, numbers, booleans, nil and __tostring;
  E. %q over every byte (followed by a digit and not), integers including
     math.mininteger, floats including the specials, and the error cases;
  F. %p for values with no address;
  G. specification validation: a seeded sweep of flag/width/precision strings
     in front of every ASCII conversion byte, including "too long";
  H. argument counting, %%, literal text with NUL bytes, and a numeric format;
  I. every literal format string in nselib/ and scripts/, with typical
     arguments for each of its conversions;
  J. a seeded random sweep of whole format strings.

Each row is `name<TAB>chunk_hex<TAB>note`. Most chunks batch many calls, each
made by `pcall(string.format, ...)` directly so that C adds no position prefix
to an error. One rewrite is applied to errors inside a batch, in the chunk and
in the open: `'string.format'` becomes `'format'`. `luaL_argerror` names the
function from the call site, and a function called by `pcall` is named by its
global path in C; the binding always says `'format'` (DIVERGENCES.md,
`format-bad-argument-naming`). The rest of every message -- the argument
number and the reason -- is compared byte for byte.
"""
from __future__ import annotations

import os
import random
import re
import sys

CASES: list[tuple[str, str, str]] = []
_seen: set[str] = set()

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))


def add(name: str, chunk: str, note: str) -> None:
    if name in _seen:
        raise SystemExit("duplicate case name: %s" % name)
    _seen.add(name)
    if "\t" in note or "\n" in note:
        raise SystemExit("note for %s contains a field separator" % name)
    CASES.append((name, chunk, note))


def lit(b) -> str:
    """A Lua string literal for arbitrary bytes (or a str, taken as latin-1)."""
    if isinstance(b, str):
        b = b.encode("latin-1")
    out = ['"']
    for c in b:
        ch = chr(c)
        if 0x20 <= c < 0x7F and ch not in '"\\':
            out.append(ch)
        else:
            out.append("\\x%02x" % c)
    out.append('"')
    return "".join(out)


def ident(s) -> str:
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    out = []
    for ch in s:
        if ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        else:
            out.append({"%": "P", "-": "M", "+": "L", " ": "S", "#": "H",
                        ".": "D", "0": "0"}.get(ch, "x%02x" % ord(ch)))
    return "".join(out) or "empty"


# Every call goes through F, which renders an error as "ERR:" .. message,
# with the one rewrite the module docstring describes.
HEAD = """local out = {}
local function F(...)
  local ok, r = pcall(string.format, ...)
  if ok then out[#out + 1] = r
  else out[#out + 1] = "ERR:" .. (string.gsub(tostring(r), "'string%.format'", "'format'")) end
end
"""
TAIL = "\nreturn table.unpack(out)\n"


def batch(lines: list[str]) -> str:
    return HEAD + "\n".join(lines) + TAIL


FLAGSETS = ["", "-", "+", " ", "#", "0", "-0", "+ ", "0+", "#0", "-#", "--", "00", "+-0 #"]
WIDTHS = ["", "1", "5", "20", "99"]
PRECS = ["", ".", ".0", ".1", ".5", ".20", ".99"]

# ---------------------------------------------------------------------------
# A. Integer conversions.
# ---------------------------------------------------------------------------
INT_VALUES = ["0", "1", "-1", "42", "-42", "255", "2147483648", "math.maxinteger",
              "math.mininteger", "3.0", "'17'", "' 0x10 '", "-0.0", "2.5", "'x'", "nil", "2^63"]
for conv in "diuoxX":
    for fl in FLAGSETS:
        for w in WIDTHS:
            for pr in PRECS:
                spec = "%" + fl + w + pr + conv
                add("A_%s" % ident(spec),
                    batch(["F(%s, %s)" % (lit(spec), v) for v in INT_VALUES]),
                    "%s over the integer values" % spec)

# ---------------------------------------------------------------------------
# B. Float conversions.
# ---------------------------------------------------------------------------
FLOAT_VALUES = [
    "0.0", "-0.0", "1.0", "-1.5", "0.1", "1/3", "2.675", "1e-5", "1e-4",
    "123456.789", "1e15", "1e16", "1e17", "1e100", "1e300", "2^53", "2^-1074",
    "2^-1022", "1.7976931348623157e308", "1/0", "-1/0", "0/0", "-(0/0)",
    "0.5", "1.5", "2.5", "9.9999995", "0.000123456789", "3", "'2.5'",
    "1.96875", "0x1.fffffffffffffp+0", "'x'",
    # Exact ties in %a where the kept digit is even, so round-half-to-even and
    # round-half-up disagree (0x1.08, 0x1.28, and the subnormal 0x0.8p-1022).
    "1.03125", "1.15625", "2^-1023",
]
F_FLAGSETS = ["", "-", "+", " ", "#", "0", "-0", "+ ", "#0", "+-0 #"]
F_WIDTHS = ["", "12", "99"]
F_PRECS = ["", ".", ".0", ".1", ".3", ".13", ".17", ".40"]
for conv in "aAeEfgG":
    for fl in F_FLAGSETS:
        for w in F_WIDTHS:
            for pr in F_PRECS:
                spec = "%" + fl + w + pr + conv
                vals = FLOAT_VALUES
                if conv == "f" and (pr in (".40",) or w == "99"):
                    # Keep the golden a reasonable size: the 300-digit values
                    # under a 40-digit precision add nothing new.
                    vals = [v for v in FLOAT_VALUES if v not in ("1e300", "1.7976931348623157e308")]
                add("B_%s" % ident(spec),
                    batch(["F(%s, %s)" % (lit(spec), v) for v in vals]),
                    "%s over the float values" % spec)
# Precision 99 and the extremes, once each, for every float conversion.
for conv in "aeEfgG":
    add("B_p99_%s" % conv,
        batch(["F(%s, %s)" % (lit("%." + "99" + conv), v)
               for v in ["0.1", "1/3", "1e300", "1.7976931348623157e308", "2^-1074", "-0.0"]]),
        "precision 99 for %%%s" % conv)

# ---------------------------------------------------------------------------
# C. %c.
# ---------------------------------------------------------------------------
add("C_all_bytes", batch(["F('%%c', %d)" % c for c in range(256)]), "%c over 0-255")
add("C_wrap", batch(["F('%%c', %s)" % v for v in ["256 + 65", "-191", "65.0", "'66'", "2^31 + 67", "1.5", "'x'"]]),
    "%c wraps to the low byte; non-integers raise")
for spec in ["%5c", "%-5c", "%1c", "%99c", "%05c", "%+c", "%.1c", "%#c", "%--3c"]:
    add("C_%s" % ident(spec), batch(["F(%s, %s)" % (lit(spec), v) for v in ["65", "0", "255"]]),
        "%s" % spec)

# ---------------------------------------------------------------------------
# D. %s.
# ---------------------------------------------------------------------------
S_VALUES = [lit(""), lit("abc"), lit("x" * 99), lit("x" * 100), lit("x" * 101),
            lit("a\x00b"), lit("\xff\x80"), "42", "1.5", "-0.0", "1e100", "true",
            "false", "nil", "2^63", "math.mininteger"]
S_FLAGS = ["", "-", "0", "+", "#", "--"]
S_WIDTHS = ["", "1", "5", "99"]
S_PRECS = ["", ".", ".0", ".3", ".99"]
for fl in S_FLAGS:
    for w in S_WIDTHS:
        for pr in S_PRECS:
            spec = "%" + fl + w + pr + "s"
            add("D_%s" % ident(spec), batch(["F(%s, %s)" % (lit(spec), v) for v in S_VALUES]),
                "%s over the %%s values" % spec)
TOSTRING = """local function T(x) return setmetatable({}, {__tostring = function() return x end}) end
"""
add("D_tostring", TOSTRING + batch([
    "F('%s', T('obj'))", "F('[%5s]', T('ab'))", "F('[%-5.1s]', T('ab'))",
    "F('%s', T(42))", "F('%s', T(1.5))", "F('%s', T({}))", "F('%s', T(nil))",
    "F('%s', T(true))", "F('%5s', T('a\\0b'))", "F('%s', T('a\\0b'))",
    "F('%s|%s', T('one'), T('two'))", "F('%d %s', 'x', T('never'))",
    "F('%s %d', T('first'), 'x')",
    "F('%s', setmetatable({}, {__tostring = function() error('boom', 0) end}))",
    "F('%s', setmetatable({}, {__tostring = 'notcallable'}))",
]), "%s through __tostring, and the order of its errors")

# ---------------------------------------------------------------------------
# E. %q.
# ---------------------------------------------------------------------------
add("E_bytes_then_digit", batch(["F('%%q', %s)" % lit(bytes([c]) + b"1") for c in range(256)]),
    "%q over every byte followed by a digit")
add("E_bytes_alone", batch(["F('%%q', %s)" % lit(bytes([c]) + b"x") for c in range(256)]),
    "%q over every byte followed by a non-digit")
add("E_values", batch(["F('%%q', %s)" % v for v in [
    "0", "1", "-1", "math.maxinteger", "math.mininteger", "0.0", "-0.0", "1.5",
    "2.0", "0.1", "1e300", "2^-1074", "1/0", "-1/0", "0/0", "-(0/0)", "nil", "true",
    "false", lit(""), lit("a\nb\rc\"d\\e\x00f\x7f"), "{}", "print or tostring",
    "coroutine.create(tostring)"]]), "%q over every value type")
add("E_modifiers", batch(["F(%s, 'a')" % lit(s) for s in ["%5q", "%-q", "%.1q", "%0q", "%#q"]]),
    "%q rejects modifiers")

# ---------------------------------------------------------------------------
# F. %p.
# ---------------------------------------------------------------------------
add("F_null", batch(["F(%s, %s)" % (lit(s), v) for s in ["%p", "%5p", "%-9p", "%10p", "%.3p", "%05p", "%+p"]
                     for v in ["nil", "true", "false", "1", "1.5"]]),
    "%p of values with no address is (null), formatted as %s")
add("F_identity",
    "local t, u = {}, {}\n"
    "return string.format('%p', t) == string.format('%p', t), "
    "string.format('%p', t) ~= string.format('%p', u), "
    "string.match(string.format('%p', t), '^0x%x+$') ~= nil, "
    "string.match(string.format('%20p', t), '^ +0x%x+$') ~= nil",
    "%p of a table: stable, distinct, hexadecimal")

# ---------------------------------------------------------------------------
# G. Specification validation.
# ---------------------------------------------------------------------------
rng = random.Random(0x666d74)  # fixed: the corpus must be reproducible
CONV_BYTES = [chr(c) for c in range(33, 127) if chr(c) not in "%"] + ["\x00", "\x80"]
G_ALPHA = "-+ #0123456789."
for i in range(150):
    lines = []
    for _ in range(25):
        n = rng.choice([0, 1, 2, 3, 4, 6, 10, 20, 21, 22, 30])
        body = "".join(rng.choice(G_ALPHA) for _ in range(n))
        conv = rng.choice(CONV_BYTES)
        # `%p` of anything with an address prints that address, which differs
        # between runs; give it values that print "(null)".
        arg = rng.choice(["1", "1.5", "nil"] if conv == "p" else ["1", "1.5", "'s'", "nil"])
        lines.append("F(%s, %s)" % (lit("%" + body + conv), arg))
    add("G_%03d" % i, batch(lines), "random specifications")
add("G_too_long_boundary", batch(["F(%s, 1)" % lit("%" + "-" * n + "d") for n in range(15, 25)]),
    "the 'invalid format (too long)' boundary")
add("G_conv_at_end", batch(["F(%s, 1)" % lit(s) for s in ["%", "%5", "%-", "%.", "%5.2", "x%"]]),
    "a specification cut off by the end of the format")

# ---------------------------------------------------------------------------
# H. Arguments, %%, literal text.
# ---------------------------------------------------------------------------
add("H_misc", batch([
    "F('')", "F('plain')", "F('%%')", "F('100%%')", "F('%%%d', 5)", "F('a\\0b%d', 1)",
    "F('%d')", "F('%d %d', 1)", "F('%s', nil)", "F('%d', 1, 2, 3)", "F(12)", "F(1.5)",
    "F(nil)", "F({})", "F('%5%')", "F('%-%')",
]), "argument counting, %%, literal text, the format's own type")

# ---------------------------------------------------------------------------
# I. Every literal format string in the shipped NSE code.
# ---------------------------------------------------------------------------
_pat_src = open(os.path.join(HERE, "gen_m6_pattern.py")).read()
_ns: dict = {}
exec(_pat_src[_pat_src.index("def lua_tokens"):_pat_src.index("PATTERN_FUNCS")], {"re": re}, _ns)
lua_tokens = _ns["lua_tokens"]


def corpus_formats() -> list[bytes]:
    found: set[bytes] = set()
    for root in ("nselib", "scripts"):
        for dirpath, _, files in os.walk(os.path.join(REPO, root)):
            for fn in sorted(files):
                if not fn.endswith((".lua", ".nse")):
                    continue
                with open(os.path.join(dirpath, fn), "rb") as fh:
                    t = list(lua_tokens(fh.read()))
                for k in range(1, len(t) - 3):
                    if t[k + 1] != ("name", "format") or t[k + 2] != ("op", "("):
                        continue
                    if t[k] == ("op", ":") and t[k - 1][0] == "str":
                        found.add(t[k - 1][1])
                    elif t[k] == ("op", ".") and t[k - 1] == ("name", "string") and t[k + 3][0] == "str":
                        found.add(t[k + 3][1])
    return sorted(found)


ARG_FOR = {"d": ["42", "-7"], "i": ["42", "-7"], "u": ["42", "3000000000"],
           "x": ["255", "48879"], "X": ["255", "48879"], "o": ["8", "511"],
           "c": ["65", "10"], "f": ["3.14159", "-0.5"], "e": ["12345.678", "1e-7"],
           "E": ["12345.678", "1e-7"], "g": ["0.0001", "1e20"], "G": ["0.0001", "1e20"],
           "a": ["1.0", "0.1"], "A": ["1.0", "0.1"], "q": [lit("a\nb\"c"), "1.5"],
           "s": [lit("abc"), "12"], "p": ["nil", "nil"]}
SPEC_RE = re.compile(rb"%([-+ #0]*)(\d*)(\.\d*)?([a-zA-Z%])")
FORMATS = corpus_formats()
for i, fmt in enumerate(FORMATS):
    lines = []
    for variant in (0, 1):
        args = []
        for m in SPEC_RE.finditer(fmt):
            c = m.group(4).decode()
            if c == "%":
                continue
            args.append(ARG_FOR.get(c, ["1", "1"])[variant])
        lines.append("F(%s%s)" % (lit(fmt), "".join(", " + a for a in args)))
    add("I_%04d" % i, batch(lines), "corpus format %s" % ident(fmt)[:60])

# ---------------------------------------------------------------------------
# J. Random whole format strings.
# ---------------------------------------------------------------------------
J_TEXT = ["", "a", "x=", " ", "\\n", "[", "]", "%%", "\x00", "\xff"]
J_CONV = list("diuoxXcfeEgGaAsq")
J_VALUES = {"i": ["0", "-5", "123456789", "math.mininteger", "7.0"],
            "f": ["0.1", "-2.5", "1e10", "1/0", "0/0", "123.456"],
            "s": [lit("hi"), lit(""), "3", "true"]}
for i in range(600):
    parts, args = [], []
    for _ in range(rng.randint(1, 6)):
        parts.append(rng.choice(J_TEXT))
        conv = rng.choice(J_CONV)
        fl = "".join(rng.choice("-+ #0") for _ in range(rng.choice([0, 0, 1, 2])))
        w = rng.choice(["", "", str(rng.randint(1, 30))])
        pr = rng.choice(["", "", "." + str(rng.randint(0, 20)), "."])
        parts.append("%" + fl + w + pr + conv)
        kind = "s" if conv in "sq" else ("f" if conv in "feEgGaA" else "i")
        args.append(rng.choice(J_VALUES[kind] + J_VALUES[rng.choice("ifs")]))
    fmt = "".join(parts).replace("\\n", "\n")
    add("J_%03d" % i, batch(["F(%s, %s)" % (lit(fmt), ", ".join(args))]), "random format")


def main() -> int:
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m6_format.py. Regenerate with ./regen_m6_format.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
