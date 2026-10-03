#!/usr/bin/env python3
"""Emit the differential corpus for Lua patterns: `string.find`, `match`,
`gmatch` and `gsub`.

These are ported into `core::nse::stdlib::pattern` from
`liblua/lstrlib.c:347-947`. They are the most-used part of Lua's standard
library in the shipped NSE corpus, and their subject is, routinely, a banner or
a packet a remote host chose. The corpus is built to reach every decision the
C makes, and then to run what NSE actually runs:

  A. every character class, upper and lower case, against all 256 bytes, and
     every shape of bracket set (ranges, negation, escapes, `]` first, `-`
     at either end) the same way;
  B. every single-character item under every quantifier, followed by every
     kind of continuation, against subjects chosen to force backtracking;
  C. anchors, including `^` in `gmatch` (a literal there) and `$` that is not
     last (a literal too);
  D. captures: nested, position, unfinished, the 32-capture limit, and
     back-references, including one to a position capture (never matches);
  E. `%b` and `%f`, including at the subject's ends, where the C reads its
     hidden NUL terminator;
  F. every error message, both when the matcher reaches the malformed piece
     and when it fails before it does (errors are lazy);
  G. `init` in every shape for all three functions that take it, `find`'s
     plain flag (any truthy value, including 0), and the "no specials" fast
     path, which checks bytes after an embedded NUL too;
  H. `gsub` replacement templates, counts, and function and table replacements
     (including `__index` metamethods, nil/false keeping the original, and the
     invalid-replacement errors);
  I. `gmatch` iteration, including empty matches and `init`;
  J. every pattern literal in the shipped `nselib/` and `scripts/` sources,
     run through all four functions against a set of realistic subjects;
  K. a seeded random sweep over the pattern grammar, malformed patterns and
     all;
  L. argument coercion and the method form;
  M. the recursion limit, exactly at and just past MAXCCALLS.

Each row is `name<TAB>chunk_hex<TAB>note`. The chunks use only what the
vendored VM ships plus the functions under test -- no `string.rep`, no
`string.format` -- so that a case fails only for the reason it is about.
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
            out.append({"%": "P", "^": "C", "$": "D", "*": "S", "+": "L",
                        "-": "M", "?": "Q", ".": "O", "(": "o", ")": "c",
                        "[": "b", "]": "e", " ": "_"}.get(ch, "x%02x" % ord(ch)))
    return "".join(out) or "empty"


# Chunk fragments. Everything a chunk calls exists in the vendored VM.
GMATCH_ALL = """
local out = {}
local it = %s
for _ = 1, 500 do
  local r = table.pack(it())
  if r[1] == nil then break end
  out[#out + 1] = r.n
  for i = 1, r.n do out[#out + 1] = r[i] end
end
return table.unpack(out)
"""


def gmatch_chunk(call: str) -> str:
    return GMATCH_ALL % call


# A chunk that applies one string function to many subjects and returns
# everything flattened, each call's results prefixed by its count, a raised
# error as `false` and its message. One case per (pattern, function) keeps the
# corpus a size the harness can run, without merging unrelated failures into
# one opaque row: a mismatch still names the pattern and the function.
#
# Every call is made by `pcall` DIRECTLY, with no Lua function between the two.
# That is deliberate: `luaL_error` prefixes its message with the position of
# the function one level up the stack, so a call from Lua code reads
# "chunk:6: malformed pattern ..." while a call from `pcall` -- a C function,
# which has no line -- reads "malformed pattern ...". The vendored VM never
# adds that prefix (DIVERGENCES.md, `error_string_gets_position`); calling
# through `pcall` takes it out of the comparison by construction instead of
# by editing the oracle's answer.
MULTI = """
local P = %s
local subjects = {%s}
local out = {}
for _, S in ipairs(subjects) do
  %s
end
return table.unpack(out)
"""

# `emit(...)` appends one call's results, count first.
EMIT = "local function emit(...) local r = table.pack(...); out[#out + 1] = r.n; for i = 1, r.n do out[#out + 1] = r[i] end end "

MULTI_BODIES = {
    "find": EMIT + "emit(pcall(string.find, S, P))",
    "match": EMIT + "emit(pcall(string.match, S, P))",
    "gsub": EMIT + 'emit(pcall(string.gsub, S, P, "<%0>"))',
    "gmatch": EMIT + """local ok, it = pcall(string.gmatch, S, P)
      if not ok then emit(ok, it) else
        for _ = 1, 200 do
          local r = table.pack(pcall(it))
          emit(table.unpack(r, 1, r.n))
          if not r[1] or r[2] == nil then break end
        end
      end""",
}


def multi_call(pattern: bytes, subjects: list[bytes], call: str) -> str:
    """MULTI with an arbitrary `emit(pcall(...))` body."""
    return MULTI % (lit(pattern), ", ".join(lit(s) for s in subjects), EMIT + call)


def multi(pattern: bytes, subjects: list[bytes], fn: str) -> str:
    return MULTI % (lit(pattern), ", ".join(lit(s) for s in subjects), MULTI_BODIES[fn])


ALL_BYTES = bytes(range(256))

# ---------------------------------------------------------------------------
# A. Character classes against all 256 bytes.
# ---------------------------------------------------------------------------
CLASS_BITMAP = """
local t = {}
for c = 0, 255 do
  t[#t + 1] = string.find(string.char(c), %s) and "1" or "0"
end
return table.concat(t)
"""

for letter in "acdglpsuwxz":
    for cl in (letter, letter.upper()):
        add("A_class_%s" % cl, CLASS_BITMAP % lit("^%" + cl + "$"),
            "%%%s against all 256 bytes" % cl)
# Escapes of non-letters are literals; escaped letters that are not classes
# too.
for esc in ".%-]^$()[*+?bfqyBF0":
    if esc in "0":
        continue  # `%0` is a back-reference error, covered in F
    if esc in "bf":
        continue  # balance and frontier, covered in E
    add("A_escape_%s" % ident(esc), CLASS_BITMAP % lit("^%" + esc + "$"),
        "%%%s against all 256 bytes" % esc)

SETS = [
    "[a]", "[abc]", "[a-c]", "[^a-c]", "[%a_]", "[^%d]", "[%d%s]", "[]]",
    "[^]]", "[]a]", "[a-]", "[-a]", "[a%-z]", "[%a-z]", "[z-a]", "[a-a]",
    "[%]]", "[%%]", "[%-]", "[%^a]", "[^^]", "[\x00-\x1f]", "[\x80-\xff]",
    "[^\x00]", "[%z]", "[%Z]", "[%w%p]", "[^%w%p%s]", "[.]", "[%.]", "[(]",
    "[)]", "[-]", "[^-]", "[a-c-e]", "[%a-]", "[\x00]", "[%x%X]", "[a-c%d]",
    "[^%A]", "[%w-]",
]
for i, s in enumerate(SETS):
    add("A_set_%02d_%s" % (i, ident(s)), CLASS_BITMAP % lit("^" + s + "$"),
        "set %r against all 256 bytes" % s)

for c in [".", "a", "\x00", "\xff", "%"]:
    if c == "%":
        continue
    add("A_single_%s" % ident(c), CLASS_BITMAP % lit("^" + c + "$"),
        "single %r against all 256 bytes" % c)

# ---------------------------------------------------------------------------
# B. Quantifier matrix.
# ---------------------------------------------------------------------------
ITEMS = ["a", ".", "%a", "[ab]", "[^a]", "%d"]
SUFFIXES = ["", "*", "+", "-", "?"]
TAILS = ["", "b", "$", "(.)", "%d", "a"]
B_SUBJECTS = ["", "a", "aaa", "aab", "ba", "abab", "a1b2", "xyz", "aaab1"]

for item in ITEMS:
    for suf in SUFFIXES:
        for tail in TAILS:
            p = item + suf + tail
            for fn in ("find", "gsub", "match"):
                add("B_%s_%s" % (fn, ident(p)),
                    multi(p.encode(), [s.encode() for s in B_SUBJECTS], fn),
                    "%s(%r) over the quantifier subjects" % (fn, p))

# Two quantified items in a row: the backtracking between them.
for a in ["a*", "a-", "a+", "a?", ".*", ".-"]:
    for b in ["a*", "a-", "a+", "a?", "b", ".*", ".-", "$"]:
        p = "(" + a + ")(" + b + ")"
        add("B_pair_%s" % ident(p),
            multi(p.encode(), [s.encode() for s in ["", "a", "aa", "aab", "aaba", "ba"]], "match"),
            "match(%r): backtracking between two quantifiers" % p)

# ---------------------------------------------------------------------------
# C. Anchors.
# ---------------------------------------------------------------------------
ANCHOR_PATTERNS = ["^a", "a$", "^$", "$a", "a$b", "^^a", "a^", "$", "^", "%$",
                   "^%^", "^a*$", "a$$", "^(a)", "(^a)", "^()", "$$", "^%a+$"]
ANCHOR_SUBJECTS = ["", "a", "aa", "ba", "a$b", "^a", "a^", "$", "$a", "^^a", "aaa"]
for p in ANCHOR_PATTERNS:
    for fn in ("find", "match", "gsub", "gmatch"):
        add("C_%s_%s" % (fn, ident(p)),
            multi(p.encode(), [s.encode() for s in ANCHOR_SUBJECTS], fn),
            "%s(%r): anchors" % (fn, p))

# ---------------------------------------------------------------------------
# D. Captures.
# ---------------------------------------------------------------------------
CAPTURE_PATTERNS = [
    "(a)(b)", "((a)(b))", "(a(b)c)", "()a()", "(a*(.)%w(%s*))",
    "(h)(e)(l)(l)(o)", "(()())", "(a)%1", "(a*)%1", "((a)%2)", "(a)(%1)",
    "(a%1)", "()%1", "%1", "(a)%2", "%0", "(a)%9", "(a", "a)", ")", "(",
    "(()", "(a)(", "((a)", "(a))", "()", "(())", "(.)%1", "(.-)%1",
    "(%a+) (%1)", "(%w)%1+", "(['\"])(.-)%1", "(%d)(%d)%2%1", "(a)(b)%2%1",
    "(%s*)$", "^(%s*)(.-)(%s*)$", "()(a)()", "(a?)", "(a-)b", "(.)(.)(.)",
    "%f[%w](%w+)", "(%b())", "()%b()()", "(%f[%a])",
]
CAPTURE_SUBJECTS = ["", "a", "ab", "abc", "aa", "abba", "hello", "x(a(b)c)y",
                    "'q' \"r\"", "1221", "  pad  ", "abab", "a a", "word word"]
for i, p in enumerate(CAPTURE_PATTERNS):
    for fn in ("find", "match", "gsub", "gmatch"):
        add("D_%02d_%s_%s" % (i, fn, ident(p)),
            multi(p.encode(), [s.encode() for s in CAPTURE_SUBJECTS], fn),
            "%s(%r): captures" % (fn, p))

# The 32-capture limit, with string and with position captures, nested and not.
for n in (31, 32, 33):
    flat = "(a)" * n
    add("D_limit_flat_%d" % n,
        "return string.find(%s, %s)" % (lit("a" * 40), lit(flat)),
        "%d flat captures" % n)
    pos = "()" * n
    add("D_limit_pos_%d" % n,
        "return string.find(%s, %s)" % (lit("a"), lit(pos)),
        "%d position captures" % n)
    nested = "(" * n + "a" + ")" * n
    add("D_limit_nested_%d" % n,
        "return string.match(%s, %s)" % (lit("a"), lit(nested)),
        "%d nested captures" % n)
# A failed branch undoes its capture, so the limit counts live captures only.
add("D_limit_undone",
    "return string.match(%s, %s)" % (lit("b" * 40), lit("(a)?" * 20 + "(b)" * 12)),
    "captures undone by failed branches do not count toward the limit")

# ---------------------------------------------------------------------------
# E. Balance and frontier.
# ---------------------------------------------------------------------------
BF_PATTERNS = [
    "%b()", "%b((", "%b)(", '%b""', "%bxy", "%b()x", "x%b()", "%b()%b[]",
    "%b\x00\x01", "%b\x00)", "(%b{})", "%b<>", "%bab",
    "%f[%w]%w+", "%f[%W]", "%f[%z]", "%f[^%z]", "%f[a]", "%f[%a]+",
    "%f[%s]", "%f[^%s]", "%f[%w]", "%f[\x00]", "%f[^\x00]", "%f[%l]%u",
    "%f[%a]%a+%f[%A]", "()%f[%w]", "%f[]a]", "%f[^]]",
]
BF_SUBJECTS = ["", "()", "(a(b)c)", "((", "))", "(a", "a)", "x(y)z(w)", "\"q\"",
               "xay", "xxyy", "\x00a\x01", "\x00)", "{a{b}}", "<a<b>>", "aab",
               "hello world", " lead", "trail ", "THE end", "]]a]", "\x00\x00"]
for i, p in enumerate(BF_PATTERNS):
    for fn in ("find", "gsub", "gmatch"):
        add("E_%02d_%s_%s" % (i, fn, ident(p)),
            multi(p.encode("latin-1"), [s.encode("latin-1") for s in BF_SUBJECTS], fn),
            "%s(%r): balance and frontier" % (fn, p))

# ---------------------------------------------------------------------------
# F. Every error, reached and not reached.
# ---------------------------------------------------------------------------
ERROR_PATTERNS = [
    "%", "a%", "[", "[a", "[^", "[%", "[%]", "[a%", "[]", "[^]", "%b", "%ba",
    "%f", "%fx", "%f[", "%f[a", "(", ")", "a)", "%1", "(a)%2", "%0", "(a)%0",
    "(a", "((a)", "%b(", "x%b", "[%", "%[", "a[b", "a(", "a%f", "a%1",
]
ERROR_SUBJECTS = ["", "a", "b", "x", "ab", "(a)"]
for i, p in enumerate(ERROR_PATTERNS):
    for fn in ("find", "match", "gsub", "gmatch"):
        add("F_%02d_%s_%s" % (i, fn, ident(p)),
            multi(p.encode(), [s.encode() for s in ERROR_SUBJECTS], fn),
            "%s(%r): errors are raised only when reached" % (fn, p))
# Lazy: the malformed tail is never parsed because the head fails first.
for p, s in [("b[", "a"), ("b%", "a"), ("b(", "a"), ("b%1", "a"),
             ("b%f", "a"), ("b%b", "a"), ("a?[", ""), ("x*%", "")]:
    add("F_lazy_%s_on_%s" % (ident(p), ident(s)),
        "return pcall(string.find, %s, %s)" % (lit(s), lit(p)),
        "%r on %r: does the malformed tail get parsed?" % (p, s))

# ---------------------------------------------------------------------------
# G. init and plain.
# ---------------------------------------------------------------------------
INITS = ["nil", "1", "0", "-1", "-3", "2", "4", "5", "6", "100", "-100",
         "math.maxinteger", "math.mininteger", "2.0", "'2'", "2.5", "'x'",
         "-4", "-5", "3"]
G_PATTERNS = ["", "a", "b", "ab", "%a", "^a", "a.b", "()", "^", "$"]
for subj in ["", "abab"]:
    for p in G_PATTERNS:
        for init in INITS:
            for fn in ("find", "match"):
                add("G_%s_%s_on_%s_init_%s" % (fn, ident(p), ident(subj) , ident(init)),
                    "return string.%s(%s, %s, %s)" % (fn, lit(subj), lit(p), init),
                    "%s with init %s" % (fn, init))
            add("G_gmatch_%s_on_%s_init_%s" % (ident(p), ident(subj), ident(init)),
                gmatch_chunk("string.gmatch(%s, %s, %s)" % (lit(subj), lit(p), init)),
                "gmatch with init %s" % init)

PLAINS = ["nil", "true", "false", "1", "0", "''", "{}"]
for p in [".", "a.b", "%a", "(", "[", "a", "", "%"]:
    for plain in PLAINS:
        for init in ["nil", "1", "3", "-2"]:
            add("G_plain_%s_%s_init_%s" % (ident(p), ident(plain), ident(init)),
                "return string.find(%s, %s, %s, %s)" % (lit("xa.b%a([.b"), lit(p), init, plain),
                "find(%r) with plain=%s init=%s" % (p, plain, init))

# The no-specials fast path looks past embedded NULs.
for s, p in [(b"a\x00b.c", b"\x00b"), (b"a\x00b.c", b"\x00."), (b"a\x00b.c", b"b."),
             (b"x\x00\x00y", b"\x00\x00"), (b"\x00", b"\x00"), (b"abc", b"\x00"),
             (b"a.b", b"\x00."), (b"a\x00^b", b"\x00^b")]:
    add("G_nul_%s_in_%s" % (ident(p), ident(s)),
        "return string.find(%s, %s)" % (lit(s), lit(p)),
        "find with an embedded NUL in the pattern")

# ---------------------------------------------------------------------------
# H. gsub.
# ---------------------------------------------------------------------------
TEMPLATES = ["", "x", "%0", "%1", "%2", "%%", "%", "%x", "%a", "[%1]", "%1%1",
             "%9", "%\x00", "%10", "a%%b", "%0%0", "<%1|%2>", "%%1", "%%%1"]
H_PATTERNS = ["a", "(a)", "(a)(b)", "()", "", "(a)()", "(b", "%w+", "(%w)(%w*)"]
for p in H_PATTERNS:
    for t in TEMPLATES:
        add("H_tpl_%s_with_%s" % (ident(p), ident(t)),
            "return string.gsub(%s, %s, %s)" % (lit("abcab ab"), lit(p), lit(t)),
            "gsub(%r, %r)" % (p, t))

MAXES = ["nil", "0", "1", "2", "3", "-1", "math.maxinteger", "math.mininteger",
         "1.0", "1.5", "'1'", "'x'", "{}", "100"]
for p in ["a", "", "^a", "x"]:
    for m in MAXES:
        add("H_max_%s_n_%s" % (ident(p), ident(m)),
            "return string.gsub(%s, %s, %s, %s)" % (lit("aaa"), lit(p), lit("<%0>"), m),
            "gsub(%r) with max %s" % (p, m))

FUNCS = {
    "count": "function(...) return select('#', ...) end",
    "nil": "function() return nil end",
    "false": "function() return false end",
    "true": "function() return true end",
    "table": "function() return {} end",
    "float": "function() return 1.5 end",
    "int": "function() return 42 end",
    "bigfloat": "function() return 2^63 end",
    "negzero": "function() return -0.0 end",
    "upper": "function(s) return s and string.upper(s) end",
    "error": "function() error('boom', 0) end",
    "errortable": "function() error({}) end",
    "multi": "function() return 'A', 'B' end",
    "none": "function() end",
    "args": "function(...) local t = {...}; local o = {} for i = 1, select('#', ...) do o[#o + 1] = tostring(t[i]) end return table.concat(o, ',') end",
    "fn": "function() return tostring end",
    "nan": "function() return 0/0 end",
}
for p in ["a", "(a)(b)", "()", "", "(a)()", "%w+", "(b"]:
    for fname, f in FUNCS.items():
        add("H_fn_%s_%s" % (ident(p), fname),
            "return string.gsub(%s, %s, %s)" % (lit("abcab"), lit(p), f),
            "gsub(%r) with a %s function" % (p, fname))

TABLES = {
    "plain": "{a = 'A', b = 'B'}",
    "false": "{a = false, b = 'B'}",
    "num": "{a = 1, b = 2.5}",
    "tbl": "{a = {}}",
    "bool": "{a = true}",
    "empty": "{}",
    "posint": "{[1] = 'one', [2] = 'two', [3] = 'three'}",
    "idxfn": "setmetatable({}, {__index = function(t, k) return '<' .. tostring(k) .. '>' end})",
    "idxtbl": "setmetatable({}, {__index = {a = 'IA'}})",
    "idxchain": "setmetatable({}, {__index = setmetatable({}, {__index = function(t, k) return k .. k end})})",
    "idxerr": "setmetatable({}, {__index = function() error('idx', 0) end})",
    "idxnil": "setmetatable({}, {__index = function() return nil end})",
}
for p in ["a", "(a)(b)", "()", "%w", "(b"]:
    for tname, t in TABLES.items():
        add("H_tbl_%s_%s" % (ident(p), tname),
            "return string.gsub(%s, %s, %s)" % (lit("abcab"), lit(p), t),
            "gsub(%r) with a %s table" % (p, tname))

# A builtin as the replacement is called once per match; `tostring` rather
# than `print`, whose output would land in the golden file.
REPLS = ["5", "1.5", "-0.0", "2^63", "math.huge", "-math.huge", "nil", "true",
         "coroutine.create(tostring)", "tostring", "0/0"]
for r in REPLS:
    add("H_repl_type_%s" % ident(r),
        "return string.gsub(%s, %s, %s)" % (lit("abc"), lit("b"), r),
        "gsub with replacement %s" % r)
add("H_repl_missing", "return string.gsub('abc', 'b')", "gsub with no replacement")
add("H_repl_bad_and_bad_max", "return string.gsub('abc', 'b', true, 'x')",
    "both the replacement and the count are bad: which is reported")
add("H_anchor_once", "return string.gsub('aaa', '^a', 'b')", "an anchored gsub replaces once")
add("H_anchor_empty", "return string.gsub('aaa', '^', 'b')", "an anchored empty gsub")
add("H_anchor_miss", "return string.gsub('baa', '^a', 'b')", "an anchored gsub that misses")
add("H_empty_subject", "return string.gsub('', '', 'x')", "empty subject, empty pattern")
add("H_empty_after_match", "return string.gsub('abc', '%w*', '-')",
    "an empty match right after a match is skipped")
add("H_unchanged_identity",
    "local s = 'abc'; local r, n = string.gsub(s, 'x', 'y'); return r == s, n",
    "nothing replaced: the original string")

# ---------------------------------------------------------------------------
# I. gmatch iteration.
# ---------------------------------------------------------------------------
I_CASES = [
    ("hello world from lua", "%a+"), ("one two  three", "%S+"), ("abc", ""),
    ("abc", "()"), ("k1=v1, k2=v2", "(%w+)=(%w+)"), ("abc", "%a*"), ("aaa", "a-"),
    ("aaa", "a?"), ("", ""), ("", "a"), ("a,b,,c", "([^,]*)"), ("x", ".-"),
    ("1 22 333", "%d+"), ("a.b.c", "[^.]+"), ("<a><b>", "%b<>"), ("aXbXc", "()X()"),
    ("THE (quick) fox", "%f[%a]%a+"), ("ab", "(a)(b)"), ("ab", "(a"),
]
for i, (s, p) in enumerate(I_CASES):
    add("I_%02d_%s" % (i, ident(p)),
        gmatch_chunk("string.gmatch(%s, %s)" % (lit(s), lit(p))),
        "gmatch(%r, %r)" % (s, p))
add("I_iterator_after_end",
    "local it = string.gmatch('ab', 'a'); return it(), it(), it()",
    "calling the iterator after it is exhausted")
add("I_unfinished_then_next",
    "local it = string.gmatch('abab', '(a'); local a = table.pack(pcall(it)); "
    "local b = table.pack(pcall(it)); return a[1], a[2], b[1], b[2]",
    "an unfinished-capture error still consumes the match")
add("I_two_iterators",
    "local s = 'a1b2'; local i1, i2 = string.gmatch(s, '%a'), string.gmatch(s, '%d'); "
    "return i1(), i2(), i1(), i2(), i1(), i2()",
    "two iterators over one subject are independent")
add("I_for_loop",
    "local t = {} for k, v in string.gmatch('a=1, b=2', '(%w+)=(%w+)') do t[#t+1] = k .. v end "
    "return table.concat(t, ';')",
    "gmatch in a generic for")

# ---------------------------------------------------------------------------
# J. Every pattern literal the shipped NSE corpus uses.
# ---------------------------------------------------------------------------

def lua_tokens(src: bytes):
    """Yield (kind, value) for a Lua source: kind is 'name', 'str' (value is
    the decoded bytes), or 'op'. Comments and numbers are skipped."""
    i, n = 0, len(src)
    while i < n:
        c = src[i:i + 1]
        if c in b" \t\r\n\f\v":
            i += 1
            continue
        if src.startswith(b"--", i):
            m = re.match(rb"--\[(=*)\[", src[i:])
            if m:
                close = b"]" + m.group(1) + b"]"
                j = src.find(close, i + m.end())
                i = n if j < 0 else j + len(close)
            else:
                j = src.find(b"\n", i)
                i = n if j < 0 else j + 1
            continue
        m = re.match(rb"\[(=*)\[", src[i:])
        if m:
            close = b"]" + m.group(1) + b"]"
            j = src.find(close, i + m.end())
            if j < 0:
                return
            body = src[i + m.end():j]
            if body.startswith(b"\r\n"):
                body = body[2:]
            elif body.startswith(b"\n"):
                body = body[1:]
            yield ("str", body)
            i = j + len(close)
            continue
        if c in (b'"', b"'"):
            q = c
            j = i + 1
            out = bytearray()
            ok = True
            while True:
                if j >= n:
                    ok = False
                    break
                ch = src[j:j + 1]
                if ch == q:
                    j += 1
                    break
                if ch == b"\n":
                    ok = False
                    break
                if ch == b"\\":
                    e = src[j + 1:j + 2]
                    simple = {b"n": 10, b"t": 9, b"r": 13, b"a": 7, b"b": 8,
                              b"f": 12, b"v": 11, b"\\": 92, b'"': 34,
                              b"'": 39, b"\n": 10}
                    if e in simple:
                        out.append(simple[e])
                        j += 2
                    elif e == b"x":
                        out.append(int(src[j + 2:j + 4], 16))
                        j += 4
                    elif e == b"z":
                        j += 2
                        while j < n and src[j:j + 1] in b" \t\r\n\f\v":
                            j += 1
                    elif e.isdigit():
                        m2 = re.match(rb"\d{1,3}", src[j + 1:])
                        out.append(int(m2.group(0)) & 0xFF)
                        j += 1 + len(m2.group(0))
                    elif e == b"u":
                        m2 = re.match(rb"u\{([0-9a-fA-F]+)\}", src[j + 1:])
                        out += chr(int(m2.group(1), 16)).encode("utf-8")
                        j += 1 + len(m2.group(0))
                    else:
                        ok = False
                        break
                    continue
                out += ch
                j += 1
            if ok:
                yield ("str", bytes(out))
            i = j
            continue
        m = re.match(rb"[A-Za-z_][A-Za-z0-9_]*", src[i:])
        if m:
            yield ("name", m.group(0).decode())
            i += m.end()
            continue
        m = re.match(rb"0[xX][0-9a-fA-F.]+([pP][+-]?\d+)?|\d+\.?\d*([eE][+-]?\d+)?|\.\d+", src[i:])
        if m:
            i += m.end()
            continue
        yield ("op", c.decode("latin-1"))
        i += 1


PATTERN_FUNCS = {"find", "match", "gmatch", "gsub"}


def corpus_patterns() -> tuple[list[bytes], list[tuple[bytes, bytes]]]:
    """Every literal pattern passed to find/match/gmatch/gsub in the shipped
    Lua, and every literal (pattern, template) pair passed to gsub."""
    pats: set[bytes] = set()
    tpls: set[tuple[bytes, bytes]] = set()
    roots = [os.path.join(REPO, "nselib"), os.path.join(REPO, "scripts")]
    for root in roots:
        for dirpath, _, files in os.walk(root):
            for fn in sorted(files):
                if not (fn.endswith(".lua") or fn.endswith(".nse")):
                    continue
                with open(os.path.join(dirpath, fn), "rb") as fh:
                    toks = list(lua_tokens(fh.read()))
                for k in range(len(toks) - 3):
                    a, b, c = toks[k], toks[k + 1], toks[k + 2]
                    if b[0] != "name" or b[1] not in PATTERN_FUNCS or c != ("op", "("):
                        continue
                    if a == ("op", ":"):
                        j = k + 3  # method form: the pattern is the first argument
                    elif a == ("op", ".") and k >= 1 and toks[k - 1] == ("name", "string"):
                        # `string.f(subject, pattern ...)`: skip the subject.
                        depth, j = 0, k + 3
                        while j < len(toks):
                            t = toks[j]
                            if t[0] == "op" and t[1] in "([{":
                                depth += 1
                            elif t[0] == "op" and t[1] in ")]}":
                                if depth == 0:
                                    j = len(toks)
                                    break
                                depth -= 1
                            elif t == ("op", ",") and depth == 0:
                                j += 1
                                break
                            j += 1
                    else:
                        continue
                    if j + 1 >= len(toks) or toks[j][0] != "str":
                        continue
                    nxt = toks[j + 1]
                    if nxt[0] == "op" and nxt[1] not in ",)":
                        continue  # the literal is part of a larger expression
                    pats.add(toks[j][1])
                    if b[1] == "gsub" and nxt == ("op", ",") and j + 3 < len(toks) \
                            and toks[j + 2][0] == "str" and toks[j + 3][0] == "op" \
                            and toks[j + 3][1] in ",)":
                        tpls.add((toks[j][1], toks[j + 2][1]))
    return sorted(pats), sorted(tpls)


J_SUBJECTS = [
    b"",
    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html; "
    b"charset=UTF-8\r\nContent-Length: 1234\r\nSet-Cookie: id=abc123; path=/; HttpOnly\r\n"
    b"Location: http://www.example.com:8080/a/b.cgi?x=1&y=%20z#frag\r\n\r\n"
    b"<html><head><title>Test Page</title><meta name=\"generator\" content=\"WordPress 5.8\">"
    b"</head><body>Hello, World! <a href='/login.php'>Login</a></body></html>",
    b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
    b"250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
    b"key1=value1&key2=value2; path=/foo/bar.cgi?x=1 user@example.com",
    b"Microsoft-IIS/10.0 nginx/1.18.0 1.2.3-beta4 v10.0.17763 Version: 3.2.1",
    b"192.168.0.1:8080 fe80::1%eth0 www.example.com 10.0.0.255/24 "
    b"00:1A:2B:3C:4D:5E [2001:db8::1]:443",
    b"<?xml version=\"1.0\"?><a b=\"c\">d &amp; e</a><!-- c --><![CDATA[x]]>",
    bytes(range(256)),
    b"  \t leading and trailing \t  ",
    b"\"quoted string\" 'single' (paren (nested)) [bracket] {brace} <angle>",
    b"Mon, 02 Jan 2006 15:04:05 GMT; expires=Tue, 03-Jan-2006 15:04:05 GMT",
    b"0x1F 0777 -12 +3.5e-2 1,234,567 0.0.0.0 255.255.255.255",
    b"line1\nline2\r\nline3\rline4\n\n",
    b"Basic realm=\"secure\", Digest realm=\"x\", nonce=\"abc\", qop=\"auth,auth-int\"",
]

if os.path.isdir(os.path.join(REPO, "nselib")):
    PATS, TPLS = corpus_patterns()
else:
    raise SystemExit("cannot find nselib/ under %s" % REPO)

for i, p in enumerate(PATS):
    for fn in ("find", "match", "gsub", "gmatch"):
        add("J_%04d_%s" % (i, fn), multi(p, J_SUBJECTS, fn),
            "corpus pattern %s via %s" % (ident(p)[:60], fn))
for i, (p, t) in enumerate(TPLS):
    add("J_tpl_%04d" % i,
        multi_call(p, J_SUBJECTS, "emit(pcall(string.gsub, S, P, %s))" % lit(t)),
        "corpus gsub template %s -> %s" % (ident(p)[:40], ident(t)[:20]))

# ---------------------------------------------------------------------------
# K. A seeded random sweep over the grammar.
# ---------------------------------------------------------------------------
rng = random.Random(0x6c706174)  # fixed: the corpus must be reproducible
K_ATOMS = ["a", "b", ".", "%a", "%d", "%s", "%w", "%A", "[ab]", "[^a]", "[a-c]",
           "%%", "%.", "%b()", "%f[%w]", "%f[%W]", "(", ")", "()", "%1", "%2",
           "^", "$", "1", " ", "[%d%s]", "%z", "[", "]", "-", "%"]
K_SUFFIX = ["", "", "", "*", "+", "-", "?"]
K_ALPHA = "ab1 ().a"
K_TPLS = ["x", "%0", "%1", "<%1>", "%%", "", "%2"]
for i in range(3000):
    p = "".join(rng.choice(K_ATOMS) + rng.choice(K_SUFFIX)
                for _ in range(rng.randint(1, 6)))
    subjects = ["".join(rng.choice(K_ALPHA) for _ in range(rng.randint(0, 12)))
                for _ in range(4)]
    fn = rng.choice(["find", "match", "gsub", "gmatch", "tpl"])
    if fn == "tpl":
        t = rng.choice(K_TPLS)
        chunk = multi_call(p.encode(), [x.encode() for x in subjects],
                           "emit(pcall(string.gsub, S, P, %s))" % lit(t))
    else:
        chunk = multi(p.encode(), [s.encode() for s in subjects], fn)
    add("K_%04d_%s" % (i, fn), chunk, "random %s(%r)" % (fn, p))

# ---------------------------------------------------------------------------
# L. Coercion and the method form.
# ---------------------------------------------------------------------------
L_CASES = [
    ("find_int_subject", "return string.find(12345, 34)"),
    ("find_float_subject", "return string.find(1.5, '%.')"),
    ("find_float_whole", "return string.find(2.0, '.0')"),
    ("match_int_pattern", "return string.match('a12b', 12)"),
    ("gsub_int_all", "return string.gsub(1000, 0, 1)"),
    ("gmatch_int", "local it = string.gmatch(123, '%d'); return it(), it(), it(), it()"),
    ("method_find", "return ('hello'):find('l+')"),
    ("method_match", "return ('key=value'):match('(%w+)=(%w+)')"),
    ("method_gsub", "return ('hello'):gsub('l', 'L')"),
    ("method_gmatch", "local t = {} for w in ('a b c'):gmatch('%a') do t[#t+1] = w end return table.concat(t)"),
    ("find_no_args", "return string.find()"),
    ("find_no_pattern", "return string.find('a')"),
    ("find_table_subject", "return string.find({}, 'a')"),
    ("find_nil_pattern", "return string.find('a', nil)"),
    ("match_bool_init", "return string.match('a', 'a', true)"),
    ("gmatch_no_pattern", "return string.gmatch('a')"),
    ("gsub_table_subject", "return string.gsub({}, 'a', 'b')"),
    ("find_init_float_integral", "return string.find('abc', 'c', 3.0)"),
    ("find_init_string_numeral", "return string.find('abc', 'c', ' 3 ')"),
    ("find_init_hex_string", "return string.find('abc', 'c', '0x3')"),
]
for name, chunk in L_CASES:
    add("L_" + name, chunk, "argument coercion: " + name)

# ---------------------------------------------------------------------------
# M. The recursion limit.
# ---------------------------------------------------------------------------
for n in (198, 199, 200, 201, 250):
    add("M_optional_%d" % n,
        "local r = table.pack(pcall(string.match, %s, %s)); return r[1], type(r[2]) == 'string' and #r[2] or r[2]"
        % (lit("a" * 260), lit("a?" * n)),
        "%d optional items, each matching, against MAXCCALLS" % n)
    add("M_optional_miss_%d" % n,
        "return pcall(string.match, %s, %s)" % (lit("b" * 10), lit("a?" * n)),
        "%d optional items that never match: no recursion" % n)
for n in (99, 100, 101):
    add("M_capture_depth_%d" % n,
        "return pcall(string.find, %s, %s)" % (lit("a" * 120), lit("(a)" * 12 + "a?" * n)),
        "captures and optionals together near the limit")
add("M_gsub_deep", "return pcall(string.gsub, %s, %s, 'x')" % (lit("a" * 300), lit("a?" * 250)),
    "gsub raises the recursion error")
add("M_gmatch_deep", "local it = string.gmatch(%s, %s); return pcall(it)" % (lit("a" * 300), lit("a?" * 250)),
    "gmatch raises the recursion error on its first call")
add("M_backtrack_long",
    "return string.find(%s, %s)" % (lit("a" * 3000 + "b"), lit("a*a*b")),
    "long greedy backtracking that succeeds")
add("M_min_long",
    "return string.find(%s, %s)" % (lit("x" * 2000 + "<end>"), lit("(.-)<end>")),
    "long lazy expansion")


def main() -> int:
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m6_pattern.py. Regenerate with ./regen_m6_pattern.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
