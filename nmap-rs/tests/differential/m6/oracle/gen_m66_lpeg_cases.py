#!/usr/bin/env python3
"""M6.6 step 0b: the seeded case generator for nmap's LPeg 0.12 (`lpeg.c`),
`nselib/re.lua` and `nselib/lpeg-utility.lua`.

    gen_m66_lpeg_cases.py [--seed N] [--random N] [--re N] > cases.txt
    gen_m66_lpeg_cases.py --self-test

Each row is `id<TAB>tags<TAB>chunk`. The chunk is Lua source with `\\`, `\\n`
and `\\t` escaped; it runs in the environment oracle/m66_lpeg_core.lua builds.
In that environment every LPeg entry point is a wrapper that calls the C
function through a direct pcall (docs/M6.6-ANALYSIS.md E6): `P`, `S`, `R`,
`V`, `B`, `C`, `Cc`, `Cmt`, `Cb`, `Carg`, `Cp`, `Cs`, `Ct`, `Cf`, `Cg`,
`locale`, `match`, `setmaxstack`, `version`, `ptree`, `pcode`, `ltype`
(lpeg.type), the operators `mul add sub div pow unm len` (the pattern
metatable's `__mul` ... `__len`), `mcall(o, name, ...)` for a method, and the
wrapped `re.*` and `U.*` (lpeg-utility). So no case's error carries a position
prefix. Chunks must not call the raw `lpeg` module (the self-test lints that).

Operator expressions are written here in ordinary Lua infix syntax, which reads
as the corpus' scripts do, and `T()` translates them to the wrapper calls:
`P"a"^0 * "b" + 1` becomes `add(mul(pow(P("a"), 0), "b"), 1)`. Arithmetic on
numeric constants (`2^32+1`, `-1`, `0/0`) stays Lua arithmetic.

Families (docs/M6.6-ANALYSIS.md §3):
  A constructors      B operators        C captures (every kind)
  D grammars/errors   E match() args     F p/string|number|table|function
  G setmaxstack       H Lua-stack and C-stack limits     I locale
  J re (corpus grammars, features, errors)   K lpeg-utility
  Q random re strings (bulk)                 R random pattern trees (bulk)
  X fixed rows: one per sabotage the plan names (§11 row 0b) and per §5 edge

Tags (comma separated, `-` for none):
  cdepth      the answer depends on the embedding's depth: its C-call depth
              (§3), or how much of the Lua stack lies below the call
  drift794    7.94 answers differently from every standalone Lua measured (an
              embedding difference); only the 7.94 agreement check accepts it
  q=LEDGERID  never run by an oracle: the C is undefined or knowingly wrong
              there (a crash or a 16-bit truncation, §1.2); the row goes to
              m66_lpeg_quarantine.txt with that ledger id, for a port pin
"""

import argparse
import random
import re as pyre
import sys

CASES = []
SEEN = set()


def add(cid, chunk, tags=()):
    if cid in SEEN:
        raise SystemExit("duplicate id " + cid)
    SEEN.add(cid)
    CASES.append((cid, chunk, tuple(tags)))


def lstr(b):
    """A Lua string literal, decimal escapes for anything not printable."""
    if isinstance(b, str):
        b = b.encode("latin-1")
    out = ['"']
    for c in b:
        ch = chr(c)
        if ch == '"' or ch == "\\":
            out.append("\\" + ch)
        elif 32 <= c < 127:
            out.append(ch)
        else:
            out.append("\\%03d" % c)
    out.append('"')
    return "".join(out)


ALL256 = bytes(range(256))


def slug(s):
    """An id component for a Lua expression."""
    return pyre.sub(r"[^A-Za-z0-9]", "_", s)

# --------------------------------------------------------------- translator
# Lua expression subset -> wrapper calls. Precedence and associativity are
# Lua's (lparser.c `priority`): + - (10,10), * / % (11,11), unary 12, ^ (14,13).

_TOK = pyre.compile(r"""
    (?P<ws>\s+)
  | (?P<num>0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<str>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')
  | (?P<op>==|~=|<=|>=|\.\.|//|[-+*/%^#(){}\[\];:,.=<>])
""", pyre.X | pyre.S)

KEYWORDS = {"nil", "true", "false", "not", "and", "or", "function", "end", "return", "local"}
NUMNAMES = {"math.huge", "math.maxinteger", "math.mininteger", "math.pi"}
BINPRI = {"+": (10, 10), "-": (10, 10), "*": (11, 11), "/": (11, 11), "%": (11, 11), "^": (14, 13)}
HELPER = {"+": "add", "-": "sub", "*": "mul", "/": "div", "^": "pow"}


def _tokens(src):
    pos, out = 0, []
    while pos < len(src):
        m = _TOK.match(src, pos)
        if not m:
            raise ValueError("cannot tokenize %r at %d" % (src, pos))
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        text = m.group(kind)
        if kind == "name" and text in KEYWORDS:
            kind = "kw"
        out.append((kind, text))
    out.append(("eof", ""))
    return out


class _Parser:
    def __init__(self, src):
        self.t = _tokens(src)
        self.i = 0
        self.src = src

    def peek(self):
        return self.t[self.i]

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, text):
        k, v = self.next()
        if v != text:
            raise ValueError("expected %r, got %r in %r" % (text, v, self.src))

    def expr(self, limit=0):
        k, v = self.peek()
        if (k == "op" and v in ("-", "#")) or (k == "kw" and v == "not"):
            if v == "not":
                raise ValueError("`not` is not translated: %r" % self.src)
            self.next()
            e = ("un", v, self.expr(12))
        else:
            e = self.simple()
        while True:
            k, v = self.peek()
            if k == "op" and v in BINPRI and BINPRI[v][0] > limit:
                self.next()
                e = ("bin", v, e, self.expr(BINPRI[v][1]))
            elif k == "op" and v in ("==", "~=", "<", ">", "<=", ">=", "..", "//"):
                raise ValueError("operator %r is not translated: %r" % (v, self.src))
            else:
                return e

    def simple(self):
        k, v = self.peek()
        if k == "num":
            self.next()
            return ("num", v)
        if k == "str":
            self.next()
            return ("str", v)
        if k == "kw" and v in ("nil", "true", "false"):
            self.next()
            return ("lit", v)
        if k == "op" and v == "{":
            return self.table()
        return self.suffixed()

    def primary(self):
        k, v = self.next()
        if k == "name":
            return ("name", v)
        if v == "(":
            e = self.expr()
            self.expect(")")
            return ("paren", e)
        raise ValueError("unexpected %r in %r" % (v, self.src))

    def args(self):
        k, v = self.peek()
        if k == "str":
            self.next()
            return [("str", v)]
        if v == "{":
            return [self.table()]
        self.expect("(")
        out = []
        if self.peek()[1] != ")":
            out.append(self.expr())
            while self.peek()[1] == ",":
                self.next()
                out.append(self.expr())
        self.expect(")")
        return out

    def suffixed(self):
        e = self.primary()
        while True:
            k, v = self.peek()
            if v == ".":
                self.next()
                e = ("field", e, self.next()[1])
            elif v == "[":
                self.next()
                key = self.expr()
                self.expect("]")
                e = ("index", e, key)
            elif v == ":":
                self.next()
                name = self.next()[1]
                e = ("method", e, name, self.args())
            elif k == "str" or v in ("(", "{"):
                e = ("call", e, self.args())
            else:
                return e

    def table(self):
        self.expect("{")
        fields = []
        while self.peek()[1] != "}":
            k, v = self.peek()
            if v == "[":
                self.next()
                key = self.expr()
                self.expect("]")
                self.expect("=")
                fields.append(("kv", key, self.expr()))
            elif k == "name" and self.t[self.i + 1][1] == "=":
                self.next()
                self.next()
                fields.append(("nv", v, self.expr()))
            else:
                fields.append(("v", None, self.expr()))
            if self.peek()[1] in (",", ";"):
                self.next()
        self.expect("}")
        return ("table", fields)


def _isnum(e):
    tag = e[0]
    if tag == "num":
        return True
    if tag == "field":
        return _emit(e) in NUMNAMES
    if tag == "paren":
        return _isnum(e[1])
    if tag == "un":
        return e[1] == "-" and _isnum(e[2])
    if tag == "bin":
        return _isnum(e[2]) and _isnum(e[3])
    return False


def _emit(e):
    tag = e[0]
    if tag in ("num", "str", "lit", "name"):
        return e[1]
    if tag == "paren":
        return "(" + _emit(e[1]) + ")"
    if tag == "field":
        return _emit(e[1]) + "." + e[2]
    if tag == "index":
        return _emit(e[1]) + "[" + _emit(e[2]) + "]"
    if tag == "call":
        return _emit(e[1]) + "(" + ", ".join(_emit(a) for a in e[2]) + ")"
    if tag == "method":
        return "mcall(" + ", ".join([_emit(e[1]), lstr(e[2])] + [_emit(a) for a in e[3]]) + ")"
    if tag == "table":
        parts = []
        for kind, key, val in e[1]:
            if kind == "kv":
                parts.append("[" + _emit(key) + "] = " + _emit(val))
            elif kind == "nv":
                parts.append(key + " = " + _emit(val))
            else:
                parts.append(_emit(val))
        return "{ " + ", ".join(parts) + " }" if parts else "{}"
    if tag == "un":
        if e[1] == "-" and _isnum(e[2]):
            return "(-" + _emit(e[2]) + ")"
        return ("unm(" if e[1] == "-" else "len(") + _emit(e[2]) + ")"
    if tag == "bin":
        op = e[1]
        if _isnum(e):
            return "(" + _emit(e[2]) + " " + op + " " + _emit(e[3]) + ")"
        if op not in HELPER:
            raise ValueError("operator %r on a non-number" % op)
        return HELPER[op] + "(" + _emit(e[2]) + ", " + _emit(e[3]) + ")"
    raise ValueError(tag)


def T(src):
    """Translate one Lua expression to wrapper calls."""
    p = _Parser(src)
    e = p.expr()
    if p.peek()[0] != "eof":
        raise ValueError("trailing input in %r" % src)
    return _emit(e)


def TL(srcs):
    """Translate a list of Lua expressions into one argument list."""
    return ", ".join(T(s) for s in srcs)


def M(pat, subj, *extra):
    """`return match(<pat>, subj, extra...)` with the pattern translated."""
    args = [T(pat), subj] + list(extra)
    return "return match(%s)" % ", ".join(args)


# ------------------------------------------------------------ A constructors
def sec_A():
    nums = ["0", "1", "2", "3", "-1", "-2", "-3", "255", "-255", "1.0", "1.5", "-1.5", "0.5",
            "-0.0", "2^32", "2^32+1", "2^32+2", "-(2^32)", "-(2^32)-1", "2^53", "1e308",
            "math.huge", "-math.huge", "0/0", "'3'", "'x'", "math.maxinteger", "math.mininteger",
            "2^31-2^31", "2^63", "-(2^63)"]
    subj = ["", "a", "abc", "abcdef", "\x00\xff"]
    for i, n in enumerate(nums):
        for j, s in enumerate(subj):
            add("A.Pnum.%d.%d" % (i, j), M("P(%s)" % n, lstr(s)))
    # sizes the C computes in `int`: 2^31-1 any's overflow numtree's 2n-1
    for i, n in enumerate(["2^31-1", "2^31+1", "-(2^31)+1", "2^32-1+2^31"]):
        add("A.Pbig.%d" % i, "return ltype(P(%s))" % n, ["q=lpeg-tree-size-int-overflow"])
    for i, v in enumerate(["true", "false", "nil", "''", "'a'", "'\\0'", "{}", "Mkeep", "Mnext", "P'a'",
                           "lpeg", "io.stdout", "coroutine.create(print)", "1", "-1", "{ 'a' }"]):
        add("A.Pv.%d" % i, "local p = P(%s); return ltype(p), match(p, 'ab')" % v)
    add("A.Pnone", "return P()")
    sets = [b"", b"a", b"abc", b"aaa", b"\x00", b"\xff", ALL256, b"]-^", b"%.", b"ba"]
    for i, st in enumerate(sets):
        for j, s in enumerate([b"", b"a", b"b", b"\x00", b"\xff", b"-", b"z"]):
            add("A.S.%d.%d" % (i, j), "return match(S(%s), %s)" % (lstr(st), lstr(s)))
    for i, a in enumerate(["12", "{}", "", "nil", "1.5", "P'a'", "'a', 'b'"]):
        add("A.Sarg.%d" % i, "return ltype(S(%s))" % a)
    ranges = ['"az"', '"za"', '"aa"', '"09", "af"', '"\\0\\31"', '"\\128\\255"', '', '"a"', '"abc"', '12', '1',
              '"az", 5', '"az", {}', '"\\255\\0"', '"09", "", "az"']
    for i, r in enumerate(ranges):
        for j, s in enumerate([b"a", b"z", b"5", b"\x00", b"\x80", b"\xff", b"", b"1"]):
            add("A.R.%d.%d" % (i, j), "return match(R(%s), %s)" % (r, lstr(s)))
    behinds = ['"a"', '"ab"', '1', '3', 'S"ab"', 'R"az"*"b"', 'P"a"+"bc"', 'P"a"+"b"', 'C"a"', '""', 'P(255)', 'P(256)',
               '-P"a"', '#P"a"', 'B"a"', 'P{"x"}', 'P(true)', 'P"a"^1', 'P"ab"*Cp()', 'Mkeep', 'P(Mkeep)*"a"',
               'P{ V"x"; x = P"ab" }', 'Cc(1)', 'P"a"^-1', 'P(false)', 'S"ab"*S"cd"', '-P"a"*"b"']
    for i, b in enumerate(behinds):
        for j, (s, init) in enumerate([("ab", 1), ("ab", 2), ("ab", 3), ("xab", 4), ("aab", 3), ("", 1)]):
            add("A.B.%d.%d" % (i, j), M("B(%s) * Cp()" % b, lstr(s), str(init)))
    for i, v in enumerate(["nil", "", "1", "'x'", "true", "1.5", "{}", "P'a'", "0/0", "2^53"]):
        add("A.V.%d" % i, "local p = V(%s); return ltype(p)" % v)
        add("A.Vm.%d" % i, "return match(V(%s), 'a')" % v)
    for i, v in enumerate(['P"a"', '1', '"a"', 'true', '{}', 'nil', 'Mkeep', 'io.stdout', '{ "x", x = P"a" }', '']):
        add("A.type.%d" % i, "return ltype(%s)" % T(v) if v else "return ltype()")
    add("A.version", "return version(), type(lpeg.version)")
    for i, a in enumerate([["P'a'"], ["'abc'"], ["V'x'"], ["{ 'S' }"], ["{ 'S', S = 'a' }"], [], ["nil"], ["1"],
                           ["{ 'S', S = V'S' * 'a' }"], ["Mkeep"], ["P'a'", "true"], ["{ 'S', S = V'T' }"], ["io.stdout"]]):
        add("A.ptree.%d" % i, "return ptree(%s)" % TL(a))
        add("A.pcode.%d" % i, "return pcode(%s)" % TL(a))
    add("A.keys", "local k = {} for n in pairs(lpeg) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')")
    add("A.mt", "local mt = getmetatable(P'a'); local k = {} for n in pairs(mt) do k[#k+1] = n end table.sort(k) "
                "return table.concat(k, ','), mt.__index == lpeg, mt.__name, getmetatable(P(1)) == mt, getmetatable('').__index == string")
    add("A.mtfns", "local mt = getmetatable(P'a'); local t = {} for _, k in ipairs { '__add', '__div', '__len', '__mul', '__pow', '__sub', '__unm', '__gc' } do "
                   "t[#t+1] = type(mt[k]) end return table.concat(t, ',')")
    add("A.setmt", "return pcall(setmetatable, P'a', {})")
    add("A.name.tostring", "local s = tostring(P'a') return s:match('^lpeg%-pattern: 0x%x+$') ~= nil")
    add("A.name.typeerr", "return pcall(string.rep, P'a', 2)")
    add("A.name.argerr", "return Cg(P'a', P'b')")


# ------------------------------------------------------------- B operators
def sec_B():
    operands = ['P"a"', '"a"', '1', 'true', 'false', '{ P"a" }', 'Mkeep', 'S"ab"', 'C"a"', 'nil', '{}', '2.5', 'io.stdout',
                '-1', '""', '0']
    subjects = ["", "a", "ab", "ba", "aab", "abab"]
    k = 0
    for op in ("*", "+", "-"):
        for a in operands:
            for b in operands:
                s = subjects[k % len(subjects)]
                add("B.bin.%d" % k, M("(%s) %s (%s)" % (a, op, b), lstr(s)))
                k += 1
    for i, a in enumerate(operands):
        add("B.neg.%d" % i, M("-(%s)" % a, "'ab'"))
        add("B.and.%d" % i, M("#(%s) * Cp()" % a, "'ab'"))
    pats = ['P"a"', 'S"ab"', 'P"ab"', 'P(1)', 'P""', 'P(true)', '#P"a"', '-P"a"', 'P"a"^0', 'C"a"', 'P"a"+""',
            'Cmt(P"a", Mkeep)', 'P(Mkeep)', 'B"a"', 'P"a"*Cp()', 'P(false)']
    exps = ["0", "1", "2", "3", "-1", "-2", "-3", "1.0", "1.5", "'2'", "'x'", "nil", "2^32", "2^32+1", "-(2^32)+1",
            "' 2 '", "'0x2'", "{}"]
    for i, p in enumerate(pats):
        for j, n in enumerate(exps):
            for kk, s in enumerate(["", "a", "aaaa", "abab", "bb"]):
                add("B.pow.%d.%d.%d" % (i, j, kk), M("(%s)^%s * Cp()" % (p, n), lstr(s)))
    add("B.eq", "return P'a' == P'a', rawequal(P'a', P'a')")
    add("B.concat", "local ok, e = pcall(function() return P'a' .. P'b' end) return ok, (e:gsub('^chunk:%d+: ', ''))")
    add("B.arith", "local ok, e = pcall(function() return P'a' % 2 end) return ok, (e:gsub('^chunk:%d+: ', ''))")
    add("B.idx", "return P'a'.match == lpeg.match, P'a'.nosuch, P'a'.P == lpeg.P")
    add("B.method.0", "return mcall(P'a', 'match', 'a')")
    add("B.method.1", "return mcall(P'ab', 'match', 'ab', 2)")
    add("B.method.2", "return mcall(P'a', 'match')")
    # identity: these return an operand itself, which rawequal sees (§5)
    ident = [("mul(x, true)", "x"), ("mul(true, x)", "x"), ("add(x, false)", "x"), ("mul(pf, x)", "pf"),
             ("add(pt, x)", "pt"), ("add(pf, x)", "x"), ("mul(x, pt)", "x"), ("P(x)", "x"), ("add(false, x)", "x"),
             ("mul(x, P(true))", "x"), ("sub(x, false)", "x"), ("pow(x, 0)", "x"), ("mul(x, '')", "x"),
             ("add(x, x)", "x"), ("mul(x, x)", "x"), ("mul(x, 0)", "x"), ("mul(false, x)", "x")]
    for i, (expr, who) in enumerate(ident):
        add("B.ident.%d" % i, "local x, pt, pf = P'a', P(true), P(false) local r = %s return rawequal(r, %s), ltype(r), match(r, 'ab')" % (expr, who))


# -------------------------------------------------------------- C captures
CAPS = [
    'C(P"a")', 'C(P"a"^0)', 'C(C"a" * C"b")', 'C(1)^0', 'C(P(1)*C(1))', 'C(C(C(1)))',
    'Cc()', 'Cc(nil)', 'Cc(1, 2, 3)', 'Cc(nil, 1, nil)', 'Cc(true, false)', 'Cc({1,2})', 'Cc("x") * Cc("y")', 'Cc(1.5, -0.0, 0/0)',
    'Cp()', 'Cp() * 1 * Cp()', 'P(1)^0 * Cp()',
    'Carg(1)', 'Carg(2)', 'Carg(3)', 'Carg(1) * Carg(1)',
    'Cs(P"a")', 'Cs((P"a"/"x" + 1)^0)', 'Cs((C"a" + 1)^0)', 'Cs((Cc("Z") * "a" + 1)^0)', 'Cs((P"a"/Fnone + 1)^0)', 'Cs((P"a"/{} + 1)^0)',
    'Cs((P"a"/{a=1} + 1)^0)', 'Cs((P"a"/{a=true} + 1)^0)', 'Cs((P"a"/{a={}} + 1)^0)', 'Cs(Cp() * 1)', 'Cs(Ct(1))', 'Cs(Cs("a") * Cs("b"))', 'Cs(C(1) * C(C(1)))',
    'Ct(C(1)^0)', 'Ct(Cg(C(1), "k")^0)', 'Ct(Cg(C(1) * C(1), "k"))', 'Ct(Cg(C(1) * C(1)))', 'Ct(Cg(Cc(), "k") * C(1))', 'Ct(Cg(C(1), 1) * C(1))', 'Ct(C(1) * Cg(C(1), 1))',
    'Ct(Cg(C(1), true))', 'Ct(Ct(C(1)) * Ct(""))', 'Ct("")', 'Ct(Cc(nil, 1))', 'Ct(Cg(C(1), 2.5))', 'Ct(Cp() * Cc(nil) * Cp())',
    'Cg(C(1) * C(1))', 'Cg(C(1), "n")', 'Cg(C(1), "n") * Cb("n")', 'Cg(C(1), "n") * Cg(C(1), "n") * Cb("n")', 'Cb("n")', 'Cg(C(1) * C(1), "n") * Cb("n") * Cb("n")',
    'Cg(Cc(), "n") * Cb("n")', 'Ct(Cg(C(1), "n") * Cb("n"))', 'Cg(C(1), "n") * Ct(Cb("n"))', 'Ct(Cg(C(1), "n")) * Cb("n")', 'Cg(C(1), "n") * (Cb("n") * "z" + Cb("n"))',
    'Cg(C(1), 1) * Cb(1)', 'Cg(C(1), 1) * Cb("1")', 'Cg(C(1), true) * Cb(true)', 'Cb({})', 'Cg(C(1), "n") * Cg(Cb("n") * C(1), "n") * Cb("n")',
    'Cg(C(1), "a") * Cg(C(1), "b") * Cb("a")', 'Cg(C(1), "a") * Cg(C(1), "b") * Cb("b") * Cb("a")',
    'Cf(C(1)^0, Gcat)', 'Cf(Cc(0) * C(1)^0, Gcat)', 'Cf(Ct("") * Cg(C(1) * C(1))^0, Gset)', 'Cf(C(1)^0, Gnil)', 'Cf(Cc(), Gcat)', 'Cf(Cc(nil), Gcat)', 'Cf(C(1) * Cc(1,2) * C(1), Gcat)',
    'Cf(C(1) * Cg(C(1) * C(1)), Gcat)', 'Cf(C(1), Gfirst)', 'Cf(C(C(1)*C(1)), Gcat)', 'Cf(C(1) * Cg(C(1) * C(1)), Gmany)',
    'Cmt(C(1), Mcaps)', 'Cmt(1, Mkeep)', 'Cmt(1, Mnext)', 'Cmt(1, Mtrue)', 'Cmt(1, Mfalse)', 'Cmt(1, Mnil)', 'Cmt(1, Mback)', 'Cmt(1, Mend)', 'Cmt(1, Mbeyond)',
    'Cmt(1, Mstr)', 'Cmt(1, Mfloat)', 'Cmt(1, Mintf)', 'Cmt(1, Mtbl)', 'Cmt(1, Mcount)', 'Cmt(C(1)*Cp()*Cc(nil), Mcount)', 'Cmt(1, Mvals)', 'Cmt(1, Mgate)^0 * Cp()',
    'Cmt(1, Merr)', 'Cmt(1, Ferrt)', 'Cmt(C(1)^0, Mcaps)', 'Cmt(Ct(C(1)), Mcaps)', 'Cmt(Cmt(1, Mvals), Mcaps)', '(Cmt(1, Mvals) * "z" + C(1))', 'Cmt(1, Mre)',
    'P(Mkeep)', 'P(Mvals)', 'P(Mfalse) + C(1)', 'P(Mnext)^0 * Cp()', 'Cmt(Cb("n"), Mcaps)', 'Cg(C(1), "n") * Cmt(Cb("n"), Mcaps)', 'Cmt(1, Mnone)', 'Cmt(1, Merrt)',
    'C(1) / Fid', 'C(1) / Fcat', 'C(1) / Fnone', 'C(1) / Fnil', 'C(1) / Ffalse', 'C(1) / Fmulti', 'C(1) / Ferr', 'C(1) / Ftab', '(C(1) * C(1)) / Fcat', 'P(1) / Fcat', '(P"z" / Fcat + 1) * Cp()',
    'Ct((C(1) / Fmulti)^0)', 'Cs((C(1) / Fmulti)^0)', '(C(1) / Fcat)^0 * Cp()', 'C(1)/Fcat * C(1)/Fcat', 'Cmt(C(1) / Fcat, Mcaps)', '(C(1) / Fcat * "z") + C(1)',
]


def sec_C():
    S = ["", "a", "ab", "abc", "aXb", "abcabc"]
    for i, c in enumerate(CAPS):
        for j, s in enumerate(S):
            add("C.%d.%d" % (i, j), M(c, lstr(s), "1", "'A1'", "22"))
    for i, c in enumerate(['Carg(0)', 'Carg(-1)', 'Carg(32767)', 'Carg(32768)', 'Carg("2")', 'Carg(1.5)', 'Carg()', 'Carg(2^32+1)', 'Carg(" 1 ")']):
        add("C.carg.%d" % i, M(c, "'a'", "1", "'A1'"))
    for i, c in enumerate(['Cf(1, nil)', 'Cf(1, 2)', 'Cmt(1)', 'Cmt(1, "x")', 'Cmt(1, {})', 'Cg()', 'C()', 'Ct()', 'Cs()', 'Cb()',
                           'Cg(1, nil)', 'Cf()', 'Cmt()', 'Cc(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)', 'Cg(1, {})', 'Cb(nil)', 'Cg(1, P"a")']):
        add("C.bad.%d" % i, M(c, "'a'"))


# -------------------------------------------------------------- D grammars
GRAMMARS = [
    '{ "S", S = P"a" * V"S" + "" }', '{ P"a" * V(1) + "" }', '{ "S", S = V"A" * V"B", A = C"a", B = C"b" }',
    '{ [1] = "S", S = "a" }', '{ "S", S = P"a", T = V"U" }', '{ "S", S = V"T" }', '{ "S" }', '{}', '{ [2] = P"a" }', '{ "S", S = {} }',
    '{ "S", S = P(true) * V"S" }', '{ "S", S = V"S" * "a" + "b" }', '{ "S", S = V"A", A = V"B", B = V"S" * "x" }', '{ "S", S = "a" + V"S" }',
    '{ "S", S = (V"E")^0, E = P"" }', '{ "S", S = (V"E" * "")^0, E = P"a"^0 }', '{ "S", S = V"E"^1, E = P"a" + P"" }',
    '{ "S", S = -V"S" * "a" }', '{ "S", S = #V"S" * "a" }', '{ "S", S = B"a" * V"S" + "a" }', '{ "S", S = C(V"S") }',
    '{ "S", S = P{ "T", T = P"a" * V"T" + "" } }', '{ "S", S = P{ V"S" } }', '{ "S", S = V"T", T = P{ "U", U = "a" } * V"S" + "b" }',
    '{ "S", S = Cmt(V"S", Mkeep) + "a" }', '{ "S", S = V"A" + V"B", A = V"B" * "x", B = "y" }', '{ "S", S = V(1) }',
    '{ "S", S = V"T", T = "t", [3] = "x" }', '{ "S", S = "s", T = "t", [1.5] = P"x" }', '{ "S", [true] = P"x", S = V(true) }',
    '{ V(2), P"b" * V(2) + "c" }', '{ "S", S = V"T", T = 1 }', '{ "S", S = V"T", T = Mkeep }',
    '{ "S", S = Ct(Cg(C"a", "x") * V"T"), T = Cb("x") }', '{ "S", S = Cg(C"a", "x") * V"T", T = Cb("x") }',
    '{ 1, P"a" }', '{ true }', '{ "S", S = V"S" }', '{ "S", S = P"a" * V"S" }', '{ "S", S = P"(" * V"S"^0 * ")" }',
    '{ "S", S = Cs((V"N" + 1)^0), N = R"09"^1 / Fcat }', '{ "S", S = V"1", ["1"] = P"a" }', '{ "S", S = V"1.0", ["1.0"] = P"a" }',
    '{ "S", S = V"2", ["2"] = P"a" }', '{ "S", S = V(1.0), [1.0] = P"a" }', '{ "S", S = V"T", T = io.stdout }',
    '{ "S", S = V"T" + V"U", T = P"a"^-1 * V"S" }', '{ "S", S = (V"S" + "a")^0 }', '{ "S", S = P"a" * V"S"^-1 }',
    '{ "S", S = B(V"T"), T = P"ab" }', '{ "S", S = B(V"S" * "a") + "b" }', '{ "S", S = V"T" * V"T", T = C"a" + "b" }',
]


def sec_D():
    subs = ["", "a", "aaa", "ab", "aaab", "xy", "yx", "(()())", "a1b22", "b", "c", "bbc"]
    for i, g in enumerate(GRAMMARS):
        add("D.build.%d" % i, "local p = P(%s); return ltype(p)" % T(g))
        for j, s in enumerate(subs):
            add("D.%d.%d" % (i, j), M("P(%s)" % g, lstr(s)))
    for n in (199, 200, 201, 250):
        add("D.rules.%d" % n, "local g = { 'r1' } for i = 1, %d do g['r'..i] = P(i %% 7 == 0 and 'x' or 'y') end return ltype(P(g))" % n)
    for n in (198, 199, 200, 201):
        add("D.leftchain.%d" % n, "local g = { 'R1' } for i = 1, %d do g['R'..i] = V('R'..(i+1)) end g['R'..(%d+1)] = P'a' return match(P(g), 'a')" % (n - 1, n - 1))
    for n in (50, 110, 199):
        add("D.fixedcount.%d" % n, "local g = { 'R%d', E = P'', R0 = P'a' } for i = 1, %d do g['R'..i] = mul(V('R'..(i-1)), V'E') end return match(B(P(g)), 'a', 2)" % (n, n))
    add("D.lr.chain", "return pcall(P, { 'a', a = V'b', b = V'c', c = V'd', d = mul(V'a', 'x') })")
    add("D.lr.unref", "return pcall(P, { 's', s = P'x', c = mul(V'd', 'x'), d = mul(V'c', 'y') })")
    add("D.emptyloop.unref", "return pcall(P, { 's', s = P'x', e = pow(P'', 0) })")
    add("D.notpat.two", "return pcall(P, { 's', s = P'x', t = io.stdout, u = io.stderr })")
    add("D.notpat.one", "return pcall(P, { 's', s = P'x', t = io.stdout })")
    add("D.undef.two", "return pcall(P, { 's', s = add(V'x', V'y') })")
    add("D.initnum", "return match(P{ 2, P'a', P'b' }, 'b')")
    add("D.initmissing", "return match(P{ 'nope', S = P'a' }, 'a')")
    add("D.initbad", "return match(P{ io.stdout }, 'a')")
    add("D.eqkeys", "local mt = { __eq = function() return true end } local k1, k2 = setmetatable({}, mt), setmetatable({}, mt) "
                    "return pcall(match, P{ k1, [k1] = mul(P'a', V(k2)), [k2] = P'b' }, 'ab')")
    add("D.outside", "return match(V'x', 'a')")
    add("D.outside2", "return match(add(V'x', 1), 'a')")
    add("D.nested", "return match(P{ 'S', S = mul(P{ 'T', T = P'x' }, V'U'), U = P'y' }, 'xy')")


# ---------------------------------------------------------- E match args
def sec_E():
    inits = ["nil", "1", "0", "-1", "-3", "2", "3", "4", "5", "100", "-100", "1.0", "1.5", "'2'", "'x'",
             "math.mininteger", "math.maxinteger", "{}", "-0.0", "' 2 '", "2^53", "-4", "-5"]
    for i, ini in enumerate(inits):
        for j, s in enumerate(["", "abc"]):
            add("E.init.%d.%d" % (i, j), M("Cp() * C(P(1)^0)", lstr(s), ini))
    subs = ["123", "1.5", "2^53", "-0.0", "nil", "{}", "true", "io.stdout", "2^63", "-1"]
    for i, s in enumerate(subs):
        add("E.subj.%d" % i, M("C(P(1)^0)", s))
    pats = ['"ab"', '2', '-1', 'true', 'false', '{ "a" }', 'Mkeep', 'nil', '{}', 'io.stdout', '0', '""']
    for i, p in enumerate(pats):
        add("E.patt.%d" % i, "return match(%s, 'abc')" % p)
    add("E.nargs", "return match()")
    add("E.onearg", "return match(P'a')")
    add("E.extra", M("Carg(1)*Carg(2)*Carg(3)", "'a'", "1", "nil", "false"))
    add("E.many", "local a = {} for i = 1, 100 do a[i] = i end return match(Carg(100), 'a', 1, table.unpack(a))")
    add("E.bin", "return match(C(pow(R('\\0\\255'), 0)), %s)" % lstr(ALL256))
    add("E.long", "local s = ('ab'):rep(50000) return match(mul(div(C(pow(P'ab', 0)), string.len), Cp()), s)")
    add("E.long2", "local s = ('a'):rep(100000) .. 'b' return match(mul(pow(add(mul(pow(P'a', 1), 'b'), 1), 0), Cp()), s)")
    add("E.nul", "return match(C('a\\0b'), 'a\\0b'), match(P'a\\0c', 'a\\0b')")


# -------------------------------------------------------- F div captures
def sec_F():
    fmts = ['""', '"x"', '"%0"', '"%1"', '"%2"', '"%9"', '"%%"', '"%a"', '"x%"', '"%"', '"%10"', '"<%1|%2|%0>"', '"%1%1%1"', '"\\0%1\\0"', '"%-1"', '"%%1"']
    bodies = ['C(1)', 'C(1) * C(1)', 'P(1)', 'C(C(1))', 'Cp() * 1', 'Ct(1)', 'Cc(nil)', 'Cc()', 'C(1)/"q%1"', 'Cs(C(1))',
              'Cc(1,2,3,4,5,6,7,8,9,10,11)', 'C(1)*C(1)*C(1)*C(1)*C(1)*C(1)*C(1)*C(1)*C(1)*C(1)*C(1)', 'Cmt(1, Mvals)', 'C(1)/Fnone',
              'Cc(1.5)', 'Cc(true)', 'C(1) * Cg(C(1), "g")']
    k = 0
    for f in fmts:
        for b in bodies:
            add("F.str.%d" % k, M("(%s) / %s" % (b, f), "'abcdefghijklm'"))
            k += 1
    nums = ["0", "1", "2", "3", "-1", "32767", "32768", "1.5", "2^31", "2^32", "2^32+1", "2^32+3", "-(2^32)+1", "'1'", "2^63", "0/0"]
    for i, n in enumerate(nums):
        for j, b in enumerate(bodies[:8]):
            add("F.num.%d.%d" % (i, j), M("(%s) / %s" % (b, n), "'abcdef'"))
    tabs = ['{a="A"}', '{a=1, b=2}', '{}', '{[1]="one"}', '{a=false}', '{a={}}', 'IDXF', '{a=nil}', 'IDXT', '{[""]="E"}', '{a=P"x"}']
    for i, t in enumerate(tabs):
        for j, b in enumerate(['C(1)', 'P(1)', 'Cp()*1', 'C(1)*C(1)', 'Cc(nil)', 'Cc()', 'Cc(0/0)', 'Cc(1)', 'C(0)']):
            add("F.tab.%d.%d" % (i, j), M("(%s) / %s" % (b, t), "'ab'"))
    for i, v in enumerate(['true', 'false', 'nil', 'io.stdout', 'P"x"', 'coroutine.create(print)']):
        add("F.bad.%d" % i, M("P(1) / %s" % v, "'ab'"))


# ------------------------------------------------------- G setmaxstack
SMS_GRAMMAR = "{ 'S', S = add(mul(mul(P'a', V'S'), 'b'), '') }"


def sec_G():
    # depth-n nesting of a self-recursive rule: each level holds two entries
    # (call and choice) on the backtrack stack
    for ms in ["nil", "0", "1", "5", "50", "99", "100", "101", "200", "1000", "-5", "'10'", "'x'", "2^32", "2^32+150",
               "1.5", "{}", "2^31", "'1000'", "' 300 '"]:
        for depth in (3, 30, 49, 50, 51, 98, 99, 100, 101, 150, 499, 500, 600):
            add("G.%s.%d" % (slug(ms), depth),
                "local ok, e = pcall(setmaxstack, %s) if not ok then return 'set', e end "
                "return match(mul(P(%s), Cp()), ('a'):rep(%d) .. ('b'):rep(%d))" % (ms, SMS_GRAMMAR, depth, depth))
    add("G.none", "setmaxstack() return match(mul(P{ 'S', S = add(mul(P'a', V'S'), '') }, Cp()), ('a'):rep(60))")
    add("G.noarg.ret", "return setmaxstack(), setmaxstack(200)")
    for n in (40, 49, 50, 51, 99, 100, 101):
        add("G.choice.%d" % n, "local p = P'z' for i = 1, %d do p = mul(P'a', add(p, 'x')) end return match(mul(p, Cp()), ('a'):rep(%d) .. 'z')" % (n, n))


# ------------------------------------------------------------- H limits
def sec_H():
    # The Lua stack's ceiling on captures (LUAI_MAXSTACK less what lies
    # below the call) depends on the embedding, as the C-call depth does:
    # rows near it are `cdepth`, and the `.rel` rows pin it relative to
    # table.unpack's ceiling in the same embedding.
    for n in (10, 1000, 900000, 999000, 999900, 999925, 999950, 999990, 1000100, 2000000):
        add("H.stackcaps.%d" % n, "local s = ('a'):rep(%d) local r = table.pack(pcall(match, pow(C(1), 0), s)) "
                                  "return r[1], r.n, r[1] and #r[r.n] or r[2]" % n, ["cdepth"] if 999000 <= n <= 1000100 else [])
    add("H.stackcaps.rel", "return stack_rel()")
    add("H.tablecaps.2e6", "return summ(match(Ct(pow(C(1), 0)), ('a'):rep(2000000)))")
    add("H.cs.1e6", "return #match(Cs(pow(div(P'a', 'bb'), 0)), ('a'):rep(1000000))")
    # Below 190 every embedding measured gives the same answer (standalone
    # Lua 5.4.4, 5.4.6, 5.4.8 and 7.94), so only the rows near the ceiling
    # are `cdepth`.
    for d in (10, 100, 150, 180, 190, 192, 193, 194, 195, 196, 197, 198, 199, 200, 250):
        add("H.reenter.%d" % d, "return reenter(%d)" % d, ["cdepth"] if d >= 190 else [])
    # 0 under every standalone Lua measured; -1 under 7.94, whose LPeg
    # re-entry costs one C level more than its gsub's. Only the 7.94 check
    # accepts that (`drift794`); the port is held to 0.
    add("H.reenter.rel", "local a, b = depth_lpeg(), depth_gsub() return a - b", ["drift794"])
    add("H.cmtdeep", "local n = 0 local p = pow(Cmt(1, function(s, i) n = n + 1 return i end), 0) return match(p, ('a'):rep(100000)), n")
    for n in (100000, 499000, 500000, 1100000):
        add("H.dyncaps.%d" % n, "local r = table.pack(pcall(match, pow(Cmt(1, Mv), 0), ('a'):rep(%d))) return r[1], r.n, r[r.n]" % n,
            ["cdepth"] if 499000 <= n <= 500000 else [])
    add("H.ktable.300", "local p = P(true) for i = 1, 300 do p = mul(p, Cc(i)) end local r = table.pack(match(p, '')) return r.n, r[1], r[300]")
    for n in (10, 16, 40, 100, 200, 299):
        add("H.nestC.%d" % n, "local p = P'a' for i = 1, %d do p = C(p) end local r = table.pack(match(p, 'a')) return r.n, r[1], r[r.n]" % n)


# ------------------------------------------------------------- I locale
LOCALE_CLASSES = ["alnum", "alpha", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit"]


def sec_I():
    add("I.keys", "local t = locale() local k = {} for n in pairs(t) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')")
    for cls in LOCALE_CLASSES:
        add("I.%s" % cls, "local p = locale()[%s] local b = {} for c = 0, 255 do b[#b+1] = match(p, string.char(c)) and '1' or '0' end return table.concat(b)" % lstr(cls))
    add("I.fill", "local t = { alpha = 1, x = 2 } local r = locale(t) return r == t, ltype(t.alpha), t.x")
    add("I.newindex", "local t = logtable() local r = locale(t) return rawequal(r, t), ltype(rawget(t, 'digit'))")
    add("I.bad", "return locale(5)")
    add("I.nil", "return ltype(locale(nil).digit)")
    add("I.str", "return locale('x')")
    add("I.extra", "return ltype(locale(nil, 1).alpha)")


# ----------------------------------------------------------------- J re
AFF = [
    ("ga", "{| ({'UA-' [%d]^6 [%d]^-3 '-' [%d][%d]?} / .)* |}"),
    ("ads", "{| ({'pub-' [%d]^16} / .)* |}"),
    ("amz", """
  body <- {| (uri / .)* |}
  uri <- 'http://' ('www.amazon.com/' ([\\?&;] 'tag=' tag / [^"'])*) / ('rcm.amazon.com/' ([\\?&;] 't=' tag / [^"'])*)
  tag <- {[%w]+ '-' [%d]+}
"""),
    ("amzn", "{| ( 'http://' ('www.')? 'amzn.to' {'/' ([%a%d])+ } / .)*|}"),
]
AFF_SUBJ = [
    "", "UA-123456-1", "xx UA-1234567-12 yy UA-12345-1 UA-123456789-12",
    "<script>_gaq.push(['_setAccount', 'UA-1234567-1']);</script>",
    "pub-1234567890123456 pub-123 pub-12345678901234567",
    '<a href="http://www.amazon.com/dp/B000?tag=abc-20&x=1">x</a> <img src="http://rcm.amazon.com/e/cm?t=nmap-21&o=1">',
    "see http://amzn.to/abc123 and http://www.amzn.to/Z9 and http://amzn.to/",
    "\x00\xffUA-000000-00\n",
]
RE_DEFS = "{ f = Fcat, g = Mkeep, mt = Mcaps, x2 = P'xx', foo = 5 }"


def sec_J():
    for name, g in AFF:
        add("J.aff.%s.build" % name, "return ltype(re.compile(%s))" % lstr(g))
        for j, s in enumerate(AFF_SUBJ):
            add("J.aff.%s.%d" % (name, j), "return mcall(re.compile(%s), 'match', %s)" % (lstr(g), lstr(s)))
    feats = [
        "'a'", '"a"', "'a' 'b'", "'a' / 'b'", "'a'*", "'a'+", "'a'?", "'a'^2", "'a'^+2", "'a'^-2", ".", "[abc]", "[^abc]", "[a-c]", "[a-]", "[]]", "[]-a]",
        "[%d]", "%d+", "%a %s %w %l %u %x %p %c %g", "%D %A %S %W", "%nl", "{.}", "{}", "{:x: . :} =x", "{:x: . :}", "{: . . :}", "{~ ('a' -> 'b' / .)* ~}",
        "{| {.}* |}", "{| {:k: . :} {:v: . :} |}", ". -> 'x%0'", "{.} -> '%1%1'", ". -> 3", "{.} {.} -> 2", "{.} -> {}", "&'a' .", "!'a' .", "('a' / 'b')*",
        "s <- 'a' s / ''", "s <- {'a'} t  t <- {'b'}", "<s> <- 'a'", "s <- t  t <- 'x'", "-- comment\n'a'", "'a' -- c", "  'a'  ", "", "'a' 'b' / 'c' 'd'",
        "{.} -> f", ". => g", "%{x}", "{.} => mt", "%x2", "%foo", "'a' ^3", "[%a%d_]+", "{[^,]*} (',' {[^,]*})*", "'\\n'", "[\\t ]",
        "{.} -> mt", "{:a: . :} {:b: . :} =a =b", "s <- '(' s* ')' / [^()]", "{| {:n: . :}* |}",
    ]
    subs = ["", "a", "ab", "abc", "aab", "bba", "a,b,,c", "xx", "\n", "12ab", "\x00\xff", "(()a)"]
    for i, f in enumerate(feats):
        add("J.feat.%d.build" % i, "return ltype(re.compile(%s, %s))" % (lstr(f), RE_DEFS))
        for j, s in enumerate(subs):
            add("J.feat.%d.%d" % (i, j), "return mcall(re.compile(%s, %s), 'match', %s)" % (lstr(f), RE_DEFS, lstr(s)))
    bad = ["(", ")", "'a", '"a', "[a", "{", "{|", "{~", "{:", "'a' ->", "s <- ", "s <- 'a' s <- 'b'", "x", "%undefined", "<x", "a <- b",
           "'a' ^", "'a' ^x", "=", "=x", "&", "!", "/ 'a'", "'a' /", "[]", "[^]", "{:x:}", "s <- t t <- s", "s <- s 'a'", "s <- ('a'?)*", "'a' -> f", ". => nope",
           "((((((((((((((((('a')))))))))))))))))", "{{{{{{{{{{{{{{{{{{{{'a'}}}}}}}}}}}}}}}}}}}}"]
    for i, b in enumerate(bad):
        add("J.bad.%d" % i, "return re.compile(%s)" % lstr(b))
        add("J.badd.%d" % i, "return re.compile(%s, %s)" % (lstr(b), RE_DEFS))
    for d in (5, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 30, 50):
        add("J.nest.paren.%d" % d, "return pcall(re.compile, ('('):rep(%d) .. \"'a'\" .. (')'):rep(%d))" % (d, d))
        add("J.nest.alt.%d" % d, "local t = {} for i = 1, %d do t[i] = \"'\" .. i .. \"'\" end return pcall(re.compile, table.concat(t, ' / '))" % d)
        add("J.nest.seq.%d" % d, "return pcall(re.compile, (\"'a' \"):rep(%d))" % d)
    for i, (s, p) in enumerate([("abc", "'b'"), ("abc", "{'b'}"), ("aaa", "'a'*"), ("x", "'y'"), ("", "''"), ("hello world", "%w+")]):
        add("J.find.%d" % i, "return re.find(%s, %s)" % (lstr(s), lstr(p)))
        add("J.find.%di" % i, "return re.find(%s, %s, 2)" % (lstr(s), lstr(p)))
        add("J.match.%d" % i, "return re.match(%s, %s)" % (lstr(s), lstr(p)))
        add("J.gsub.%d" % i, "return re.gsub(%s, %s, '<%%0>')" % (lstr(s), lstr(p)))
    add("J.gsub.fn", "return re.gsub('a1b22', '[%d]+', Fcat)")
    add("J.gsub.tab", "return re.gsub('a1b2', '{[%d]}', { ['1'] = 'one' })")
    add("J.updatelocale", "re.updatelocale() return re.match('a1', '%a %d')")
    add("J.compile.patt", "local p = P'a' return rawequal(re.compile(p), p)")
    add("J.compile.nil", "return re.compile(nil)")
    add("J.compile.num", "return mcall(re.compile(12), 'match', '12')")
    add("J.match.bad", "return re.match('a', '(')")


# -------------------------------------------------------- K lpeg-utility
def sec_K():
    for i, (lit, subj) in enumerate([("abc", "ABC"), ("abc", "aBcd"), ("", "x"), ("a1-", "A1-"), ("x", "y"), ("\x00\xe9", "\x00\xc9")]):
        add("K.caseless.%d" % i, "return match(C(U.caseless(%s)), %s)" % (lstr(lit), lstr(subj)))
    for i, (p, s) in enumerate([('P"b"', "aab"), ('C"b"', "aab"), ('P"z"', "aab"), ('Cp()', "")]):
        add("K.anywhere.%d" % i, "return match(U.anywhere(%s), %s)" % (T(p), lstr(s)))
    for i, (s, sep) in enumerate([("a,b,,c", "','"), ("a,b,,c", "P','"), ("", "P','"), ("abc", "P''"), ("a;b", "S',;'")]):
        add("K.split.%d" % i, "return U.split(%s, %s)" % (lstr(s), T(sep)))
    for i, (p, s) in enumerate([('P"cat"', "concat cat"), ('C"cat"', "the cat"), ('P"x"', "xx x")]):
        add("K.awb.%d" % i, "return match(U.atwordboundary(%s), %s)" % (T(p), lstr(s)))
    for i, (a, s) in enumerate([("", r'"abc"'), ("", r'"a\"b\\c\d"'), ("\"'\"", r"'a\'b'"), ("'\"', '#'", r'"a#"b##"'), ("", r'"unterminated')]):
        add("K.eq.%d" % i, "return match(U.escaped_quote(%s), %s)" % (a, lstr(s)))
    add("K.localize", "return match(U.localize{ div(pow(V'digit', 1), tonumber) }, '123x')")
    fp = ('SF-Port80-TCP:V=7.94%I=7%D=1/1%Time=0%P=x86_64-pc-linux-gnu%r(NULL,6,"abc\\x41\\n")%r'
          '(GetRequest,1A,"HTTP/1\\.0\\x20200\\x20OK\\r\\n\\r\\n")%r(X,0,"")')
    add("K.parse_fp", "return U.parse_fp(%s)" % lstr(fp))
    add("K.parse_fp.badesc", "return U.parse_fp(%s)" % lstr('SF:%r(NULL,6,"abc\\x\\n")'))
    for probe in ("NULL", "GetRequest", "X", "Nope", "Get.equest"):
        add("K.get_response.%s" % probe, "return U.get_response(%s, %s)" % (lstr(fp), lstr(probe)))
    add("K.parse_fp.unterm", "return U.parse_fp(%s)" % lstr('SF:%r(NULL,6,"abc'))
    add("K.debug", "local g = U.debug({ 'S', S = P'a' }, function() end) return match(P(g), 'a')")


# ------------------------------------------------------------- X fixed rows
# One or more rows for every sabotage docs/M6.6-ANALYSIS.md §11 names (so a
# fixed row, not only a random one, catches it) and for every §5 edge.
# In a chunk, «expr» is an infix pattern expression that T() translates.

def TX(chunk):
    return pyre.sub("«(.*?)»", lambda m: T(m.group(1)), chunk)


def addx(cid, chunk, tags=()):
    add("X." + cid, TX(chunk), tags)


SUBJ_A = "('a'):rep(%d)"


def sec_X():
    # -- S14: Cb must find its group by name, past a nearer group of another name
    for i, (e, s) in enumerate([
            ('Cg(C(1), "a") * Cg(C(1), "b") * Cb("a")', "xy"),
            ('Cg(C(1), "a") * Cg(C(1), "b") * Cb("b") * Cb("a")', "xy"),
            ('Ct(Cg(C(1), "a") * Cg(C(1), "b") * Cg(Cb("a"), "c"))', "xy"),
            ('Cg(C(1), "a") * Cg(C(1)) * Cb("a")', "xy"),
            ('Cg(C(1), "a") * Cg(C(1), "b") * Cg(C(1), "c") * Cb("a") * Cb("c")', "xyz"),
            ('Cg(C(1), "a") * Cb("b")', "x"),
            ('Cg(C(1) * C(1), "a") * Cg(C(1), "b") * Cb("a")', "xyz"),
            ('Cg(C(1), "a") * C(Cg(C(1), "b")) * Cb("a")', "xy"),
            ('Cs(Cg(C(1), "a") * Cg(C(1), "b") * Cb("a"))', "xy")]):
        addx("cb.names.%d" % i, "return match(«%s», %s)" % (e, lstr(s)))
    # -- S16: Carg's key is an argument number, not a ktable index. Joining
    #    two patterns that both have a ktable shifts the right one's keys
    #    (correctkeys); it must not shift Carg's. A Carg alone has no ktable,
    #    so the right side carries a constant of its own.
    for i, e in enumerate(['Cc("k") * Carg(2)', 'Cc("k", "l") * Carg(1)', 'Cg(C(1), "n") * Carg(1)', '(Cc("k") + Cc("j")) * Carg(2)',
                           'Carg(1) * Cc("k")', 'Cc("k") * Cc("l") * Carg(3)', 'Ct(Cc("k") * Carg(2))', 'C(1) / {} * Carg(1)',
                           'Cc("k") * (C(1) / "%1" * Carg(2))', 'P{ "S", S = Cc("k") * V"T", T = Carg(2) }',
                           'Cc("k") * (Carg(2) * Cc("j"))', 'Cc("k", "l") * (Cc("j") * Carg(1))', '(Cc("k") * Cc("l")) * (Carg(3) * Cc("j"))',
                           'Ct(Cc("k") * (Carg(2) * Cg(C(1), "g")))', 'Cc("k") * (Carg(2) + Cc("j"))', 'Cc("k") * Cs(Carg(2) * Cc("j"))']):
        addx("carg.join.%d" % i, "return match(«%s», 'x', 1, 'A1', 'A2', 'A3', 'A4')" % e)
    # -- S08: dynamic captures are discarded on backtrack; kept, they exhaust
    #    the Lua stack only near 10^6 (review_seqgates dyn_bt.lua)
    for n in (10, 100000, 1000000):
        addx("dyncap.bt.%d" % n, "return summ(match(«Ct(((Cmt(1, Mv) * 'z') + C(1))^0)», %s))" % (SUBJ_A % n))
    addx("dyncap.bt.cs.1000000", "local r = match(«Cs(((Cmt(1, Mv) * 'z') + 1)^0)», %s) return #r, r:sub(1, 3)" % (SUBJ_A % 1000000))
    addx("dyncap.bt.small", "return match(«Ct(((Cmt(1, Mvals) * 'z') + C(1))^0)», 'aza')")
    addx("dyncap.bt.cs", "return match(«Cs(((Cmt(1, Mvals) * 'z') + 1)^0)», 'aza')")
    # -- S07 (a float position accepted by truncation), S06 (a backward
    #    position), and the rest of Cmt's result decoding (§5)
    cmt_results = [("i0", "KR('i', 0)"), ("i1", "KR('i', 1)"), ("back", "KR('i', -1)"), ("back2", "KR('i', -2)"),
                   ("f0", "KR('f', 0)"), ("f1", "KR('f', 1)"), ("h0", "KR('h', 0)"), ("h1", "KR('h', 1)"), ("hm", "KR('h', -1)"),
                   ("s0", "KR('s', 0)"), ("s1", "KR('s', 1)"), ("sp", "KR('sp', 1)"), ("hex", "KR('x', 1)"), ("exp", "KR('e', 1)"),
                   ("nf", "KR('nf', 0)"), ("x", "K('x')"), ("tbl", "K({})"), ("zero", "K(0)"), ("big", "K(2^63)"),
                   ("bigi", "K(math.maxinteger)"), ("true", "K(true)"), ("trueext", "K(true, 'x', nil, 3)"), ("false", "K(false)"),
                   ("nil", "K(nil)"), ("none", "K()"), ("end", "Mend"), ("beyond", "Mbeyond"), ("str25", "K('2.5')"), ("str20", "K('2.0')"),
                   ("f35", "K(3.5)"), ("f45", "K(4.5)"), ("f20", "K(2.0)"), ("f30", "K(3.0)"), ("nan", "K(0/0)"), ("inf", "K(1/0)"),
                   ("pos2caps", "K(3, 'c1', nil)"), ("err", "Merr"), ("errt", "Merrt")]
    for name, f in cmt_results:
        for j, s in enumerate(["abc", "abcdef"]):
            addx("cmt.res.%s.%d" % (name, j), "return match(mul(Cmt(P(1), %s), Cp()), %s)" % (f, lstr(s)))
    addx("cmt.res.minint", "return match(Cmt(P(1), K(math.mininteger)), 'abc')", ["q=lpeg-initposition-negation-overflow"])
    addx("cmt.res.many", "return select('#', match(Cmt(P(1), K(true, table.unpack({}, 1, 5000))), 'abc'))",
         ["q=lpeg-doublecap-stack-overread"])
    addx("cmt.args", "return match(Cmt(P'ab', Mcaps), 'abc'), match(«Cmt(C(1) * Cc(nil) * C(1), Mcount)», 'abc')")
    addx("cmt.pf", "return match(«P(Mnext) * Cp()», 'abc')")
    addx("cmt.nested_match", "return match(«Cmt(1, Mre) * Cp()», 'aaab')")
    # -- /f inside a Cmt runs at match time; outside one, only on success (§5)
    addx("fcap.inside_cmt", "return match(«Cmt(C(1) / Fcat, Mfalse) + C(1)», 'a')")
    addx("fcap.outside", "return match(«(C(1) / Fcat * 'z') + C(1)», 'a')")
    addx("fcap.inside_cmt_ok", "return match(«Cmt(C(1) / Fcat, Mcaps) * C(1) / Fcat», 'ab')")
    # -- S10: MAXSTRCAPS is 10 (the whole match and nine nested captures)
    for k in (8, 9, 10, 11, 12):
        body = " * ".join(["C(1)"] * k)
        for j, fmt in enumerate(["%9", "%1%9", "%8|%9", "<%0>", "%1|%2|%3|%4|%5|%6|%7|%8|%9"]):
            addx("maxstrcaps.%d.%d" % (k, j), "return match(«(%s) / %s», 'abcdefghijklm')" % (body, lstr(fmt)))
        nested = "C(1)"
        for _ in range(k - 1):
            nested = "C(%s * 1)" % nested
        addx("maxstrcaps.nested.%d" % k, "return match(«(%s) / '%%1|%%9'», 'abcdefghijklm')" % nested)
    # -- string captures (§5)
    for i, (e, s) in enumerate([
            ('C(1) / "%"', "a"), ('C(1) / "x%"', "a"), ('C(1) / "%x%%"', "a"), ('C(1) / "%2"', "a"),
            ('(C(C(1) * C(1)) * C(1)) / "%0|%1|%2|%3|%4"', "abc"), ('(C(C(1) * C(1)) * C(1)) / "%1|%2|%3|%4"', "abc"),
            ('C(C(1)^0) / "%9|%0"', "abcdefghijkl"), ('C(C(1)^0) / "%10"', "abcdefghijkl"),
            ('(P(1) / Fmulti) / "%1"', "a"), ('(P(1) / Fnone) / "%1"', "a"), ('(P(1) / Ftab) / "%1"', "a"),
            ('Cg(C(1), "n") / "%1"', "a"), ('Cc(1.0) / "%1"', ""), ('Cc(2^63) / "<%1>"', ""), ('Cc(-0.0) / "%1"', ""),
            ('Cc(math.mininteger) / "%1"', ""), ('Cc(true) / "%1"', ""), ('(C(1) * Cp()) / "%2"', "a"),
            ('Cs(P(1) / Fmulti)', "a"), ('Cs(P(1) / Ftab)', "a"), ('Cs(P(1) / Ffalse)', "a"), ('Cs((P(1) / Fnone) * C(1))', "ab"),
            ('Cs(Cc(-0.0) * 1)', "a"), ('Cs(Cc(1.0) * 1)', "a"), ('Cs(Cc(2^53) * 1)', "a")]):
        addx("strcap.%d" % i, "return match(«%s», %s)" % (e, lstr(s)))
    # -- group names are strings (luaL_checkstring), §5
    for i, (e, s) in enumerate([
            ('Ct(Cg(C(1), 1))', "x"), ('Ct(Cg(C(1), 0/0))', "x"), ('Ct(Cg(C(1), 2.0))', "x"), ('Ct(Cg(C(1), 2.5))', "x"),
            ('Ct(Cg(C(1), 2^53))', "x"), ('Ct(Cg(C(1), -0.0))', "x"), ('Ct(Cg(C(1), math.mininteger))', "x"),
            ('Cg(C(1), 1.0) * Cb(1)', "x"), ('Cg(C(1), "1") * Cb(1)', "x"), ('Cg(C(1), 1) * Cb("1")', "x"),
            ('Cg(C(1), 1.5) * Cb("1.5")', "x"), ('Cb(1.5)', "x"), ('Cb(true)', "x"), ('Cg(C(1), true)', "x"),
            ('C(Cg(C"a", "x")) * Cb"x"', "a"), ('Cg(C"a", "x") * C(Cb"x")', "a"), ('Cg(C"a", "x") * Cb"x" * Cg(C"b", "x") * Cb"x"', "ab"),
            ('Cg(C"a" * C"b", "x") * Cb"x"', "ab"), ('Cg(P"a", "x") * Cb"x"', "a"), ('Ct(Cg(P"x", "k"))', "x"),
            ('Ct(Cg(P"x" / Fnone, "k"))', "x"), ('Ct(Cg(Cc(nil) * Cc(1), "k"))', ""), ('Ct(Cg(Cc(1), "k") * Cg(Cc(2), "k"))', ""),
            ('Ct(Cc(1) * Cg(Cc("v"), 1) * Cc(2))', ""), ('Ct(Cc(nil, nil, 3))', ""), ('Cg(C(1) * C(1), "n")', "ab")]):
        addx("group.%d" % i, "return match(«%s», %s)" % (e, lstr(s)))
    addx("group.eqname", "local mt = { __eq = function() return true end } local a, b = setmetatable({}, mt), setmetatable({}, mt) "
                         "return match(«Cg(C(1), a) * Cb(b)», 'x')")
    # -- grammar keys that convert to 1 are the [1] slot (§5)
    for i, g in enumerate(['{ "S", S = V"1", ["1"] = P"a" }', '{ "S", S = V"1.0", ["1.0"] = P"a" }', '{ "S", S = V"2", ["2"] = P"a" }',
                           '{ "S", S = V(1.0), [1.0] = P"a" }', '{ "S", S = V(1) }', '{ [1.0] = "S", S = P"a" }', '{ ["1"] = "S", S = P"a" }',
                           '{ "S", [1.5] = V(2), [2] = V(3), [3] = P"a", S = V(1.5) }']):
        addx("gkey.%d" % i, "return match(«P(%s)», 'a')" % g)
    # -- table queries (§5): false is a value; a nil or NaN key gives none;
    #    __index is honoured (S09: a rawget would miss it)
    for i, (e, s) in enumerate([
            ('C(1) / {a=false}', "a"), ('(P(1) / Fnil) / {}', "a"), ('Cc(nil) / {}', ""), ('Cc(0/0) / {}', ""),
            ('C(1) / IDXF', "a"), ('C(1) / IDXF', "b"), ('(C(1) * C(1)) / IDXF', "ab"), ('C(1) / IDXT', "a"),
            ('C(1) / IDXT', "b"), ('C(1) / IDXT', "c"), ('Cs((C(1) / IDXF)^0)', "ab"), ('Ct((C(1) / IDXT)^0)', "abc"),
            ('(C(1) * C(1)) / {a=1, b=2}', "ab"), ('Cc(1) / {"one"}', ""), ('Cc(1.0) / {"one"}', ""), ('P(1) / {}', "a")]):
        addx("query.%d" % i, "return match(«%s», %s)" % (e, lstr(s)))
    # -- initposition: negative, 0 and -0.0 count from the end; both ends crop
    for i, ini in enumerate(["0", "-0.0", "0.0", "-0", "-1", "-3", "-4", "-100", "4", "5", "100", "' 2 '", "'0x2'", "1.5",
                             "math.maxinteger", "math.mininteger + 1", "-(2^53)"]):
        for j, s in enumerate(["abc", ""]):
            addx("init.%d.%d" % (i, j), "return match(«Cp() * C(P(1)^0)», %s, %s)" % (lstr(s), ini))
    addx("init.minint", "return match(Cp(), 'abc', math.mininteger)", ["q=lpeg-initposition-negation-overflow"])
    # -- integer arguments narrowed to a 32-bit int (E11, §5)
    for i, e in enumerate(['P(2^32+2)', 'P(1.5)', 'P(2^63)', 'P(-(2^32))', 'P(-(2^32)+1)', 'P(2^32-1)', 'P"a"^(2^32+1)',
                           'P"a"^(2^32-1)', 'P"a"^(-(2^32)+2)', 'C(1) / (2^32+1)', 'C(1) / 1.5', 'C(1) / 2^63', 'P"a"^1.5',
                           'C(1) / -1', 'C(1) / "2"', 'P"a"^" 2 "', 'P"a"^"0x2"']):
        addx("narrow.%d" % i, "return match(«%s», 'aaa')" % e)
    addx("narrow.carg", "return match(Carg(2^32+1), '', 1, 'X')")
    addx("narrow.carg2", "return match(Carg(2^32+2), '', 1, 'X', 'Y')")
    for i, ms in enumerate(["2^32+1000", "2^31", "2^32+50", "-(2^32)+1000"]):
        for d in (49, 50, 499, 500):
            addx("narrow.sms.%d.%d" % (i, d), "setmaxstack(%s) return match(mul(P(%s), Cp()), ('a'):rep(%d) .. ('b'):rep(%d))" % (ms, SMS_GRAMMAR, d, d))
    addx("narrow.sms.flt", "return setmaxstack(1000.5)")
    addx("narrow.sms.tbl", "return setmaxstack({})")
    addx("narrow.sms.ret", "return select('#', setmaxstack(100))")
    # -- S05 (limit + 1), S04 (no limit), S12 (INITBACK): the backtrack ceiling
    #    at the boundary depth for a sweep of setmaxstack values
    for ms in (100, 101, 102, 103, 104, 150, 151, 199, 200, 201, 202, 203, 255, 256, 257, 400, 401, 1000, 1001):
        b = ms // 2
        for d in (b - 1, b, b + 1):
            addx("limit.%d.%d" % (ms, d), "setmaxstack(%d) return match(mul(P(%s), Cp()), ('a'):rep(%d) .. ('b'):rep(%d))" % (ms, SMS_GRAMMAR, d, d))
    for ms in ("5", "50", "99", "nil", "'150'", "' 150 '"):
        for d in (49, 50, 74, 75, 76):
            addx("limit.%s.%d" % (slug(ms), d), "setmaxstack(%s) return match(mul(P(%s), Cp()), ('a'):rep(%d) .. ('b'):rep(%d))" % (ms, SMS_GRAMMAR, d, d))
    # -- identity-returning constructors, through rawequal (§5)
    for i, (expr, who) in enumerate([("P(x)", "x"), ("mul(x, true)", "x"), ("mul(true, x)", "x"), ("add(x, false)", "x"),
                                     ("mul(pf, x)", "pf"), ("add(pt, x)", "pt"), ("add(pf, x)", "x"), ("sub(x, pf)", "x")]):
        addx("ident.%d" % i, "local x, pt, pf = P'a', P(true), P(false) return rawequal(%s, %s)" % (expr, who))
    # -- ptree/pcode process their arguments, then refuse (E5)
    for i, a in enumerate([['"abc"'], ['V"x"'], ['{ "S" }'], [], ['{ "S", S = V"S" * "a" }'], ['P"a"', 'true'], ['V"x"', 'true'],
                           ['{ "S", S = P"a" }'], ['{}'], ['Mkeep']]):
        args = TL(a)
        addx("ptree.%d" % i, "return ptree(%s)" % args)
        addx("pcode.%d" % i, "return pcode(%s)" % args)
    # -- a grammar table's __index: getfirstrule reads the initial rule with
    #    lua_gettable (lpeg.c:2932), the one place grammar construction can
    #    call Lua; every other rule is read raw (lua_next)
    for i, (g, v) in enumerate([("{ 'S' }", "P'a'"), ("{ 'S', S = P'b' }", "P'a'"), ("{ 'S' }", "nil"), ("{ 'S' }", "'x'"),
                                ("{ 'S' }", "'ERR'"), ("{ 1 }", "P'a'"), ("{ 'S', T = V'U' }", "P'a'"),
                                ("{ 'S', T = P'c' }", "V'T'"), ("{ 'S' }", "Mkeep"), ("{ P'z' }", "P'a'")]):
        addx("gindex.%d" % i, "return ltype(P(gmeta(%s, %s)))" % (T(g), T(v)))
        addx("gindex.%d.m" % i, "return match(P(gmeta(%s, %s)), 'abc')" % (T(g), T(v)))
    addx("gindex.op", "return match(mul(gmeta({ 'S' }, P'a'), 'b'), 'abc')")
    # -- locale: C-locale classes, and writes through __newindex in class order
    addx("locale.newindex", "local t = logtable() locale(t) local k = {} for n in pairs(t) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')")
    addx("locale.sizes", "local t = locale() local r = {} for _, k in ipairs { 'alnum', 'alpha', 'cntrl', 'digit', 'graph', 'lower', 'print', 'punct', 'space', 'upper', 'xdigit' } do "
                         "local n = 0 for c = 0, 255 do if match(t[k], string.char(c)) then n = n + 1 end end r[#r+1] = k .. n end return table.concat(r, ' ')")
    addx("locale.high", "local t = locale() local n = 0 for _, p in pairs(t) do for c = 128, 255 do if match(p, string.char(c)) then n = n + 1 end end end return n")
    addx("locale.ret", "local t = {} return rawequal(locale(t), t)")
    addx("locale.count", "local t = locale(nil) local n = 0 for k in pairs(t) do n = n + 1 end return n")
    # -- Cf is 0.12's fold
    for i, (e, s) in enumerate([
            ('Cf(C(1) * (P(1) / Fnone), Gcat)', "ab"), ('Cf(P(1), Gcat)', "a"), ('Cf(P(1) / Fnone, Gcat)', "a"),
            ('Cf((C(1) * C(1)) * C(1), Gcat)', "abc"), ('Cf(C(1), 3)', "a"), ('Cf(C(1) * C(1)^0, Gcat)', "abc"),
            ('Cf(Cc(1, 2) * C(1), Gmany)', "a"), ('Cf(C(1) * Cg(C(1) * C(1)) * Cg(Cc()), Gmany)', "abc")]):
        addx("fold.%d" % i, "return match(«%s», %s)" % (e, lstr(s)))
    # -- error objects propagate unchanged
    addx("errobj.cmt", "return match(«Cmt(1, Merrt)», 'a')")
    addx("errobj.f", "return match(«C(1) / Ferrt», 'a')")
    addx("errobj.str", "return match(«C(1) / Ferr», 'a')")
    addx("errobj.pcall", "local ok, e = pcall(match, «Cmt(1, Merrt)», 'a') return ok, e")
    # -- constructor and argument messages, verbatim (§5)
    for i, e in enumerate(['P()', 'R("a")', 'R(12)', 'R("ab", "c")', 'S(12)', 'S({})', 'B(P"a"^1)', 'B(C"a")', 'B(P"")', 'B(P(256))',
                           'V(nil)', 'Carg(0)', 'Carg(32768)', 'Carg(-1)', 'Cg(1, {})', 'Cb()', 'Cmt(1)', 'Cf(1)', 'C(1) / true',
                           'P(1) + nil', 'P(1) * {}', 'P{ V({}) }', 'P{ "S", S = V"T", T = 3.5 }', 'P{ "S", S = V"T", T = io.stdout }',
                           'P{ "S" }', '(P"" )^0', 'P""^-3', 'Cc(1) * Cc(2) ^ 1', 'P{ P"a" }', 'P(io.stdout)']):
        addx("msg.%d" % i, "return ltype(«%s»)" % e)
    addx("msg.matchbad.1", "return match(P(1), {})")
    addx("msg.matchbad.2", "return match(P(1))")
    addx("msg.matchbad.3", "return mcall(P(1), 'match')")
    addx("msg.matchbad.4", "return match(nil, 'abcd')")
    addx("msg.matchbad.5", "return match(P(1), 'a', {})")
    addx("msg.matchbad.6", "return match(P(1), 'a', 1.5)")
    addx("msg.maxrules", "local g = { 'r1' } for i = 1, 199 do g['r'..i] = P'a' end local ok1 = pcall(P, g) g['r200'] = P'a' local ok2, e2 = pcall(P, g) return ok1, ok2, e2")
    # -- the 16-bit truncations (§1.2, D4): below each threshold the C is
    #    right and the row is golden; past it the C reads nil or another
    #    value and the row is quarantined with the semantic answer to pin
    # (the constants are sequenced as a balanced tree, as the analysis
    # measured them: a left-deep chain copies O(n^2) tree nodes)
    for n, tags in ((32767, ()), (32768, ["q=lpeg-ktable-key-16bit"]), (65537, ["q=lpeg-ktable-key-16bit"])):
        addx("ktable.%d" % n, "local parts = {} for i = 1, %d do parts[i] = Cc(i) end "
                              "while #parts > 1 do local np = {} for i = 1, #parts, 2 do np[#np + 1] = parts[i + 1] and mul(parts[i], parts[i + 1]) or parts[i] end parts = np end "
                              "local t = match(Ct(parts[1]), '') local wrong = 0 for i = 1, %d do if t[i] ~= i then wrong = wrong + 1 end end "
                              "return #t, wrong, t[1], t[%d]" % (n, n, n), tags)
    # (`grow` first fills and drops 4n ordinary captures, so the capture list
    # is already long enough: otherwise the C grows it from the runtime-capture
    # path, where `doublecap` over-reads -- lpeg-doublecap-stack-overread)
    for n, tags in ((30000, ()), (33000, ["q=lpeg-runtime-capture-index-16bit"])):
        addx("rtcap.%d" % n, "local grow = «(C(1) * Cc(1) * Cc(2) * Cc(3))^0 * false + true» "
                             "local r = table.pack(match(«grow * Cmt(P(1), Mv)^0», %s)) return r.n, r[1], r[r.n]" % (SUBJ_A % n), tags)
    # -- crashes and undefined behaviour in the C (§1.2): never run by an
    #    oracle, kept for the port's pins
    addx("ub.ccnil", "return match(Cc(nil), '')", ["q=lpeg-cc-nil-without-ktable"])
    addx("ub.jump1", "return match(add(unm(mul(S'', 'a')), 'c'), 'c')", ["q=lpeg-codegen-jump-out-of-code"])
    addx("ub.jump2", "return match(pow(P{ P'' }, -1), '')", ["q=lpeg-codegen-jump-out-of-code"])
    addx("ub.getfirst", "return ltype(P{ 'A', A = B(sub(P'a', V'A')) })", ["q=lpeg-getfirst-unbounded-recursion"])
    addx("ub.nestC", "local p = P'a' for i = 1, 300 do p = C(p) end return select('#', match(p, 'a'))", ["q=lpeg-nested-capture-lua-stack-overflow"])
    addx("ub.bigstr", "return ltype(P(string.rep('a', 2^31)))", ["q=lpeg-pattern-string-size-overflow"])
    addx("ub.starsize", "return ltype(pow(P'a', 2^31))", ["q=lpeg-tree-size-int-overflow"])
    addx("ub.gc", "local p p = Cmt(1, function() local mt = getmetatable(p) mt.__gc(p) collectgarbage() return true end) "
                  "return match(mul(p, 1), 'ab')", ["q=lpeg-code-freed-during-match"])
    # -- __name (E7): type errors and tostring say lpeg-pattern
    addx("name.tostring", "return tostring(P'a'):match('^lpeg%-pattern: 0x%x+$') ~= nil")
    addx("name.rep", "return pcall(string.rep, P(1))")
    addx("name.setmt", "return pcall(setmetatable, P(1), {})")
    addx("name.cg", "return Cg(P'a', P'b')")
    addx("name.match", "return match(P'a', P'b')")


# ---------------------------------------------------------- R random trees
ALPH = [b"a", b"b", b"c", b"0", b"\x00", b"\xff", b"-", b" "]


class RandGen:
    """Random pattern trees, written directly in wrapper-call form."""

    def __init__(self, rng):
        self.r = rng

    def lit(self):
        n = self.r.choice([0, 1, 1, 1, 2, 2, 3])
        return b"".join(self.r.choice(ALPH) for _ in range(n))

    def leaf(self, rules):
        r = self.r
        k = r.randrange(16)
        if k < 4:
            return "P(%s)" % lstr(self.lit())
        if k == 4:
            return "P(%d)" % r.choice([-2, -1, 0, 1, 1, 2, 3])
        if k == 5:
            return r.choice(["P(true)", "P(false)"])
        if k == 6:
            st = bytes(sorted(set(r.choice(ALPH)[0] for _ in range(r.randrange(0, 4)))))
            return "S(%s)" % lstr(st)
        if k == 7:
            return r.choice(['R("ac")', 'R("09")', 'R("\\0\\31", "ab")', 'R("za")', 'R("\\128\\255")'])
        if k == 8:
            return r.choice(["Cp()", "Cc()", "Cc(1)", "Cc('k', 2)", "Cc(nil)", "Carg(1)", "Carg(2)", "Cb('g')", "Cb(1)"])
        if k == 9:
            return r.choice(["P(Mkeep)", "P(Mnext)", "P(Mgate)", "P(Mvals)", "P(Mfalse)"])
        if k in (10, 11) and rules:
            return "V(%s)" % lstr(r.choice(rules)) if r.random() < 0.9 else 'V("undefined")'
        if k == 12:
            return lstr(self.lit())  # a bare string operand
        return "P(%s)" % lstr(self.lit())

    def expr(self, d, rules):
        r = self.r
        if d <= 0 or r.random() < 0.18:
            return self.leaf(rules)
        k = r.randrange(30)
        e = lambda: self.expr(d - 1, rules)
        if k < 5:
            return "mul(%s, %s)" % (e(), e())
        if k < 9:
            return "add(%s, %s)" % (e(), e())
        if k == 9:
            return "sub(%s, %s)" % (e(), e())
        if k == 10:
            return "unm(%s)" % e()
        if k == 11:
            return "len(%s)" % e()
        if k in (12, 13):
            return "pow(%s, %d)" % (e(), r.choice([-2, -1, 0, 0, 1, 1, 2]))
        if k == 14:
            return "C(%s)" % e()
        if k == 15:
            return "Cs(%s)" % e()
        if k == 16:
            return "Ct(%s)" % e()
        if k == 17:
            return r.choice(["Cg(%s)", "Cg(%s, 'g')", "Cg(%s, 1)", "Cg(%s, 'h')"]) % e()
        if k == 18:
            return "Cf(%s, %s)" % (e(), r.choice(["Gcat", "Gfirst", "Gnil"]))
        if k == 19:
            return "Cmt(%s, %s)" % (e(), r.choice(["Mkeep", "Mnext", "Mcaps", "Mcount", "Mfalse", "Mtrue", "Mgate", "Mback", "Mend"]))
        if k == 20:
            return "B(%s)" % e()
        if k == 21:
            return "div(%s, %s)" % (e(), lstr(r.choice(["%0", "%1", "<%1%2>", "x", "%%", "%1-%0", "%3"])))
        if k == 22:
            return "div(%s, %d)" % (e(), r.choice([0, 1, 2, 3]))
        if k == 23:
            return "div(%s, %s)" % (e(), r.choice(["Fid", "Fcat", "Fnone", "Fmulti", "Ffalse"]))
        if k == 24:
            return "div(%s, { a = 'A', b = 2, [''] = 'E' })" % e()
        if k == 25 and d >= 2:
            return self.grammar(d - 1)
        return "mul(%s, %s)" % (e(), e())

    def grammar(self, d):
        r = self.r
        names = r.sample(["A", "B", "C", "D"], r.randrange(1, 4))
        parts = [lstr(names[0])]
        for nme in names:
            parts.append("%s = %s" % (nme, self.expr(d, names)))
        return "P{ %s }" % ", ".join(parts)

    def subject(self):
        r = self.r
        k = r.random()
        if k < 0.85:
            return lstr(b"".join(r.choice(ALPH) for _ in range(r.randrange(0, 11))))
        if k < 0.95:
            return "(%s):rep(%d)" % (lstr(b"".join(r.choice(ALPH) for _ in range(r.randrange(1, 4)))), r.choice([50, 300, 2000]))
        return lstr(bytes(r.randrange(256) for _ in range(r.randrange(0, 40))))


def sec_R(rng, n):
    g = RandGen(rng)
    for i in range(n):
        d = rng.choice([1, 2, 3, 3, 4, 4, 5, 6, 8])
        subj = g.subject()
        if ":rep(" in subj:
            d = min(d, 3)
        top = g.grammar(d) if rng.random() < 0.15 else g.expr(d, [])
        call = rng.random()
        if call < 0.7:
            m = "match(p, %s)" % subj
        elif call < 0.85:
            m = "match(p, %s, %d)" % (subj, rng.choice([-3, -1, 0, 1, 2, 3, 12]))
        elif call < 0.95:
            m = "match(p, %s, 1, 'X1', 2)" % subj
        else:
            m = "mcall(p, 'match', %s)" % subj
        add("R.%d" % i, "local p = %s; return %s" % (top, m))


# ------------------------------------------------------------ Q random re
def sec_Q(rng, n):
    atoms = ["'a'", "'b'", '"ab"', ".", "[ab]", "[^a]", "[a-c]", "%d", "%a", "%s", "%w", "{}", "''", "%nl"]

    def rexp(d):
        if d <= 0 or rng.random() < 0.25:
            return rng.choice(atoms)
        k = rng.randrange(12)
        e = lambda: rexp(d - 1)
        if k < 3:
            return "%s %s" % (e(), e())
        if k < 5:
            return "%s / %s" % (e(), e())
        if k == 5:
            return "(%s)%s" % (e(), rng.choice(["*", "+", "?", "^2", "^-2", "^+1"]))
        if k == 6:
            return rng.choice(["{%s}", "{|%s|}", "{~%s~}", "{:n: %s :}", "&%s", "!%s", "(%s)"]) % e()
        if k == 7:
            return "(%s) -> %s" % (e(), rng.choice(["'<%1>'", "{}", "0", "1", "f"]))
        if k == 8:
            return "(%s) => g" % e()
        return "(%s)" % e()

    defs = "{ f = Fcat, g = Mgate }"
    for i in range(n):
        src = rexp(rng.choice([1, 2, 3, 4, 5]))
        if rng.random() < 0.15:  # mutate to reach error paths
            b = list(src)
            for _ in range(rng.randrange(1, 3)):
                op = rng.randrange(3)
                pos = rng.randrange(len(b) + 1)
                if op == 0 and b:
                    del b[min(pos, len(b) - 1)]
                else:
                    b.insert(pos, rng.choice("()[]{}'\"/%*+?^<-=&!:|~ ab"))
            src = "".join(b)
        if rng.random() < 0.2:
            src = "s <- %s / ''  t <- s" % src
        subj = lstr(b"".join(rng.choice([b"a", b"b", b"c", b"1", b" ", b"\n"]) for _ in range(rng.randrange(0, 9))))
        add("Q.%d" % i, "return mcall(re.compile(%s, %s), 'match', %s)" % (lstr(src), defs, subj))


# ------------------------------------------------------------- output

FAMILIES = "ABCDEFGHIJKQRX"
RAW_LPEG_CALL = pyre.compile(r"\blpeg\s*\.\s*\w+\s*[(\"'{]")


def esc_chunk(chunk):
    for c in chunk:
        if not (32 <= ord(c) < 127 or c in "\n\t"):
            raise ValueError("non-ASCII byte in chunk: %r" % chunk[:80])
    return chunk.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def lint():
    for cid, chunk, tags in CASES:
        fam = cid.split(".")[0]
        if fam not in FAMILIES:
            raise SystemExit("unknown family in id %s" % cid)
        if pyre.search(r"\s", cid):
            raise SystemExit("whitespace in id %r" % cid)
        if RAW_LPEG_CALL.search(chunk):
            raise SystemExit("%s calls the raw lpeg module, not through a direct pcall: %s" % (cid, chunk[:120]))
        if "«" in chunk or "»" in chunk:
            raise SystemExit("%s: untranslated expression" % cid)
        for t in tags:
            if t not in ("cdepth", "drift794") and not pyre.fullmatch(r"q=[a-z0-9-]+", t):
                raise SystemExit("%s: bad tag %r" % (cid, t))
        esc_chunk(chunk)


def build(seed, nrandom, nre):
    del CASES[:]
    SEEN.clear()
    rng = random.Random(seed)
    for f in (sec_A, sec_B, sec_C, sec_D, sec_E, sec_F, sec_G, sec_H, sec_I, sec_J, sec_K, sec_X):
        f()
    sec_R(rng, nrandom)
    sec_Q(rng, nre)
    lint()


def write(out, seed, nrandom, nre):
    out.write("# M6.6 step 0b LPeg corpus: oracle/gen_m66_lpeg_cases.py --seed %d --random %d --re %d\n" % (seed, nrandom, nre))
    out.write("# id<TAB>tags<TAB>chunk (\\\\, \\n, \\t escaped); run by oracle/m66_lpeg_core.lua\n")
    for cid, chunk, tags in CASES:
        out.write("%s\t%s\t%s\n" % (cid, ",".join(tags) if tags else "-", esc_chunk(chunk)))


def self_test():
    checks = [
        ('P"a"^0 * "b" + 1', 'add(mul(pow(P("a"), 0), "b"), 1)'),
        ('-P"a" * #P"b"', 'mul(unm(P("a")), len(P("b")))'),
        ('-x^2', 'unm(pow(x, 2))'),
        ('P(2^32+1)', 'P(((2 ^ 32) + 1))'),
        ('P(-(2^32)-1)', 'P(((-((2 ^ 32))) - 1))'),
        ('P(-1)', 'P((-1))'),
        ('P(0/0)', 'P((0 / 0))'),
        ('P(-math.huge)', 'P((-math.huge))'),
        ('C(1) / -1', 'div(C(1), (-1))'),
        ('{ "S", S = P"a" * V"S" + "" }', '{ "S", S = add(mul(P("a"), V("S")), "") }'),
        ('P{ "S", [1.5] = V(2), [true] = 3 }', 'P({ "S", [1.5] = V(2), [true] = 3 })'),
        ('p:match("a", 2)', 'mcall(p, "match", "a", 2)'),
        ('a - b - c', 'sub(sub(a, b), c)'),
        ('a ^ b ^ c', 'pow(a, pow(b, c))'),
        ('(a + b) * c', 'mul((add(a, b)), c)'),
        ('io.stdout', 'io.stdout'),
        ('C(1) / {a=false}', 'div(C(1), { a = false })'),
        ('Cc(1.5, -0.0, 0/0)', 'Cc(1.5, (-0.0), (0 / 0))'),
        ("P'a'^1.5", "pow(P('a'), 1.5)"),
        ('P"a"^" 2 "', 'pow(P("a"), " 2 ")'),
    ]
    bad = 0
    for src, want in checks:
        got = T(src)
        if got != want:
            print("translate %r: got %r, want %r" % (src, got, want))
            bad += 1
    for src in ['a .. b', 'a == b', 'not a', 'f(']:
        try:
            T(src)
            print("translate %r: accepted, must refuse" % src)
            bad += 1
        except ValueError:
            pass
    build(1, 2000, 300)
    a = [c for c in CASES]
    build(1, 2000, 300)
    if a != CASES:
        print("generation is not deterministic for a seed")
        bad += 1
    build(2, 2000, 300)
    if [c[0] for c in a] != [c[0] for c in CASES] or a == CASES:
        print("a different seed must give the same ids and different random rows")
        bad += 1
    try:
        CASES.append(("X.lint", "return lpeg.match(lpeg.P'a', 'a')", ()))
        lint()
        print("the lint passed a raw lpeg call")
        bad += 1
    except SystemExit:
        pass
    print("self-test: %d translator checks, %s" % (len(checks), "FAIL" if bad else "ok"))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--random", type=int, default=50000)
    ap.add_argument("--re", type=int, default=6000)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        sys.exit(self_test())
    build(a.seed, a.random, a.re)
    write(sys.stdout, a.seed, a.random, a.re)
    fams = {}
    for cid, _, _ in CASES:
        fams[cid.split(".")[0]] = fams.get(cid.split(".")[0], 0) + 1
    sys.stderr.write("cases=%d %s\n" % (len(CASES), " ".join("%s=%d" % kv for kv in sorted(fams.items()))))


if __name__ == "__main__":
    main()
