#!/usr/bin/env python3
"""M6.6 step b: the LPeg tree corpus — constructions that never match.

Each row is `id<TAB>hex(chunk)<TAB>note`. The chunk runs in the environment
m66b_tree_core.lua builds (the lpeg functions as globals, `ltype`, `mt` the
pattern metatable, helpers), under the tree's standalone Lua on one side and
the port's test-only registration on the other.

Step b ports trees, not matching, so a case observes what construction
decides: a result's type and identity (`rawequal`), the metatable, and every
error, byte for byte. Rows:

  A  P's coercions of every type, with 32-bit narrowing (E11)
  B  the operators over every operand kind, with identity
  C  the capture constructors and their argument checks
  D  grammars: initial rules, keys that convert to 1, MAXRULES, undefined
     and non-pattern rules, left recursion, empty loops
  E  lpeg.B: fixed length, captures, too long
  F  p^n: narrowing, string and float exponents, empty loop bodies
  G  p / x for every kind of x
  H  setmaxstack's argument checks and results
  I  locale: classes, order of __newindex
  J  the metatable, tostring and type errors (__name, E7)
  L  ptree and pcode: arguments processed, then the debug-mode error
  M  constructions whose analyses take many steps (the 2^n verifier chain,
     B and ^n over it) and deep nesting
  Z  the Phase-0 corpus's rows that never call match
  Q  random construction programs
and, from the step b review (sec_review, in the families above): left calls
through B, which the C builds (lpeg-getfirst-unbounded-recursion); sizes past
the C's `int` where it raises a deterministic error ("block too big", or the
check that comes before its writes; lpeg-tree-size-int-overflow); a grammar's
__index and locale's __newindex in their variants; __name as `%s` prints it
(E7); and lpeg-utility's split of a string separator (U06).

Rows the C answers by crashing or with undefined behaviour are never
generated (LESSONS #033): P(n) and p^n whose sizes wrap the C's `int` to
-2, -1 or a short size, and match-time uses of the left recursions the C's
verifier misses. Nor are the rows where the port differs on purpose: a left
recursion past a sub-grammar in a nullable context, which the port refuses
(unit tests and lpeg_tree_limits pin it), and a yield from a constructor's
callback (lpeg-callback-may-yield, pinned there too). Error messages are
compared exactly; only the "hashorder" class (a rule name the grammar
table's traversal order picks) is masked, by the core, except in rows noted
`[exact]`, where one rule alone can be named.

Usage: gen_m66b_trees.py > m66b_tree_cases.txt
"""
import random
import sys

CASES = []
SEEN = set()


def add(cid, chunk, note=""):
    if cid in SEEN:
        raise SystemExit("duplicate id " + cid)
    if "\t" in note or "\n" in note:
        raise SystemExit("bad note " + cid)
    SEEN.add(cid)
    CASES.append((cid, chunk, note))


def lstr(b):
    """A Lua string literal, decimal escapes for anything not printable."""
    if isinstance(b, str):
        b = b.encode("latin-1")
    out = ['"']
    for c in b:
        ch = chr(c)
        if ch in '"\\':
            out.append("\\" + ch)
        elif 32 <= c < 127:
            out.append(ch)
        else:
            out.append("\\%03d" % c)
    out.append('"')
    return "".join(out)


def guarded(expr):
    """A chunk: build `expr` in a function, report its type or its error."""
    return ("local ok, r = pcall(function() return %s end) "
            "if not ok then return false, r end return true, ltype(r)" % expr)


# Numbers as Lua source, and the C int each narrows to (lua_tointeger, then
# truncation to 32 bits). Only those whose trees stay small are used where a
# size follows from them.
NUMBERS = [
    ("0", 0), ("1", 1), ("2", 2), ("3", 3), ("-1", -1), ("-2", -2), ("-3", -3),
    ("255", 255), ("-255", -255), ("1000", 1000), ("-1000", -1000),
    ("1.0", 1), ("1.5", 0), ("-1.5", 0), ("0.5", 0), ("-0.0", 0), ("2.0^2", 4),
    ("2^32", 0), ("2^32+1", 1), ("2^32+2", 2), ("2^32-1", -1), ("-(2^32)", 0),
    ("-(2^32)-1", -1), ("3*2^32+5", 5), ("2^53", 0), ("2^53+2", 2), ("1e308", 0),
    ("math.huge", 0), ("-math.huge", 0), ("0/0", 0), ("math.maxinteger", -1),
    ("math.mininteger", 0), ("2^63", 0), ("-(2^63)", 0), ("0x7fffffff00000003", 3),
]


# ------------------------------------------------------------------ A coercions
def sec_A():
    values = ['""', '"a"', '"abc"', '"\\0"', '"\\255\\0x"', '("ab"):rep(500)', '"3"',
              "true", "false", "nil", "F", "G", "co", "Named", "{}", 'P"a"', "lpeg", "mt",
              'S"ab"', 'Cc(nil)', '{ P"x" }']
    values += [n for n, _ in NUMBERS]
    for i, v in enumerate(values):
        add("A.P.%d" % i,
            "local v = %s local ok, p = pcall(P, v) if not ok then return false, p end "
            "return true, ltype(p), rawequal(p, v)" % v, "P(%s)" % v)
        # The same conversion reached as an operand: getpatt in __mul.
        add("A.mul.%d" % i,
            "local v = %s local ok, p = pcall(mt.__mul, v, P'z') if not ok then return false, p end "
            "return true, ltype(p)" % v)
    add("A.P.none", "return pcall(P)")
    add("A.P.two", "local p = P'a' local q, r = P(p, 2) return rawequal(p, q), r")
    add("A.P.results", "return select('#', P('a', 'b', 'c'))")
    # A function is a run-time capture; two functions are two captures.
    add("A.P.fn2", "return ltype(P(F) * P(G)), ltype(P(F) + F)")


# ------------------------------------------------------------------ B operators
OPERANDS = [
    ("pa", 'P"a"', True), ("sab", 'S"ab"', True), ("ca", 'C"a"', True),
    ("cck", 'Cc("k")', True), ("tr", "P(true)", True), ("fa", "P(false)", True),
    ("any", "P(1)", True), ("rep0", 'P"a"^0', True), ("vx", 'V"x"', True),
    ("fn", "P(F)", True), ("gp", 'P{ "S", S = P"s" }', True),
    ("sa", '"a"', False), ("se", '""', False), ("n1", "1", False), ("n0", "0", False),
    ("nm1", "-1", False), ("n25", "2.5", False), ("bt", "true", False), ("bf", "false", False),
    ("g", '{ "S", S = P"s" }', False), ("gbad", "{}", False), ("f", "F", False),
    ("nil", "nil", False), ("named", "Named", False),
]


def sec_B():
    ops = [("mul", "*"), ("add", "+"), ("sub", "-")]
    for oname, op in ops:
        for an, a, apat in OPERANDS:
            for bn, b, bpat in OPERANDS:
                if not (apat or bpat):
                    continue  # not an LPeg call: arithmetic on plain values
                if not apat and a.startswith('"') and not bpat:
                    continue
                add("B.%s.%s.%s" % (oname, an, bn),
                    "local a, b = %s, %s local ok, r = pcall(function() return a %s b end) "
                    "if not ok then return false, r end "
                    "return true, ltype(r), rawequal(r, a), rawequal(r, b)" % (a, b, op))
    for an, a, apat in OPERANDS:
        if not apat:
            continue
        add("B.unm.%s" % an,
            "local a = %s local ok, r = pcall(function() return -a end) "
            "if not ok then return false, r end return true, ltype(r), rawequal(r, a)" % a)
        add("B.len.%s" % an,
            "local a = %s local ok, r = pcall(function() return #a end) "
            "if not ok then return false, r end return true, ltype(r), rawequal(r, a)" % a)
    # The metamethods called directly: no Lua caller, named '?'.
    for mm in ["__mul", "__add", "__sub", "__unm", "__len", "__div", "__pow"]:
        for i, args in enumerate(["", "nil", "P'a'", "P'a', nil", "1, 2", "'a', 'b'", "co",
                                  "P'a', P'b'", "{}, P'a'", "P'a', {}"]):
            args = ", " + args if args else ""
            add("B.direct.%s.%d" % (mm.strip("_"), i), "return pcall(mt.%s%s)" % (mm, args))
    # Charsets merge; anything else nests.
    add("B.charsets", "local u = S'ab' + S'cd' local d = S'ab' - 'a' local n = P(1) + 'a' "
                      "return ltype(u), ltype(d), ltype(n), ltype(R'az' - R'mz')")
    add("B.eq", "return P'a' == P'a', rawequal(P'a', P'a')")
    add("B.concat", "local ok, e = pcall(function() return P'a' .. P'b' end) return ok, e")
    add("B.idx", "return P'a'.match == lpeg.match, P'a'.nosuch, P'a'.version == version")
    add("B.method", "return ltype(P'a':B()), pcall(P'a'.Cg, P'a', {})")


# ------------------------------------------------------------------ C captures
ARGS = ['P"a"', '"a"', "1", "true", "nil", '{ "S", S = P"s" }', "{}", "F", "co", "Named", "2.5"]


def sec_C():
    for name in ["C", "Cs", "Ct", "Cp", "Cg"]:
        add("C.%s.none" % name, "return pcall(%s)" % name)
        for i, a in enumerate(ARGS):
            add("C.%s.%d" % (name, i), "local ok, p = pcall(%s, %s) return ok, ok and ltype(p) or p" % (name, a))
    # Cg's name: a string, a number made a string; anything else refused,
    # before the pattern is looked at.
    for i, n in enumerate(['"n"', "1", "1.5", "0/0", "nil", "true", "{}", "F", "-0.0", "2^63"]):
        for j, p in enumerate(['P"a"', "nil", "{}"]):
            add("C.Cg.name.%d.%d" % (i, j), "local ok, r = pcall(Cg, %s, %s) return ok, ok and ltype(r) or r" % (p, n))
    for i, n in enumerate(['"n"', "1", "1.5", "nil", "true", "{}", "F"]):
        add("C.Cb.%d" % i, "local ok, r = pcall(Cb, %s) return ok, ok and ltype(r) or r" % n)
    add("C.Cb.none", "return pcall(Cb)")
    for i, n in enumerate(["0", "1", "-1", "32767", "32768", "2^32+1", "2^32+32768", "'2'",
                           "1.5", "nil", "{}", "math.maxinteger", "2^31", "-(2^31)"]):
        add("C.Carg.%d" % i, "local ok, r = pcall(Carg, %s) return ok, ok and ltype(r) or r" % n)
    add("C.Carg.none", "return pcall(Carg)")
    for i, args in enumerate(["", "nil", "nil, nil", "1", "1, 2, 3", "nil, 1, nil", "true, false",
                              "{}, F", "1.5, -0.0, 0/0", "'k', 'k'"]):
        args = ", " + args if args else ""
        add("C.Cc.%d" % i, "local ok, r = pcall(Cc%s) return ok, ok and ltype(r) or r" % args)
    add("C.Cc.many", "local t = {} for i = 1, 300 do t[i] = i end return ltype(Cc(table.unpack(t)))")
    for name in ["Cf", "Cmt"]:
        for i, f in enumerate(["F", "nil", "1", "'x'", "{}", "co", "Named"]):
            for j, p in enumerate(['P"a"', "nil", "{}", "1"]):
                add("C.%s.%d.%d" % (name, i, j), "local ok, r = pcall(%s, %s, %s) return ok, ok and ltype(r) or r" % (name, p, f))
        add("C.%s.none" % name, "return pcall(%s)" % name)
    # Constants and labels join constant tables (wide keys, D4).
    add("C.join.300", "local p = P(true) for i = 1, 300 do p = p * Cc(i) end return ltype(p)")
    # Past 32,767 and 65,536 constants, where the C's 16-bit keys wrap (D4):
    # joined pairwise, so the copying is n log n.
    add("C.join.70000", "local ps = {} for i = 1, 70000 do ps[i] = Cc(i) end "
                        "while #ps > 1 do local q = {} for i = 1, #ps, 2 do "
                        "q[#q + 1] = ps[i + 1] and ps[i] * ps[i + 1] or ps[i] end ps = q end "
                        "return ltype(ps[1])")
    add("C.join.mixed", "return ltype(Cc('k') * Carg(2) * Cg(Cc(1), 'g') * Cb('g') * (P'a' / {}) * Cmt(1, F))")
    add("C.V", "local r = {} for i, v in ipairs{1, 'x', true, 2.5, F, P'a'} do r[i] = ltype(V(v)) end "
               "return r, pcall(V), pcall(V, nil), ltype(V(false))")


# ------------------------------------------------------------------ D grammars
GRAMMARS = [
    '{ "S", S = P"a" * V"S" + "" }', '{ P"a" * V(1) + "" }', '{ "S", S = V"A" * V"B", A = C"a", B = C"b" }',
    '{ [1] = "S", S = "a" }', '{ "S", S = P"a", T = V"U" }', '{ "S", S = V"T" }', '{ "S" }', '{}',
    '{ [2] = P"a" }', '{ "S", S = {} }', '{ "S", S = P(true) * V"S" }', '{ "S", S = V"S" * "a" + "b" }',
    '{ "S", S = V"A", A = V"B", B = V"S" * "x" }', '{ "S", S = "a" + V"S" }',
    '{ "S", S = (V"E")^0, E = P"" }', '{ "S", S = (V"E" * "")^0, E = P"a"^0 }',
    '{ "S", S = V"E"^1, E = P"a" + P"" }', '{ "S", S = -V"S" * "a" }', '{ "S", S = #V"S" * "a" }',
    '{ "S", S = B"a" * V"S" + "a" }', '{ "S", S = C(V"S") }', '{ "S", S = P{ "T", T = P"a" * V"T" + "" } }',
    '{ "S", S = P{ V"S" } }', '{ "S", S = V"T", T = P{ "U", U = "a" } * V"S" + "b" }',
    '{ "S", S = Cmt(V"S", F) + "a" }', '{ "S", S = V"A" + V"B", A = V"B" * "x", B = "y" }',
    '{ "S", S = V(1) }', '{ "S", S = V"T", T = "t", [3] = "x" }', '{ "S", S = "s", T = "t", [1.5] = P"x" }',
    '{ "S", [true] = P"x", S = V(true) }', '{ V(2), P"b" * V(2) + "c" }', '{ "S", S = V"T", T = 1 }',
    '{ "S", S = V"T", T = F }', '{ "S", S = Ct(Cg(C"a", "x") * V"T"), T = Cb("x") }',
    '{ 1, P"a" }', '{ true }', '{ "S", S = V"S" }', '{ "S", S = P"a" * V"S" }',
    '{ "S", S = P"(" * V"S"^0 * ")" }', '{ "S", S = Cs((V"N" + 1)^0), N = R"09"^1 / F }',
    '{ 2, [2] = P"a" }', '{ 1.5, [1.5] = P"a" }', '{ "S", S = P"a", ["1"] = 5 }',
    '{ "S", S = P"a", [" 0x1 "] = {} }', '{ "S", S = P"a", ["1.0"] = 5, [1.0] = P"q" }',
    '{ P"x", [1.0] = P"y" }', '{ "S", S = V(1.0) }', '{ "S", S = V"1" }',
    '{ "S", S = V(P"a") }', '{ "S", S = V{} }', '{ "S", S = V(F) }', '{ "S", S = V(2.5) }',
    '{ "S\\0x", ["S\\0x"] = V"S\\0y" }', '{ "S", S = P"s", T = "\\0z" }',
    '{ "S", S = (P"a"^0)^0 }', '{ "S", S = (P"a"^-1)^1 }', '{ "S", S = (#P"a")^0 }',
    '{ "S", S = (-P"a")^0 }', '{ "S", S = (B"a")^0 }', '{ "S", S = (P{ P"" })^0 }',
    '{ "S", S = (P{ P"a" })^0 }', '{ "S", S = (Cmt(P"", F))^0 }', '{ "S", S = (P"a" + Cc(1))^0 }',
    '{ "S", S = P"a" * V"T", T = (P"")^0 }', '{ "S", S = P"a", T = (P"")^0 }',
    '{ "S", S = V"T" * V"T", T = P"" + "b" }', '{ "S", S = V"T" * V"S", T = P"" + "b" }',
    '{ "S", S = V"T" + V"S" * "x", T = "y" }', '{ 3, [3] = P"t" }',
    '{ "S", S = Cg(V"S") + "a" }', '{ "S", S = Ct(V"S" * "a") }', '{ "S", S = (V"S" / F) * "a" }',
]


def sec_D():
    for i, g in enumerate(GRAMMARS):
        # One candidate rule unless the grammar has two or more rules that
        # could each be named.
        add("D.%d" % i, "local ok, r = pcall(P, %s) return ok, ok and ltype(r) or r" % g, g)
    # A rule name is shown as `%s` shows it: a number as Lua writes it, a
    # string up to its first NUL, anything else as `(a type)`.
    exact = [
        ('{ "S", S = V"S" }', "self"), ('{ "S", S = V"T" }', "undef"), ('{ "S", S = V(2.5) }', "undef float"),
        ('{ "S", S = V(P"a") }', "undef pattern"), ('{ "S", S = V{} }', "undef table"),
        ('{ "S", S = V"1" }', "undef string 1"), ('{ "S", S = P"s", T = 7 }', "not a pattern"),
        ('{ "S", S = P"s", [2.5] = 7 }', "float key"), ('{ "S", S = P"s", [true] = 7 }', "boolean key"),
        ('{ "S", S = P"s", [F] = 7 }', "function key"), ('{ "S\\0x", ["S\\0x"] = V"S\\0y" }', "nul name"),
        ('{ "S", S = (P"")^0 }', "empty loop"), ('{ "S", S = V(-0.0) * "a" }', "-0.0 name"),
        ('{ "S", S = V(2^53) }', "big float name"), ('{ "S", S = V(1e100) }', "1e100 name"),
        ('{ "S", S = V(0/0) }', "nan name"), ('{ "S", S = V(1/0) }', "inf name"),
        ('{ "S", S = V"S" * "a" + "b" }', "self through choice"),
        ('{ "S", S = Cmt(V"S", F) }', "self through Cmt"), ('{ "S", S = (V"S")^0 }', "self through rep"),
        ('{ 2, [2] = V(2) }', "integer name"), ('{ [1] = V(1) }', "first rule is 1"),
    ]
    for i, (g, n) in enumerate(exact):
        add("D.x.%d" % i, "return pcall(P, %s)" % g, "[exact] " + n)
    # MAXRULES: the count is checked after the tree is built.
    for n in (198, 199, 200, 201, 250):
        add("D.rules.%d" % n,
            "local g = { 'r1' } for i = 1, %d do g['r'..i] = P(i %% 7 == 0 and 'x' or 'y') end "
            "local ok, r = pcall(P, g) return ok, ok and ltype(r) or r" % n)
        add("D.rules.op.%d" % n,
            "local g = { 'r1' } for i = 1, %d do g['r'..i] = P'y' end "
            "local ok, r = pcall(function() return P'a' * g end) return ok, ok and ltype(r) or r" % n)
    add("D.rules.notpat", "local g = { 'r1' } for i = 1, 300 do g['r'..i] = P'y' end g.r7 = 7 return pcall(P, g)")
    add("D.lr.chain", "return pcall(P, { 'a', a = V'b', b = V'c', c = V'd', d = V'a' * 'x' })")
    add("D.lr.unref", "return pcall(P, { 's', s = P'x', c = V'd' * 'x', d = V'c' * 'y' })")
    add("D.emptyloop.unref", "return ltype(P{ 's', s = P'x', e = (P'')^0 })")
    add("D.notpat.two", "return pcall(P, { 's', s = P'x', t = 'str', u = 'str2' })")
    # The initial rule through __index: a table, and a function (a call).
    add("D.index.table", "return ltype(P(setmetatable({ 'S' }, { __index = { S = P'a' } })))")
    add("D.index.fn", "local seen local g = setmetatable({ 'S' }, { __index = function(t, k) seen = k return P'a' end }) "
                      "return ltype(P(g)), seen")
    add("D.index.fnnil", "return pcall(P, setmetatable({ 'S' }, { __index = function() return nil end }))")
    add("D.index.fnbad", "return pcall(P, setmetatable({ 'S' }, { __index = function() return 7 end }))")
    add("D.index.err", "return pcall(P, setmetatable({ 'S' }, { __index = function() error('boom', 0) end }))")
    add("D.index.errt", "local ok, e = pcall(P, setmetatable({ 'S' }, { __index = function() error({ 1 }) end })) "
                        "return ok, type(e), e[1]")
    add("D.index.rules", "return ltype(P(setmetatable({ 'S', T = P'b' }, { __index = function() return V'T' end })))")
    add("D.index.notraw", "return pcall(P, setmetatable({ 2 }, { __index = function(t, k) return k == 2 and P'a' end }))")
    # A number names the initial rule (`lua_isstring`); NaN cannot key the
    # position table, and the VM's message is raised unpositioned.
    add("D.index.nan", "return pcall(P, setmetatable({ 0/0 }, { __index = function() return P'a' end }))")
    add("D.index.num", "return ltype(P(setmetatable({ 2.5 }, { __index = function(t, k) return k == 2.5 and P'a' end })))")
    add("D.index.op", "return pcall(function() return P'x' * setmetatable({ 'S' }, { __index = { S = P'a' } }) end)")
    add("D.nested.deep", "local g = P'a' for i = 1, 50 do g = P{ 'S', S = g * V'S' + '' } end return ltype(g)")
    add("D.reuse", "local t = { 'S', S = P'a' * V'S' + '' } local p, q = P(t), P(t) return rawequal(p, q), ltype(p)")


# ------------------------------------------------------------------ E lpeg.B
def sec_E():
    behinds = ['"a"', '"ab"', "1", "3", 'S"ab"', 'R"az" * "b"', 'P"a" + "bc"', 'P"a" + "b"', 'C"a"', '""',
               "P(255)", "P(256)", '-P"a"', '#P"a"', 'B"a"', 'P{ P"x" }', "P(true)", "P(false)", 'P"a"^1',
               'P"ab" * Cp()', "F", 'P(F) * "a"', 'P{ V"x"; x = P"ab" }', 'P{ "x", x = P"a" * V"y", y = P"b" }',
               'P{ "x", x = P"a" * V"x" + "b" }', '-P"a" * "b"', '#P"a" * "b"', 'P"a" - "b"',
               'P"a" * Cc(1)', '(P"a" + "b") * (P"c" + "d")', 'P"abc" + "def"', 'P"ab" + "c"', "-1", "P(-3) * 2",
               "nil", "{}", '{ "S", S = P"ab" }', "co", "P(1)^-1", "P(254) * B(1)", "P(256) - 'a'"]
    for i, b in enumerate(behinds):
        add("E.B.%d" % i, "local ok, r = pcall(B, %s) return ok, ok and ltype(r) or r" % b, "B(%s)" % b)
    add("E.B.none", "return pcall(B)")
    add("E.B.op", "return pcall(function() return B(P'a'^1) end)")


# ------------------------------------------------------------------ F p^n
def sec_F():
    bases = ['P"a"', 'S"ab"', "P(1)", 'P""', "P(true)", "P(false)", '#P"a"', '-P"a"', 'P"a"^0', 'C"a"',
             'P"a" + ""', 'Cmt(P"a", F)', 'B"a"', 'P(F)', 'P{ "S", S = P"a" * V"S" + "" }', 'P"ab"',
             'Cc(1)', 'Cp()']
    exps = ["0", "1", "2", "3", "-1", "-2", "-3", "1.0", "'2'", "'-1'", "'x'", "nil", "2^32", "2^32+1",
            "-(2^32)+1", "1.5", "2^53", "math.maxinteger", "math.mininteger", "{}", "true", "P'a'", "'0x10'"]
    for i, b in enumerate(bases):
        for j, n in enumerate(exps):
            add("F.%d.%d" % (i, j), "local b = %s local ok, r = pcall(function() return b ^ %s end) "
                                    "return ok, ok and ltype(r) or r" % (b, n), "%s ^ %s" % (b, n))
        add("F.direct.%d" % i, "return pcall(mt.__pow, %s, 2)" % b)
    for i, b in enumerate(['"a"', "1", "nil", "{}", "true"]):
        add("F.notpat.%d" % i, "return pcall(mt.__pow, %s, 2)" % b)
    add("F.none", "return pcall(mt.__pow)")
    add("F.one", "return pcall(mt.__pow, P'a')")
    # Order: the exponent is checked before the pattern.
    add("F.order", "return pcall(mt.__pow, 'a', 'x')")
    add("F.big", "return ltype(P'a'^100000), ltype(P'a'^-100000), ltype(P'ab'^1000 * P'c'^-1000)")
    add("F.nested", "return ltype(((P'a'^2)^-2)^3)")


# ------------------------------------------------------------------ G p / x
def sec_G():
    rhs = ['"x"', '"%1"', '""', "{}", '{ a = 1 }', "F", "0", "1", "2", "3", "-1", "32767", "32768", "1.5",
           "2^31", "2^32", "2^32+1", "2^32+3", "-(2^32)+1", "'1'", "true", "false", "nil", "co", "Named",
           "math.maxinteger", "0/0", "P'a'"]
    lhs = ['P"a"', 'C"a"', 'Cc("k")', "P(1)"]
    for i, l in enumerate(lhs):
        for j, r in enumerate(rhs):
            add("G.%d.%d" % (i, j), "local a = %s local ok, r = pcall(function() return a / %s end) "
                                    "return ok, ok and ltype(r) or r" % (l, r), "%s / %s" % (l, r))
    for j, r in enumerate(["'x'", "1", "32768", "true", "{}"]):
        for i, l in enumerate(["nil", "1", "{}", "'a'"]):
            add("G.direct.%d.%d" % (i, j), "return pcall(mt.__div, %s, %s)" % (l, r))
    add("G.direct.none", "return pcall(mt.__div)")


# ------------------------------------------------------------------ H setmaxstack
def sec_H():
    for i, v in enumerate(["", "nil", "0", "5", "100", "1000", "-5", "'10'", "'x'", "1.5", "2^32", "2^32+150",
                           "{}", "true", "'1000.0'", "1000.0", "math.maxinteger", "F"]):
        args = ", " + v if v else ""
        add("H.%d" % i, "local r = table.pack(pcall(setmaxstack%s)) return r.n, r[1], r[2]" % args)
    add("H.op", "return pcall(function() setmaxstack('y') end)")


# ------------------------------------------------------------------ I locale
def sec_I():
    add("I.keys", "local t = locale() local k = {} for n, v in pairs(t) do k[#k+1] = n .. '=' .. ltype(v) end "
                  "table.sort(k) return table.concat(k, ',')")
    add("I.order", "local order = {} local t = setmetatable({}, { __newindex = function(t, k, v) "
                   "order[#order+1] = k rawset(t, k, v) end }) local r = locale(t) "
                   "return rawequal(r, t), table.concat(order, ','), ltype(t.digit)")
    add("I.fill", "local t = { alpha = 1, x = 2 } local r = locale(t) return rawequal(r, t), ltype(t.alpha), t.x")
    add("I.redirect", "local u = {} local t = setmetatable({}, { __newindex = u }) locale(t) "
                      "return next(t), ltype(u.space), ltype(u.xdigit)")
    add("I.stop", "local n = 0 local t = setmetatable({}, { __newindex = function(t, k, v) n = n + 1 "
                  "if k == 'graph' then error('stop at ' .. k, 0) end rawset(t, k, v) end }) "
                  "local ok, e = pcall(locale, t) return ok, e, n, ltype(t.digit), t.lower")
    for i, v in enumerate(["5", "nil", "false", "'x'", "F", "P'a'"]):
        add("I.arg.%d" % i, "local ok, r = pcall(locale, %s) return ok, type(r) == 'table' and 'table' or r" % v)
    add("I.none", "return type(locale())")
    add("I.fresh", "return rawequal(locale(), locale())")


# ------------------------------------------------------------------ J metatable, __name
def sec_J():
    add("J.keys", "local k = {} for n in pairs(lpeg) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')")
    add("J.mt", "local k = {} for n in pairs(mt) do k[#k+1] = n end table.sort(k) "
                "return table.concat(k, ','), mt.__index == lpeg, mt.__name, getmetatable(P'x') == mt")
    add("J.mtfns", "return type(mt.__gc), type(mt.__mul), rawequal(mt.__index, lpeg)")
    add("J.gc", "return pcall(mt.__gc, 5), select('#', mt.__gc(P'a'))")
    # Only whether it fails: the message is the VM's base library's.
    add("J.setmt", "return (pcall(setmetatable, P'a', {})), getmetatable(P'a') == mt")
    add("J.kind", "return kind(P'a'), kind(P{ 'S', S = P'a' }), kind(Named), kind(setmetatable({}, { __name = 5 })), "
                  "kind(setmetatable({}, { __name = 'X', __tostring = function() return 'T' end })), "
                  "kind({}), kind(F)")
    add("J.tostring", "return tostring(setmetatable({}, { __name = 'X', __tostring = function() return 'T' end })), "
                      "string.format('%s', P'a'):match('^lpeg%-pattern: ') ~= nil")
    add("J.typeerr", "return perr(function() return string.rep(P'a', 2) end), "
                     "perr(function() return string.rep(Named, 2) end), "
                     "perr(function() return string.format('%d', P'a') end), "
                     "perr(function() return string.char(P(1)) end), "
                     "perr(function() return string.rep('x', setmetatable({}, { __name = 7 })) end)")
    add("J.typeerr.lpeg", "return pcall(P, co), pcall(C, Named), pcall(Cf, P'a', P'b'), pcall(locale, P'a')")
    add("J.type", "local r = {} for i, v in ipairs{ P'a', 'a', 1, true, Named, F, co, mt, lpeg } do "
                  "r[i] = tostring(ltype(v)) end return table.concat(r, ','), ltype(), ltype(nil)")
    add("J.version", "return version(), type(version), version(1, 2), select('#', version())")
    add("J.arith", "local ok, e = pcall(function() return P'a' % 2 end) return ok, e")


# ------------------------------------------------------------------ L ptree, pcode
def sec_L():
    for i, a in enumerate(["P'a'", "'a'", "1", "nil", "{}", '{ "S", S = V"S" }', '{ "S", S = P"a" }', "V'x'",
                           "V'x' * 'a'", "C(V'x')", "P{ 'S', S = P'a' * V'S' + 'b' }"]):
        add("L.ptree.%d" % i, "return pcall(lpeg.ptree, %s)" % a)
        add("L.ptreec.%d" % i, "return pcall(lpeg.ptree, %s, true)" % a)
        add("L.pcode.%d" % i, "return pcall(lpeg.pcode, %s)" % a)
    add("L.ptree.none", "return pcall(lpeg.ptree)")
    add("L.pcode.none", "return pcall(lpeg.pcode)")


# ------------------------------------------------------------------ M long analyses, depth
def sec_M():
    for k in (8, 12, 16):
        add("M.chain.%d" % k, "return ltype(P(chain(%d)))" % k)
        add("M.chainB.%d" % k, "local ok, r = pcall(B, P(chain(%d))) return ok, ok and ltype(r) or r" % k)
        add("M.chainpow.%d" % k, "return ltype(P(chain(%d))^1)" % k)
        add("M.chainempty.%d" % k, "local ok, r = pcall(function() return P(chain(%d, P''))^1 end) return ok, r" % k)
        add("M.chainnofail.%d" % k, "local p = P(chain(%d, P'')) return rawequal(p + 'x', p)" % k)
        add("M.chainlong.%d" % k, "local ok, r = pcall(B, P(chain(%d, P'aa'))) return ok, ok and ltype(r) or r" % k)
    for d in (200, 1000, 5000):
        for name, f in [("Ct", "Ct"), ("not", "function(p) return -p end"), ("and", "function(p) return #p end"),
                        ("rep", "function(p) return p^-1 end"), ("Cs", "Cs"), ("C", "C"),
                        ("seq", "function(p) return p * 'b' end"), ("lseq", "function(p) return 'b' * p end"),
                        ("choice", "function(p) return p + 'b' end"), ("grammar", "function(p) return P{ p } end"),
                        ("Cmt", "function(p) return Cmt(p, F) end")]:
            add("M.nest.%s.%d" % (name, d), "return ltype(nest(%d, %s))" % (d, f))
    add("M.nest.B", "return pcall(B, nest(300, function(p) return -p * 'b' end))")


# ------------------------------------------------------------------ Z Phase 0's rows
# The rows of the M6.6 Phase-0 corpus (gen_lpeg_cases.py, seed 1) that never
# call `match`, verbatim but for its helper names (`Mkeep`, `Fcat` -> `F`);
# those that need `io.stdout` or a re-entrant match are left to later steps.
PHASE0 = [
    ('A.Pnum.19', 'local ok, p = pcall(P, 2^53); return ok, ok and ltype(p) or p'),
    ('A.Pnum.20', 'local ok, p = pcall(P, 1e308); return ok, ok and ltype(p) or p'),
    ('A.Pnum.21', 'local ok, p = pcall(P, math.huge); return ok, ok and ltype(p) or p'),
    ('A.Pnum.22', 'local ok, p = pcall(P, -math.huge); return ok, ok and ltype(p) or p'),
    ('A.Pnum.26', 'local ok, p = pcall(P, math.maxinteger); return ok, ok and ltype(p) or p'),
    ('A.Pnum.27', 'local ok, p = pcall(P, math.mininteger); return ok, ok and ltype(p) or p'),
    ('A.S.bad', 'return S({})'),
    ('A.S.none', 'return S()'),
    ('A.V.0', 'local p = V(nil); return ltype(p)'),
    ('A.V.1', 'local p = V(); return ltype(p)'),
    ('A.V.2', 'local p = V(1); return ltype(p)'),
    ('A.V.3', "local p = V('x'); return ltype(p)"),
    ('A.V.4', 'local p = V(true); return ltype(p)'),
    ('A.V.5', 'local p = V(1.5); return ltype(p)'),
    ('A.V.6', 'local p = V({}); return ltype(p)'),
    ('A.V.7', "local p = V(P'a'); return ltype(p)"),
    ('A.type.0', 'return ltype(P"a")'),
    ('A.type.1', 'return ltype(1)'),
    ('A.type.2', 'return ltype("a")'),
    ('A.type.3', 'return ltype(true)'),
    ('A.type.4', 'return ltype({})'),
    ('A.type.5', 'return ltype(nil)'),
    ('A.type.6', 'return ltype(F)'),
    ('A.type.8', 'return ltype({ "x", x = P"a" })'),
    ('A.version', 'return version(), type(version)'),
    ('A.ptree', "return lpeg.ptree(P'a')"),
    ('A.pcode', "return lpeg.pcode(P'a')"),
    ('A.keys', "local k = {} for n in pairs(lpeg) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')"),
    ('A.mt', "local mt = getmetatable(P'a'); local k = {} for n in pairs(mt) do k[#k+1] = n end table.sort(k) return table.concat(k, ','), mt.__index == lpeg, mt.__name"),
    ('A.setmt', "local mt = getmetatable(P'a'); return pcall(setmetatable, P'a', {})"),
    ('B.pow.str', "return pcall(function() return 'a'^2 end)"),
    ('B.eq', "return P'a' == P'a', rawequal(P'a', P'a')"),
    ('B.concat', "return pcall(function() return P'a' .. P'b' end)"),
    ('D.build.0', 'local p = P({ "S", S = P"a" * V"S" + "" }); return ltype(p)'),
    ('D.build.1', 'local p = P({ P"a" * V(1) + "" }); return ltype(p)'),
    ('D.build.2', 'local p = P({ "S", S = V"A" * V"B", A = C"a", B = C"b" }); return ltype(p)'),
    ('D.build.3', 'local p = P({ [1] = "S", S = "a" }); return ltype(p)'),
    ('D.build.4', 'local p = P({ "S", S = P"a", T = V"U" }); return ltype(p)'),
    ('D.build.5', 'local p = P({ "S", S = V"T" }); return ltype(p)'),
    ('D.build.6', 'local p = P({ "S" }); return ltype(p)'),
    ('D.build.7', 'local p = P({}); return ltype(p)'),
    ('D.build.8', 'local p = P({ [2] = P"a" }); return ltype(p)'),
    ('D.build.9', 'local p = P({ "S", S = {} }); return ltype(p)'),
    ('D.build.10', 'local p = P({ "S", S = P(true) * V"S" }); return ltype(p)'),
    ('D.build.11', 'local p = P({ "S", S = V"S" * "a" + "b" }); return ltype(p)'),
    ('D.build.12', 'local p = P({ "S", S = V"A", A = V"B", B = V"S" * "x" }); return ltype(p)'),
    ('D.build.13', 'local p = P({ "S", S = "a" + V"S" }); return ltype(p)'),
    ('D.build.14', 'local p = P({ "S", S = (V"E")^0, E = P"" }); return ltype(p)'),
    ('D.build.15', 'local p = P({ "S", S = (V"E" * "")^0, E = P"a"^0 }); return ltype(p)'),
    ('D.build.16', 'local p = P({ "S", S = V"E"^1, E = P"a" + P"" }); return ltype(p)'),
    ('D.build.17', 'local p = P({ "S", S = -V"S" * "a" }); return ltype(p)'),
    ('D.build.18', 'local p = P({ "S", S = #V"S" * "a" }); return ltype(p)'),
    ('D.build.19', 'local p = P({ "S", S = B"a" * V"S" + "a" }); return ltype(p)'),
    ('D.build.20', 'local p = P({ "S", S = C(V"S") }); return ltype(p)'),
    ('D.build.21', 'local p = P({ "S", S = P{ "T", T = P"a" * V"T" + "" } }); return ltype(p)'),
    ('D.build.22', 'local p = P({ "S", S = P{ V"S" } }); return ltype(p)'),
    ('D.build.23', 'local p = P({ "S", S = V"T", T = P{ "U", U = "a" } * V"S" + "b" }); return ltype(p)'),
    ('D.build.24', 'local p = P({ "S", S = Cmt(V"S", F) + "a" }); return ltype(p)'),
    ('D.build.25', 'local p = P({ "S", S = V"A" + V"B", A = V"B" * "x", B = "y" }); return ltype(p)'),
    ('D.build.26', 'local p = P({ "S", S = V(1) }); return ltype(p)'),
    ('D.build.27', 'local p = P({ "S", S = V"T", T = "t", [3] = "x" }); return ltype(p)'),
    ('D.build.28', 'local p = P({ "S", S = "s", T = "t", [1.5] = P"x" }); return ltype(p)'),
    ('D.build.29', 'local p = P({ "S", [true] = P"x", S = V(true) }); return ltype(p)'),
    ('D.build.30', 'local p = P({ V(2), P"b" * V(2) + "c" }); return ltype(p)'),
    ('D.build.31', 'local p = P({ "S", S = V"T", T = 1 }); return ltype(p)'),
    ('D.build.32', 'local p = P({ "S", S = V"T", T = F }); return ltype(p)'),
    ('D.build.33', 'local p = P({ "S", S = Ct(Cg(C"a", "x") * V"T"), T = Cb("x") }); return ltype(p)'),
    ('D.build.34', 'local p = P({ "S", S = Cg(C"a", "x") * V"T", T = Cb("x") }); return ltype(p)'),
    ('D.build.35', 'local p = P({ 1, P"a" }); return ltype(p)'),
    ('D.build.36', 'local p = P({ true }); return ltype(p)'),
    ('D.build.37', 'local p = P({ "S", S = V"S" }); return ltype(p)'),
    ('D.build.38', 'local p = P({ "S", S = P"a" * V"S" }); return ltype(p)'),
    ('D.build.39', 'local p = P({ "S", S = P"(" * V"S"^0 * ")" }); return ltype(p)'),
    ('D.build.40', 'local p = P({ "S", S = Cs((V"N" + 1)^0), N = R"09"^1 / F }); return ltype(p)'),
    ('D.rules.199', "local g = { 'r1' } for i = 1, 199 do g['r'..i] = P(i % 7 == 0 and 'x' or 'y') end return ltype(P(g))"),
    ('D.rules.200', "local g = { 'r1' } for i = 1, 200 do g['r'..i] = P(i % 7 == 0 and 'x' or 'y') end return ltype(P(g))"),
    ('D.rules.201', "local g = { 'r1' } for i = 1, 201 do g['r'..i] = P(i % 7 == 0 and 'x' or 'y') end return ltype(P(g))"),
    ('D.rules.250', "local g = { 'r1' } for i = 1, 250 do g['r'..i] = P(i % 7 == 0 and 'x' or 'y') end return ltype(P(g))"),
    ('D.lr.chain', "return pcall(P, { 'a', a = V'b', b = V'c', c = V'd', d = V'a' * 'x' })"),
    ('D.lr.unref', "return pcall(P, { 's', s = P'x', c = V'd' * 'x', d = V'c' * 'y' })"),
    ('D.emptyloop.unref', "return pcall(P, { 's', s = P'x', e = (P'')^0 })"),
    ('D.notpat.two', "return pcall(P, { 's', s = P'x', t = 'str', u = 'str2' })"),
    ('D.notpat.one', "return pcall(P, { 's', s = P'x', t = 'str' })"),
    ('I.keys', "local t = locale() local k = {} for n in pairs(t) do k[#k+1] = n end table.sort(k) return table.concat(k, ',')"),
    ('I.fill', 'local t = { alpha = 1, x = 2 } local r = locale(t) return r == t, ltype(t.alpha), t.x'),
    ('I.bad', 'return locale(5)'),
    ('I.nil', 'return ltype(locale(nil).digit)'),
]


def sec_Z():
    for cid, chunk in PHASE0:
        # Its message is the VM base library's `setmetatable` argument error,
        # which is not LPeg's ("type error, expected Table, found userdata";
        # DIVERGENCES.md `vm-base-library-argument-errors`); J.setmt keeps the
        # outcome.
        if cid == "A.setmt":
            continue
        add("Z." + cid, chunk, "phase 0")
    # `lp_V` checks argument 1 after pushing its result: with none, the
    # pattern names itself.
    add("Z.V.none", "return ltype(V()), pcall(P, { 'S', S = V() })", "[exact]")
    add("Z.V.noneptree", "return pcall(lpeg.ptree, V(), true)", "[exact]")


# ------------------------------------------------------------------ Q random programs
ALPH = [b"a", b"b", b"0", b"\x00", b"\xff", b" "]


class RandGen:
    def __init__(self, rng):
        self.r = rng

    def lit(self):
        n = self.r.choice([0, 1, 1, 2, 3])
        return b"".join(self.r.choice(ALPH) for _ in range(n))

    def leaf(self, rules):
        r = self.r
        k = r.randrange(14)
        if k < 3:
            return "P%s" % lstr(self.lit())
        if k == 3:
            return "P(%d)" % r.choice([-2, -1, 0, 1, 2, 3])
        if k == 4:
            return r.choice(["P(true)", "P(false)"])
        if k == 5:
            return "S%s" % lstr(bytes(sorted(set(r.choice(ALPH)[0] for _ in range(r.randrange(0, 3))))))
        if k == 6:
            return r.choice(['R"ac"', 'R"09"', 'R("\\0\\31", "ab")', 'R"za"'])
        if k == 7:
            return r.choice(["Cp()", "Cc()", "Cc(1)", "Cc('k', 2)", "Cc(nil)", "Carg(1)", "Cb('g')"])
        if k == 8:
            return r.choice(["P(F)", "P(G)"])
        if k in (9, 10) and rules:
            return "V%s" % lstr(r.choice(rules)) if r.random() < 0.9 else 'V"undefined"'
        if k == 11:
            return lstr(self.lit())
        return "P%s" % lstr(self.lit())

    def expr(self, d, rules, in_behind=False):
        """No open call inside lpeg.B and no sub-grammar inside a rule: those
        are where the C's verifier misses left recursion (excluded above)."""
        r = self.r
        if d <= 0 or r.random() < 0.2:
            leaf = self.leaf(rules if not in_behind else [])
            return leaf
        k = r.randrange(28)
        e0 = lambda: self.expr(d - 1, rules, in_behind)

        # A bare string operand is a pattern only through LPeg's own
        # metamethods: two bare strings, or one on the left of `/`, `^`, `-`
        # or `#`, would be arithmetic on strings, the VM's error and not
        # LPeg's (`vm-error-varinfo`).
        def e(left=False):
            x = e0()
            return "P(%s)" % x if left and x.startswith('"') else x
        if k < 10:
            a, b = e(), e()
            if a.startswith('"') and b.startswith('"'):
                a = "P(%s)" % a
            return "(%s %s %s)" % (a, "*" if k < 5 else "+" if k < 9 else "-", b)
        if k == 10:
            return "(-%s)" % e(True)
        if k == 11:
            return "(#%s)" % e(True)
        if k in (12, 13):
            return "(%s)^%d" % (e(True), r.choice([-2, -1, 0, 0, 1, 2]))
        if k == 14:
            return "C(%s)" % e()
        if k == 15:
            return "Cs(%s)" % e()
        if k == 16:
            return "Ct(%s)" % e()
        if k == 17:
            return r.choice(["Cg(%s)", "Cg(%s, 'g')", "Cg(%s, 1)"]) % e()
        if k == 18:
            return "Cf(%s, F)" % e()
        if k == 19:
            return "Cmt(%s, F)" % e()
        if k == 20:
            return "B(%s)" % self.expr(d - 1, [], True)
        if k == 21:
            return "(%s / %s)" % (e(True), lstr(r.choice(["%0", "%1", "x"])))
        if k == 22:
            return "(%s / %d)" % (e(True), r.choice([0, 1, 2]))
        if k == 23:
            return "(%s / F)" % e(True)
        if k == 24:
            return "(%s / { a = 1 })" % e(True)
        if k == 25 and d >= 2 and not rules and not in_behind:
            return self.grammar(d - 1)
        return "(%s * %s)" % (e(True), e())

    def grammar(self, d):
        r = self.r
        names = r.sample(["A", "B", "C", "D"], r.randrange(1, 4))
        parts = [lstr(names[0])]
        for nme in names:
            parts.append("%s = %s" % (nme, self.expr(d, names)))
        return "P{ %s }" % ", ".join(parts)


def sec_Q(seed, n):
    g = RandGen(random.Random(seed))
    for i in range(n):
        if i % 3 == 0:
            expr = g.grammar(3)
        else:
            expr = g.expr(4, [])
        add("Q.%d" % i, guarded(expr), "random")


# ------------------------------------------------------------------ the step b review
# The rows of the step b review's probes (2026-10-10) that the C answers
# deterministically, by area. Each is run as `[exact]`: none names a rule
# that traversal order picks.
REVIEW_F1 = [
    # Left calls under a predicate in B's body: built by the C, which crashes
    # only when a match compiles some uses of them.
    ("D.lr.behind.0", 'return ltype(P{ "A", A = P"a" + B(#V"A" * "a") })'),
    ("D.lr.behind.1", 'return ltype(P{ "A", A = B(P"a" - V"A") })'),
    ("D.lr.behind.2", 'return ltype(P{ "S", S = V"A" + "z", A = B(#V"A" * "a") })'),
    ("D.lr.behind.3", 'return ltype(P{ "A", A = B(#V"A" * "a") + "x" }), ltype(P{ "A", A = C(B(-V"A" * "a")) })'),
    ("D.lr.behind.4", 'return ltype(P{ "A", A = V"C", C = B(#(V"A" * "b") * "c") })'),
]
REVIEW_F3 = [
    # The C's `int` size wraps to -3 or below: "block too big", unpositioned.
    ("A.size.p30p1", "return pcall(P, 2^30 + 1)"),
    ("A.size.p31m1", "return pcall(function() return P(2^31 - 1) end)"),
    ("A.size.m30", "return pcall(P, -(2^30))"),
    ("A.size.m30m1", "return pcall(P, -(2^30) - 1)"),
    ("A.size.p15e8", "return pcall(P, 1500000000)"),
    ("A.size.m15e8", "return pcall(P, -1500000000)"),
    ("F.size.a30", "return pcall(function() return P'a' ^ (2^30) end)"),
    ("F.size.e30", "return pcall(function() return P'' ^ (2^30) end)"),
    ("F.size.and31", "return pcall(function() return (#P'a') ^ (2^31 - 1) end)"),
    ("F.size.space28", "return pcall(function() return (R'\\33\\126' + V'space') ^ (2^28) end)"),
    ("F.size.am31", "return pcall(function() return P'a' ^ -(2^31 - 1) end)"),
    # Wrapped to 0: the check for an empty loop comes before the C's writes.
    ("F.size.e31", "return pcall(function() return P'' ^ (2^31 - 1) end)"),
    # A grammar of 300 rules of 2^23 - 1 nodes wraps negative; of 520,
    # past 2^32 to a positive size, and then the count is refused.
    ("D.size.300", "local p = P(2^22) local g = { 'r1' } for i = 1, 300 do g['r' .. i] = p end return pcall(P, g)"),
    ("D.size.520", "local p = P(2^22) local g = { 'r1' } for i = 1, 520 do g['r' .. i] = p end return pcall(P, g)"),
]


def review_rows():
    """The probe rows, from the review's files as committed below."""
    return REVIEW_INDEX + REVIEW_LOCALE + REVIEW_NAME


REVIEW_INDEX = [
    ("D.idx.nested", "local g = setmetatable({ 'S' }, { __index = setmetatable({}, { __index = function(t, k) return P'a' end }) }) return pcall(P, g)"),
    ("D.idx.nested2", "local inner = setmetatable({}, { __index = { S = P'a' } }) return pcall(P, setmetatable({ 'S' }, { __index = inner }))"),
    ("D.idx.num", "return pcall(P, setmetatable({ 'S' }, { __index = 5 }))"),
    ("D.idx.str", "return pcall(P, setmetatable({ 'S' }, { __index = 'str' }))"),
    ("D.idx.strlen", "return pcall(P, setmetatable({ 'len' }, { __index = 'str' }))"),
    ("D.idx.bool", "return pcall(P, setmetatable({ 'S' }, { __index = true }))"),
    ("D.idx.loop", "local t = { 'S' } setmetatable(t, { __index = t }) return pcall(P, t)"),
    ("D.idx.loop2", "local a = {} local b = setmetatable({}, { __index = a }) setmetatable(a, { __index = b }) return pcall(P, setmetatable({ 'S' }, { __index = a }))"),
    ("D.idx.rettable", "return pcall(P, setmetatable({ 'S' }, { __index = function() return { 'T', T = P'a' } end }))"),
    ("D.idx.retmulti", "return ltype(P(setmetatable({ 'S' }, { __index = function() return P'a', 5 end })))"),
    ("D.idx.retfalse", "return pcall(P, setmetatable({ 'S' }, { __index = function() return false end }))"),
    ("D.idx.retstr", "return pcall(P, setmetatable({ 'S' }, { __index = function() return 'abc' end }))"),
    ("D.idx.retfn", "return pcall(P, setmetatable({ 'S' }, { __index = function() return F end }))"),
    ("D.idx.addrule", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) rawset(t, 'T', P'b') return V'T' end }))"),
    ("D.idx.addbad", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) rawset(t, 'T', 7) return P'a' end }))"),
    ("D.idx.add300", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) for i = 1, 300 do rawset(t, 'r' .. i, P'x') end return P'a' end }))"),
    ("D.idx.add199", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) for i = 1, 199 do rawset(t, 'r' .. i, P'x') end return P'a' end }))"),
    ("D.idx.add200", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) for i = 1, 200 do rawset(t, 'r' .. i, P'x') end return P'a' end }))"),
    ("D.idx.setfirst", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) rawset(t, 1, 'Q') rawset(t, 'Q', 5) return P'a' end }))"),
    ("D.idx.unsetfirst", "return pcall(P, setmetatable({ 'S', T = P'b' }, { __index = function(t, k) rawset(t, 1, nil) return V'T' end }))"),
    ("D.idx.errlvl1", "return pcall(P, setmetatable({ 'S' }, { __index = function() error('boom') end }))"),
    ("D.idx.errlvl2", "return pcall(P, setmetatable({ 'S' }, { __index = function() error('boom', 2) end }))"),
    ("D.idx.errnil", "local ok, e = pcall(P, setmetatable({ 'S' }, { __index = function() error(nil) end })) return ok, e == nil"),
    ("D.idx.reenter", "return ltype(P(setmetatable({ 'S' }, { __index = function() return P(setmetatable({ 'T' }, { __index = function() return P'b' end })) end })))"),
    ("D.idx.args", "local n, a, b local g = setmetatable({ 2.5 }, { __index = function(...) n = select('#', ...) a, b = ... return P'a' end }) local p = P(g) return n, rawequal(a, g), b"),
    ("D.idx.op2", "return pcall(function() return P'x' + setmetatable({ 'S' }, { __index = function() error('e2', 0) end }) end)"),
    ("D.idx.op1", "return pcall(function() return setmetatable({ 'S' }, { __index = function() error('e1', 0) end }) * P'x' end)"),
    ("D.idx.both", "local log = {} local function g(n) return setmetatable({ n }, { __index = function(t, k) log[#log + 1] = k return P(k) end }) end local r = mt.__add(g'a', g'b') return table.concat(log, ','), ltype(r)"),
    ("D.idx.both2", "local log = {} local function g(n) return setmetatable({ n }, { __index = function(t, k) log[#log + 1] = k return P(k) end }) end local ok = pcall(mt.__sub, g'a', g'b') return table.concat(log, ','), ok"),
    ("D.idx.div", "return pcall(function() return setmetatable({ 'S' }, { __index = function() return P'a' end }) / 'x' end)"),
    ("D.idx.B", "return ltype(B(setmetatable({ 'S' }, { __index = function() return P'a' end })))"),
    ("D.idx.Cmtorder", "local n = 0 local ok, e = pcall(Cmt, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), 5) return ok, e, n"),
    ("D.idx.Cforder", "local n = 0 local ok, e = pcall(Cf, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), 5) return ok, e, n"),
    ("D.idx.Cgorder", "local n = 0 local ok, e = pcall(Cg, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), {}) return ok, e, n"),
    ("D.idx.poworder", "local n = 0 local ok, e = pcall(mt.__pow, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), 2) return ok, e, n"),
    ("D.idx.divorder", "local n = 0 local ok, e = pcall(mt.__div, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), true) return ok, e, n"),
    ("D.idx.divnumorder", "local n = 0 local ok, e = pcall(mt.__div, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end }), -1) return ok, e, n"),
    ("D.idx.ptree", "local n = 0 local ok, e = pcall(lpeg.ptree, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end })) return ok, e, n"),
    ("D.idx.pcode", "local n = 0 local ok, e = pcall(lpeg.pcode, setmetatable({ 'S' }, { __index = function() n = n + 1 return P'a' end })) return ok, e, n"),
    # Re-entry without end: the C's call depth stops it.
    ("D.idx.deep", "local d = 0 local function mk() return setmetatable({ 'S' }, { __index = function() d = d + 1 return P(mk()) end }) end local ok, e = pcall(P, mk()) return ok, e, d > 150"),
    ("D.idx.calltbl", "return pcall(P, setmetatable({ 'S' }, { __index = setmetatable({}, { __call = function() return P'a' end }) }))"),
    ("D.idx.pat", "return pcall(P, setmetatable({ 'S' }, { __index = P'x' }))"),
    ("D.idx.pat2", "return pcall(P, setmetatable({ 'nosuch' }, { __index = P'x' }))"),
    ("D.idx.lpeg", "return pcall(P, setmetatable({ 'version' }, { __index = lpeg }))"),
    ("D.idx.co", "return pcall(P, setmetatable({ 'S' }, { __index = co }))"),
    ("D.idx.fn2", "return pcall(P, setmetatable({ 'S' }, { __index = setmetatable({}, { __index = setmetatable({}, { __index = function(t, k) return P(k) end }) }) }))"),
    ("D.idx.rawget", "return pcall(P, setmetatable({ 'S' }, { __index = rawget }))"),
    ("D.idx.P", "return pcall(P, setmetatable({ 'S' }, { __index = P }))"),
    ("D.idx.V", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) return V(k) end }))"),
    ("D.idx.Pidx", "return pcall(P, setmetatable({ 'S' }, { __index = function(t, k) return P(t) end }))"),
    # Keys that do or do not convert to 1, and initial rules of every kind.
    ("D.key.s1", "return pcall(P, { 'S', S = P's', ['1'] = 5 })"),
    ("D.key.s1sp", "return pcall(P, { 'S', S = P's', [' 1 '] = 5 })"),
    ("D.key.s10", "return pcall(P, { 'S', S = P's', ['1.0'] = 5 })"),
    ("D.key.s0x1", "return pcall(P, { 'S', S = P's', ['0x1'] = 5 })"),
    ("D.key.s1e0", "return pcall(P, { 'S', S = P's', ['1e0'] = 5 })"),
    ("D.key.splus1", "return pcall(P, { 'S', S = P's', ['+1'] = 5 })"),
    ("D.key.s1nul", "return pcall(P, { 'S', S = P's', ['1\\0'] = 5 })"),
    ("D.key.sinf", "return pcall(P, { 'S', S = P's', ['inf'] = 5 })"),
    ("D.key.s0x1p0", "return pcall(P, { 'S', S = P's', ['0x1p0'] = 5 })"),
    ("D.key.s1dot", "return pcall(P, { 'S', S = P's', ['1.'] = 5 })"),
    ("D.key.sdot1", "return pcall(P, { 'S', S = P's', ['.1e1'] = 5 })"),
    ("D.key.stab", "return pcall(P, { 'S', S = P's', ['\\t1\\n'] = 5 })"),
    ("D.key.svt", "return pcall(P, { 'S', S = P's', ['\\v1\\f'] = 5 })"),
    ("D.key.s0001", "return pcall(P, { 'S', S = P's', ['0001'] = 5 })"),
    ("D.key.near1", "return pcall(P, { 'S', S = P's', [1 + 2^-52] = 5 })"),
    ("D.key.firstnum", "return pcall(P, { 2, [2] = P'a', ['2'] = 5 })"),
    ("D.key.firststr", "return pcall(P, { '2', ['2'] = P'a', [2] = 5 })"),
    ("D.first.f2p63", "return pcall(P, { 2^63 })"),
    ("D.first.negz", "return pcall(P, { -0.0 })"),
    ("D.first.mininteger", "return pcall(P, { math.mininteger })"),
    ("D.first.inf", "return pcall(P, { 1/0 })"),
    ("D.first.tbl", "return pcall(P, { {} })"),
    ("D.first.nul", "return pcall(P, { 'a\\0b' })"),
    ("D.first.long", "return pcall(P, { ('x'):rep(300) })"),
    ("D.first.pctname", "return pcall(P, { '%d%s' })"),
    ("D.first.pi", "return pcall(P, { math.pi, [math.pi] = 5 })"),
    ("D.first.big", "return pcall(P, { 2^53, [2^53] = 5 })"),
    ("D.first.rawnil", "return pcall(P, setmetatable({}, { __index = function() return 'S' end }))"),
    ("D.first.pat", "local a = P'a' local g = { a, x = V(1) } return ltype(P(g))"),
    ("D.first.used", "return pcall(P, { V(1) * 'a' })"),
    ("D.first.empty", "return pcall(P, { '', [''] = V'' })"),
    ("D.undef.pct", "return pcall(P, { 'S', S = V'%s%d' })"),
]
REVIEW_LOCALE = [
    ("I.loc.num", "return pcall(locale, setmetatable({}, { __newindex = 5 }))"),
    ("I.loc.str", "return pcall(locale, setmetatable({}, { __newindex = 'abc' }))"),
    ("I.loc.raw", "local log = {} local t = setmetatable({ alpha = 1, space = 2 }, { __newindex = function(t, k, v) log[#log + 1] = k rawset(t, k, v) end }) locale(t) return table.concat(log, ','), ltype(t.alpha), ltype(t.space)"),
    ("I.loc.errt", "local e0 = {} local ok, e = pcall(locale, setmetatable({}, { __newindex = function() error(e0) end })) return ok, rawequal(e, e0)"),
    ("I.loc.errlvl1", "return pcall(locale, setmetatable({}, { __newindex = function() error('x') end }))"),
    ("I.loc.loop", "local t = {} setmetatable(t, { __newindex = t }) return pcall(locale, t)"),
    ("I.loc.extra", "local t = {} return rawequal(locale(t, 5, 6), t), select('#', locale(t, 1))"),
    ("I.loc.nilextra", "return type(locale(nil, 5)), select('#', locale())"),
    ("I.loc.ret", "local t = setmetatable({}, { __newindex = function() return 1, 2, 3 end }) return rawequal(locale(t), t)"),
    ("I.loc.deep", "local d = 0 local function f(t, k, v) d = d + 1 locale(setmetatable({}, { __newindex = f })) end local ok, e = pcall(locale, setmetatable({}, { __newindex = f })) return ok, e, d > 150"),
    ("I.loc.mtkey", "local t = setmetatable({}, { __newindex = function(t, k, v) rawset(t, k, ltype(v)) end }) locale(t) return t.alnum, t.xdigit"),
    ("I.loc.calltbl", "local log = {} local t = setmetatable({}, { __newindex = setmetatable({}, { __call = function() log[#log+1] = 1 end }) }) locale(t) return #log, next(t) == nil"),
    ("I.loc.pat", "return pcall(locale, setmetatable({}, { __newindex = P'x' }))"),
    ("I.loc.P", "return pcall(locale, setmetatable({}, { __newindex = P }))"),
    ("I.loc.rawset", "local t = setmetatable({}, { __newindex = rawset }) locale(t) return ltype(t.alpha)"),
]
REVIEW_NAME = [
    # `__name` as `%s` prints it: up to its first NUL, byte for byte, from
    # any value's metatable in a type error.
    ("J.name.nul", "return kind(setmetatable({}, { __name = 'a\\0b' }))"),
    ("J.name.hi", "return kind(setmetatable({}, { __name = '\\255x' }))"),
    ("J.name.empty", "return kind(setmetatable({}, { __name = '' }))"),
    ("J.name.num", "return kind(setmetatable({}, { __name = 5 })), kind(setmetatable({}, { __name = true }))"),
    ("J.name.idx", "return kind(setmetatable({}, setmetatable({}, { __index = { __name = 'X' } })))"),
    # (Called from Lua, so that the stdlib's function is named as the C
    # names it; stdlib-bad-argument-naming.)
    ("J.name.te.nul", "return perr(function() return string.rep(setmetatable({}, { __name = 'a\\0b' }), 1) end)"),
    ("J.name.te.hi", "return perr(function() return string.rep(setmetatable({}, { __name = '\\255x' }), 1) end)"),
    ("J.name.te.num", "return perr(function() return string.rep(setmetatable({}, { __name = 5 }), 1) end)"),
    ("J.name.te.strmt", "local smt = getmetatable('') smt.__name = 'Str' local a, b = perr(function() return string.rep('x', 'y') end) smt.__name = nil return a, b"),
    ("J.name.te.strmt2", "local smt = getmetatable('') smt.__name = 'Str' local a, b = pcall(B, 'x', 'y') local c, d = pcall(Cmt, P'a', 'x') local e, f = pcall(locale, 'x') smt.__name = nil return a, b, c, d, e, f"),
    ("J.name.te.lpeg", "return pcall(Cf, P'a', Named), pcall(Cmt, P'a', setmetatable({}, { __name = 'a\\0b' })), pcall(locale, P'a'), pcall(Cb, Named)"),
    ("J.name.te.lpeg2", "return pcall(mt.__pow, Named, 1), pcall(mt.__pow, P'a', Named), pcall(B, Named), pcall(lpeg.pcode, Named)"),
]
REVIEW_UTILITY = [
    ("U06", 'return pcall(U.split, "a,b,,c", ",")'),
    ("U06b", 'return pcall(U.split, "a,b,,c", 5)'),
    ("U.anywhere", 'return ltype(U.anywhere(P"a")), ltype(U.localize({ V"alpha" })), ltype(U.atwordboundary(P"x"))'),
]


def sec_review():
    for cid, chunk in REVIEW_F1 + REVIEW_F3 + review_rows():
        add(cid, chunk, "[exact] review")
    # lpeg-utility.lua as nselib has it, loaded with lpeg and a stub stdnse
    # under a fixed chunk name: `split` with a string separator builds a
    # grammar whose `sep` rule is a string (U06).
    here = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
    with open(__import__("os").path.join(here, "../../../../../nselib/lpeg-utility.lua"), "rb") as fh:
        src = fh.read().hex()
    load = ('local src = ("%s"):gsub("%%x%%x", function(c) return string.char(tonumber(c, 16)) end) '
            'local env = setmetatable({ require = function(n) if n == "lpeg" then return lpeg '
            'elseif n == "stdnse" then return {} else return _G[n] end end }, { __index = _G }) '
            'local U = load(src, "@nselib/lpeg-utility.lua", "t", env)() ' % src)
    for cid, chunk in REVIEW_UTILITY:
        add("D." + cid, load + chunk, "[exact] review")


def main():
    sec_A()
    sec_B()
    sec_C()
    sec_D()
    sec_E()
    sec_F()
    sec_G()
    sec_H()
    sec_I()
    sec_J()
    sec_L()
    sec_M()
    sec_Z()
    sec_review()
    sec_Q(66, 3000)
    out = sys.stdout
    out.write("# M6.6 step b LPeg tree corpus: id<TAB>hex(chunk)<TAB>note. "
              "Generated by oracle/gen_m66b_trees.py; do not edit.\n")
    for cid, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (cid, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
