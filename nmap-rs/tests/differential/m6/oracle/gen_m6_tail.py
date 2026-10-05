#!/usr/bin/env python3
"""Emit the differential corpus for the tail of the standard library.

`core::nse::stdlib::base` binds `_G`, `rawequal`, `xpcall`, `load` and
`coroutine.wrap`, and `core::nse::stdlib::strrep` ports `string.rep`. The
oracle is nmap's own `liblua/`. The corpus reaches every decision in each:

  A. string.rep over strings (empty, one byte, NUL bytes, numbers) crossed
     with counts (negative, zero, small, every kind of non-integer and
     non-number) and separators (absent, nil, empty, NUL, number, table),
     plus the size limit: each side of `l + lsep > MAXSIZE / n`;
  B. rawequal over every pair from a pool of values chosen where equality is
     subtle -- integer vs float, the 2^53 and 2^63 edges, both zeroes, NaN,
     strings by content, references by identity -- and the argument checks;
  C. xpcall: what the protected function returns or raises, crossed with what
     the handler does (returns one value, several, none, raises), non-callable
     functions, callable tables, nesting, and the argument check;
  D. coroutine.wrap: values in and out of yields and returns (nil holes and
     varargs included), errors (strings, tables, after a yield), resuming a
     dead or running coroutine, and the argument check;
  E. load: text and binary chunks under every mode string, environments
     (absent, nil, a table, a number), chunk names of every shape and length
     around `luaO_chunkid`'s limits, syntax errors at known lines, and reader
     functions (pieces, numbers, empty-string and nil termination, bad
     returns, errors);
  F. _G.

Each row is `name<TAB>chunk_hex<TAB>note`. Chunks call the function under
test through `pcall` directly so that C adds no position prefix to an error
message, and compare every message byte for byte with two exceptions, both in
the open:

  * `'string.rep'` and `'coroutine.wrap'` become `'rep'` and `'wrap'` inside a
    chunk, because `luaL_argerror` names a function called by `pcall` by its
    global path and the binding always says the short name (DIVERGENCES.md,
    `tail-bad-argument-naming`);
  * a syntax error is compared on its `chunkid:line:` prefix only, and a
    binary chunk the mode allows on being refused -- the VM's compiler words
    its errors its own way, and the port never loads bytecode
    (`load-syntax-error-wording`, `load-never-loads-bytecode`).

Runtime errors raised by the VM itself ("attempt to index a nil value") are
kept out of the corpus. When it was written, the vendored VM handed them to
`pcall` as a userdata (`vm-runtime-errors-are-not-strings`). M6.4a closed
that, and `m64_errors_cases.txt` now covers them against `liblua/`.
"""
from __future__ import annotations

import sys

CASES: list[tuple[str, str, str]] = []
_seen: set[str] = set()

# Rewrites an argument error's function name to the binding's, then returns
# every value unchanged otherwise. `R(pcall(f, ...))` keeps the count.
PROLOGUE = r"""
local function fix(v)
  if type(v) == "string" then
    v = v:gsub("'string%.rep'", "'rep'")
    v = v:gsub("'coroutine%.wrap'", "'wrap'")
  end
  return v
end
local function R(...)
  local t = table.pack(...)
  for i = 1, t.n do t[i] = fix(t[i]) end
  return t.n, table.unpack(t, 1, t.n)
end
"""


def add(name: str, chunk: str, note: str) -> None:
    if name in _seen:
        raise SystemExit("duplicate case name: %s" % name)
    _seen.add(name)
    if "\t" in note or "\n" in note:
        raise SystemExit("note for %s contains a field separator" % name)
    CASES.append((name, PROLOGUE + chunk, note))


def lua_str(b: bytes) -> str:
    """A Lua string literal for any bytes."""
    out = []
    for c in b:
        ch = chr(c)
        if ch.isalnum() or ch in " _-.,:;!?()[]{}<>=+*/%&|^~#@$'":
            out.append(ch)
        else:
            out.append("\\%03d" % c)
    return '"' + "".join(out) + '"'


# --------------------------------------------------------------------------
# A. string.rep

MAXSIZE = 2**31 - 1
# Results longer than this are not built: the corpus checks sizes, not bulk.
BIG = 1 << 16

REP_STRINGS = [
    ("empty", '""', b""),
    ("x", '"x"', b"x"),
    ("ab", '"ab"', b"ab"),
    ("nul", '"a\\0b"', b"a\x00b"),
    ("int", "12", b"12"),
    ("float", "1.5", b"1.5"),
    ("negzero", "-0.0", b"-0.0"),
]

REP_COUNTS = [
    ("min", "math.mininteger", -(2**63)),
    ("m1", "-1", -1),
    ("zero", "0", 0),
    ("one", "1", 1),
    ("two", "2", 2),
    ("three", "3", 3),
    ("seventeen", "17", 17),
    ("f3", "3.0", 3),
    ("fneg", "-2.0", -2),
    ("s2", '"2"', 2),
    ("s_sp", '" 3 "', 3),
    ("shex", '"0x4"', 4),
    ("sfl", '"2.0"', 2),
]
# Counts that are always an error, whatever the string.
REP_BAD_COUNTS = [
    ("f35", "3.5"),
    ("inf", "1/0"),
    ("nan", "0/0"),
    ("f2_63", "2^63"),
    ("sabc", '"abc"'),
    ("s35", '"3.5"'),
    ("nil", "nil"),
    ("tbl", "{}"),
    ("bool", "true"),
    ("none", None),
]

REP_SEPS = [
    ("nosep", None, b""),
    ("nilsep", "nil", b""),
    ("emptysep", '""', b""),
    ("comma", '", "', b", "),
    ("nulsep", '"\\0"', b"\x00"),
    ("numsep", "0", b"0"),
]


def gen_rep() -> None:
    for sn, sl, sb in REP_STRINGS:
        for cn, cl, cv in REP_COUNTS:
            for pn, pl, pb in REP_SEPS:
                args = [sl, cl] + ([pl] if pl is not None else [])
                add(
                    "rep_%s_%s_%s" % (sn, cn, pn),
                    "return R(pcall(string.rep, %s))" % ", ".join(args),
                    "string.rep value",
                )
        batch = []
        for cn, cl in REP_BAD_COUNTS:
            args = [sl] + ([cl] if cl is not None else [])
            batch.append("R(pcall(string.rep, %s))" % ", ".join(args))
        add(
            "rep_badcount_%s" % sn,
            "local t = {}\n"
            + "".join("t[#t+1] = select(3, %s)\n" % b for b in batch)
            + "return table.unpack(t)",
            "string.rep count errors",
        )
    # Bad strings and separators.
    for name, args in [
        ("s_nil", "nil, 1"),
        ("s_tbl", "{}, 1"),
        ("s_bool", "true, 1"),
        ("s_none", ""),
        ("sep_tbl", '"a", 2, {}'),
        ("sep_bool", '"a", 2, false'),
        ("sep_tbl_n0", '"a", 0, {}'),
        ("s_tbl_n0", "{}, 0"),
        ("method", '("ab"):rep(2, "-")'),
    ]:
        if name == "method":
            add("rep_" + name, "return R(%s)" % args, "string.rep as a method")
        else:
            call = "pcall(string.rep, %s)" % args if args else "pcall(string.rep)"
            add("rep_" + name, "return R(%s)" % call, "string.rep argument check")

    # The size limit: unit = len(s) + len(sep); refused iff unit > MAXSIZE // n.
    # Only refused calls and small results are run; a call the C accepts with a
    # gigabyte-sized result would allocate it.
    rows = []
    for slen in [0, 1, 2, 3, 7, 1000]:
        for seplen in [0, 1, 5]:
            unit = slen + seplen
            if unit == 0:
                continue
            for n in sorted({MAXSIZE // unit, MAXSIZE // unit + 1, MAXSIZE, MAXSIZE + 1,
                             2**31, 2**32, 2**62, 2**63 - 1}):
                refused = unit > MAXSIZE // n
                total = slen * n + seplen * (n - 1)
                if not refused and total > BIG:
                    continue
                rows.append((slen, seplen, n))
    for slen, seplen, n in rows:
        add(
            "rep_limit_%d_%d_%d" % (slen, seplen, n),
            'local ok, r = pcall(string.rep, ("s"):rep(%d), %d, ("p"):rep(%d))\n'
            "if ok then return ok, #r end return ok, r" % (slen, n, seplen),
            "string.rep size limit",
        )
    # Empty unit, any count: the C loops n times; keep n small enough to finish.
    for n in [1, 2, 1000, 1 << 20]:
        add("rep_emptyunit_%d" % n, 'return #string.rep("", %d), #string.rep("", %d, "")' % (n, n),
            "string.rep empty result")
    add("rep_emptyunit_huge_sep", 'return pcall(string.rep, "", math.maxinteger, "x")',
        "string.rep: empty string, non-empty separator, huge count")
    add("rep_content", 'local r = string.rep("ab\\0", 5, "|") return r, #r', "string.rep content")


# --------------------------------------------------------------------------
# B. rawequal

RAW_POOL = [
    "nil", "true", "false", "0", "-0.0", "0.0", "1", "1.0", "-1", "-1.0",
    "2^53", "(1 << 53)", "(1 << 53) + 1", "2^63", "math.maxinteger",
    "math.maxinteger + 0.0", "math.mininteger", "-2^63", "1/0", "-1/0", "0/0",
    '""', '"a"', '"1"', '"a\\0b"', "T", "U", "F", "G", "CO", "print_or_nil",
    "1e300", "0.5",
]
RAW_SETUP = """
local T, U = {}, {}
local F = function() end
local G = function() end
local CO = coroutine.create(F)
local print_or_nil = tostring
local S = setmetatable({}, {__eq = function() return true end})
"""


def gen_rawequal() -> None:
    for i, a in enumerate(RAW_POOL):
        body = RAW_SETUP + "return " + ", ".join(
            "rawequal(%s, %s)" % (a, b) for b in RAW_POOL
        )
        add("rawequal_row_%02d" % i, body, "rawequal %s against the pool" % a)
    add("rawequal_self", RAW_SETUP + "local x = T return rawequal(x, T), rawequal(S, S), "
        "rawequal(S, setmetatable({}, getmetatable(S))), S == setmetatable({}, getmetatable(S))",
        "rawequal ignores __eq")
    add("rawequal_strings_built", 'local a = "ab" .. "c" local b = "a" .. "bc" return rawequal(a, b), '
        'rawequal(("x"):rep(100), ("x"):rep(50) .. ("x"):rep(50))', "rawequal on built strings")
    add("rawequal_extra_args", "return rawequal(1, 1, 2), rawequal(1, 2, 1)", "rawequal ignores extras")
    for name, args in [("none", ""), ("one", "1"), ("one_nil", "nil")]:
        add("rawequal_args_" + name, "return R(pcall(rawequal%s))" % (", " + args if args else ""),
            "rawequal argument check")
    add("rawequal_nil_nil", "return rawequal(nil, nil)", "rawequal explicit nils")


# --------------------------------------------------------------------------
# C. xpcall

XP_FUNCS = [
    ("ret_none", "function() end"),
    ("ret_one", "function() return 1 end"),
    ("ret_many", "function() return 1, nil, 'three' end"),
    ("ret_args", "function(...) return select('#', ...), ... end"),
    ("err_str", "function() error('boom', 0) end"),
    ("err_tbl", "function() error(ET) end"),
    ("err_nil", "function() error(nil) end"),
    ("err_num", "function() error(42) end"),
    ("err_false", "function() error(false) end"),
    ("err_after_pcall", "function() pcall(error, 'inner') error('outer', 0) end"),
    ("nested_xpcall", "function() return xpcall(error, function(e) return 'in:' .. tostring(e) end, 'z', 0) end"),
    ("nil", "nil"),
    ("number", "42"),
    ("string", "'str'"),
    ("plain_table", "{}"),
    ("callable", "setmetatable({}, {__call = function(self, ...) return 'called', select('#', ...) end})"),
]
XP_HANDLERS = [
    ("h_tag", "function(e) return 'H:' .. tostring(e) end"),
    ("h_type", "function(e) return type(e) end"),
    ("h_many", "function(e) return 1, 2, 3 end"),
    ("h_none", "function(e) end"),
    ("h_ident", "function(e) return e end"),
    ("h_raises", "function(e) error('in handler', 0) end"),
    ("h_raises_tbl", "function(e) error({}) end"),
    ("h_nargs", "function(...) return select('#', ...) end"),
]
XP_SETUP = "local ET = setmetatable({}, {__tostring = function() return 'ET' end})\n"


def gen_xpcall() -> None:
    for fn, f in XP_FUNCS:
        for hn, h in XP_HANDLERS:
            add(
                "xpcall_%s_%s" % (fn, hn),
                XP_SETUP + "local function show(...) local t = table.pack(...) for i = 1, t.n do "
                "if type(t[i]) == 'table' then t[i] = tostring(t[i]) end end "
                "return t.n, table.unpack(t, 1, t.n) end\n"
                "return show(xpcall(%s, %s, 'a', nil, 3))" % (f, h),
                "xpcall",
            )
    for name, args in [
        ("no_handler", "function() end"),
        ("nil_handler", "function() end, nil"),
        ("num_handler", "function() end, 1"),
        ("tbl_handler", "function() end, {}"),
        ("callable_handler", "function() end, setmetatable({}, {__call = function() end})"),
        ("none", ""),
    ]:
        add("xpcall_args_" + name, "return R(pcall(xpcall%s))" % (", " + args if args else ""),
            "xpcall argument check")
    add("xpcall_in_coroutine",
        "local co = coroutine.create(function() return xpcall(function() "
        "local v = coroutine.yield(1) error(v, 0) end, function(e) return 'H:' .. e end) end)\n"
        "local a, b = coroutine.resume(co) local c, d, e = coroutine.resume(co, 'sent') return a, b, c, d, e",
        "xpcall across a yield in the protected function")
    add("xpcall_deep",
        "local function f(n) if n == 0 then error('deep', 0) end return f(n - 1) end\n"
        "return xpcall(f, function(e) return e .. '!' end, 100)",
        "xpcall of a deep error")
    for k in [1, 2, 3, 10, 100]:
        add("xpcall_handler_fails_%d_times" % k,
            "local n = 0\nreturn xpcall(error, function(e) n = n + 1 if n <= %d then error('again' .. n, 0) end "
            "return 'H' .. n .. ':' .. tostring(e) end, 'x', 0)" % k,
            "an error in the handler goes back through the handler")
    add("xpcall_handler_fails_with_table",
        "local n = 0 return xpcall(error, function(e) n = n + 1 if n == 1 then error({}) end return type(e) end, 'x', 0)",
        "a table raised in the handler goes back through the handler")
    add("xpcall_handler_always_fails",
        "local n = 0 local ok, e = xpcall(error, function(e) n = n + 1 error(e, 0) end, 'x', 0) return ok, e, n > 100",
        "a handler that never returns")
    add("xpcall_handler_sees_value",
        "local seen return xpcall(error, function(e) seen = e return 'h' end, 'v', 0), seen",
        "xpcall handler argument")


# --------------------------------------------------------------------------
# D. coroutine.wrap

WRAP_CASES = [
    ("gen", "local function gen(n) return coroutine.wrap(function() for i = 1, n do coroutine.yield(i) end end) end\n"
            "local t = {} for v in gen(10) do t[#t+1] = v end return #t, table.concat(t, ',')"),
    ("in_out", "local w = coroutine.wrap(function(a) local b = coroutine.yield(a + 1) local c, d = coroutine.yield(b * 2) return c, d, 'end' end)\n"
               "return w(1), w(10), w('x', 'y')"),
    ("varargs", "local w = coroutine.wrap(function(...) local n = select('#', ...) local r = table.pack(coroutine.yield(n, ...)) return r.n, table.unpack(r, 1, r.n) end)\n"
                "local a = table.pack(w(nil, 2, nil)) local b = table.pack(w(nil, nil)) return a.n, a[1], a[3], b.n, b[1], b[2], b[3]"),
    ("return_none", "local w = coroutine.wrap(function() end) return select('#', w())"),
    ("yield_none", "local w = coroutine.wrap(function() coroutine.yield() return 1 end) return select('#', w()), w()"),
    ("dead", "local w = coroutine.wrap(function() return 1 end) w() return R(pcall(w))"),
    ("dead_twice", "local w = coroutine.wrap(function() return 1 end) w() pcall(w) return R(pcall(w))"),
    ("err_str", "local w = coroutine.wrap(function() error('inner', 0) end) return R(pcall(w))"),
    ("err_str_after_yield", "local w = coroutine.wrap(function() coroutine.yield(1) error('late', 0) end) return w(), R(pcall(w))"),
    ("err_tbl", "local E = {} local w = coroutine.wrap(function() error(E) end) local ok, e = pcall(w) return ok, e == E"),
    ("err_nil", "local w = coroutine.wrap(function() error(nil) end) return R(pcall(w))"),
    ("err_num", "local w = coroutine.wrap(function() error(7) end) return R(pcall(w))"),
    ("dead_after_err", "local w = coroutine.wrap(function() error('x', 0) end) pcall(w) return R(pcall(w))"),
    ("running", "local w w = coroutine.wrap(function() return R(pcall(w)) end) return w()"),
    ("nested", "local outer = coroutine.wrap(function() local inner = coroutine.wrap(function() coroutine.yield('i1') return 'i2' end)\n"
               "coroutine.yield(inner()) coroutine.yield(inner()) return 'o' end) return outer(), outer(), outer()"),
    ("yield_through", "local co = coroutine.create(function() local w = coroutine.wrap(function() coroutine.yield('w') return 'wdone' end)\n"
                      "local a = w() local b = coroutine.yield(a) return b, w() end)\n"
                      "local r1 = table.pack(coroutine.resume(co)) local r2 = table.pack(coroutine.resume(co, 'back'))\n"
                      "return r1.n, r1[1], r1[2], r2.n, r2[1], r2[2], r2[3]"),
    ("status_inside", "local w = coroutine.wrap(function() local co, main = coroutine.running() return coroutine.status(co), main end) return w()"),
    ("type", "return type(coroutine.wrap(function() end))"),
    ("tail_running", "local w = coroutine.wrap(function() local c, m = coroutine.running() return m end) return w()"),
    ("tail_yield", "local w = coroutine.wrap(function() coroutine.yield('y') return 'r' end) local function f() return w() end\n"
                   "local a = f() local b = f() return a, b"),
    ("tail_yield_main", "local w = coroutine.wrap(function() coroutine.yield('first') return 'second' end) return w()"),
    ("callable_table", "return R(pcall(coroutine.wrap, setmetatable({}, {__call = function() end})))"),
    ("many_values", "local w = coroutine.wrap(function(...) return ... end) local t = {} for i = 1, 200 do t[i] = i end\n"
                    "return select('#', w(table.unpack(t))), select(200, w(table.unpack(t)))"),
    ("resume_after_return", "local w = coroutine.wrap(function() return 'only' end) local a = w() local ok, e = pcall(w) local ok2, e2 = pcall(w) return a, ok, fix(e), ok2, fix(e2)"),
    ("create_vs_wrap", "local f = function(a) return coroutine.yield(a) end local w = coroutine.wrap(f) local co = coroutine.create(f)\n"
                       "return w(1), select(2, coroutine.resume(co, 1)), w(2), select(2, coroutine.resume(co, 2))"),
]


def gen_wrap() -> None:
    for name, body in WRAP_CASES:
        add("wrap_" + name, body, "coroutine.wrap")
    for name, args in [("none", ""), ("nil", "nil"), ("num", "1"), ("str", "'f'"), ("tbl", "{}")]:
        add("wrap_args_" + name, "return R(pcall(coroutine.wrap%s))" % (", " + args if args else ""),
            "coroutine.wrap argument check")


# --------------------------------------------------------------------------
# E. load

MODES = [None, "nil", '""', '"t"', '"b"', '"bt"', '"tb"', '"x"', '"tx"', '"bbb"', '"t\\0b"', '"b\\0t"', "1"]


def prefix_of(expr: str) -> str:
    # The `chunkid:line:` prefix of a load error, or the whole value if none.
    return "local f, e = %s if f then return 'loaded' end return (e:match('^(.-:%%d+:)') or e)" % expr


def gen_load() -> None:
    # Modes over text and binary chunks.
    for i, m in enumerate(MODES):
        mode_args = "" if m is None else ", nil, " + m
        add("load_mode_%02d_text" % i,
            "local f, e = load('return 7'%s) if f then return f() end return f, e" % mode_args,
            "load mode against a text chunk")
        add("load_mode_%02d_binary" % i,
            "local f, e = load('\\27Lua'%s) return f, (e:find('(mode is', 1, true) and e or 'refused')" % mode_args,
            "load mode against a binary chunk")
    add("load_binary_empty_after_sig", "local f, e = load('\\27') return f == nil, type(e)", "a lone signature byte")
    add("load_binary_like_later", "local f, e = load(' \\27') return f == nil, (e:match('^(.-:%d+:)'))",
        "ESC not first is text")

    # Environments.
    envs = [
        ("absent", "load(SRC)"),
        ("nil", "load(SRC, 'c', 't', nil)"),
        ("table", "load(SRC, 'c', 't', {x = 5, tostring = tostring})"),
        ("number", "load(SRC, 'c', 't', 5)"),
        ("globals", "load(SRC, 'c', 't', _G)"),
    ]
    sources = [
        ("const", "return 1, 2"),
        ("varargs", "return ..."),
        ("global_x", "return x"),
        ("set_global", "y_from_load = 9 return y_from_load"),
    ]
    for en, ex in envs:
        for sn, src in sources:
            # Globals through a nil or number environment raise a VM runtime
            # error, which this VM does not deliver as a string; skip those.
            if en in ("nil", "number") and sn in ("global_x", "set_global"):
                continue
            add("load_env_%s_%s" % (en, sn),
                "x = 'global x' y_from_load = nil\nlocal f = assert(%s)\n"
                "local r = table.pack(f('a', nil)) return r.n, table.unpack(r, 1, r.n), rawget(_G, 'y_from_load')"
                % ex.replace("SRC", repr(src).replace("\\'", "'")),
                "load environment")
    add("load_env_isolated", "local env = {} local f = load('z = 3 return z', 'c', 't', env) "
        "return f(), env.z, rawget(_G, 'z')", "load writes the given environment")
    add("load_env_shared", "local env = {} load('n = 1', 'c', 't', env)() load('n = n + 1', 'c', 't', env)() return env.n",
        "two chunks share an environment")
    add("load_env_upvalue_only", "local f = load('local a = 1 return a', 'c', 't', 5) return f()",
        "a chunk that never touches _ENV")
    add("load_returns_one", "return select('#', load('return 1'))", "load returns the function alone")
    add("load_fresh_each_time", "local a, b = load('return 1'), load('return 1') return a == b, a() == b()",
        "two loads, two functions")
    add("load_g_inside", "return load('return _G')() == _G", "_G seen from a loaded chunk")

    # Chunk names, through a syntax error's prefix.
    names = [
        ("eq_empty", '"="'), ("eq_short", '"=abc"'),
        ("eq_58", '"=" .. ("y"):rep(58)'), ("eq_59", '"=" .. ("y"):rep(59)'),
        ("eq_60", '"=" .. ("y"):rep(60)'), ("eq_200", '"=" .. ("y"):rep(200)'),
        ("eq_nul", '"=ab\\0cd"'), ("eq_nl", '"=ab\\ncd"'),
        ("at_empty", '"@"'), ("at_short", '"@file.lua"'),
        ("at_58", '"@" .. ("a"):rep(57) .. "Z"'), ("at_59", '"@" .. ("a"):rep(58) .. "Z"'),
        ("at_60", '"@" .. ("a"):rep(59) .. "Z"'), ("at_61", '"@" .. ("a"):rep(60) .. "Z"'),
        ("at_200", '"@" .. ("0123456789"):rep(20)'), ("at_nul", '"@ab\\0cd"'),
        ("str_empty", '""'), ("str_short", '"src"'),
        ("str_43", '("s"):rep(43)'), ("str_44", '("s"):rep(44)'),
        ("str_45", '("s"):rep(45)'), ("str_46", '("s"):rep(46)'), ("str_200", '("s"):rep(200)'),
        ("str_nl", '"ab\\ncd"'), ("str_nl_first", '"\\nab"'), ("str_long_nl", '("s"):rep(50) .. "\\nx"'),
        ("str_cr", '"ab\\rcd"'), ("str_nul", '"ab\\0cd"'), ("str_nul_nl", '"ab\\0c\\nd"'),
        ("str_quote", '"a\\"b"'), ("num", "42"), ("float", "1.5"),
    ]
    for n, expr in names:
        add("load_name_" + n, prefix_of("load('(', %s)" % expr), "chunk name in an error")
    add("load_name_default_short", prefix_of("load('return +')"), "the chunk text names itself")
    add("load_name_default_long", prefix_of("load(('-'):rep(0) .. 'return 1 +' .. (' '):rep(60))"),
        "a long chunk text names itself, cut")
    add("load_name_default_nl", prefix_of("load('local a = 1\\nreturn +')"), "a multi-line chunk names its first line")
    add("load_name_bad", "return R(pcall(load, 'x', {}))", "a chunk name of the wrong type")
    add("load_mode_bad_type", "return R(pcall(load, 'x', nil, {}))", "a mode of the wrong type")

    # Syntax errors: the line in the prefix.
    syntax = [
        ("eof", "return 1 +"), ("paren", "("), ("line3", "local a = 1\nlocal b = 2\nreturn a +"),
        ("line5_token", "x = \n\n\n\n 1 1"), ("unfinished_str", "return 'abc"),
        ("unfinished_long", "return [[abc\n\n"), ("bad_escape", "return '\\q'"),
        ("bad_number", "return 3x"), ("goto", "goto nowhere"), ("break_outside", "break"),
        ("assign_call", "f() = 1"), ("crlf", "a = 1\r\nb = 2\r\nreturn +"),
        ("blank_lines", "\n\n\n\n\n\n\n\n\n("), ("comment_then", "-- c\n--[[ x\n y ]]\n)"),
        ("end_missing", "if true then\nreturn 1\n"), ("dup_label", "::a:: ::a::"),
        ("big_line", "\n" * 300 + "+"),
    ]
    for n, src in syntax:
        add("load_syntax_" + n, prefix_of("load(%s)" % lua_str(src.encode())), "syntax error line")

    # Valid chunks of every kind still load and run.
    valid = [
        ("closure", "local a = 1 return function() a = a + 1 return a end"),
        ("loop", "local s = 0 for i = 1, 10 do s = s + i end return s"),
        ("goto_ok", "do goto e end ::e:: return 'e'"),
        ("shebang_text", "return '#!'"),
        ("long_string", "return [==[a]]b]==]"),
        ("int_div", "return 7 // 2, 7.0 // 2, 2^2"),
    ]
    for n, src in valid:
        add("load_valid_" + n, "local f = assert(load(%s)) local r = f() if type(r) == 'function' then return r(), r() end "
            "return f()" % lua_str(src.encode()), "load of a valid chunk")
    add("load_numeric_chunk", prefix_of("load(42)"), "a number is converted to a string chunk")
    add("load_numeric_ok", "return load(42, '=n') == nil", "a number chunk is text")

    # Readers.
    readers = [
        ("pieces", "{'return ', '4', '2'}"),
        ("numbers", "{'return ', 4, 2.5}"),
        ("empty_stops", "{'return 1', '', '+ 1'}"),
        ("nil_first", "{}"),
        ("one_byte_each", "{'r','e','t','u','r','n',' ','7'}"),
        ("syntax", "{'return ', '+'}"),
        ("multiline", "{'local a = 1\\n', 'local b = 2\\n', 'return a + b'}"),
    ]
    for n, parts in readers:
        add("load_reader_" + n,
            "local parts = %s local i = 0 local calls = 0\n"
            "local f, e = load(function() calls = calls + 1 i = i + 1 return parts[i] end)\n"
            "if f then return 'f', calls, f() end return f, (type(e) == 'string' and (e:match('^(.-:%%d+:)') or e) or e), calls"
            % parts, "load from a reader function")
    for n, ret in [("table", "{}"), ("bool", "true"), ("func", "print or tostring")]:
        add("load_reader_bad_" + n,
            "local f, e = load(function() return %s end) return f, (e:gsub('^chunk:%%d+: ', ''))" % ret,
            "a reader returning a non-string")
    add("load_reader_err_str", "return R(load(function() error('r', 0) end))", "a reader that raises a string")
    add("load_reader_err_tbl", "local E = {} local f, e = load(function() error(E) end) return f, e == E",
        "a reader that raises a table")
    add("load_reader_err_late", "local n = 0 return R(load(function() n = n + 1 if n == 2 then error('late', 0) end return 'return 1' end))",
        "a reader that raises after a piece")
    add("load_reader_binary_mode_t",
        "local i = 0 return R(load(function() i = i + 1 return ({'\\27', 'Lua'})[i] end, 'c', 't'))",
        "a reader's binary chunk under mode 't'")
    add("load_reader_binary",
        "local i = 0 local f, e = load(function() i = i + 1 return ({'\\27', 'Lua'})[i] end) "
        "return f, (e:find('(mode is', 1, true) and e or 'refused')",
        "a reader's binary chunk, refused")
    add("load_reader_name", prefix_of("load(function() return nil end, '=rdr')"), "a reader's chunk name")
    add("load_reader_default_name",
        "local i = 0 local f, e = load(function() i = i + 1 return ({'(', nil})[i] end) return (e:match('^(.-:%d+:)'))",
        "a reader's default chunk name")
    add("load_reader_mode",
        "local i = 0 return R(load(function() i = i + 1 return ({'return 1'})[i] end, 'c', 'b'))",
        "a reader under a mode that refuses text")
    add("load_reader_env",
        "local i = 0 local f = load(function() i = i + 1 return ({'return x'})[i] end, 'c', 't', {x = 'env x'}) return f()",
        "a reader with an environment")
    for n, args in [("none", ""), ("nil", "nil"), ("table", "{}"), ("bool", "true")]:
        add("load_args_" + n, "return R(pcall(load%s))" % (", " + args if args else ""), "load argument check")


# --------------------------------------------------------------------------
# F. _G

def gen_g() -> None:
    add("g_self", "return _G == _G._G, _G._G._G == _G, type(_G), rawget(_G, '_G') == _G", "_G._G is _G")
    add("g_assign", "_G.via_g = 5 return via_g", "_G is the globals table")
    add("g_lookup", "return _G.string == string, _G['rawequal'] == rawequal, _G.load == load, _G.xpcall == xpcall",
        "_G holds the globals")
    add("g_rebind", "local old = _G _G = 1 local r = old._G return r, old.rawequal ~= nil", "_G is an ordinary global")


def main() -> None:
    gen_rep()
    gen_rawequal()
    gen_xpcall()
    gen_wrap()
    gen_load()
    gen_g()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m6_tail.py; regenerate with ./regen_m6_tail.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
