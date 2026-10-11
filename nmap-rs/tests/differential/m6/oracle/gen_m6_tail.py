#!/usr/bin/env python3
"""Emit the differential corpus for the tail of the standard library.

`core::nse::stdlib::base` binds the base library (`lbaselib.c`), the
coroutine library (`lcorolib.c`), `string.char`, the string metatable's
arithmetic and the argument checks of `table.insert`, `table.remove` and
`table.concat`, and `core::nse::stdlib::strrep` ports `string.rep`. The
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
  F. _G;
  G. the rest of the base library: `pcall`, `rawlen`/`rawget`/`rawset`,
     `next`/`pairs`/`ipairs`, `select`, `type`, `tostring`, `tonumber`,
     `getmetatable`/`setmetatable`, `collectgarbage`, `assert`, `error`,
     `warn` -- each over a pool of argument kinds (none, nil, booleans,
     numbers, strings, tables with and without a `__name`, functions,
     threads), and each decision of the C (protected metatables, `__pairs`
     truncated and padded to three, `ipairs` through `__index`, `tostring`'s
     `__tostring` results, `b_str2int`'s numerals in every base, `select`'s
     ranges, `error`'s levels, `collectgarbage`'s options with the state they
     change put back);
  H. the coroutine library: `create`, `resume`, `status` (`normal`
     included), `isyieldable`, `running`, `close` (suspended, dead, dead of an
     error and closed twice, running, normal), and `wrap`'s positioned errors;
  I. `string.char` and the string metatable's arithmetic metamethods called
     directly, over numeric and other strings, numbers, absent arguments and
     a table's own metamethod;
  J. the argument checks of `table.insert`, `table.remove` and
     `table.concat`.

Each row is `name<TAB>chunk_hex<TAB>note`. Chunks call the function under
test through `pcall` directly so that C adds no position prefix to an error
message, or from a Lua function to pin the position it adds, and compare
every message byte for byte with two exceptions, both in the open:

  * `'string.X'`, `'coroutine.X'` and `'table.X'` become `'X'` inside a
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
    v = v:gsub("'string%.(%a+)'", "'%1'")
    v = v:gsub("'coroutine%.(%a+)'", "'%1'"):gsub("'table%.(%a+)'", "'%1'")
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
    add("load_reader_bad_positioned", "return load(function() return {} end)",
        "generic_reader's error carries load's caller's position")
    add("load_reader_bad_nested", "local function f() return load(function() return true end) end return f()",
        "generic_reader's error carries load's caller's position")
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


# --------------------------------------------------------------------------
# G. the rest of the base library

# Argument kinds: (name, Lua expression or None for no argument at all). The
# references render as `table:<table>` and so on, never as addresses.
POOL = [
    ("none", None),
    ("nil", "nil"),
    ("false", "false"),
    ("true", "true"),
    ("int", "7"),
    ("float", "2.5"),
    ("str", '"s"'),
    ("numstr", '"10"'),
    ("table", "{}"),
    ("named", 'setmetatable({}, {__name = "Named"})'),
    ("func", "function() end"),
    ("thread", "coroutine.create(function() end)"),
]


def args(*parts: str | None) -> str:
    """`, a, b` for the arguments that are there (a `None` ends the list)."""
    out = []
    for p in parts:
        if p is None:
            break
        out.append(p)
    return "".join(", " + a for a in out)


def gen_base() -> None:
    for fn in ["type", "rawlen", "getmetatable", "tostring", "next", "pairs", "ipairs",
               "setmetatable", "rawget", "select", "assert", "tonumber"]:
        for pn, pv in POOL:
            add("base_arg_%s_%s" % (fn, pn),
                "return R(pcall(function(...) local t = table.pack(%s(...)) "
                "for i = 1, t.n do local v = t[i] if type(v) == 'string' and v:match('^%%a+: ') "
                "then t[i] = v:match('^(%%a+): ') end end return table.unpack(t, 1, t.n) end%s))"
                % (fn, args(pv)),
                "%s of each kind of argument" % fn)
    # Positioned: called from a Lua function, an argument error carries its
    # caller's position, as `luaL_where(L, 1)` gives it.
    for name, call in [
        ("rawlen", "rawlen(5)"), ("rawget", "rawget(5, 1)"), ("rawset", "rawset({}, 1)"),
        ("type", "type()"), ("select", "select(0)"), ("next", "next()"),
        ("pairs", "pairs()"), ("ipairs", "ipairs()"), ("tostring", "tostring()"),
        ("tonumber", "tonumber()"), ("tonumber_base", "tonumber('1', 99)"),
        ("getmetatable", "getmetatable()"), ("setmetatable", "setmetatable({}, 1)"),
        ("protected", "setmetatable(setmetatable({}, {__metatable = 1}), {})"),
        ("assert", "assert(false, 'msg')"), ("assert_default", "assert(nil)"),
        ("error_level", "error('e', {})"), ("collectgarbage", "collectgarbage('x')"),
        ("warn", "warn()"), ("pcall", "pcall()"), ("xpcall", "xpcall(print)"),
        ("tostring_result", "tostring(setmetatable({}, {__tostring = function() return true end}))"),
        ("load", "load({})"),
    ]:
        add("base_positioned_" + name,
            "local function f()\n  return %s\nend\nreturn R(pcall(f))" % call,
            "an error raised for a Lua caller has its position")
        add("base_escaped_" + name, "return %s" % call,
            "an error that escapes the chunk, position and all")

    # rawlen, rawget, rawset
    for name, body in [
        ("rawlen_holes", "local t = {1, 2, 3} return rawlen(t), rawlen(''), rawlen('a\\0b')"),
        ("rawlen_lenmt", "return rawlen(setmetatable({1, 2}, {__len = function() return 9 end}))"),
        ("rawget_index", "local t = setmetatable({}, {__index = function() return 'mm' end}) return rawget(t, 1), t[1]"),
        ("rawget_keys", "local t = {10, 20, x = 'x'} return rawget(t, 1.0), rawget(t, 'x'), rawget(t, 0/0), rawget(t, nil), rawget(t, 3)"),
        ("rawget_extra", "return rawget({5}, 1, 2, 3)"),
        ("rawset_newindex", "local log = 0 local t = setmetatable({}, {__newindex = function() log = log + 1 end}) rawset(t, 1, 'a') t[2] = 'b' return t[1], rawget(t, 2), log"),
        ("rawset_float_key", "local t = {} rawset(t, 2.0, 'x') local k = next(t) return t[2], math.type(k)"),
        ("rawset_ret", "local t = {} return rawequal(rawset(t, 'k', 1), t), t.k"),
        ("rawset_delete", "local t = {k = 1} rawset(t, 'k', nil) return t.k, next(t)"),
        ("rawset_nil_key", "return R(pcall(rawset, {}, nil, 1))"),
        ("rawset_nan_key", "return R(pcall(rawset, {}, 0/0, 1))"),
        ("rawset_nil_key_nil_value", "return R(pcall(rawset, {}, nil, nil))"),
        ("rawset_nan_key_nil_value", "return R(pcall(rawset, {}, 0/0, nil))"),
        ("rawset_two", "return R(pcall(rawset, {}, 'k'))"),
        ("rawset_one", "return R(pcall(rawset, {}))"),
        ("rawset_named", "return R(pcall(rawset, setmetatable({}, {__name = 'N'}), 1, 2))"),
        ("rawset_string", "return R(pcall(rawset, 's', 1, 2))"),
    ]:
        add("base_" + name, body, "raw access")

    # next, pairs, ipairs
    for name, body in [
        ("next_empty", "return select('#', next({})), next({})"),
        ("next_array_hole", "local t = {1, 2, 3} t[2] = nil return next(t, 2)"),
        ("next_last", "local t = {7} return select('#', next(t, 1)), next(t, 1)"),
        ("next_absent_key", "return R(pcall(next, {a = 1}, 'b'))"),
        ("next_absent_int", "return R(pcall(next, {1, 2}, 10))"),
        ("next_absent_float", "return R(pcall(next, {1, 2}, 1.5))"),
        ("next_float_key", "local t = {10, 20} return next(t, 1.0)"),
        ("next_extra", "return next({5}, nil, 'x')"),
        ("pairs_is_next", "return pairs({}) == next, select(2, pairs('x')), select(3, pairs({}))"),
        ("pairs_sorted", "local t = {1, 2, a = 3, b = 4} local k = {} for x in pairs(t) do k[#k + 1] = tostring(x) end table.sort(k) return table.concat(k, ',')"),
        ("pairs_mt_arg", "local t = setmetatable({}, {__pairs = function(...) return select('#', ...), (...) end}) local n, s = pairs(t) return n, rawequal(s, t)"),
        ("pairs_mt_callable", "local t = setmetatable({}, {__pairs = setmetatable({}, {__call = function(self, x) return 'f', 's', 'c', 'd' end})}) return pairs(t)"),
        ("pairs_mt_not_callable", "return R(pcall(pairs, setmetatable({}, {__pairs = 5})))"),
        ("pairs_mt_raises", "return R(pcall(pairs, setmetatable({}, {__pairs = function() error('inner', 0) end})))"),
        ("pairs_mt_loop", "local t = setmetatable({}, {__pairs = function(t) local i = 0 return function() i = i + 1 if i <= 3 then return i, i * i end end, t, nil end}) local s = 0 for k, v in pairs(t) do s = s + v end return s"),
        ("ipairs_holes", "local t = {1, 2, nil, 4} local n = 0 for _ in ipairs(t) do n = n + 1 end return n"),
        ("ipairs_false_values", "local t = {false, false, 3} local n = 0 for _ in ipairs(t) do n = n + 1 end return n"),
        ("ipairs_index_fn", "local t = setmetatable({}, {__index = function(t, i) if i <= 3 then return i * 10 end end}) local s = 0 for i, v in ipairs(t) do s = s + v end return s"),
        ("ipairs_index_chain", "local t = setmetatable({1}, {__index = setmetatable({nil, 2}, {__index = {nil, nil, 3}})}) local s = {} for i, v in ipairs(t) do s[#s + 1] = v end return table.concat(s, ',')"),
        ("ipairs_index_raises", "local t = setmetatable({}, {__index = function() error('idx', 0) end}) return R(pcall(function() for _ in ipairs(t) do end end))"),
        ("ipairs_string_iter", "local n = 0 for _ in ipairs('abc') do n = n + 1 end return n"),
        ("ipairs_number_iter", "return R(pcall(function() for _ in ipairs(5) do end end))"),
        ("ipairs_nil_iter", "return R(pcall(function() for _ in ipairs(nil) do end end))"),
        ("ipairs_named_iter", "return R(pcall(function() for _ in ipairs(setmetatable({}, {__name = 'N', __index = 5})) do end end))"),
        ("ipairs_aux_direct", "local f = ipairs({}) return f({10, 20}, 0), f({10, 20}, 1), select('#', f({10, 20}, 2))"),
        ("ipairs_aux_bad", "local f = ipairs({}) return R(pcall(f, {}, 'x'))"),
        ("ipairs_aux_float", "local f = ipairs({}) return f({10, 20}, 1.0)"),
        ("ipairs_aux_wrap", "local f = ipairs({}) return select('#', f({}, math.maxinteger))"),
        ("ipairs_same_aux", "return ipairs({}) == ipairs({1}), select(3, ipairs({}))"),
    ]:
        add("base_" + name, body, "iteration")

    # select
    for idx in ["'#'", "'#x'", "''", "0", "1", "2", "3", "4", "-1", "-3", "-4", "1.0", "1.5",
                "'2'", "'x'", "nil", "{}", "math.mininteger", "math.maxinteger", None]:
        for an, al in [("noargs", ""), ("one", ", 'a'"), ("three", ", 'a', nil, 'c'")]:
            if idx is None:
                body = "return R(pcall(select))"
                if an != "noargs":
                    continue
            else:
                body = "return R(pcall(select, %s%s))" % (idx, al)
            add("base_select_%s_%s" % (
                "none" if idx is None else idx.replace("'", "q").replace(".", "p").replace("-", "m")
                .replace("{}", "tbl").replace("#", "hash").replace("math", "").replace(" ", ""), an),
                body, "select's index and its range")

    # tostring
    for name, body in [
        ("tostring_prims", "return tostring(nil), tostring(true), tostring(false), tostring(-0.0), tostring(1e100), tostring(3), tostring(2^63), tostring(math.mininteger)"),
        ("tostring_string", "return tostring('a\\0b')"),
        ("tostring_mt_str", "return tostring(setmetatable({}, {__tostring = function() return 'obj' end}))"),
        ("tostring_mt_int", "local s = tostring(setmetatable({}, {__tostring = function() return 42 end})) return s, math.type(s)"),
        ("tostring_mt_float", "return tostring(setmetatable({}, {__tostring = function() return 1.5 end}))"),
        ("tostring_mt_table", "return R(pcall(tostring, setmetatable({}, {__tostring = function() return {} end})))"),
        ("tostring_mt_nil", "return R(pcall(tostring, setmetatable({}, {__tostring = function() end})))"),
        ("tostring_mt_bool", "return R(pcall(tostring, setmetatable({}, {__tostring = function() return true end})))"),
        ("tostring_mt_multi", "return tostring(setmetatable({}, {__tostring = function() return 'a', 'b' end}))"),
        ("tostring_mt_not_callable", "return R(pcall(tostring, setmetatable({}, {__tostring = 5})))"),
        ("tostring_mt_callable", "return tostring(setmetatable({}, {__tostring = setmetatable({}, {__call = function() return 'called' end})}))"),
        ("tostring_mt_raises", "return R(pcall(tostring, setmetatable({}, {__tostring = function() error('ts', 0) end})))"),
        ("tostring_mt_arg", "local t = setmetatable({}, {__tostring = function(...) return tostring(select('#', ...)) end}) return tostring(t)"),
        ("tostring_name", "return (tostring(setmetatable({}, {__name = 'My.Type'})):match('^My%.Type: '))"),
        ("tostring_name_not_string", "return (tostring(setmetatable({}, {__name = 5})):match('^table: '))"),
        ("tostring_name_and_mt", "return tostring(setmetatable({}, {__name = 'N', __tostring = function() return 'ts' end}))"),
        ("tostring_extra", "return tostring(1, 2, 3)"),
    ]:
        add("base_" + name, body, "tostring")

    # tonumber: strings in every base, and the argument checks
    strs = ['"10"', '"0x10"', '" 10 "', '"1e1"', '"z"', '"-ff"', '"+ff"', '""', '" "', '"1 0"',
            '"10\\0"', '"1.5"', '"inf"', '"nan"', '"0x"', '"7fffffffffffffff"', '"8000000000000000"',
            '"zzzzzzzzzzzzzz"', '"\\t\\n12\\v\\f\\r"', '"- 1"', '"1_0"']
    bases = [None, "nil", "2", "8", "10", "16", "36", "1", "37", "'16'", "16.0", "16.5", "{}"]
    for i, sv in enumerate(strs):
        for j, b in enumerate(bases):
            add("base_tonumber_%02d_%02d" % (i, j),
                "return R(pcall(tonumber, %s%s))" % (sv, "" if b is None else ", " + b),
                "tonumber of a string, in a base")
    for name, body in [
        ("tonumber_num_base", "return R(pcall(tonumber, 10, 16))"),
        ("tonumber_nums", "return tonumber(10), tonumber(2.5), math.type(tonumber('10')), math.type(tonumber('10.0'))"),
        ("tonumber_others", "return tonumber({}), tonumber(true), tonumber(nil), select('#', tonumber(nil))"),
        ("tonumber_nil_base", "return tonumber('10', nil)"),
        ("tonumber_none_base", "return R(pcall(tonumber, nil, 10))"),
    ]:
        add("base_" + name, body, "tonumber")

    # getmetatable / setmetatable
    for name, body in [
        ("getmt_kinds", "return getmetatable(1), getmetatable(nil), getmetatable(print), getmetatable(coroutine.create(print)), getmetatable('').__index == string"),
        ("getmt_protected", "return getmetatable(setmetatable({}, {__metatable = 'locked'}))"),
        ("getmt_protected_false", "return getmetatable(setmetatable({}, {__metatable = false}))"),
        ("getmt_protected_table", "local p = {} return rawequal(getmetatable(setmetatable({}, {__metatable = p})), p)"),
        ("getmt_plain", "local m = {} return rawequal(getmetatable(setmetatable({}, m)), m)"),
        ("getmt_index_ignored", "local m = setmetatable({}, {__index = function() return 'via index' end}) return rawequal(getmetatable(setmetatable({}, m)), m)"),
        ("setmt_protected", "return R(pcall(setmetatable, setmetatable({}, {__metatable = 'locked'}), {}))"),
        ("setmt_protected_false", "return R(pcall(setmetatable, setmetatable({}, {__metatable = false}), {}))"),
        ("setmt_protected_nil", "return R(pcall(setmetatable, setmetatable({}, {__metatable = 1}), nil))"),
        ("setmt_unprotect", "local t = setmetatable({}, {}) setmetatable(t, nil) return getmetatable(t)"),
        ("setmt_ret", "local t = {} return rawequal(setmetatable(t, {}), t)"),
        ("setmt_nil_arg2", "return getmetatable(setmetatable({}, nil))"),
        ("setmt_extra", "local t = {} local m = {} setmetatable(t, m, 5) return rawequal(getmetatable(t), m)"),
    ]:
        add("base_" + name, body, "metatables")
    for pn, pv in POOL:
        add("base_arg_setmt2_" + pn, "return R(pcall(function() return type(setmetatable({}%s)) end))" % args(pv),
            "setmetatable's second argument")

    # pcall
    for pn, pv in POOL:
        add("base_arg_pcall_" + pn, "return R(pcall(pcall%s))" % args(pv), "pcall of each kind of value")
    for name, body in [
        ("pcall_nil_count", "return select('#', pcall(nil))"),
        ("pcall_pcall_nil", "return R(pcall(pcall, nil))"),
        ("pcall_args", "return pcall(function(...) return select('#', ...), ... end, 1, nil, 3)"),
        ("pcall_results", "return select('#', pcall(function() return 1, 2, 3 end))"),
        ("pcall_error_nil", "return R(pcall(error))"),
        ("pcall_error_table", "local e = {} local ok, x = pcall(error, e) return ok, rawequal(x, e)"),
        ("pcall_callable", "return pcall(setmetatable({}, {__call = function(self, a) return a end}), 7)"),
        ("pcall_call_number", "return R(pcall(setmetatable({}, {__call = 5})))"),
        ("pcall_call_chain", "return pcall(setmetatable({}, {__call = setmetatable({}, {__call = function(a, b, c) return type(a), type(b), c end})}), 'x')"),
        ("pcall_named", "return R(pcall(setmetatable({}, {__name = 'Foo'})))"),
        ("pcall_named_call", "return R(pcall(setmetatable({}, {__name = 'Foo', __call = 5})))"),
        ("pcall_nested", "return pcall(pcall, pcall, error, 'x', 0)"),
        ("xpcall_named", "return xpcall(setmetatable({}, {__name = 'Foo'}), function(m) return 'H:' .. m end)"),
        ("xpcall_call_number", "return xpcall(setmetatable({}, {__call = 5}), function(m) return 'H:' .. m end)"),
    ]:
        add("base_" + name, body, "pcall")

    # error and assert
    for i, lvl in enumerate([None, "nil", "0", "1", "2", "3", "100", "-1", "'2'", "1.0", "1.5", "'x'", "{}",
                             "math.maxinteger", "math.mininteger", "2^31 + 1"]):
        add("base_error_level_%02d" % i,
            "local function inner() error('m'%s) end\nlocal function outer() inner() end\nreturn R(pcall(outer))"
            % ("" if lvl is None else ", " + lvl),
            "error's level")
    for name, body in [
        ("error_number", "return R(pcall(error, 42))"),
        ("error_number_level", "local function f() error(42, 1) end return R(pcall(f))"),
        ("error_table_level", "local e = {} local function f() error(e, 1) end local ok, x = pcall(f) return ok, rawequal(x, e)"),
        ("error_tail", "local function f() return error('t') end return R(pcall(f))"),
        ("assert_true", "return assert(1, 2, 3)"),
        ("assert_true_count", "return select('#', assert(true))"),
        ("assert_none", "return R(pcall(assert))"),
        ("assert_nil", "return R(pcall(assert, nil))"),
        ("assert_false_nil", "return R(pcall(assert, false, nil))"),
        ("assert_false_msg", "return R(pcall(assert, false, 'msg'))"),
        ("assert_false_num", "return R(pcall(assert, false, 5))"),
        ("assert_false_table", "local e = {} local ok, x = pcall(assert, false, e) return ok, rawequal(x, e)"),
        ("assert_false_extra", "return R(pcall(assert, false, 'm', 'extra'))"),
        ("assert_in_function", "local function f() assert(false, 'in f') end return R(pcall(f))"),
        ("assert_default_in_function", "local function f() assert(false) end return R(pcall(f))"),
    ]:
        add("base_" + name, body, "error and assert")

    # collectgarbage: every option, with whatever state it changes put back
    # (the oracle runs every row in one state). The standalone `lua` runs its
    # collector in generational mode and nmap in incremental, so no row shows
    # which mode a state starts in.
    for name, body in [
        ("cg_default", "return collectgarbage()"),
        ("cg_collect", "return collectgarbage('collect')"),
        ("cg_nil", "return collectgarbage(nil)"),
        ("cg_count", "return math.type(collectgarbage('count')), collectgarbage('count') > 0"),
        ("cg_step", "return type(collectgarbage('step')), type(collectgarbage('step', 0)), type(collectgarbage('step', 10))"),
        ("cg_stop_restart", "local a = collectgarbage('stop') local b = collectgarbage('isrunning') local c = collectgarbage('restart') return a, b, c, collectgarbage('isrunning')"),
        ("cg_isrunning", "return collectgarbage('isrunning')"),
        ("cg_setpause", "local a = collectgarbage('setpause', 150) local b = collectgarbage('setpause', a) return a, b"),
        ("cg_setpause_none", "local a = collectgarbage('setpause') local b = collectgarbage('setpause', a) return a, b"),
        ("cg_setpause_odd", "local a = collectgarbage('setpause', 1001) local b = collectgarbage('setpause', 2000) local c = collectgarbage('setpause', a) return a, b, c"),
        ("cg_setstepmul", "local a = collectgarbage('setstepmul', 300) local b = collectgarbage('setstepmul', a) return a, b"),
        ("cg_mode_roundtrip", "local a = collectgarbage('incremental') local b = collectgarbage(a) collectgarbage(a) return b, type(a)"),
        ("cg_mode_generational", "local a = collectgarbage('generational') local b = collectgarbage('generational', 10, 50) local c = collectgarbage(a) collectgarbage(a) return b, c == 'generational'"),
        ("cg_incremental_params", "local a = collectgarbage('incremental', 0, 0, 0) local p = collectgarbage('setpause', 200) collectgarbage(a) return p"),
        ("cg_incremental_pause", "local p0 = collectgarbage('setpause', 200) local a = collectgarbage('incremental', 120) local p = collectgarbage('setpause', p0) collectgarbage(a) return p"),
        ("cg_bad_option", "return R(pcall(collectgarbage, 'bogus'))"),
        ("cg_number_option", "return R(pcall(collectgarbage, 1))"),
        ("cg_table_option", "return R(pcall(collectgarbage, {}))"),
        ("cg_nul_option", "return math.type(collectgarbage('count\\0junk'))"),
        ("cg_bad_step_arg", "return R(pcall(collectgarbage, 'step', 'x'))"),
        ("cg_bad_pause_arg", "return R(pcall(collectgarbage, 'setpause', 1.5))"),
        ("cg_bad_gen_arg", "return R(pcall(collectgarbage, 'generational', {}))"),
        ("cg_bad_inc_arg", "return R(pcall(collectgarbage, 'incremental', 1, 2, 'x'))"),
    ]:
        add("base_" + name, body, "collectgarbage")

    # warn: warnings stay off (`luaL_newstate`'s default), so nothing is
    # written; the arguments are checked all the same.
    for name, body in [
        ("warn_off", "return select('#', warn('hidden'))"),
        ("warn_pieces", "return select('#', warn('a', 'b', 3))"),
        ("warn_control_off", "warn('@off') return select('#', warn('@unknown'))"),
        ("warn_none", "return R(pcall(warn))"),
        ("warn_table", "return R(pcall(warn, {}))"),
        ("warn_second", "return R(pcall(warn, 'a', nil))"),
        ("warn_third", "return R(pcall(warn, 'a', 'b', true))"),
        ("warn_named", "return R(pcall(warn, setmetatable({}, {__name = 'N'})))"),
    ]:
        add("base_" + name, body, "warn")

    add("base_version", "return _VERSION", "_VERSION")
    # Not through `_G`: section F's `g_rebind` leaves the oracle's `_G` a
    # number for the rows after it.
    add("base_globals", "return type(assert), type(collectgarbage), type(error), type(getmetatable), "
        "type(ipairs), type(load), type(next), type(pairs), type(pcall), type(rawequal), type(rawget), "
        "type(rawlen), type(rawset), type(select), type(setmetatable), type(tonumber), type(tostring), "
        "type(type), type(warn), type(xpcall)", "the base library's functions")


# --------------------------------------------------------------------------
# H. the coroutine library

def gen_coroutine() -> None:
    for fn in ["create", "resume", "status", "close", "isyieldable", "wrap"]:
        for pn, pv in POOL:
            if fn == "isyieldable" and pv is None:
                continue
            add("co_arg_%s_%s" % (fn, pn),
                "return R(pcall(function(...) local r = table.pack(coroutine.%s(...)) "
                "for i = 1, r.n do r[i] = type(r[i]) == 'string' and r[i] or type(r[i]) end "
                "return table.unpack(r, 1, r.n) end%s))" % (fn, args(pv)),
                "coroutine.%s of each kind of argument" % fn)
    for name, body in [
        ("create_callable", "return R(pcall(coroutine.create, setmetatable({}, {__call = function() end})))"),
        ("create_named", "return R(pcall(coroutine.create, setmetatable({}, {__name = 'N'})))"),
        ("status_cycle", "local co = coroutine.create(function() coroutine.yield() end) local a = coroutine.status(co) coroutine.resume(co) local b = coroutine.status(co) coroutine.resume(co) return a, b, coroutine.status(co)"),
        ("status_running", "return coroutine.wrap(function() return coroutine.status((coroutine.running())) end)()"),
        ("status_main", "return coroutine.status((coroutine.running()))"),
        ("status_normal", "local co1, co2 co2 = coroutine.create(function() return coroutine.status(co1) end) co1 = coroutine.create(function() return select(2, coroutine.resume(co2)) end) return select(2, coroutine.resume(co1))"),
        ("status_main_from_inside", "local main = coroutine.running() return coroutine.wrap(function() return coroutine.status(main) end)()"),
        ("status_error", "local co = coroutine.create(function() error('x') end) coroutine.resume(co) return coroutine.status(co)"),
        ("resume_values", "local co = coroutine.create(function(a, b) local c, d = coroutine.yield(a + b, nil) return c, d, 'end' end) local r1 = table.pack(coroutine.resume(co, 1, 2)) local r2 = table.pack(coroutine.resume(co, 'x')) return r1.n, r1[2], r1[3], r2.n, r2[2], r2[3], r2[4]"),
        ("resume_dead", "local co = coroutine.create(function() end) coroutine.resume(co) return coroutine.resume(co)"),
        ("resume_dead_error", "local co = coroutine.create(function() error('boom', 0) end) local a, b = coroutine.resume(co) return a, b, coroutine.resume(co)"),
        ("resume_self", "return coroutine.wrap(function() return coroutine.resume((coroutine.running())) end)()"),
        ("resume_main", "return coroutine.resume((coroutine.running()))"),
        ("resume_normal", "local co1, co2 co2 = coroutine.create(function() return coroutine.resume(co1) end) co1 = coroutine.create(function() return coroutine.resume(co2) end) local r = table.pack(coroutine.resume(co1)) return r.n, r[1], r[2], r[3], r[4]"),
        ("resume_error_table", "local e = {} local co = coroutine.create(function() error(e) end) local ok, x = coroutine.resume(co) return ok, rawequal(x, e)"),
        ("resume_error_position", "local co = coroutine.create(function() error('pos') end) return coroutine.resume(co)"),
        ("resume_runtime_error", "local co = coroutine.create(function() local x = nil return x.y end) local ok, e = coroutine.resume(co) return ok, (e:gsub(' %(.*%)$', ''))"),
        ("resume_count", "local co = coroutine.create(function() coroutine.yield() end) return select('#', coroutine.resume(co))"),
        ("isyieldable_main", "return coroutine.isyieldable()"),
        ("isyieldable_inside", "return coroutine.wrap(function() return coroutine.isyieldable() end)()"),
        ("isyieldable_self", "return coroutine.wrap(function() return coroutine.isyieldable((coroutine.running())) end)()"),
        ("isyieldable_main_arg", "return coroutine.isyieldable((coroutine.running()))"),
        ("isyieldable_main_from_inside", "local main = coroutine.running() return coroutine.wrap(function() return coroutine.isyieldable(main) end)()"),
        ("isyieldable_suspended", "local co = coroutine.create(function() coroutine.yield() end) local a = coroutine.isyieldable(co) coroutine.resume(co) return a, coroutine.isyieldable(co)"),
        ("isyieldable_dead", "local co = coroutine.create(function() end) coroutine.resume(co) return coroutine.isyieldable(co)"),
        ("isyieldable_normal", "local co1, co2 co2 = coroutine.create(function() return coroutine.isyieldable(co1) end) co1 = coroutine.create(function() return select(2, coroutine.resume(co2)) end) return select(2, coroutine.resume(co1))"),
        ("isyieldable_nil", "return R(pcall(coroutine.isyieldable, nil))"),
        ("running_main", "local co, main = coroutine.running() return type(co), main, select('#', coroutine.running())"),
        ("running_inside", "local co co = coroutine.create(function() local c, m = coroutine.running() return rawequal(c, co), m end) return select(2, coroutine.resume(co))"),
        ("close_fresh", "local co = coroutine.create(function() end) return coroutine.close(co), coroutine.status(co)"),
        ("close_suspended", "local co = coroutine.create(function() coroutine.yield() end) coroutine.resume(co) return coroutine.close(co), coroutine.status(co), coroutine.resume(co)"),
        ("close_dead", "local co = coroutine.create(function() return 1 end) coroutine.resume(co) return coroutine.close(co)"),
        ("close_dead_error", "local co = coroutine.create(function() error('boom') end) coroutine.resume(co) local r = table.pack(coroutine.close(co)) return r.n, r[1], r[2], coroutine.close(co)"),
        ("close_dead_error_table", "local e = {} local co = coroutine.create(function() error(e) end) coroutine.resume(co) local ok, x = coroutine.close(co) return ok, rawequal(x, e)"),
        ("close_dead_error_nil", "local co = coroutine.create(function() error(nil) end) coroutine.resume(co) local r = table.pack(coroutine.close(co)) return r.n, r[1], r[2]"),
        ("close_dead_error_after_yield", "local co = coroutine.create(function() coroutine.yield() error('late', 0) end) coroutine.resume(co) coroutine.resume(co) return coroutine.close(co)"),
        ("close_running", "return R(coroutine.wrap(function() return pcall(coroutine.close, (coroutine.running())) end)())"),
        ("close_main", "return R(pcall(coroutine.close, (coroutine.running())))"),
        ("close_normal", "local co1, co2 co2 = coroutine.create(function() return pcall(coroutine.close, co1) end) co1 = coroutine.create(function() return select(3, coroutine.resume(co2)) end) return R(select(2, coroutine.resume(co1)))"),
        ("close_running_positioned", "local function f() return coroutine.close((coroutine.running())) end return R(pcall(f))"),
        ("close_wrapped_error", "local co local w = coroutine.wrap(function() co = coroutine.running() error('w', 0) end) pcall(w) return coroutine.status(co), coroutine.close(co)"),
        ("close_then_resume", "local co = coroutine.create(function() coroutine.yield(1) end) coroutine.resume(co) coroutine.close(co) return coroutine.resume(co)"),
        ("wrap_error_positioned", "local w = coroutine.wrap(function() error('inner', 0) end) local function f() return w() end return R(pcall(f))"),
        ("wrap_error_table_positioned", "local e = {} local w = coroutine.wrap(function() error(e) end) local function f() return w() end local ok, x = pcall(f) return ok, rawequal(x, e)"),
        ("wrap_dead_positioned", "local w = coroutine.wrap(function() end) w() local function f() return w() end return R(pcall(f))"),
        ("wrap_error_number", "local w = coroutine.wrap(function() error(5) end) local function f() return w() end return R(pcall(f))"),
        ("wrap_running_positioned", "local w w = coroutine.wrap(function() local function f() return w() end return pcall(f) end) return R(w())"),
        # The VM's own `continue` and `yieldto` are removed by the NSE
        # runtime, not here (`vm-nonstandard-coroutine-functions`).
        ("coroutine_functions", "local k = {} for _, n in ipairs({'close', 'create', 'isyieldable', 'resume', 'running', 'status', 'wrap', 'yield'}) do k[#k + 1] = type(coroutine[n]) end return table.concat(k, ',')"),
    ]:
        add("co_" + name, body, "coroutines")


# --------------------------------------------------------------------------
# I. string.char and the string metatable's arithmetic

STR_OPERANDS = [
    ("i3", '"3"'), ("f15", '"1.5"'), ("hex", '"0x10"'), ("sp", '" 4 "'), ("bad", '"a"'),
    ("nul", '"1\\0"'), ("n4", "4"), ("n25", "2.5"), ("zero", "0"), ("szero", '"0"'),
    ("nil", "nil"), ("tbl", "{}"), ("tmm", "T"), ("bool", "true"),
]
EVENTS = ["__add", "__sub", "__mul", "__mod", "__pow", "__div", "__idiv", "__unm"]


def gen_string() -> None:
    setup = ("local mt = getmetatable('')\n"
             "local T = setmetatable({}, {__add = function(a, b) return 'T+' .. type(a) end, "
             "__unm = function(a, b) return 'T-' .. type(a) .. type(b) end, __idiv = 5})\n")
    for ev in EVENTS:
        for an, av in STR_OPERANDS:
            for bn, bv in [("i3", '"3"'), ("n2", "2"), ("bad", '"x"'), ("zero", '"0"'), ("tmm", "T"),
                           ("tbl", "{}"), ("none", None)]:
                add("str_%s_%s_%s" % (ev[2:], an, bn),
                    setup + "return R(pcall(mt.%s, %s%s))" % (ev, av, "" if bv is None else ", " + bv),
                    "the string metatable's %s called directly" % ev)
        add("str_%s_none" % ev[2:], setup + "return R(pcall(mt.%s))" % ev, "no arguments at all")
        add("str_%s_positioned" % ev[2:],
            setup + "local function f() return mt.%s('a', 1) end\nreturn R(pcall(f))" % ev,
            "trymt's error is positioned")
    for name, body in [
        ("mt_keys", "local k = {} for n in pairs(getmetatable('')) do k[#k + 1] = n end table.sort(k) return table.concat(k, ',')"),
        ("mt_add_types", "local mt = getmetatable('') return math.type(mt.__add('1', '2')), math.type(mt.__add('1', '2.0')), math.type(mt.__div('4', '2')), math.type(mt.__idiv('7', '2'))"),
        ("mt_unm_second", "return getmetatable('').__unm('2', '3')"),
        ("mt_unm_one", "return R(pcall(getmetatable('').__unm, '2'))"),
        ("mt_add_overflow", "return getmetatable('').__add(tostring(math.maxinteger), '1') == math.mininteger"),
        ("mt_same_fn", "local mt = getmetatable('') return mt.__add == mt.__add, mt.__add ~= mt.__sub"),
        ("mt_called_mm_raises", "local T = setmetatable({}, {__add = function() error('in mm', 0) end}) return R(pcall(getmetatable('').__add, 'x', T))"),
        ("mt_called_mm_multi", "local T = setmetatable({}, {__add = function() return 1, 2, 3 end}) return select('#', getmetatable('').__add('x', T))"),
        ("ops_unchanged", "return '10' + 1, '3' * '4', -'2', '7' // '2', '2' ^ '2', '7' % '4', '1' / '4'"),
    ]:
        add("str_" + name, body, "string arithmetic")
    for pn, pv in POOL:
        add("str_arg_char_" + pn, "return R(pcall(string.char%s))" % args(pv), "string.char of each kind of argument")
    for name, body in [
        ("char_range", "return string.char(0, 65, 255) == '\\0A\\255', #string.char()"),
        ("char_256", "return R(pcall(string.char, 256))"),
        ("char_neg", "return R(pcall(string.char, -1))"),
        ("char_float", "return string.char(65.0), R(pcall(string.char, 65.5))"),
        ("char_strnum", "return string.char('65', ' 66 ', '0x43')"),
        ("char_third", "return R(pcall(string.char, 65, 66, 'x'))"),
        ("char_huge", "return R(pcall(string.char, math.maxinteger))"),
        ("char_minint", "return R(pcall(string.char, math.mininteger))"),
        ("char_positioned", "local function f() return string.char(256) end return R(pcall(f))"),
        ("char_method", "return ('x').char(104, 105)"),
    ]:
        add("str_" + name, body, "string.char")


# --------------------------------------------------------------------------
# J. table.insert, table.remove and table.concat's checks

def gen_table() -> None:
    show = ("local function show(t) local o = {} for i = 1, 6 do o[i] = tostring(rawget(t, i)) end "
            "return table.concat(o, ',') end\n")
    for i, call in enumerate([
        "table.insert()", "table.insert(T)", "table.insert(T, 'x')", "table.insert(T, 1, 'x')",
        "table.insert(T, 1, 'x', 'y')", "table.insert(T, 0, 'x')", "table.insert(T, 4, 'x')",
        "table.insert(T, 5, 'x')", "table.insert(T, -1, 'x')", "table.insert(T, '2', 'x')",
        "table.insert(T, 2.0, 'x')", "table.insert(T, 2.5, 'x')", "table.insert(T, 'x', 'x')",
        "table.insert(T, nil, 'x')", "table.insert(T, math.mininteger, 'x')",
        "table.insert(T, math.maxinteger, 'x')", "table.insert('s', 'x')", "table.insert(nil, 'x')",
        "table.insert(setmetatable({}, {__name = 'N'}), 1, 2, 3)",
        "table.insert(setmetatable({1}, {__index = function() end}), 'x')",
        "table.remove()", "table.remove(T)", "table.remove(T, 1)", "table.remove(T, 3)",
        "table.remove(T, 4)", "table.remove(T, 5)", "table.remove(T, 0)", "table.remove(T, -1)",
        "table.remove(T, '1')", "table.remove(T, 1.5)", "table.remove(T, 'x')", "table.remove(T, nil)",
        "table.remove({}, 0)", "table.remove({}, 1)", "table.remove({}, 2)", "table.remove({}, -1)",
        "table.remove('s')", "table.remove(5, 1)",
        "table.concat(T)", "table.concat(T, ',')", "table.concat(T, 1)", "table.concat(T, {})",
        "table.concat(T, ',', 2)", "table.concat(T, ',', 2, 3)", "table.concat(T, ',', 3, 2)",
        "table.concat(T, ',', 1, 4)", "table.concat(T, ',', 0)", "table.concat(T, ',', 'x')",
        "table.concat(T, ',', 1, 'x')", "table.concat(T, ',', 1.5)", "table.concat({1, {}, 3})",
        "table.concat({1, 2.5, 'x'}, '-')", "table.concat({true})", "table.concat({1, nil, 3}, ',', 1, 3)",
        "table.concat({}, ',', 1, 1e15)", "table.concat('s')", "table.concat()",
        "table.concat({print})", "table.concat({1, 2}, nil, nil, nil)",
    ]):
        add("tab_%02d" % i, show + "local T = {1, 2, 3}\nreturn R(pcall(function() local r = table.pack(%s) "
            "return r.n, r[1], show(T) end))" % call, "table library argument checks")
    for name, body in [
        ("insert_positioned", "local function f() table.insert({}, 1, 2, 3) end return R(pcall(f))"),
        ("insert_bounds_positioned", "local function f() table.insert({}, 5, 1) end return R(pcall(f))"),
        ("remove_positioned", "local function f() table.remove({}, 5) end return R(pcall(f))"),
        ("concat_positioned", "local function f() return table.concat({1, {}}) end return R(pcall(f))"),
        ("concat_type_positioned", "local function f() return table.concat(5) end return R(pcall(f))"),
        ("insert_newindex", "local log = {} local t = setmetatable({}, {__newindex = function(t, k, v) log[#log + 1] = k rawset(t, k, v) end}) table.insert(t, 'a') table.insert(t, 1, 'b') return table.concat(log, ','), t[1], t[2]"),
        ("remove_shift", "local t = {1, 2, 3, 4} local r = table.remove(t, 2) return r, table.concat(t, ','), #t"),
        ("insert_shift", "local t = {1, 2, 3} table.insert(t, 1, 0) table.insert(t, 5, 4) return table.concat(t, ',')"),
    ]:
        add("tab_" + name, body, "table library")


def main() -> None:
    gen_rep()
    gen_rawequal()
    gen_xpcall()
    gen_wrap()
    gen_load()
    gen_g()
    gen_base()
    gen_coroutine()
    gen_string()
    gen_table()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m6_tail.py; regenerate with ./regen_m6_tail.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
