#!/usr/bin/env python3
"""Emit the M6.4b differential corpus: the limits PUC-Lua puts on a running
state, and the errors it raises at them.

The oracle is nmap's own `liblua/`. Every case is a chunk named `=chunk`; the
driver (`oracle/m6_pattern_driver.lua`) renders what it returns, or the error
that escapes it, as hex, positions included.

  A. C-call depth (`LUAI_MAXCCALLS`, 200). Every way a call takes a level of
     PUC-Lua's C stack -- a call from a C function (`pcall`, a `gsub`
     callback, `load`'s reader), a metamethod, a generic `for` iterator, a
     coroutine resume -- recursed until "C stack overflow", from inside every
     kind of caller. Each case returns how many levels it reached, so the
     count is compared exactly, not just the message.
  B. Lua stack depth (`LUAI_MAXSTACK`): runaway recursion ends in a catchable
     "stack overflow" with the caller's position; deep but bounded recursion
     does not. Depths are not compared at the limit itself -- the two VMs lay
     out frames differently -- only well inside and well past it.
  C. `__index` / `__newindex` chains (`MAXTAGLOOP`, 2,000): at, below and
     above the limit, loops, and non-table, non-function metamethod values.
  D. Results a call may push (`lua_checkstack`): `table.unpack`, and
     `string.byte`, well inside and well past the limit.

Each row is `name<TAB>chunk_hex<TAB>note`.
"""

import sys

CASES = []
_seen = set()


def add(name, chunk, note):
    if name in _seen:
        raise SystemExit("duplicate case: " + name)
    _seen.add(name)
    CASES.append((name, chunk, note))


# Ways to recurse until the C stack overflows. Each defines `probe`, which
# returns `ok, e` with `d` counting the levels reached.
PROBES = [
    ("gsub", """local function f(c) d = d + 1 return (string.gsub(c, ".", f)) end
local function probe() return pcall(f, "a") end"""),
    ("gsub_method", """local function f(c) d = d + 1 return (c:gsub(".", f)) end
local function probe() return pcall(f, "a") end"""),
    ("gsub_table_index", """local repl = setmetatable({}, {})
local function f(c) d = d + 1 return (string.gsub(c, ".", repl)) end
getmetatable(repl).__index = function(t, k) return f(k) end
local function probe() return pcall(f, "a") end"""),
    ("pcall", """local function f() d = d + 1 local ok, e = pcall(f) if not ok then error(e, 0) end return ok end
local function probe() return pcall(f) end"""),
    ("pcall_returns", """local function f() d = d + 1 return pcall(f) end
local function probe() return f() end"""),
    ("xpcall_body", """local function f() d = d + 1 local ok, e = xpcall(f, function(m) return m end) if not ok then error(e, 0) end return ok end
local function probe() return pcall(f) end"""),
    ("index", """local t = setmetatable({}, {__index = function(t, k) d = d + 1 return t[k] end})
local function probe() return pcall(function() return t.x end) end"""),
    ("newindex", """local t = setmetatable({}, {})
getmetatable(t).__newindex = function(t, k, v) d = d + 1 t[k] = v end
local function probe() return pcall(function() t.x = 1 end) end"""),
    ("add", """local mt = {}
mt.__add = function(a, b) d = d + 1 return a + b end
local t = setmetatable({}, mt)
local function probe() return pcall(function() return t + 1 end) end"""),
    ("concat", """local mt = {}
mt.__concat = function(a, b) d = d + 1 return a .. b end
local t = setmetatable({}, mt)
local function probe() return pcall(function() return t .. "x" end) end"""),
    ("lt", """local mt = {}
mt.__lt = function(a, b) d = d + 1 return a < b end
local a, b = setmetatable({}, mt), setmetatable({}, mt)
local function probe() return pcall(function() return a < b end) end"""),
    ("eq", """local mt = {}
mt.__eq = function(a, b) d = d + 1 return a == b end
local a, b = setmetatable({}, mt), setmetatable({}, mt)
local function probe() return pcall(function() return a == b end) end"""),
    ("len", """local mt = {}
mt.__len = function(a) d = d + 1 return #a end
local t = setmetatable({}, mt)
local function probe() return pcall(function() return #t end) end"""),
    ("unm", """local mt = {}
mt.__unm = function(a) d = d + 1 return -a end
local t = setmetatable({}, mt)
local function probe() return pcall(function() return -t end) end"""),
    ("tostring", """local t = setmetatable({}, {})
getmetatable(t).__tostring = function(x) d = d + 1 return tostring(x) end
local function probe() return pcall(tostring, t) end"""),
    ("tforcall", """local function f() d = d + 1 for _ in f do end end
local function probe() return pcall(f) end"""),
    ("coroutine", """local function f() d = d + 1 return coroutine.resume(coroutine.create(f)) end
local function probe() return f() end"""),
    ("coroutine_error", """local function f() d = d + 1 local ok, e = coroutine.resume(coroutine.create(f)) if not ok then error(e, 0) end return ok end
local function probe() return pcall(f) end"""),
    ("load_reader", """local function f() d = d + 1 local n = 0 return load(function() n = n + 1 if n == 1 then f() return "return 1" end return nil end) end
local function probe() return pcall(f) end"""),
]

# Callers to run a probe from: `{run}` stands for `ok, e = probe()`.
CONTEXTS = [
    ("top", "{run}"),
    ("pcall", "pcall(function() {run} end)"),
    ("pcall2", "pcall(pcall, function() {run} end)"),
    ("coroutine", "coroutine.resume(coroutine.create(function() {run} end))"),
    ("coroutine2", "coroutine.resume(coroutine.create(function() coroutine.resume(coroutine.create(function() {run} end)) end))"),
    ("wrap", "coroutine.wrap(function() {run} end)()"),
    ("index_fn", "local _ = setmetatable({}, {__index = function() {run} end}).x"),
    ("call_meta", "setmetatable({}, {__call = function() {run} end})()"),
    ("gsub_cb", "string.gsub(\"a\", \".\", function() {run} end)"),
    ("tfor", "for _ in function() {run} return nil end do end"),
    ("tostring_meta", "tostring(setmetatable({}, {__tostring = function() {run} return \"\" end}))"),
    # Resumed from deeper than it yielded, then from shallower: a coroutine
    # runs one level above whoever resumed it last.
    ("resumed_deeper", "local co = coroutine.create(function() coroutine.yield() {run} end) coroutine.resume(co) pcall(pcall, function() coroutine.resume(co) end)"),
    ("resumed_shallower", "local co = coroutine.create(function() pcall(function() coroutine.yield() {run} end) end) pcall(pcall, pcall, function() coroutine.resume(co) end) coroutine.resume(co)"),
    # The message handler; known to differ (`xpcall-handler-runs-after-unwind`).
    ("xpcall_handler", "xpcall(error, function(m) {run} return m end)"),
]


def section_a():
    for pname, defs in PROBES:
        for cname, ctx in CONTEXTS:
            body = ctx.replace("{run}", "ok, e = probe()")
            add("cdepth_%s_in_%s" % (pname, cname),
                "local d = 0\n%s\nlocal ok, e\n%s\nreturn ok, e, d" % (defs, body),
                "C stack overflow")
    # Escaping, and the position a metamethod's overflow carries.
    add("cdepth_escaped_gsub",
        "local function f(c) return (string.gsub(c, '.', f)) end\nf('a')",
        "escaped C stack overflow, from a C function")
    add("cdepth_escaped_index",
        "local t = setmetatable({}, {__index = function(t, k) return t[k] end})\nreturn t.x",
        "escaped C stack overflow, from a metamethod")
    add("cdepth_recovers",
        "local function f(c) return (string.gsub(c, '.', f)) end\n"
        "local a = {pcall(f, 'a')}\nlocal b = {pcall(f, 'a')}\n"
        "return a[1], a[2], b[1], b[2], string.gsub('abc', '.', function(c) return c:upper() end)",
        "the C-call count unwinds with the error")
    add("cdepth_call_meta_is_free",
        "local d = 0\nlocal t = setmetatable({}, {})\n"
        "getmetatable(t).__call = function(self, n) d = d + 1 if n == 0 then return d end return self(n - 1) end\n"
        "return pcall(t, 500)",
        "__call takes no C level")
    add("cdepth_index_table_is_free",
        "local d = 0\nlocal function f(c) d = d + 1 return (c:gsub('.', f)) end\n"
        "local base = {} for i = 1, 50 do base = setmetatable({}, {__index = base}) end\n"
        "local ok, e = pcall(function() return base.missing, f('a') end)\nreturn ok, e, d",
        "a chain of __index tables takes no C level")


def section_b():
    add("stack_recursion", "local function f() return 1 + f() end\nreturn pcall(f)",
        "runaway Lua recursion")
    add("stack_recursion_escaped", "local function f() return 1 + f() end\nreturn f()",
        "escaped stack overflow")
    add("stack_recursion_args", "local function f(a, b, c) return 1 + f(a, b, c) end\nreturn pcall(f, 1, 2, 3)",
        "recursion with arguments")
    add("stack_recursion_locals",
        "local function f() local a, b, c, d, e, g, h = 1, 2, 3, 4, 5, 6, 7 return a + f() end\nreturn pcall(f)",
        "recursion with locals")
    add("stack_method_recursion",
        "local t = {}\nfunction t:m() return 1 + self:m() end\nreturn pcall(t.m, t)",
        "method recursion")
    add("stack_in_coroutine",
        "local function f() return 1 + f() end\nreturn coroutine.resume(coroutine.create(f))",
        "stack overflow inside a coroutine")
    add("stack_recovers",
        "local function f() return 1 + f() end\nlocal a, b = pcall(f)\nlocal c, d = pcall(f)\n"
        "local function g(n) if n == 0 then return 0 end return 1 + g(n - 1) end\nreturn a, b, c, d, g(1000)",
        "a thread that overflowed runs on")
    add("stack_call_meta_recursion",
        "local t = setmetatable({}, {})\ngetmetatable(t).__call = function(self) local r = self() return r end\nreturn pcall(t)",
        "__call recursion overflows the Lua stack")
    for n in [1000, 10000, 50000]:
        add("stack_deep_ok_%d" % n,
            "local function f(n) if n == 0 then return 0 end return 1 + f(n - 1) end\nreturn f(%d)" % n,
            "deep recursion within the limit")
    add("stack_tail_unbounded",
        "local function f(n) if n == 0 then return 'done' end return f(n - 1) end\nreturn f(2000000)",
        "a tail call takes no stack")


def chain(n, kind, final):
    head = "local t = {}\nlocal cur = t\nfor i = 1, %d do local n = {} setmetatable(cur, {%s = n}) cur = n end\n" % (n, kind)
    return head + final


def section_c():
    for n in [1, 10, 1998, 1999, 2000, 2001, 2002, 3000]:
        add("chain_index_%d" % n,
            chain(n, "__index", "cur.x = 5\nreturn pcall(function() return t.x end)"),
            "__index chain")
        add("chain_index_miss_%d" % n,
            chain(n, "__index", "return pcall(function() return t.x end)"),
            "__index chain, key absent everywhere")
        add("chain_newindex_%d" % n,
            chain(n, "__newindex", "local ok, e = pcall(function() t.x = 1 end)\nreturn ok, e, rawget(cur, 'x'), rawget(t, 'x')"),
            "__newindex chain")
    for name, src in [
        ("index_loop", "local t = {} setmetatable(t, {__index = t})\nreturn pcall(function() return t.x end)"),
        ("index_loop2", "local a, b = {}, {} setmetatable(a, {__index = b}) setmetatable(b, {__index = a})\nreturn pcall(function() return a.x end)"),
        ("newindex_loop", "local t = {} setmetatable(t, {__newindex = t})\nreturn pcall(function() t.x = 1 end)"),
        ("index_escaped_loop", "local t = {} setmetatable(t, {__index = t})\nreturn t.x"),
        ("index_string_tm", "local t = setmetatable({}, {__index = 'abc'})\nreturn t.len == string.len, t.upper('q'), pcall(function() return t.nope end)"),
        ("index_number_tm", "local t = setmetatable({}, {__index = 5})\nreturn pcall(function() return t.x end)"),
        ("index_bool_tm", "local t = setmetatable({}, {__index = true})\nreturn pcall(function() return t.x end)"),
        ("index_number_tm_escaped", "local t = setmetatable({}, {__index = 5})\nreturn t.x"),
        ("newindex_string_tm", "local t = setmetatable({}, {__newindex = 'abc'})\nreturn pcall(function() t.x = 1 end)"),
        ("newindex_number_tm", "local t = setmetatable({}, {__newindex = 5})\nreturn pcall(function() t.x = 1 end)"),
        ("index_callable_table", "local c = setmetatable({}, {__call = function() return 'called' end})\nlocal t = setmetatable({}, {__index = c})\nreturn t.x, rawget(c, 'x')"),
        ("newindex_callable_table", "local c = setmetatable({}, {__call = function() error('called') end})\nlocal t = setmetatable({}, {__newindex = c})\nt.x = 1\nreturn rawget(t, 'x'), rawget(c, 'x')"),
        ("newindex_existing_key", "local inner = {x = 1}\nlocal t = setmetatable({}, {__newindex = inner})\nt.x = 2\nreturn rawget(t, 'x'), inner.x"),
        ("newindex_present_in_first", "local inner = {}\nlocal t = setmetatable({x = 1}, {__newindex = inner})\nt.x = 2\nreturn rawget(t, 'x'), inner.x"),
        ("index_fn_gets_intermediate", "local seen\nlocal inner = setmetatable({}, {__index = function(tt, k) seen = tt return k .. '!' end})\nlocal t = setmetatable({}, {__index = inner})\nreturn t.k, seen == inner, seen == t"),
        ("newindex_fn_gets_intermediate", "local seen\nlocal inner = setmetatable({}, {__newindex = function(tt, k, v) seen = tt end})\nlocal t = setmetatable({}, {__newindex = inner})\nt.k = 1\nreturn seen == inner, seen == t"),
        ("method_through_chain", "local base = {m = function(self, x) return x * 2 end}\nlocal t = base\nfor i = 1, 100 do t = setmetatable({}, {__index = t}) end\nreturn t:m(21)"),
        ("rawget_ignores_chain", "local t = setmetatable({}, {__index = {x = 1}})\nreturn rawget(t, 'x'), t.x"),
    ]:
        add("chain_" + name, src, "metamethod values")


def section_d():
    for name, src in [
        ("unpack_ok", "return select('#', table.unpack({}, 1, 100000))"),
        ("unpack_many", "return pcall(table.unpack, {}, 1, 2000000)"),
        ("unpack_huge", "return pcall(table.unpack, {}, 1, 1e15)"),
        ("unpack_full_range", "return pcall(table.unpack, {}, math.mininteger, math.maxinteger)"),
        ("unpack_intmax", "return pcall(table.unpack, {}, 1, 2147483647)"),
        ("unpack_empty", "return select('#', table.unpack({}, 1, 0)), select('#', table.unpack({}, math.maxinteger, math.mininteger))"),
        ("unpack_values", "local t = {} for i = 1, 300 do t[i] = i end\nreturn select('#', table.unpack(t)), select(300, table.unpack(t))"),
        ("byte_ok", "return select('#', string.byte(string.rep('a', 100000), 1, -1))"),
        ("byte_many", "return pcall(string.byte, string.rep('a', 2000000), 1, -1)"),
        ("byte_values", "return string.byte('hello', 1, -1)"),
    ]:
        add("results_" + name, src, "results a call may push")


def main():
    section_a()
    section_b()
    section_c()
    section_d()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m64_limits.py; regenerate with ./regen_m64_limits.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
