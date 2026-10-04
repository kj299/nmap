#!/usr/bin/env python3
"""Emit the M6.4b memory corpus: what a script sees when memory runs out.

The oracle is nmap's own `liblua/`, each case run in a fresh process under
`ulimit -v` (regen_m64_memory.sh); the port runs each in a fresh VM under a
memory budget (crates/core/tests/memory_differential.rs). The two limits are
not the same number, and the two heaps are not laid out alike, so no case
depends on where exactly memory runs out: every request either fits easily
under both or fails under both by orders of magnitude, and every runaway
allocation is one that fails eventually under any limit. What is compared is
what a script can observe -- that a refusal is the catchable error "not
enough memory", where it surfaces, which handlers see it, and that the
script runs on afterwards.

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


# Requests no limit allows: refused up front.
HUGE = [
    ("rep", "string.rep('x', 2e9)"),
    ("rep_sep", "string.rep('x', 3e8, 'yy')"),
    ("rep_long_unit", "string.rep(string.rep('x', 1000), 1e6)"),
    ("format", "string.format(string.rep('%s', 200), table.unpack((function() local s = string.rep('a', 1e7) local t = {} for i = 1, 200 do t[i] = s end return t end)()))"),
    ("gsub", "string.gsub(string.rep('a', 1e6), 'a', string.rep('b', 5000))"),
    ("concat_table", "table.concat((function() local s = string.rep('a', 1e6) local t = {} for i = 1, 2000 do t[i] = s end return t end)())"),
    ("concat_op", "(function() local s = string.rep('x', 1e6) return s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s .. s end)()"),
]

# Allocations that grow without end: they fail eventually, under any limit.
RUNAWAY = [
    ("doubling", "local s = 'x' while true do s = s .. s end"),
    ("table_ints", "local t = {} for i = 1, 1e12 do t[i] = i end"),
    ("table_hash", "local t = {} for i = 1, 1e12 do t[i * 0.5] = i end"),
    ("strings", "local t = {} for i = 1, 1e12 do t[i] = string.rep('s', 1000) .. i end"),
    ("tables", "local t = {} for i = 1, 1e12 do t[i] = {i, i, i, string.rep('x', 500) .. i} end"),
    ("closures", "local t = {} for i = 1, 1e12 do local s = string.rep('c', 500) .. i t[i] = function() return s end end"),
    ("coroutines", "local t = {} for i = 1, 1e12 do t[i] = coroutine.create(function() return i end) end"),
    ("nested", "local t = {} local cur = t for i = 1, 1e12 do cur[1] = {string.rep('n', 500) .. i} cur = cur[1] end"),
]


def section_refused():
    for name, expr in HUGE:
        add("huge_%s" % name, "return pcall(function() return %s end)" % expr,
            "a request no limit allows")
        add("huge_%s_escaped" % name, "local r = %s\nreturn #r" % expr,
            "escaped: the chunk fails with it")
    add("huge_in_coroutine",
        "return coroutine.resume(coroutine.create(function() return string.rep('x', 2e9) end))",
        "inside a coroutine")
    add("huge_in_wrap",
        "return pcall(coroutine.wrap(function() return string.rep('x', 2e9) end))",
        "through coroutine.wrap")
    add("huge_in_gsub_callback",
        "return pcall(string.gsub, 'abc', '.', function(c) return string.rep(c, 2e9) end)",
        "inside a gsub callback")
    add("huge_in_index",
        "local t = setmetatable({}, {__index = function(t, k) return string.rep(k, 2e9) end})\n"
        "return pcall(function() return t.x end)",
        "inside __index")
    add("huge_in_tostring",
        "local t = setmetatable({}, {__tostring = function() return string.rep('x', 2e9) end})\n"
        "return pcall(tostring, t)",
        "inside __tostring")


def section_runaway():
    for name, body in RUNAWAY:
        add("runaway_%s" % name,
            "local ok, e = pcall(function() %s end)\ncollectgarbage()\n"
            "local u = {} for i = 1, 1000 do u[i] = tostring(i) end\nreturn ok, e, #u" % body,
            "runs out, is caught, and the script runs on")
    add("runaway_held_then_dropped",
        "local t = {}\nlocal ok, e = pcall(function() for i = 1, 1e12 do t[i] = string.rep('h', 1000) .. i end end)\n"
        "local held = #t > 100\nt = nil\ncollectgarbage()\n"
        "local u = {} for i = 1, 1000 do u[i] = string.rep('u', 100) .. i end\nreturn ok, e, held, #u",
        "what a failed loop built is dropped, and memory comes back")
    add("runaway_escaped",
        "local t = {} for i = 1, 1e12 do t[i] = string.rep('e', 1000) .. i end",
        "a runaway the chunk does not catch")
    add("runaway_in_coroutine",
        "local co = coroutine.create(function() local t = {} for i = 1, 1e12 do t[i] = string.rep('k', 1000) .. i end end)\n"
        "local ok, e = coroutine.resume(co)\nreturn ok, e, coroutine.status(co)",
        "a coroutine that runs out dies with the error")


def section_handlers():
    add("xpcall_skips_handler",
        "return xpcall(function() return string.rep('x', 2e9) end, function(m) return 'H:' .. m end)",
        "LUA_ERRMEM goes past the message handler")
    add("xpcall_runaway_skips_handler",
        "return xpcall(function() local t = {} for i = 1, 1e12 do t[i] = string.rep('z', 1000) .. i end end, "
        "function(m) return 'H:' .. m end)",
        "also when a loop runs out")
    add("xpcall_same_text_is_handled",
        "return xpcall(function() error('not enough memory', 0) end, function(m) return 'H:' .. m end)",
        "the same text, raised by error, is an ordinary error")
    add("xpcall_rethrown_is_handled",
        "local ok, e = pcall(string.rep, 'x', 2e9)\n"
        "return ok, e, xpcall(function() error(e, 0) end, function(m) return 'H:' .. tostring(m) end)",
        "re-raised by error, the message is an ordinary error")
    add("xpcall_handler_runs_out",
        "return xpcall(function() error('first', 0) end, function(m) return string.rep('x', 2e9) end)",
        "a handler that runs out")
    add("error_object_is_a_string",
        "local ok, e = pcall(string.rep, 'x', 2e9)\nreturn type(e), e == 'not enough memory', #e",
        "the error is the string itself")


def section_within():
    add("within_rep", "return #string.rep('x', 1e6)", "well within any limit")
    add("within_table", "local t = {} for i = 1, 1e5 do t[i] = i end return #t", "well within any limit")
    add("within_strings",
        "local t = {} for i = 1, 1e4 do t[i] = string.rep('w', 100) .. i end return #t, t[1e4]:sub(-5)",
        "well within any limit")
    add("within_garbage",
        "local n = 0 for i = 1, 2000 do local s = string.rep('g', 1e5) .. i n = n + #s end return n",
        "garbage far past the limit, never live at once")
    add("within_after_refusal",
        "local a = {pcall(string.rep, 'x', 2e9)}\nlocal b = {pcall(string.rep, 'x', 2e9)}\n"
        "return a[1], a[2], b[1], b[2], #string.rep('y', 1e5)",
        "a refusal leaves nothing behind")


def main():
    section_refused()
    section_runaway()
    section_handlers()
    section_within()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m64_memory.py; regenerate with ./regen_m64_memory.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
