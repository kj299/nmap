#!/usr/bin/env python3
"""Emit the M6.4a differential corpus: errors the VM raises, and `for` loops.

The oracle is nmap's own `liblua/`. Every case is a chunk named `=chunk`; the
driver (`oracle/m6_pattern_driver.lua`) renders what it returns, or the error
that escapes it, as hex. Unlike the earlier corpora, the gate compares escaped
errors WITH their `chunk:LINE:` position: the VM now adds it.

  A. every runtime error the VM raises -- index, call, arithmetic (including
     string operands, which go through the string metatable), bitwise,
     concatenation, comparison, length, division by zero, table keys -- over
     operands of every type, caught by pcall and escaped;
  B. numeric `for` loops over a grid of start, limit and step values: the
     integer extremes, floats including the infinities and NaN, numeric and
     non-numeric strings, and the wrong types, printing the iterations (capped)
     or the error;
  C. `error` at every level, with string and non-string values, through Lua
     functions, pcall, coroutines; `assert`;
  D. positions: errors on later lines, after comments and blank lines, and
     inside multi-line statements.

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


# Values of every type, as expressions. Each is bound to a local `v` inside
# the case, so that culprit descriptions name a local where PUC-Lua can.
VALUES = [
    ("nil", "nil"), ("true", "true"), ("int", "7"), ("float", "1.5"), ("zero", "0"),
    ("str", "'abc'"), ("numstr", "'10'"), ("floatstr", "'2.5'"), ("table", "{}"),
    ("func", "function() return 1 end"), ("co", "coroutine.create(function() end)"),
    ("named", "setmetatable({}, {__name = 'MyType'})"),
    ("named_num", "setmetatable({}, {__name = 5})"),
]

BINOPS = [
    ("add", "+"), ("sub", "-"), ("mul", "*"), ("div", "/"), ("mod", "%"), ("pow", "^"),
    ("idiv", "//"), ("band", "&"), ("bor", "|"), ("bxor", "~"), ("shl", "<<"), ("shr", ">>"),
    ("concat", ".."), ("lt", "<"), ("le", "<="), ("gt", ">"), ("ge", ">="), ("eq", "=="),
]


def section_a():
    for an, a in VALUES:
        for bn, b in VALUES:
            for on, op in BINOPS:
                add("bin_%s_%s_%s" % (an, on, bn),
                    "local a, b = %s, %s\nreturn pcall(function() return a %s b end)" % (a, b, op),
                    "binary operator")
    for vn, v in VALUES:
        for on, expr in [("unm", "-x"), ("bnot", "~x"), ("len", "#x"), ("index", "x.k"),
                         ("index_int", "x[1]"), ("call", "x()"), ("method", "x:m()"),
                         ("newindex", "(function() x.k = 1 end)()")]:
            add("un_%s_%s" % (on, vn),
                "local x = %s\nreturn pcall(function() return %s end)" % (v, expr), "unary operator")
    # Escaped, so the position comes from the chunk itself.
    for vn, v in VALUES[:6]:
        add("escaped_index_%s" % vn, "local x = %s\nreturn x.k" % v, "an escaped index error")
        add("escaped_arith_%s" % vn, "local x = %s\nreturn {} + x" % v, "an escaped arithmetic error")
    for name, src in [
        ("idiv_zero", "local a, b = 1, 0 return a // b"),
        ("mod_zero", "local a, b = 1, 0 return a % b"),
        ("idiv_zero_neg", "local a, b = -7, 0 return a // b"),
        ("fdiv_zero", "local a, b = 1, 0 return a / b, a // 0.0, a % 0.0 ~= a % 0.0"),
        ("str_idiv_zero", "return pcall(function() return '1' // '0' end)"),
        ("str_mod_zero", "return pcall(function() return '1' % 0 end)"),
        ("key_nil", "local t = {} t[nil] = 1"),
        ("key_nan", "local t = {} t[0/0] = 1"),
        ("key_nil_rawset", "return pcall(rawset, {}, nil, 1)"),
        ("concat_many", "local x return pcall(function() return 'a' .. 1 .. x .. 'b' end)"),
        ("concat_many2", "local x return pcall(function() return x .. 'a' .. 'b' end)"),
        ("concat_tail", "local x return pcall(function() return 'a' .. 'b' .. x end)"),
        ("concat_two_bad", "local x, y return pcall(function() return 'a' .. x .. y end)"),
        ("concat_float", "return 1.5 .. '' .. 2 .. -0.0"),
        ("cmp_mixed", "return pcall(function() return 1 < '2' end)"),
        ("cmp_str_num", "return pcall(function() return 'a' <= 1 end)"),
        ("call_through_meta", "local t = setmetatable({}, {__call = 5}) return pcall(function() return t() end)"),
        ("index_through_meta", "local t = setmetatable({}, {__index = function(t, k) error('idx ' .. k) end}) return pcall(function() return t.foo end)"),
        ("arith_meta_err", "local t = setmetatable({}, {__add = function() error('in add', 0) end}) return pcall(function() return t + 1 end)"),
        ("tostring_err", "local ok, e = pcall(function() local x; return x.y end) return type(e), #e > 0"),
        ("err_in_pcall_direct", "return pcall(error)"),
        ("len_string", "return #'abc', pcall(function() return #5 end)"),
    ]:
        add("misc_" + name, src, "runtime error")


FOR_VALUES = [
    ("i0", "0"), ("i1", "1"), ("im1", "-1"), ("i3", "3"), ("i10", "10"),
    ("max", "math.maxinteger"), ("min", "math.mininteger"),
    ("maxm1", "math.maxinteger - 1"), ("minp1", "math.mininteger + 1"),
    ("f05", "0.5"), ("fm05", "-0.5"), ("f15", "1.5"), ("big", "1e300"), ("f2_63", "2^63"),
    ("inf", "1/0"), ("ninf", "-1/0"), ("nan", "0/0"),
    ("s1", "'1'"), ("s25", "'2.5'"), ("sx", "'x'"), ("ssp", "' 3 '"),
    ("nil", "nil"), ("tbl", "{}"), ("bool", "true"),
]
FOR_STEPS = [
    ("s1", "1"), ("s2", "2"), ("sm1", "-1"), ("sm3", "-3"), ("s0", "0"), ("s00", "0.0"),
    ("s05", "0.5"), ("sm05", "-0.5"), ("smax", "math.maxinteger"), ("smin", "math.mininteger"),
    ("sinf", "1/0"), ("snan", "0/0"), ("sstr", "'1'"), ("sx", "'x'"), ("snil", "nil"),
]
FOR_BODY = (
    "local out, n = {}, 0\n"
    "local ok, e = pcall(function()\n"
    "  for i = %s, %s, %s do\n"
    "    n = n + 1\n"
    "    if n <= 6 then out[#out + 1] = math.type(i) .. ':' .. tostring(i) end\n"
    "    if n >= 40 then break end\n"
    "  end\n"
    "end)\n"
    "return ok, e, n, table.concat(out, ',')"
)


def section_b():
    for iname, init in FOR_VALUES:
        for lname, limit in FOR_VALUES:
            for sname, step in FOR_STEPS:
                add("for_%s_%s_%s" % (iname, lname, sname), FOR_BODY % (init, limit, step), "numeric for")
    for iname, init in FOR_VALUES:
        for lname, limit in FOR_VALUES:
            add("for2_%s_%s" % (iname, lname),
                (FOR_BODY % (init, limit, "1")).replace(", 1 do", " do"), "numeric for, default step")
    add("for_var_is_copy", "local s = 0 for i = 1, 3 do i = i * 10 s = s + i end return s", "assigning the control variable")
    add("for_float_accum", "local t = {} for x = 0, 1, 0.1 do t[#t+1] = x end return #t, t[#t]", "float accumulation")
    add("for_escaped_step0", "for i = 1, 2, 0 do end", "escaped 'for' step is zero")
    add("for_escaped_init", "for i = 'a', 2 do end", "escaped bad initial value")


def section_c():
    defs = (
        "local function lvl(m, l) error(m, l) end\n"
        "local function mid(m, l) lvl(m, l) end\n"
        "local function outer(m, l) mid(m, l) end\n"
    )
    for lvl in ["nil", "0", "1", "2", "3", "4", "5", "9", "-1", "1.0", "'2'"]:
        add("error_level_%s" % lvl.replace("'", "q").replace(".", "_").replace("-", "m"),
            defs + "return pcall(outer, 'msg', %s)" % lvl, "error at a level")
    for name, src in [
        ("table", "return pcall(error, {})"),
        ("number", "return pcall(function() error(42) end)"),
        ("nil", "return pcall(function() error() end)"),
        ("nil_lvl", "return pcall(function() error(nil, 2) end)"),
        ("direct_pcall", "return pcall(error, 'x')"),
        ("direct_pcall_lvl2", "return pcall(error, 'x', 2)"),
        ("in_coroutine", "local co = coroutine.create(function() error('in co') end) return coroutine.resume(co)"),
        ("in_coroutine_lvl2", "local co = coroutine.create(function() error('in co', 2) end) return coroutine.resume(co)"),
        ("wrap", "local w = coroutine.wrap(function() error('in wrap') end) return pcall(w)"),
        ("xpcall", "return xpcall(function() error('x') end, function(e) return 'H:' .. e end)"),
        ("escaped", "error('top')"),
        ("escaped_lvl2", "local function f() error('two', 2) end\nf()"),
        ("escaped_table", "error({})"),
        ("assert_plain", "return pcall(function() assert(false) end)"),
        ("assert_msg", "return pcall(function() assert(nil, 'given') end)"),
        ("assert_tbl", "return pcall(function() assert(false, {}) end)"),
        ("assert_direct", "return pcall(assert, false)"),
        ("assert_escaped", "assert(1 == 2)"),
        ("tail_call", "local function f() return error('tail') end return pcall(function() return f() end)"),
    ]:
        add("error_" + name, src, "error and assert")


def section_d():
    add("line_after_blank", "\n\n\nlocal x\nreturn x.y", "position after blank lines")
    add("line_after_comment", "-- a\n--[[ b\nc ]]\nlocal x\nreturn x.y", "position after comments")
    add("line_in_function", "local function f()\n  local a = 1\n\n  return a .. {}\nend\nreturn pcall(f)", "position inside a function")
    add("line_multi_expr", "local t = {}\nreturn pcall(function()\n  return 1 +\n    t\nend)", "an operator split over lines")
    add("line_multi_call", "local x\nreturn pcall(function()\n  return f(\n    1,\n    x.y)\nend)", "an argument on a later line")
    add("line_multi_table", "local x\nreturn pcall(function()\n  local t = {\n    a = 1,\n    b = x.y,\n  }\nend)", "a table constructor over lines")
    add("line_long_string", "local s = [[\n\n\n]]\nlocal x\nreturn pcall(function() return x.y end)", "after a long string")
    add("line_error_call", "return pcall(function()\n\n  error('late')\nend)", "error on a later line")


def main():
    section_a()
    section_b()
    section_c()
    section_d()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m64_errors.py; regenerate with ./regen_m64_errors.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
