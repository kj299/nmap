#!/usr/bin/env python3
"""Emit the M6.4c stdlib corpus: `utf8`, `os` (the clock), `io` (files) and
`debug.getinfo`, as NSE scripts get them.

The oracle is nmap's own `liblua/`, run with `TZ=UTC` from
`tests/differential/m6/` (so `fixtures/io/...` resolves) and with
`/tmp/m64io/` as a scratch directory for files a case writes. The port runs
each case with the same fixture files in an in-memory file system, and the
same scratch directory in it.

  A. utf8: every function over valid and invalid sequences and a grid of
     positions, strict and lax, and `char` over the encodable range's edges.
  B. os.date over every conversion, in UTC and "local" time, at times from the
     year 1 to past 9999, as a table and as text; os.time over complete,
     partial, unnormalised and invalid tables; os.difftime.
  C. io: every read format over fixture files with lines, numbers, binary
     data and no newline; lines iterators; seek; writing and reading back;
     the errors of each, and of closed files and bad modes.
  D. debug.getinfo of Lua functions, main chunks and C functions, by level
     and by value, with each option letter.

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


def lua_str(b):
    """A Lua string literal for bytes `b`."""
    return '"' + "".join("\\%d" % c if c < 32 or c >= 127 or chr(c) in '"\\' else chr(c) for c in b) + '"'


UTF8_STRINGS = [
    ("empty", b""),
    ("ascii", b"abc"),
    ("two", "h\u00e9llo".encode()),
    ("three", "\u20ac1".encode()),
    ("four", "a\U0001F600b".encode()),
    ("max", "\U0010FFFF".encode()),
    ("ff", b"\xff"),
    ("overlong", b"\xc0\x80"),
    ("overlong3", b"\xe0\x80\x80"),
    ("surrogate", b"\xed\xa0\x80"),
    ("past_max", b"\xf4\x90\x80\x80"),
    ("five", b"\xf8\x88\x80\x80\x80"),
    ("six", b"\xfc\x84\x80\x80\x80\x80"),
    ("six_max", b"\xfd\xbf\xbf\xbf\xbf\xbf"),
    ("fe", b"\xfe\x80\x80\x80\x80\x80\x80"),
    ("lead_cont", b"\x80abc"),
    ("truncated", b"ab\xc3"),
    ("truncated4", b"\xf0\x9f\x98"),
    ("mixed", b"a\xc3\xa9\xff\xe2\x82\xacz"),
    ("nul", b"a\x00\xc3\xa9"),
]


def section_utf8():
    for name, s in UTF8_STRINGS:
        L = lua_str(s)
        add("utf8_len_%s" % name, "return utf8.len(%s)" % L, "utf8.len")
        add("utf8_len_lax_%s" % name, "return utf8.len(%s, 1, -1, true)" % L, "utf8.len lax")
        for i in [-8, -1, 0, 1, 2, 4, 8]:
            for j in [-9, -1, 0, 2, 7]:
                add("utf8_len_%s_%d_%d" % (name, i, j),
                    "return pcall(utf8.len, %s, %d, %d)" % (L, i, j), "utf8.len positions")
        add("utf8_codepoint_all_%s" % name, "return pcall(utf8.codepoint, %s, 1, -1)" % L, "codepoint")
        add("utf8_codepoint_lax_%s" % name, "return pcall(utf8.codepoint, %s, 1, -1, true)" % L, "codepoint lax")
        for i in [-3, 0, 1, 2, 3, 5]:
            add("utf8_codepoint_%s_%d" % (name, i), "return pcall(utf8.codepoint, %s, %d)" % (L, i), "codepoint at")
        for n in [-3, -1, 0, 1, 2, 3, 6]:
            add("utf8_offset_%s_%d" % (name, n), "return pcall(utf8.offset, %s, %d)" % (L, n), "offset")
            for i in [-2, 1, 2, 3]:
                add("utf8_offset_%s_%d_%d" % (name, n, i),
                    "return pcall(utf8.offset, %s, %d, %d)" % (L, n, i), "offset from")
        for lax in ["false", "true"]:
            add("utf8_codes_%s_%s" % (name, lax),
                "local t = {}\nlocal ok, e = pcall(function() for p, c in utf8.codes(%s, %s) do t[#t+1] = p .. ':' .. c end end)\n"
                "return ok, e, table.concat(t, ',')" % (L, lax), "codes")
        add("utf8_match_%s" % name,
            "local t = {}\nfor c in string.gmatch(%s, utf8.charpattern) do t[#t+1] = #c end\nreturn table.concat(t, ',')" % L,
            "charpattern")
    for v in ["0", "65", "0x7F", "0x80", "0x7FF", "0x800", "0xFFFF", "0x10000", "0x10FFFF", "0x110000",
              "0x3FFFFFF", "0x4000000", "0x7FFFFFFF", "0x80000000", "-1", "math.mininteger", "3.0", "'66'",
              "1.5", "nil", "{}"]:
        add("utf8_char_%s" % v.replace("'", "q").replace(".", "_").replace("-", "m").replace("{}", "tbl"),
            "return pcall(utf8.char, %s)" % v, "char")
    add("utf8_char_many", "return utf8.char(72, 0xE9, 0x20AC, 0x1F600, 0)", "char, several")
    add("utf8_char_none", "return utf8.char()", "char, none")
    add("utf8_charpattern", "return utf8.charpattern", "charpattern")
    add("utf8_codes_iter_args", "local f, s, i = utf8.codes('ab') return type(f), s, i", "codes returns")
    add("utf8_codes_bad", "return pcall(utf8.codes, '\\128ab')", "codes on a continuation byte")
    add("utf8_len_bad_arg", "return pcall(utf8.len, {})", "len type error")
    add("utf8_offset_cont", "return pcall(utf8.offset, '\\195\\169', 1, 2)", "offset from a continuation byte")


TIMES = ["0", "1", "-1", "59", "86399", "86400", "951782400", "951868800", "1000000000",
         "2147483647", "2147483648", "-2147483648", "253402300799", "253402300800",
         "-62135596800", "-62135596801", "-62198755200", "67767976233316799", "67767976233316800",
         "-67768040609740800", "-67768040609740801", "2^62|0", "math.mininteger"]
CONVERSIONS = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%"
TWO_CHAR = ["Ec", "EC", "Ex", "EX", "Ey", "EY", "Od", "Oe", "OH", "OI", "Om", "OM", "OS", "Ou", "OU",
            "OV", "Ow", "OW", "Oy"]


def section_os():
    for t in TIMES:
        tn = t.replace("-", "m").replace("^", "e").replace("|", "_").replace(".", "_")
        for bang in ["", "!"]:
            fmt = "".join("%s=%%%s|" % (c if c != "%" else "pct", c) for c in CONVERSIONS)
            add("os_date_%s%s" % ("utc_" if bang else "", tn),
                "return pcall(os.date, %s, %s)" % (lua_str((bang + fmt).encode()), t), "os.date conversions")
            add("os_date_two_%s%s" % ("utc_" if bang else "", tn),
                "return pcall(os.date, %s, %s)" % (lua_str((bang + "|".join("%" + c for c in TWO_CHAR)).encode()), t),
                "os.date E and O conversions")
            add("os_date_t_%s%s" % ("utc_" if bang else "", tn),
                "local ok, t = pcall(os.date, '%s*t', %s)\n"
                "if not ok then return ok, t end\n"
                "return t.year, t.month, t.day, t.hour, t.min, t.sec, t.yday, t.wday, t.isdst" % (bang, t),
                "os.date table")
    # Every day of a few years near ISO week boundaries.
    for y in [2004, 2005, 2008, 2009, 2010, 2020, 2021]:
        add("os_date_weeks_%d" % y,
            "local out = {}\nfor d = -3, 7 do\n"
            "  local t = os.time{year=%d, month=1, day=d, hour=12}\n"
            "  out[#out+1] = os.date('!%%Y-%%m-%%d %%a %%U %%W %%V %%G %%g %%u %%w %%j', t)\n"
            "end\nfor d = 25, 34 do\n"
            "  local t = os.time{year=%d, month=12, day=d, hour=12}\n"
            "  out[#out+1] = os.date('!%%Y-%%m-%%d %%a %%U %%W %%V %%G %%g %%u %%w %%j', t)\n"
            "end\nreturn table.concat(out, '|')" % (y, y), "week numbers around new year")
    for name, f in [("default", "nil"), ("empty", "''"), ("literal", "'no conversions'"),
                    ("pct_end", "'%'"), ("bad", "'%Q'"), ("bad_rest", "'%Q and more'"), ("E_alone", "'%E'"),
                    ("Ez", "'%Ez'"), ("width", "'%5d'"), ("bang_only", "'!'"), ("star_t_nul", "'*t\\0x'"),
                    ("nul_inside", "'a\\0%Y'"), ("number_fmt", "12"), ("table_fmt", "{}")]:
        add("os_date_fmt_%s" % name,
            "local ok, r = pcall(os.date, %s, 0)\nif type(r) == 'table' then r = 'table' end\nreturn ok, r" % f,
            "os.date formats")
    add("os_date_time_float", "return pcall(os.date, '!%Y', 1.0)", "time as an integral float")
    add("os_date_time_frac", "return pcall(os.date, '!%Y', 1.5)", "time with a fraction")
    add("os_date_time_str", "return pcall(os.date, '!%Y', '86400')", "time as a numeral")
    add("os_date_time_bad", "return pcall(os.date, '!%Y', 'x')", "time not a number")
    add("os_date_type", "return type(os.date()), type(os.date('*t'))", "now")

    def tm(**kw):
        return "{" + ", ".join("%s=%s" % (k, v) for k, v in kw.items()) + "}"
    tables = [
        ("epoch", tm(year=1970, month=1, day=1, hour=0)),
        ("noon_default", tm(year=2000, month=1, day=1)),
        ("full", tm(year=2021, month=6, day=15, hour=13, min=45, sec=30)),
        ("leap", tm(year=2000, month=2, day=29, hour=0)),
        ("month13", tm(year=2000, month=13, day=1, hour=0)),
        ("month0", tm(year=2000, month=0, day=1, hour=0)),
        ("month_neg", tm(year=2000, month=-25, day=1, hour=0)),
        ("day0", tm(year=2000, month=3, day=0, hour=0)),
        ("day400", tm(year=2000, month=1, day=400, hour=0)),
        ("day_neg", tm(year=2000, month=1, day=-400, hour=0)),
        ("sec_big", tm(year=2000, month=1, day=1, hour=0, sec=100000)),
        ("min_neg", tm(year=2000, month=1, day=1, hour=0, min=-1)),
        ("hour48", tm(year=2000, month=1, day=1, hour=48)),
        ("all_wrap", tm(year=1999, month=12, day=31, hour=23, min=59, sec=60)),
        ("isdst_false", tm(year=2000, month=1, day=1, hour=0, isdst="false")),
        ("isdst_true", tm(year=2000, month=1, day=1, hour=0, isdst="true")),
        ("minus_one", tm(year=1969, month=12, day=31, hour=23, min=59, sec=59)),
        ("year1", tm(year=1, month=1, day=1, hour=0)),
        ("year0", tm(year=0, month=1, day=1, hour=0)),
        ("year_neg", tm(year=-1000, month=1, day=1, hour=0)),
        ("year_big", tm(year=100000000, month=1, day=1, hour=0)),
        ("year_int_max", tm(year=2147483647, month=1, day=1, hour=0)),
        ("year_past_int", tm(year=2147485547, month=1, day=1, hour=0)),
        ("year_past_int2", tm(year=2147485548, month=1, day=1, hour=0)),
        ("year_low", tm(year=-2147481748, month=1, day=1, hour=0)),
        ("year_low2", tm(year=-2147481749, month=1, day=1, hour=0)),
        ("strings", tm(year="'2000'", month="'2'", day="'3'", hour="'4'")),
        ("floats", tm(year=2000.0, month=2.0, day=3.0)),
        ("frac", tm(year=2000.5, month=1, day=1)),
        ("bad_type", tm(year=2000, month="'x'", day=1)),
        ("bool_field", tm(year=2000, month=1, day="true")),
        ("no_year", tm(month=1, day=1)),
        ("no_month", tm(year=2000, day=1)),
        ("no_day", tm(year=2000, month=1)),
        ("sec_out", tm(year=2000, month=1, day=1, sec=2**31)),
        ("month_out", tm(year=2000, month=2**31, day=1)),
        ("month_edge", tm(year=2000, month=2**31 - 1 + 1, day=1)),
    ]
    for name, t in tables:
        add("os_time_%s" % name,
            "local t = %s\nlocal ok, r = pcall(os.time, t)\n"
            "return ok, r, t.year, t.month, t.day, t.hour, t.min, t.sec, t.yday, t.wday, t.isdst" % t,
            "os.time")
    add("os_time_none", "return math.type(os.time())", "os.time now")
    add("os_time_nil", "return math.type(os.time(nil))", "os.time nil")
    add("os_time_bad", "return pcall(os.time, 5)", "os.time type error")
    add("os_time_roundtrip", "local t = os.time() return os.time(os.date('*t', t)) == t", "round trip")
    for a, b in [("10", "3"), ("3", "10"), ("0", "0"), ("math.maxinteger", "math.mininteger"),
                 ("1.0", "2"), ("1.5", "1"), ("'5'", "1"), ("1", "nil"), ("{}", "1")]:
        add("os_difftime_%s_%s" % (a.replace(".", "_").replace("'", "q"), b.replace(".", "_").replace("'", "q")),
            "return pcall(os.difftime, %s, %s)" % (a, b), "os.difftime")
    add("os_difftime_one", "return pcall(os.difftime, 5)", "os.difftime one argument")
    add("os_clock", "return math.type(os.clock())", "os.clock")


IO = "fixtures/io/"


def section_io():
    reads = [
        ("lines_default", "lines.txt", "f:read()"),
        ("lines_l", "lines.txt", "f:read('l')"),
        ("lines_L", "lines.txt", "f:read('L')"),
        ("lines_star", "lines.txt", "f:read('*l')"),
        ("lines_a", "lines.txt", "f:read('a')"),
        ("lines_all_a", "lines.txt", "f:read('a', 'a')"),
        ("lines_several", "lines.txt", "f:read('l', 'l', 'l', 'l', 'l', 'l')"),
        ("lines_L_several", "lines.txt", "f:read('L', 'L', 'L', 'L', 'L', 'L')"),
        ("lines_n", "lines.txt", "f:read('n')"),
        ("lines_0", "lines.txt", "f:read(0)"),
        ("lines_5", "lines.txt", "f:read(5)"),
        ("lines_mix", "lines.txt", "f:read(3, 'l', 0, 'L', 100, 0)"),
        ("lines_huge", "lines.txt", "f:read(1000000)"),
        ("empty_l", "empty.txt", "f:read('l')"),
        ("empty_L", "empty.txt", "f:read('L')"),
        ("empty_a", "empty.txt", "f:read('a')"),
        ("empty_0", "empty.txt", "f:read(0)"),
        ("empty_5", "empty.txt", "f:read(5)"),
        ("empty_n", "empty.txt", "f:read('n')"),
        ("numbers_n", "numbers.txt", "f:read('n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n')"),
        ("numbers_n_then_l", "numbers.txt", "f:read('n', 'l', 'n', 'n', 'l')"),
        ("crlf", "crlf.txt", "f:read('l', 'L', 'l')"),
        ("binary_a", "binary.bin", "f:read('a')"),
        ("binary_l", "binary.bin", "f:read('l', 'l')"),
        ("long_l", "long.txt", "#f:read('l'), f:read('l')"),
        ("big_a", "big.txt", "#f:read('a')"),
        ("bad_format", "lines.txt", "f:read('x')"),
        ("bad_format_star", "lines.txt", "f:read('*x')"),
        ("bad_format_type", "lines.txt", "f:read({})"),
        ("neg_count", "lines.txt", "f:read(-1)"),
        ("float_count", "lines.txt", "f:read(2.0)"),
        ("frac_count", "lines.txt", "f:read(2.5)"),
    ]
    for name, file, expr in reads:
        add("io_read_%s" % name,
            "local f = assert(io.open(%r))\nlocal r = table.pack(pcall(function() return %s end))\nf:close()\n"
            "return table.unpack(r, 1, r.n)" % (IO + file, expr), "file:read")
    for name, file, fmts in [("plain", "lines.txt", ""), ("L", "lines.txt", "'L'"), ("n", "numbers.txt", "'n'"),
                             ("two", "lines.txt", "1, 'l'"), ("empty", "empty.txt", ""),
                             ("crlf", "crlf.txt", "")]:
        args = (", " + fmts) if fmts else ""
        add("io_lines_%s" % name,
            "local t = {}\nlocal ok, e = pcall(function() for a, b in io.lines(%r%s) do t[#t+1] = tostring(a) .. '/' .. tostring(b) end end)\n"
            "return ok, e, table.concat(t, '|')" % (IO + file, args), "io.lines")
        add("io_flines_%s" % name,
            "local f = assert(io.open(%r))\nlocal t = {}\nfor a, b in f:lines(%s) do t[#t+1] = tostring(a) .. '/' .. tostring(b) end\n"
            "local after = io.type(f)\nf:close()\nreturn table.concat(t, '|'), after" % (IO + file, fmts),
            "file:lines")
    add("io_lines_missing", "return pcall(io.lines, 'fixtures/io/nonexistent')", "io.lines on a missing file")
    add("io_lines_too_many", "return pcall(io.lines, 'fixtures/io/lines.txt', " + ", ".join(["'l'"] * 251) + ")",
        "io.lines with too many formats")
    add("io_lines_closes", "local it = io.lines('fixtures/io/empty.txt')\nit()\nreturn pcall(it)",
        "io.lines iterator after the end")
    for name, path, mode in [("missing", "fixtures/io/nonexistent", "r"), ("dir_missing", "/nonexistent-dir/x", "w"),
                             ("bad_mode", "fixtures/io/lines.txt", "x"), ("bad_mode_plus", "fixtures/io/lines.txt", "r++"),
                             ("mode_b", "fixtures/io/lines.txt", "rb"), ("mode_bb", "fixtures/io/lines.txt", "rbb"),
                             ("mode_rplusb", "fixtures/io/lines.txt", "r+b"), ("mode_empty", "fixtures/io/lines.txt", ""),
                             ("mode_nul", "fixtures/io/lines.txt", "r\\0x")]:
        add("io_open_%s" % name,
            "local f, e, n = io.open(%r, %s)\nif f then f:close() return 'opened' end\nreturn f, e, n" % (path, lua_str(mode.encode()) if "\\0" not in mode else '"r\\0x"'),
            "io.open")
    add("io_open_bad_name", "return pcall(io.open, {})", "io.open type error")
    seeks = [("cur", "f:seek()"), ("set", "f:seek('set', 6), f:read(6)"), ("end", "f:seek('end'), f:read('a')"),
             ("end_back", "f:seek('end', -9), f:read('a')"), ("cur_fwd", "f:read(3), f:seek('cur', 2), f:read(4)"),
             ("before_start", "f:seek('set', -1)"), ("bad_whence", "f:seek('middle')"),
             ("after_read", "f:read('l'), f:seek()"), ("frac", "f:seek('set', 1.5)")]
    for name, expr in seeks:
        add("io_seek_%s" % name,
            "local f = assert(io.open('fixtures/io/lines.txt'))\nlocal r = table.pack(pcall(function() return %s end))\nf:close()\n"
            "return table.unpack(r, 1, r.n)" % expr, "file:seek")
    writes = [
        ("strings", "f:write('a', 'b', 'c\\n')"),
        ("numbers", "f:write(1, ' ', 2.5, ' ', 1.0, ' ', -0.0, ' ', 1e100, ' ', 2^63, ' ', math.mininteger)"),
        ("chain", "f:write('x'):write('y')"),
        ("bad", "f:write({})"),
        ("nil", "f:write(nil)"),
        ("binary", "f:write('\\0\\1\\255')"),
    ]
    for name, expr in writes:
        add("io_write_%s" % name,
            "local path = '/tmp/m64io/w_%s'\nlocal f = assert(io.open(path, 'w'))\n"
            "local r = table.pack(pcall(function() return %s end))\nf:close()\n"
            "local g = assert(io.open(path, 'rb'))\nlocal back = g:read('a')\ng:close()\n"
            "return r[1], io.type(r[2]) or r[2], back" % (name, expr), "file:write")
    add("io_update_mode",
        "local path = '/tmp/m64io/upd'\nlocal f = assert(io.open(path, 'w+'))\nf:write('hello world')\n"
        "f:seek('set', 6)\nlocal w = f:read('a')\nf:seek('set', 0)\nf:write('J')\nf:seek('set', 0)\n"
        "local all = f:read('a')\nf:close()\nreturn w, all", "w+ reading and writing")
    add("io_append",
        "local path = '/tmp/m64io/app'\nlocal f = assert(io.open(path, 'w'))\nf:write('one\\n')\nf:close()\n"
        "f = assert(io.open(path, 'a'))\nf:write('two\\n')\nf:close()\n"
        "f = assert(io.open(path))\nlocal all = f:read('a')\nf:close()\nreturn all", "append")
    add("io_read_then_write",
        "local path = '/tmp/m64io/rw'\nlocal f = assert(io.open(path, 'w'))\nf:write('abcdef')\nf:close()\n"
        "f = assert(io.open(path, 'r+'))\nlocal a = f:read(2)\nf:seek('cur', 0)\nf:write('XY')\nf:seek('set', 0)\n"
        "local all = f:read('a')\nf:close()\nreturn a, all", "r+ read then write")
    add("io_output_redirect",
        "local path = '/tmp/m64io/out'\nlocal old = io.output()\nio.output(path)\nio.write('via io.write ', 7, '\\n')\n"
        "io.close()\nio.output(old)\nlocal f = assert(io.open(path))\nlocal all = f:read('a')\nf:close()\nreturn all",
        "io.output and io.write")
    add("io_output_missing_dir", "return pcall(io.output, '/nonexistent-dir/x')", "io.output to a missing directory")
    add("io_closed_read",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nf:close()\nreturn pcall(f.read, f)", "read a closed file")
    add("io_closed_close",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nf:close()\nreturn pcall(f.close, f)", "close twice")
    add("io_closed_tostring",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nf:close()\nreturn tostring(f)", "tostring of a closed file")
    add("io_tostring_open",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nlocal s = tostring(f)\nf:close()\nreturn s:match('^file %(') ~= nil",
        "tostring of an open file")
    add("io_type",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nlocal a = io.type(f)\nf:close()\n"
        "return a, io.type(f), io.type(5), io.type(io.stdout)", "io.type")
    add("io_close_stdout", "return io.stdout:close()", "closing standard output")
    add("io_bad_self", "return pcall(io.stdout.read, 5)", "a method on something that is not a file")
    add("io_setvbuf",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nlocal a = f:setvbuf('no')\n"
        "local b = table.pack(pcall(f.setvbuf, f, 'bogus'))\nf:close()\nreturn a, b[1], b[2]", "setvbuf")
    add("io_flush",
        "local f = assert(io.open('/tmp/m64io/fl', 'w'))\nlocal r = f:flush()\nf:close()\nreturn io.type(r)", "flush")
    add("io_close_returns",
        "local f = assert(io.open('fixtures/io/lines.txt'))\nreturn f:close()", "close's result")


def section_debug():
    for name, src in [
        ("main_S", "local i = debug.getinfo(1, 'S') return i.what, i.source, i.short_src, i.linedefined"),
        ("main_l", "\n\nlocal i = debug.getinfo(1, 'l') return i.currentline"),
        ("func_S", "local function f()\n  local i = debug.getinfo(1, 'S')\n  return i.what, i.short_src, i.linedefined\nend\nreturn f()"),
        ("func_l", "local function f()\n\n  return debug.getinfo(1, 'l').currentline\nend\nreturn f()"),
        ("level2", "local function f() return debug.getinfo(2, 'Sl') end\nlocal function g()\n  local i = f()\n  return i.what, i.currentline, i.linedefined\nend\nreturn g()"),
        ("level0", "local i = debug.getinfo(0, 'S') return i.what, i.source, i.short_src, i.linedefined, i.lastlinedefined"),
        ("past_top", "return debug.getinfo(100)"),
        ("by_value_lua", "local function f(a, b, ...) end\nlocal i = debug.getinfo(f, 'Su')\nreturn i.what, i.linedefined, i.nparams, i.isvararg, i.nups"),
        ("by_value_c", "local i = debug.getinfo(print, 'Su')\nreturn i.what, i.source, i.short_src, i.linedefined, i.nparams, i.isvararg, i.nups"),
        ("by_value_l", "local function f() end\nreturn debug.getinfo(f, 'l').currentline"),
        ("by_value_func", "local function f() end\nreturn debug.getinfo(f, 'f').func == f"),
        ("upvalues", "local a, b = 1, 2\nlocal function f() return a + b end\nreturn debug.getinfo(f, 'u').nups"),
        ("bad_option", "return pcall(debug.getinfo, 1, 'X')"),
        ("bad_gt", "return pcall(debug.getinfo, 1, '>S')"),
        ("bad_level_type", "return pcall(debug.getinfo, 'x')"),
        ("t_option", "return debug.getinfo(1, 't').istailcall"),
        ("from_pcall", "return pcall(function() local i = debug.getinfo(2, 'S') return i.what end)"),
        ("traceback_nonstring", "local t = {} return debug.traceback(t) == t"),
        ("traceback_first_line", "return (debug.traceback('msg'):match('^([^\\n]*)\\n'))"),
        ("traceback_header", "return (debug.traceback('msg'):match('^[^\\n]*\\n([^\\n]*)'))"),
        ("traceback_nil", "return (debug.traceback():match('^([^\\n]*)'))"),
    ]:
        add("debug_" + name, src, "debug")


def main():
    section_utf8()
    section_os()
    section_io()
    section_debug()
    out = sys.stdout
    out.write("# name\tchunk_hex\tnote\n")
    out.write("# Generated by oracle/gen_m64_stdlib.py; regenerate with ./regen_m64_stdlib.sh.\n")
    for name, chunk, note in CASES:
        out.write("%s\t%s\t%s\n" % (name, chunk.encode("latin-1").hex(), note))


if __name__ == "__main__":
    main()
