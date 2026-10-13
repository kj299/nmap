-- The probe for the base and coroutine libraries (lbaselib.c, lcorolib.c),
-- with string.char, the string metatable's arithmetic and the table
-- functions' checks, as an NSE script meets them: run as a prerule by nmap
-- 7.94 with --datadir set to this repository, and by the port's engine
-- (crates/core/tests/base_differential.rs). It writes one line per row to the
-- file named by --script-args out=PATH, `row|name|values`, then `done`, and
-- calls `warn`, whose output nmap writes to standard error (the generator
-- records those lines as `warn|...`).
--
-- What only an NSE state shows, which the tail corpus (the standalone `lua`)
-- cannot: the warning system as nmap's `luaL_newstate` leaves it (off until
-- "@on"), the collector's starting mode (incremental), and the coroutine
-- functions inside a script's own coroutine. The rest are the base library's
-- argument checks and results, every one deterministic.
--
-- A row whose error carries a position is run in a chunk loaded under a fixed
-- name, so no path of this file appears in the golden. A `pcall` is the last
-- expression of its row, so none of its results is cut.

description = "M6 base-library probe"
categories = {"m6probe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local nmap = require "nmap"

prerule = function() return true end

local out
local function w(s) out:write(s, "\n") end

local function esc(s)
  return (s:gsub("[^\32-\126]", function(c) return string.format("\\x%02x", c:byte()) end)
           :gsub("|", "\\x7c"))
end

local function render(v)
  local t = type(v)
  if t == "table" or t == "function" or t == "thread" or t == "userdata" then return t end
  return esc(tostring(v))
end

local function row(name, ...)
  local p = table.pack(...)
  local s = {}
  for i = 1, p.n do s[i] = render(p[i]) end
  w("row|" .. name .. "|" .. table.concat(s, ","))
end

-- A chunk loaded as "probe", run under pcall: its error is positioned there.
local function inchunk(src) return pcall(assert(load(src, "=probe"))) end

action = function()
  out = assert(io.open(assert(nmap.registry.args.out, "out=PATH"), "w"))

  -- warn: off until "@on", control messages are one piece, pieces are joined,
  -- each cut at a NUL.
  warn("hidden1") warn("@on") warn("shown1") warn("a", "b", 3) warn("@off") warn("hidden2")
  warn("x", "@on") warn("shown2") warn("@on", "y") warn("z\0cut") warn("@off")
  row("warn_noarg", pcall(warn))
  row("warn_table", pcall(warn, "a", {}))

  -- coroutines, from inside the script's own
  row("isyieldable", coroutine.isyieldable())
  row("isyieldable_self", coroutine.isyieldable((coroutine.running())))
  row("status_self", coroutine.status((coroutine.running())))
  row("running_main", select(2, coroutine.running()))
  row("close_self", pcall(coroutine.close, (coroutine.running())))
  local outer = coroutine.running()
  local co = coroutine.create(function() return coroutine.status(outer) end)
  row("status_normal", coroutine.resume(co))
  row("resume_dead", coroutine.resume(co))
  local dead = coroutine.create(function() error("boom", 0) end)
  coroutine.resume(dead)
  row("close_dead", coroutine.close(dead))
  row("close_again", coroutine.close(dead))
  row("create_table", pcall(coroutine.create, setmetatable({}, {__call = function() end})))
  row("wrap_error", pcall(coroutine.wrap(function() error({}) end)))

  -- collectgarbage, as nmap's state starts it
  row("cg_collect", collectgarbage("collect"), collectgarbage())
  row("cg_isrunning", collectgarbage("isrunning"))
  row("cg_mode", collectgarbage("incremental"))
  row("cg_pause", collectgarbage("setpause", 200), collectgarbage("setstepmul", 100))
  row("cg_stop", collectgarbage("stop"), collectgarbage("isrunning"), collectgarbage("restart"), collectgarbage("isrunning"))
  row("cg_count", math.type(collectgarbage("count")))
  row("cg_step", type(collectgarbage("step")))
  row("cg_bad", pcall(collectgarbage, "bogus"))

  -- pcall, raw access, pairs, select, type, tostring, tonumber, metatables
  row("pcall_nil", pcall(pcall, nil))
  row("pcall_none", pcall(pcall))
  row("rawlen", pcall(rawlen, "abc"))
  row("rawlen_bad", inchunk("return rawlen(5)"))
  row("rawset_2", pcall(rawset, {}, "k"))
  row("rawget_1", pcall(rawget, {}))
  row("rawequal", rawequal("a", "a"), rawequal({}, {}))
  row("rawequal_one", pcall(rawequal, 1))
  row("pairs_n", select('#', pairs({})), select('#', ipairs({})))
  row("pairs_meta", select('#', pairs(setmetatable({}, {__pairs = function() return 1, 2, 3, 4 end}))))
  local idx = setmetatable({}, {__index = function(_, i) if i <= 3 then return i * 10 end end})
  local sum = 0
  for _, v in ipairs(idx) do sum = sum + v end
  row("ipairs_index", sum)
  row("next_float", pcall(next, {[1] = 1}, 1.0))
  row("next_none", pcall(next))
  row("select0", pcall(select, 0))
  row("select_neg", select(-1, "a", "b"), select('#', select(2, "a", "b", "c")))
  row("select_far", pcall(select, -5, "a"))
  row("type_none", pcall(type))
  row("tostring_bad", pcall(tostring, setmetatable({}, {__tostring = function() return {} end})))
  row("tostring_num", tostring(setmetatable({}, {__tostring = function() return 42 end})))
  row("tostring_name", (tostring(setmetatable({}, {__name = "Thing"})):gsub("0x%x+", "ADDR")))
  row("tonumber", tonumber("  0x10  "), tonumber("1e1"), tonumber(" 10 ", 16), tonumber("z", 36))
  row("tonumber_base", tonumber("-ff", 16), tonumber("7fffffffffffffff", 16), tonumber("ffffffffffffffffff", 16))
  row("tonumber_bad", tonumber("1 0", 10), tonumber("", 10), tonumber("8", 8), tonumber("0x", 16))
  row("tonumber_base37", pcall(tonumber, "10", 37))
  row("tonumber_number", pcall(tonumber, 10, 16))
  row("getmt_locked", getmetatable(setmetatable({}, {__metatable = "locked"})))
  row("setmt_locked", pcall(setmetatable, setmetatable({}, {__metatable = 1}), {}))
  row("setmt_bad", pcall(setmetatable, {}, 5))
  row("assert_false", pcall(assert, false))
  row("assert_msg", pcall(assert, nil, "msg"))
  row("assert_none", pcall(assert))
  row("error_table", pcall(error, setmetatable({}, {__tostring = function() return "T" end})))
  row("error_level", inchunk("error('lvl', 1)"))
  row("version", _VERSION)

  -- string.char, the string metatable's arithmetic, the table checks
  row("char", pcall(string.char, 256))
  row("char_ok", string.char(72, 105))
  row("str_add", getmetatable("").__add("3", 4), getmetatable("").__add("3"))
  row("str_arith_bad", pcall(getmetatable("").__add, "x", 1))
  row("insert4", pcall(table.insert, {}, 1, 2, 3))
  row("insert_pos", pcall(table.insert, {}, 5, 1))
  row("remove_pos", pcall(table.remove, {1, 2}, 7))
  row("concat_bad", pcall(table.concat, {1, {}, 3}))

  -- table borders (vm-table-border-is-not-luas)
  local t = {} t[1]=1 t[2]=2 t[4]=4 t[6]=6 t[8]=8
  row("border_sparse", #t)
  local u = {1,2,3,4,5,6,7,8} u[8] = nil u[4] = nil
  local a = #u u[7] = nil
  row("border_len_twice", a, #u)
  local h = {} h[1]=1 h[2]=2 h[4]=4 h[6]=6 h[8]=8 table.insert(h, 'x')
  local k = {} for i = 1, 10 do k[#k + 1] = tostring(h[i]) end
  row("border_insert_holes", table.concat(k, ","))
  local function va(...) local v = {...} return #v end
  row("border_vararg", va(1, nil, 3), #table.pack(1, nil, 3), #{1, nil, 3, nil})

  w("done")
  out:close()
end
