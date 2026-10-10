-- M6.6 step 0b: the case runner for the LPeg corpus (m66_lpeg_cases.txt).
--
-- One file, run unchanged by both oracles:
--   * oracle/m66_lpeg_driver.lua, under this tree's standalone Lua + LPeg
--     (oracle/build_lua_oracle.sh) -- the golden, the spec (M6.5 D1(c));
--   * oracle/m66_lpeg_probe.nse, a prerule under nmap 7.94 with --datadir set
--     to this tree -- the agreement check.
-- Both load it with load(text, "=m66_lpeg_core.lua"), so a position inside it
-- reads the same on every host.
--
-- Every LPeg entry point a case reaches goes through a DIRECT pcall
-- (docs/M6.6-ANALYSIS.md E6): the constructors, `match` and the pattern
-- metatable's operators in a case's environment are wrappers that call
-- `pcall(lpeg.f, ...)`. luaL_where(L, 1) then names pcall, a C function, so no
-- error carries a `chunk:N:` prefix, and luaL_argerror names the function as
-- the C finds it (`lpeg.P` through package.loaded, `?` for a metamethod).
-- A failed call is re-raised as a marker object; the runner reports the
-- message as status `err`. An error that escapes without passing through a
-- wrapper (a bug in a case) is status `xerr`, reported raw.
--
-- Output, one line per case:   id TAB status TAB values TAB log
--   status  ok | err | xerr | loaderr
--   values  the chunk's results (ok) or the error value (err/xerr), rendered
--           by `render` below: typed, table keys sorted, and never tostring()
--           of a table, userdata or function (addresses differ run to run)
--   log     the calls the deterministic helper callbacks saw, in order, or -
-- Bytes outside printable ASCII, `"` and `\` are written \xHH, so a line
-- holds no tab or newline. Strings and tables past a size bound render as
-- their length and an FNV-1a digest of the full rendering.
--
-- `census` mode (oracle/classify_m66_lpeg.py steps) runs each case under a
-- debug hook instead and reports what it needs from an engine (see census_row).

local lpeg = require "lpeg"
local re = require "re"
local U = require "lpeg-utility"

local assert, error, getmetatable, ipairs, load, next, pairs, pcall, rawequal, rawget, rawset, select, setmetatable, tonumber, tostring, type =
  assert, error, getmetatable, ipairs, load, next, pairs, pcall, rawequal, rawget, rawset, select, setmetatable, tonumber, tostring, type
local sformat, schar, sbyte, srep, sgsub, ssub = string.format, string.char, string.byte, string.rep, string.gsub, string.sub
local concat, pack, unpack, sort = table.concat, table.pack, table.unpack, table.sort
local mtype = math.type
local G = _G

local MT = getmetatable(lpeg.P(true))

-- ------------------------------------------------------------------ rendering

local function esc(s)
  return (sgsub(s, '[%z\1-\31\127-\255"\\]', function(c) return sformat("\\x%02x", sbyte(c)) end))
end

local function fnv(s)
  local h = 2166136261
  for i = 1, #s do
    h = ((h ~ sbyte(s, i)) * 16777619) & 0xffffffff
  end
  return sformat("%08x", h)
end

-- The nselib directory differs between hosts and harnesses; the file name and
-- line do not. A position inside this runner says nothing about LPeg (it is
-- where the harness ran out of stack, say), so its line is dropped: editing
-- the runner must not move the golden.
local function npath(s)
  s = sgsub(s, "[^%s'\"]*nselib/([%w%-_]+%.lua):", "%1:")
  return (sgsub(s, "m66_lpeg_core%.lua:%d+:", "m66_lpeg_core.lua:"))
end

local STR_MAX, TAB_MAX = 512, 4096
local ERRMT = { __name = "m66-error" }   -- marks an error re-raised by X

local TORDER = { boolean = 1, number = 2, string = 3, table = 4, userdata = 5, ["function"] = 6, thread = 7 }
local function keycmp(a, b)
  local ta, tb = type(a), type(b)
  if ta ~= tb then return TORDER[ta] < TORDER[tb] end
  if ta == "number" then
    if a ~= a then return false end
    if b ~= b then return true end
    if a == b then return mtype(a) == "integer" and mtype(b) == "float" end
    return a < b
  end
  if ta == "string" then return a < b end
  if ta == "boolean" then return (not a) and b end
  return false
end

local render
local function render_str(v)
  v = npath(v)
  if #v > STR_MAX then
    return sformat('s#%d:%s:"%s"', #v, fnv(v), esc(ssub(v, 1, 48)))
  end
  return 's"' .. esc(v) .. '"'
end

render = function(v, seen, depth)
  local t = type(v)
  if t == "nil" then return "nil"
  elseif t == "boolean" then return v and "true" or "false"
  elseif t == "number" then
    if mtype(v) == "integer" then return "i" .. sformat("%d", v) end
    if v ~= v then return "fnan" end
    return "f" .. sformat("%.17g", v)
  elseif t == "string" then return render_str(v)
  elseif t == "table" then
    if getmetatable(v) == ERRMT then return "E(" .. render(v.e, seen, depth) .. ")" end
    if seen[v] then return "<cycle>" end
    if depth > 16 then return "<deep>" end
    seen[v] = true
    local items = {}
    for k in next, v do
      items[#items + 1] = { k = k, s = render(k, seen, depth + 1) .. "=" .. render(rawget(v, k), seen, depth + 1) }
    end
    -- numbers, strings and booleans by value; any other key by its rendering
    sort(items, function(x, y)
      local tx, ty = type(x.k), type(y.k)
      if tx ~= ty or tx == "number" or tx == "string" or tx == "boolean" then return keycmp(x.k, y.k) end
      return x.s < y.s
    end)
    local parts = {}
    for i = 1, #items do parts[i] = items[i].s end
    seen[v] = nil
    local r = "{" .. concat(parts, ",") .. "}"
    if #r > TAB_MAX then
      return sformat("{#%d:%d:%s}", #items, #r, fnv(r))
    end
    return r
  elseif t == "userdata" then
    return lpeg.type(v) == "pattern" and "<pattern>" or "<userdata>"
  else
    return "<" .. t .. ">"
  end
end

-- ------------------------------------------------------------ the case env

-- X(f, ...): call f through a direct pcall. A failure is re-raised as an ERRMT
-- marker (unchanged if it already is one: an error from a nested wrapped call
-- that propagated through LPeg is that call's error).
local function X(f, ...)
  local r = pack(pcall(f, ...))
  if r[1] then return unpack(r, 2, r.n) end
  local e = r[2]
  if getmetatable(e) == ERRMT then error(e, 0) end
  error(setmetatable({ e = e }, ERRMT), 0)
end

local function W(f)
  return function(...) return X(f, ...) end
end

-- summary of a value too big to render whole (a capture table of 10^6 items)
local function summ(t)
  if type(t) ~= "table" then return type(t), t end
  local n = #t
  return n, t[1], t[n]
end

local function show(...)
  local n = select("#", ...)
  local p = {}
  for i = 1, n do
    local v = select(i, ...)
    local t = type(v)
    if t == "string" then p[i] = #v > 64 and ("s#" .. #v) or v
    elseif t == "number" then p[i] = (mtype(v) == "integer" and "i" or "f") .. sformat("%.17g", v)
    elseif t == "boolean" then p[i] = v and "T" or "F"
    elseif t == "nil" then p[i] = "nil"
    elseif t == "table" then p[i] = "t#" .. #v
    elseif t == "userdata" then p[i] = lpeg.type(v) or "u"
    else p[i] = t end
  end
  return n .. "(" .. concat(p, ",") .. ")"
end

local function make_env()
  local LOG = {}
  local function log(tag, ...)
    if #LOG < 200 then LOG[#LOG + 1] = tag .. show(...)
    elseif #LOG == 200 then LOG[#LOG + 1] = "..." end
  end
  local E = setmetatable({}, { __index = G })
  E.lpeg = lpeg            -- the raw module: identity checks only, never called
  E.LOG = LOG
  for _, k in ipairs { "P", "S", "R", "V", "B", "C", "Cc", "Cmt", "Cb", "Carg", "Cp", "Cs", "Ct",
                       "Cf", "Cg", "locale", "match", "setmaxstack", "version", "ptree", "pcode" } do
    E[k] = W(lpeg[k])
  end
  E.ltype = W(lpeg.type)
  E.mul, E.add, E.sub, E.div = W(MT.__mul), W(MT.__add), W(MT.__sub), W(MT.__div)
  E.pow, E.unm, E.len = W(MT.__pow), W(MT.__unm), W(MT.__len)
  E.MT = MT
  E.call = X
  E.mcall = function(o, k, ...) return X(o[k], o, ...) end
  E.re = {}
  for _, k in ipairs { "compile", "match", "find", "gsub", "updatelocale" } do E.re[k] = W(re[k]) end
  E.U = {}
  for k, v in pairs(U) do
    if type(v) == "function" then E.U[k] = W(v) end
  end
  E.summ = summ
  -- function captures (p / F)
  E.Fid = function(...) log("Fid", ...); return ... end
  E.Fcat = function(...) log("Fcat", ...); return show(...) end
  E.Fnone = function(...) log("Fnone", ...) end
  E.Fnil = function(...) log("Fnil", ...); return nil end
  E.Ffalse = function(...) log("Ffalse", ...); return false end
  E.Fmulti = function(...) log("Fmulti", ...); return "m", 7, 2.5, false end
  E.Ferr = function(...) log("Ferr", ...); error("Ferr raised", 0) end
  E.Ferrt = function(...) log("Ferrt", ...); error({ code = 7 }) end
  E.Ftab = function(...) log("Ftab", ...); return { ... } end
  E.Fq = function(c) return c end                 -- silent identity, for bulk rows
  -- fold functions (Cf)
  E.Gcat = function(a, b) log("Gcat", a, b); return show(a) .. "+" .. show(b) end
  E.Gfirst = function(a, b) log("Gfirst", a, b); return a end
  E.Gnil = function(a, b) log("Gnil", a, b); return nil end
  E.Gset = function(t, k, v) log("Gset", t, k, v); if type(t) == "table" and k ~= nil then rawset(t, k, v == nil and true or v) end; return t end
  E.Gmany = function(a, ...) log("Gmany", a, ...); return show(a, ...) end
  -- match-time functions (Cmt / P(function))
  E.Mkeep = function(s, i, ...) log("Mkeep", i, ...); return i end
  E.Mnext = function(s, i, ...) log("Mnext", i, ...); return i + 1 end
  E.Mtrue = function(s, i, ...) log("Mtrue", i, ...); return true end
  E.Mfalse = function(s, i, ...) log("Mfalse", i, ...); return false end
  E.Mnil = function(s, i, ...) log("Mnil", i, ...); return nil end
  E.Mnone = function(s, i, ...) log("Mnone", i, ...) end
  E.Mback = function(s, i, ...) log("Mback", i, ...); return i - 1 end
  E.Mend = function(s, i, ...) log("Mend", i, ...); return #s + 1 end
  E.Mbeyond = function(s, i, ...) log("Mbeyond", i, ...); return #s + 2 end
  E.Mstr = function(s, i, ...) log("Mstr", i, ...); return tostring(i) end
  E.Mfloat = function(s, i, ...) log("Mfloat", i, ...); return i + 0.5 end
  E.Mintf = function(s, i, ...) log("Mintf", i, ...); return i + 0.0 end
  E.Mtbl = function(s, i, ...) log("Mtbl", i, ...); return {} end
  E.Mcaps = function(s, i, ...) log("Mcaps", i, ...); return i, ... end
  E.Mcount = function(s, i, ...) log("Mcount", i, ...); return i, select("#", ...) end
  E.Mvals = function(s, i, ...) log("Mvals", i, ...); return true, "v1", 2, nil end
  E.Mgate = function(s, i, ...) log("Mgate", i, ...); return (i % 2 == 0) and i or false end
  E.Merr = function(s, i, ...) log("Merr", i, ...); error("Merr raised", 0) end
  E.Merrt = function(s, i, ...) log("Merrt", i, ...); error({ code = 9 }, 0) end
  E.Mre = function(s, i, ...) log("Mre", i); return lpeg.match(lpeg.P "a" ^ 0, s, i) end
  E.Mv = function(s, i) return i, "v" end          -- silent: the 10^6 rows
  E.Mq = function(s, i) return i end               -- silent keep
  -- K(...): a match-time function returning exactly these values
  E.K = function(...)
    local vals = pack(...)
    return function(s, i, ...) log("K", i, ...); return unpack(vals, 1, vals.n) end
  end
  -- KR(kind, d): a match-time function returning position i+d in some form
  E.KR = function(kind, d)
    return function(s, i, ...)
      log("KR", i, ...)
      local p = i + d
      if kind == "i" then return p
      elseif kind == "f" then return p + 0.0
      elseif kind == "h" then return p + 0.5
      elseif kind == "s" then return tostring(p)
      elseif kind == "sp" then return " " .. p .. " "
      elseif kind == "x" then return sformat("0x%x", p)
      elseif kind == "e" then return p .. "e0"
      elseif kind == "nf" then return -p + 0.0
      end
      error("bad KR kind", 0)
    end
  end
  -- tables for query captures
  E.IDXF = setmetatable({}, { __index = function(t, k) log("IDXF", k); return "mt" .. tostring(k) end })
  E.IDXT = setmetatable({}, { __index = { a = "A", b = false } })
  -- a grammar table whose __index answers any missing key with v (or
  -- raises, for "ERR"): lpeg.P reads the initial rule through it
  E.gmeta = function(t, v)
    return setmetatable(t, { __index = function(_, k)
      log("GI", k)
      if v == "ERR" then error("gmeta raised", 0) end
      return v
    end })
  end
  E.logtable = function()
    return setmetatable({}, { __newindex = function(t, k, v) log("NI", k); rawset(t, k, v) end })
  end
  -- C-call depth: re-entry through LPeg and, for reference, through gsub,
  -- in the same embedding (the `cdepth` rows).
  E.reenter = function(depth, subj)
    local p
    local d = 0
    p = lpeg.P(function(s, i)
      d = d + 1
      if d >= depth then return i end
      local r = lpeg.match(p, s, i)
      return r and i or false
    end)
    local ok, r = pcall(lpeg.match, p, subj or "x")
    return ok, (ok and r or (type(r) == "string" and r or render(r, {}, 0))), d
  end
  E.depth_lpeg = function()
    local d, p = 0
    p = lpeg.P(function(s, i)
      d = d + 1
      local ok, r = pcall(lpeg.match, p, s, i)
      if not ok then error(r, 0) end
      return i
    end)
    local ok, e = pcall(lpeg.match, p, "x")
    return d, ok, e
  end
  E.depth_gsub = function()
    local d, f = 0
    f = function(c)
      d = d + 1
      local ok, r = pcall(sgsub, "x", ".", f)
      if not ok then error(r, 0) end
      return c
    end
    local ok, e = pcall(sgsub, "x", ".", f)
    return d, ok, e
  end
  -- The Lua stack's ceiling on captures, relative to table.unpack's in the
  -- same frame: the absolute ceiling moves with whatever lies below the call
  -- (the `cdepth` rows); this difference does not (-5 under both oracles).
  E.stack_rel = function()
    local p = lpeg.C(1) ^ 0
    local function maxok(lo, hi, test)   -- the largest n in [lo, hi) passing test
      assert(test(lo) and not test(hi), "stack_rel: ceiling outside the search window")
      while hi - lo > 1 do
        local mid = (lo + hi) // 2
        if test(mid) then lo = mid else hi = mid end
      end
      return lo
    end
    local caps = maxok(900000, 1000001, function(n) return (pcall(lpeg.match, p, srep("a", n))) end)
    local unp = maxok(900000, 1000001, function(n) return (pcall(unpack, {}, 1, n)) end)
    return caps - unp
  end
  return E, LOG
end

-- ------------------------------------------------------------ case file

local UNESC = { ["\\"] = "\\", n = "\n", t = "\t" }
local function unesc(s)
  return (sgsub(s, "\\(.)", function(c)
    local r = UNESC[c]
    if not r then error("bad escape in case chunk: \\" .. c, 0) end
    return r
  end))
end

local function read_cases(path, start)
  local fh = assert(io.open(path, "r"))
  local rows = {}
  local skipping = start ~= nil and start ~= ""
  for line in fh:lines() do
    if line ~= "" and ssub(line, 1, 1) ~= "#" then
      local id, tags, chunk = line:match("^([^\t]+)\t([^\t]*)\t([^\t]*)$")
      if not id then error("malformed row: " .. line, 0) end
      if skipping and id == start then skipping = false end
      if not skipping then rows[#rows + 1] = { id = id, tags = tags, chunk = unesc(chunk) } end
    end
  end
  fh:close()
  return rows
end

local function reset()
  -- process-global LPeg state must not leak from one case into the next
  pcall(lpeg.setmaxstack, 100)
end

local function run_row(row)
  local E, LOG = make_env()
  local f, lerr = load(row.chunk, "=chunk", "t", E)
  local status, payload
  if not f then
    status, payload = "loaderr", render(lerr, {}, 0)
  else
    local r = pack(pcall(f))
    if r[1] then
      status = "ok"
      local parts = {}
      for i = 2, r.n do parts[#parts + 1] = render(r[i], {}, 0) end
      payload = #parts > 0 and concat(parts, " ") or "-"
    else
      local e = r[2]
      if getmetatable(e) == ERRMT then
        status, payload = "err", render(e.e, {}, 0)
      else
        status, payload = "xerr", render(e, {}, 0)
      end
    end
  end
  reset()
  local lg = #LOG > 0 and esc(npath(concat(LOG, ";"))) or "-"
  return status, payload, lg
end

-- ------------------------------------------------------------ census mode
--
-- What a case needs from an engine, measured rather than guessed from its
-- text. A debug hook watches every call and return:
--   match   lpeg.match was called (directly, as a method, or by re/U)
--   luacap  some pattern handed to match contains a capture kind that calls
--           Lua: Cmt or P(function), p/function, Cf, or p/table (__index).
--           Taint flows through every constructor and operator from its
--           arguments to its result; a grammar table is tainted by its rule
--           values. Cc's values are constants and never taint.
--   localet lpeg.locale was given a table (it writes through __newindex)
--   reU     a function of nselib/re.lua or nselib/lpeg-utility.lua ran
--   dynm    lpeg.match called a Lua function (a capture, or an __index)
--   dync    another LPeg function called a Lua function: locale's
--           __newindex, or the __index of a grammar table, which
--           getfirstrule reads with lua_gettable (lpeg.c:2932)
-- `dynm` cross-checks `luacap`: a case whose matched patterns hold no
-- Lua-calling capture must never have match call Lua (classify_m66_lpeg.py
-- fails if it does).

local function census_row(row)
  local LPEGFN = {}
  for k, v in pairs(lpeg) do if type(v) == "function" then LPEGFN[v] = k end end
  for k, v in pairs(MT) do if type(v) == "function" then LPEGFN[v] = k end end
  local taint = setmetatable({}, { __mode = "k" })
  local flags = { match = false, luacap = false, localet = false, reU = false, dynm = false, dync = false }
  local pending = {}

  local function argtaint(v, seen)
    local t = type(v)
    if t == "function" then return true end
    if t == "userdata" then return taint[v] == true end
    if t == "table" then
      seen = seen or {}
      if seen[v] then return false end
      seen[v] = true
      for _, rv in next, v do
        if argtaint(rv, seen) then return true end
      end
    end
    return false
  end

  local getinfo, getlocal = debug.getinfo, debug.getlocal
  -- per function: false for C, "lua" for a Lua function, "reU" for one of
  -- re.lua's or lpeg-utility.lua's (cached: a callback runs up to 10^6 times)
  local kind = setmetatable({}, { __mode = "k" })
  local function hook(ev)
    local f = getinfo(2, "f").func
    local name = LPEGFN[f]
    if name then
      local info = getinfo(2, "r")
      if ev == "return" then
        -- an error unwinds a frame with no return event; drop such stale entries
        while #pending > 0 and pending[#pending][1] ~= f do pending[#pending] = nil end
        local e = pending[#pending]
        pending[#pending] = nil
        if e and e[2] then
          for i = 1, info.ntransfer do
            local _, v = getlocal(2, info.ftransfer + i - 1)
            if type(v) == "userdata" then taint[v] = true end
          end
        end
        return
      end
      local args = {}
      for i = 1, info.ntransfer do
        local _, v = getlocal(2, info.ftransfer + i - 1)
        args[i] = v
      end
      local t = false
      if name == "match" then
        flags.match = true
        if argtaint(args[1]) then flags.luacap = true end
      elseif name == "locale" then
        if type(args[1]) == "table" then flags.localet = true end
      elseif name == "Cmt" or name == "Cf" then
        t = true
      elseif name == "__div" then
        local a2 = type(args[2])
        t = a2 == "function" or a2 == "table" or argtaint(args[1])
      elseif name == "Cc" or name == "Carg" or name == "Cb" or name == "Cp" or name == "V"
          or name == "R" or name == "S" or name == "type" or name == "version"
          or name == "setmaxstack" then
        t = false
      else
        for i = 1, #args do if argtaint(args[i]) then t = true; break end end
      end
      pending[#pending + 1] = { f, t }
    elseif ev ~= "return" then
      local k = kind[f]
      if k == nil then
        local info = getinfo(2, "S")
        if info.what ~= "Lua" then k = false
        elseif info.source:find("nselib/re%.lua$") or info.source:find("nselib/lpeg%-utility%.lua$") then k = "reU"
        else k = "lua" end
        kind[f] = k
      end
      if k then
        if k == "reU" then flags.reU = true end
        local caller = getinfo(3, "f")
        local cname = caller and LPEGFN[caller.func]
        if cname == "match" then flags.dynm = true
        elseif cname then flags.dync = true end
      end
    end
  end

  local E = make_env()
  local f = load(row.chunk, "=chunk", "t", E)
  if f then
    debug.sethook(hook, "cr")
    pcall(f)
    debug.sethook()
  end
  reset()
  return flags
end

-- ------------------------------------------------------------ entry points

local function run(cases_path, out, opts)
  opts = opts or {}
  local rows = read_cases(cases_path, opts.start)
  local n = 0
  for _, row in ipairs(rows) do
    if opts.census then
      local fl = census_row(row)
      local s = {}
      for _, k in ipairs { "match", "luacap", "localet", "reU", "dynm", "dync" } do
        if fl[k] then s[#s + 1] = k end
      end
      out:write(row.id, "\t", #s > 0 and concat(s, ",") or "-", "\n")
    else
      local status, payload, lg = run_row(row)
      out:write(row.id, "\t", status, "\t", payload, "\t", lg, "\n")
    end
    if opts.flush then out:flush() end
    n = n + 1
  end
  return n
end

-- `run_row` runs one case ({ id, tags, chunk }, the chunk unescaped) and
-- returns its status, values and log: the port's corpus gate
-- (crates/core/tests/lpeg_corpus_differential.rs) calls it row by row.
return { run = run, run_row = run_row, render = render, make_env = make_env }
