-- M6.6 step b: the case runner shared by the oracle and the port.
--
-- The tree's standalone Lua (oracle/lua, with lpeg.c) loads this file through
-- m66b_tree_driver.lua; the port loads the same file into a VM with the
-- test-only `lpeg` registration (crates/core/tests/lpeg_tree_differential.rs).
-- Both then call `run_one` on every case, so the two sides render their
-- results with the same code, and differ only where LPeg does.
--
-- Every case builds patterns and never matches one: step b ports trees,
-- constructors and the verifier, not the matching machine. What a case can
-- observe is a pattern's type, its identity (`rawequal`), the metatable, and
-- every error message.
--
-- Errors are compared byte for byte, prefix and all: cases call LPeg through
-- a direct `pcall` (no position, `lpeg.X` naming) or from a function in the
-- chunk (`chunk:1:` and the operator's name), and both sides agree on both.
-- One exception, the "hashorder" class (docs/M6.6-ANALYSIS.md §3): four grammar
-- errors name the first offending rule in table-traversal order, which is
-- salted per process, so the name is masked — unless the case is marked
-- `[exact]`, which the generator does only where one rule can be named.
--
-- Returns { run_one = function(chunk, note) -> status, payload }.

local lpeg = lpeg
local sformat, concat, mtype = string.format, table.concat, math.type

local TORDER = { boolean = 1, number = 2, string = 3, table = 4, userdata = 5, ["function"] = 6, thread = 7 }

local function keycmp(a, b)
  local ta, tb = type(a), type(b)
  if ta ~= tb then return TORDER[ta] < TORDER[tb] end
  if ta == "number" or ta == "string" then return a < b end
  if ta == "boolean" then return (not a) and b end
  return false
end

local HASHORDER = {
  "^(rule ')(.*)(' is not a pattern)$",
  "^(rule ')(.*)(' may be left recursive)$",
  "^(empty loop in rule ')(.*)(')$",
  "^(rule ')(.*)(' undefined in given grammar)$",
}

local function mask(s)
  local pre, rest = s:match("^(chunk:%d+: )(.*)$")
  if not pre then pre, rest = "", s end
  for _, p in ipairs(HASHORDER) do
    local a, _, c = rest:match(p)
    if a then return pre .. a .. "?" .. c end
  end
  return s
end

local render
render = function(v, exact, seen, depth)
  local t = type(v)
  if t == "nil" then return "nil"
  elseif t == "boolean" then return v and "T" or "F"
  elseif t == "number" then
    if mtype(v) == "integer" then return "i" .. sformat("%d", v) end
    if v ~= v then return "fnan" end
    return "f" .. sformat("%.17g", v)
  elseif t == "string" then
    if not exact then v = mask(v) end
    return "s" .. #v .. ":" .. v
  elseif t == "table" then
    if seen[v] then return "<cycle>" end
    if depth > 20 then return "<deep>" end
    seen[v] = true
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys, keycmp)
    local parts = {}
    for i = 1, #keys do
      local k = keys[i]
      parts[i] = render(k, exact, seen, depth + 1) .. "=" .. render(v[k], exact, seen, depth + 1)
    end
    seen[v] = nil
    return "{" .. concat(parts, ",") .. "}"
  elseif t == "userdata" then
    return lpeg.type(v) == "pattern" and "<pattern>" or "<userdata>"
  else
    return "<" .. t .. ">"
  end
end

local NAMES = { "P", "S", "R", "V", "B", "C", "Cc", "Cmt", "Cb", "Carg", "Cp", "Cs", "Ct",
                "Cf", "Cg", "locale", "setmaxstack", "version" }

-- What every case chunk sees, besides `_G`.
local function make_env()
  local E = setmetatable({}, { __index = _G })
  E.lpeg = lpeg
  for _, k in ipairs(NAMES) do E[k] = lpeg[k] end
  E.ltype = lpeg.type
  E.mt = getmetatable(lpeg.P(1))
  E.F = function() end
  E.G = function(a) return a end
  E.Named = setmetatable({}, { __name = "Named" })
  E.co = coroutine.create(function() end)
  -- `pcall`, with the position a Lua caller gives an error removed: for the
  -- stdlib's own messages, which the port raises without one
  -- (`stdlib-errors-have-no-position`).
  E.perr = function(f, ...)
    local r = table.pack(pcall(f, ...))
    if not r[1] and type(r[2]) == "string" then r[2] = r[2]:gsub("^chunk:%d+: ", "") end
    return table.unpack(r, 1, r.n)
  end
  -- What `tostring` calls the kind of a value, without its address.
  E.kind = function(v) return (tostring(v):match("^(.-): 0?x?%x+$")) end
  -- A grammar of `n` rules, each calling the next twice: the verifier's
  -- worst case, 2^n steps.
  E.chain = function(n, last)
    local g = { "R1" }
    for i = 1, n do g["R" .. i] = lpeg.V("R" .. (i + 1)) + lpeg.V("R" .. (i + 1)) end
    g["R" .. (n + 1)] = last or lpeg.P"a"
    return g
  end
  -- Patterns nested `n` deep under `f`.
  E.nest = function(n, f, p)
    p = p or lpeg.P"a"
    for _ = 1, n do p = f(p) end
    return p
  end
  return E
end

local function run_one(chunk, note)
  local exact = note ~= nil and note:find("[exact]", 1, true) ~= nil
  local E = make_env()
  local f, lerr = load(chunk, "=chunk", "t", E)
  local status, payload
  if not f then
    status, payload = "loaderr", render(lerr, exact, {}, 0)
  else
    local r = table.pack(pcall(f))
    if r[1] then
      status = "ok"
      local parts = { "n" .. (r.n - 1) }
      for i = 2, r.n do parts[#parts + 1] = render(r[i], exact, {}, 0) end
      payload = concat(parts, " ")
    else
      status = "err"
      payload = render(r[2], exact, {}, 0)
    end
  end
  lpeg.setmaxstack(100) -- registry state must not leak between cases
  return status, payload
end

return { run_one = run_one }
