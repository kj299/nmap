-- Run ONE case of the M6.4b memory corpus through nmap's own Lua, in a
-- process of its own, so that no case inherits another's heap.
--
--   ./oracle/lua oracle/m64_memory_one.lua NAME CHUNK_HEX
--
-- Prints the case's row as oracle/m6_pattern_driver.lua renders it. The
-- regeneration script runs this under `ulimit -v`.

local name, chunk_hex = arg[1], arg[2]

local function hexdecode(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function render_one(v)
  local t = type(v)
  if t == "number" then
    if v ~= v then return "float:nan" end
    return string.format("%s:%s", math.type(v), tostring(v))
  elseif t == "string" then
    return "string:" .. hex(v)
  elseif t == "nil" or t == "boolean" then
    return string.format("%s:%s", t, tostring(v))
  else
    return string.format("%s:<%s>", t, t)
  end
end

local function render(ok, ...)
  if not ok then
    local e = ...
    if type(e) == "string" then return "error\t" .. hex(e) end
    return "error\t-"
  end
  local parts = {}
  for i = 1, select("#", ...) do
    parts[#parts + 1] = render_one((select(i, ...)))
  end
  return "ok\t" .. table.concat(parts, " ")
end

local f = assert(load(hexdecode(chunk_hex), "=chunk"))
-- The case's result is rendered after its garbage is gone, so that rendering
-- does not itself run out.
local row = table.pack(pcall(f))
f = nil
collectgarbage()
io.write(name, "\t", render(table.unpack(row, 1, row.n)), "\n")
