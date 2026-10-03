-- Drive the Lua-pattern corpus through nmap's OWN Lua.
--
-- Run as:  ./oracle/lua oracle/m6_pattern_driver.lua m6_pattern_cases.txt
--
-- Values render exactly as oracle/m60_coerce_driver.lua renders them:
-- `subtype:text`, with strings as hex. What differs is errors. The coercion
-- and strpack corpora drop the message; this one keeps it, hex-encoded,
-- because for the pattern matcher the message IS behaviour: "malformed
-- pattern (missing ']')" versus a plain miss is the whole of what a lazy-
-- error case tests, and every message the matcher raises comes from
-- `luaL_error` inside a C function, which carries no position prefix.
--
-- The exception is `luaL_argerror` ("bad argument #1 to 'find' ..."), whose
-- function name depends on how the call was made -- a tail call names it
-- 'string.find', a plain call 'find', a method call shifts the argument
-- number. The Rust harness compares only the status of those, and says so.
-- A non-string error value renders as "-".

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

local path = assert(arg[1], "usage: lua m6_pattern_driver.lua CASES.txt")
local fh = assert(io.open(path, "r"))

io.write("# name\toracle_status\toracle_value\n")
io.write("# The verdict of nmap's OWN Lua 5.4, built from liblua/ by\n")
io.write("# oracle/build_lua_oracle.sh. Regenerate with ./regen_m6_pattern.sh.\n")
io.write("# An error renders as \"error\" and its message in hex.\n")

for line in fh:lines() do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local name, chunk_hex = line:match("^([^\t]+)\t([^\t]*)\t")
    if not name then
      io.stderr:write("malformed row: " .. line .. "\n")
      os.exit(1)
    end
    local f = load(hexdecode(chunk_hex), "=chunk")
    if not f then
      io.write(string.format("%s\tloaderror\t-\n", name))
    else
      io.write(string.format("%s\t%s\n", name, render(pcall(f))))
    end
  end
end

fh:close()
