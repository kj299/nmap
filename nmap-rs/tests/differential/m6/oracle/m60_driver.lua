-- Drive the M6.0 semantics corpus through nmap's OWN Lua and print a canonical
-- verdict per case.
--
-- Run as:  ./oracle/lua oracle/m60_driver.lua m60_semantics_cases.txt
--
-- The rendering is deliberately more than `tostring`. Two runtimes can agree on
-- what a value prints as and still disagree on what it IS: `7 // 2` and
-- `7 / 2 - 0.5` both print "3" under some settings, but one is an integer and
-- the other a float, and NSE's binary libraries branch on `math.type`. So each
-- value is rendered as `subtype:text`, where subtype distinguishes integer from
-- float and text is Lua's own `tostring`.
--
-- Errors are rendered too, because "is this an error?" is itself the observable
-- behaviour in several cases (integer division by zero is a *Lua error*, which
-- a script can pcall; a host-language panic is not, and cannot be caught). The
-- message has its "chunk:LINE:" position prefix stripped, since that is an
-- artifact of how the harness loads the chunk rather than a property of Lua.

local function hexdecode(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function render_one(v)
  local t = type(v)
  if t == "number" then
    -- NaN's printed sign is platform noise (glibc prints "-nan" for the
    -- default quiet NaN); canonicalize so the golden is portable.
    if v ~= v then return "float:nan" end
    return string.format("%s:%s", math.type(v), tostring(v))
  elseif t == "string" then
    -- byte strings may hold NUL and non-UTF-8; hex keeps the file one line per case
    return string.format("string:%s", (v:gsub(".", function(c)
      return string.format("%02x", c:byte())
    end)))
  elseif t == "nil" or t == "boolean" then
    return string.format("%s:%s", t, tostring(v))
  else
    -- tables/functions have addresses in tostring, which are not reproducible
    return string.format("%s:<%s>", t, t)
  end
end

local function render(ok, ...)
  if not ok then
    local msg = tostring((...))
    msg = msg:gsub("^%[?string[^%]]*%]?:%d+:%s*", "")   -- strip position prefix
    msg = msg:gsub("^chunk:%d+:%s*", "")
    return "error\t" .. msg
  end
  local n = select("#", ...)
  local parts = {}
  for i = 1, n do
    parts[#parts + 1] = render_one((select(i, ...)))
  end
  return "ok\t" .. table.concat(parts, " ")
end

local path = assert(arg[1], "usage: lua m60_driver.lua CASES.txt")
local fh = assert(io.open(path, "r"))

io.write("# name\toracle_status\toracle_value\n")
io.write("# The verdict of nmap's OWN Lua 5.4, built from liblua/ by\n")
io.write("# oracle/build_lua_oracle.sh. Regenerate with ./regen_m60.sh.\n")
io.write("# Numbers render as `integer:N` or `float:N` because NSE branches on\n")
io.write("# math.type; strings render as hex because they are byte strings.\n")

for line in fh:lines() do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local name, chunk_hex = line:match("^([^\t]+)\t([^\t]*)\t")
    if not name then
      io.stderr:write("malformed row: " .. line .. "\n")
      os.exit(1)
    end
    local chunk = hexdecode(chunk_hex)
    local f, lerr = load(chunk, "chunk")
    if not f then
      io.write(string.format("%s\tloaderror\t%s\n", name, (lerr:gsub("^chunk:%d+:%s*", ""))))
    else
      io.write(string.format("%s\t%s\n", name, render(pcall(f))))
    end
  end
end

fh:close()
