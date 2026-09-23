-- Drive the M6.0 arithmetic corpus through nmap's OWN Lua.
--
-- Run as:  ./oracle/lua oracle/m60_arith_driver.lua m60_arith_cases.txt
--
-- Floats render as their raw IEEE-754 bit pattern, NOT as text. That is the
-- whole reason this driver exists separately from m60_driver.lua: `%.14g` is
-- lossy, so two doubles differing in their last three significant digits print
-- identically and a wrong arithmetic result would pass unnoticed. Bits are
-- exact, and they also distinguish +0.0 from -0.0, which `tostring` does not
-- and which `fmod`'s sign rules can turn on. Formatting itself is gated by
-- m60_floatfmt_cases.txt, where the text is the thing under test.
--
-- NaN is canonicalized to one pattern: the sign and payload of a produced NaN
-- are not specified by IEEE and differ between an interpreter and a JIT-less
-- VM for reasons that are not bugs.

local function hexdecode(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local NAN_CANON = "7ff8000000000000"

local function render_one(v)
  local t = type(v)
  if t == "number" then
    if math.type(v) == "integer" then
      return string.format("integer:%d", v)
    end
    if v ~= v then return "float:" .. NAN_CANON end
    -- ">d" is big-endian IEEE-754 double: the bit pattern, most significant
    -- byte first, so the hex reads the way the standard writes it.
    return "float:" .. (string.pack(">d", v):gsub(".", function(c)
      return string.format("%02x", c:byte())
    end))
  elseif t == "string" then
    return "string:" .. (v:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  elseif t == "nil" or t == "boolean" then
    return string.format("%s:%s", t, tostring(v))
  else
    return string.format("%s:<%s>", t, t)
  end
end

local function render(ok, ...)
  if not ok then
    -- The message is implementation text; that it IS an error is the property.
    return "error\t-"
  end
  local n = select("#", ...)
  local parts = {}
  for i = 1, n do
    parts[#parts + 1] = render_one((select(i, ...)))
  end
  return "ok\t" .. table.concat(parts, " ")
end

local path = assert(arg[1], "usage: lua m60_arith_driver.lua CASES.txt")
local fh = assert(io.open(path, "r"))

io.write("# name\toracle_status\toracle_value\n")
io.write("# The verdict of nmap's OWN Lua 5.4, built from liblua/ by\n")
io.write("# oracle/build_lua_oracle.sh. Regenerate with ./regen_m60.sh.\n")
io.write("# Floats are raw IEEE-754 bit patterns (big-endian hex), not text.\n")

for line in fh:lines() do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local name, chunk_hex = line:match("^([^\t]+)\t([^\t]*)\t")
    if not name then
      io.stderr:write("malformed row: " .. line .. "\n")
      os.exit(1)
    end
    local f, lerr = load(hexdecode(chunk_hex), "chunk")
    if not f then
      io.write(string.format("%s\tloaderror\t-\n", name))
    else
      io.write(string.format("%s\t%s\n", name, render(pcall(f))))
    end
  end
end

fh:close()
