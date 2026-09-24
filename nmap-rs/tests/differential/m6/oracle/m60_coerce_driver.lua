-- Drive the M6.0 string-coercion corpus through nmap's OWN Lua.
--
-- Run as:  ./oracle/lua oracle/m60_coerce_driver.lua m60_coerce_cases.txt
--
-- Separate from m60_driver.lua for one reason: the error MESSAGE is not part of
-- the contract here. Roughly half of these 1,875 cases are expected to raise --
-- every bitwise operator on a string, every comparison across types, every
-- operand that is not a numeral -- and requiring the text to match would turn a
-- corpus about conversion into a corpus about wording. So an error renders as
-- the bare word "error". That "this raises rather than answering" IS the
-- property under test for most of these: `'10' | 0` used to answer 10.
--
-- Values render as `subtype:text`, where subtype is `math.type` for numbers.
-- Both halves matter and neither is redundant: the whole defect being gated is
-- a case where the text was right and the subtype was not.

local function hexdecode(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function render_one(v)
  local t = type(v)
  if t == "number" then
    -- NaN's printed sign is platform noise; canonicalize so the golden travels.
    if v ~= v then return "float:nan" end
    return string.format("%s:%s", math.type(v), tostring(v))
  elseif t == "string" then
    -- Byte strings: hex keeps one line per case even with NUL and non-UTF-8.
    return "string:" .. (v:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  elseif t == "nil" or t == "boolean" then
    return string.format("%s:%s", t, tostring(v))
  else
    return string.format("%s:<%s>", t, t)
  end
end

local function render(ok, ...)
  if not ok then return "error\t-" end
  local parts = {}
  for i = 1, select("#", ...) do
    parts[#parts + 1] = render_one((select(i, ...)))
  end
  return "ok\t" .. table.concat(parts, " ")
end

local path = assert(arg[1], "usage: lua m60_coerce_driver.lua CASES.txt")
local fh = assert(io.open(path, "r"))

io.write("# name\toracle_status\toracle_value\n")
io.write("# The verdict of nmap's OWN Lua 5.4, built from liblua/ by\n")
io.write("# oracle/build_lua_oracle.sh. Regenerate with ./regen_m60.sh.\n")
io.write("# An error renders as \"error\" with no message: the message is\n")
io.write("# implementation detail, the raising is the contract.\n")

for line in fh:lines() do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local name, chunk_hex = line:match("^([^\t]+)\t([^\t]*)\t")
    if not name then
      io.stderr:write("malformed row: " .. line .. "\n")
      os.exit(1)
    end
    local f = load(hexdecode(chunk_hex), "chunk")
    if not f then
      io.write(string.format("%s\tloaderror\t-\n", name))
    else
      io.write(string.format("%s\t%s\n", name, render(pcall(f))))
    end
  end
end

fh:close()
