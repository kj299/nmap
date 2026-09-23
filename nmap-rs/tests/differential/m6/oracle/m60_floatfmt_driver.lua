-- Drive the M6.0 float-formatting corpus through nmap's OWN Lua.
--
-- Run as:  ./oracle/lua oracle/m60_floatfmt_driver.lua m60_floatfmt_cases.txt
--
-- Each case is an IEEE-754 bit pattern rather than a numeral, so that the value
-- reaching `tostring` is the exact double the corpus names: a decimal literal
-- would have to survive the generator, the file and Lua's lexer first, and
-- -0.0 is not writable as a literal at all.
--
-- Two columns, not one. `tostring(v)` and `'' .. v` are separate paths in a
-- VM -- one goes through the tostring metamethod lookup, the other through the
-- concatenation operator -- and a port can easily fix one and leave the other.
-- The driver asserts they agree here, since in Lua they must, and emits both so
-- the Rust side has to match each independently.

local function hexdecode(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local path = assert(arg[1], "usage: lua m60_floatfmt_driver.lua CASES.txt")
local fh = assert(io.open(path, "r"))

io.write("# name\ttostring\tconcat\n")
io.write("# The verdict of nmap's OWN Lua 5.4, built from liblua/ by\n")
io.write("# oracle/build_lua_oracle.sh. Regenerate with ./regen_m60.sh.\n")

for line in fh:lines() do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local name, bits_hex = line:match("^([^\t]+)\t([^\t]*)\t")
    if not name then
      io.stderr:write("malformed row: " .. line .. "\n")
      os.exit(1)
    end
    -- ">d" is big-endian binary64, the same order the generator wrote.
    local v = string.unpack(">d", hexdecode(bits_hex))
    if math.type(v) ~= "float" then
      io.stderr:write("case " .. name .. " did not unpack to a float\n")
      os.exit(1)
    end
    local ts = tostring(v)
    local cc = "" .. v
    if ts ~= cc then
      io.stderr:write(string.format(
        "case %s: tostring is %q but concat is %q -- Lua itself disagrees\n", name, ts, cc))
      os.exit(1)
    end
    if ts:find("[\t\n]") then
      io.stderr:write("case " .. name .. " printed a field separator\n")
      os.exit(1)
    end
    io.write(string.format("%s\t%s\t%s\n", name, ts, cc))
  end
end

fh:close()
