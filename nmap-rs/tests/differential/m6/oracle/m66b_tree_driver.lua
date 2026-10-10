-- M6.6 step b oracle driver:  lua m66b_tree_driver.lua CORE.lua CASES.txt
--
-- Runs every case through m66b_tree_core.lua's `run_one` and prints one line
-- per case: id <TAB> ok|err|loaderr <TAB> hex(payload). The port runs the same
-- core over the same cases (crates/core/tests/lpeg_tree_differential.rs).
local core = dofile(assert(arg[1]))

local function unhex(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

for line in io.lines(assert(arg[2])) do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local id, hx, note = line:match("^([^\t]+)\t([^\t]*)\t?(.*)$")
    if not id then error("malformed row: " .. line) end
    local status, payload = core.run_one(unhex(hx), note)
    io.write(id, "\t", status, "\t", hex(payload), "\n")
  end
end
