description = [[Probe: unittest.run_tests() over every library unittest.lua lists, as
scripts/unittest.nse runs it with no unittest.tests, and how each library that
fails does: the module it could not find, or `silent_require` for the table
stdnse.silent_require raises.]]
categories = {"safe"}
author = "probe"
local unittest = require "unittest"
prerule = function() return true end
action = function()
  local out = assert(io.open(nmap.registry.args.out, "w"))
  local fails = unittest.run_tests()
  local names = {}
  for name in pairs(fails) do names[#names + 1] = name end
  table.sort(names)
  for _, name in ipairs(names) do
    local f = tostring(fails[name])
    local kind = f:match("^Failed to load: .-module '([^']+)' not found")
    if not kind and f:match("^Failed to load: table: ") then kind = "silent_require" end
    out:write(name, "\t", kind or ("other: " .. f:gsub("\n", "\\n")), "\n")
  end
  out:close()
  return "done"
end
