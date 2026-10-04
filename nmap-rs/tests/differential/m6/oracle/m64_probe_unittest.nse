description = "Probe: run each nselib library's unit tests and record the failures."
categories = {"safe"}
author = "probe"
local unittest = require "unittest"
prerule = function() return true end
action = function()
  local out = assert(io.open(nmap.registry.args.out, "w"))
  for name in io.lines(nmap.registry.args.libs) do
    local ok, fails = pcall(unittest.run_tests, {name})
    if not ok then
      out:write(name, "\terror\t", (tostring(fails):gsub("\n", "\\n")), "\n")
    else
      local f = fails[name]
      out:write(name, "\t", f == nil and "pass" or ("fail\t" .. (tostring(f):gsub("\n", "\\n"))), "\n")
    end
  end
  out:close()
  return "done"
end
