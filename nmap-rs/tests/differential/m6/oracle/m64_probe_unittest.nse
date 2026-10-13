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
      if f == nil then
        -- A suite that passed: how many tests it ran (TestSuite.__call's
        -- second result), so that a suite which ran none, or only some,
        -- cannot pass for one that ran them all (M6.6 step e).
        local m = package.loaded[name]
        local suite = type(m) == "table" and rawget(m, "test_suite")
        local n = suite and select(2, suite()) or 0
        out:write(name, "\tpass\t", tostring(n), "\n")
      else
        out:write(name, "\tfail\t", (tostring(f):gsub("\n", "\\n")), "\n")
      end
    end
  end
  out:close()
  return "done"
end
