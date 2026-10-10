-- M6.6 step 0b: run the LPeg corpus under this tree's standalone Lua + LPeg.
--
--   ./oracle/lua oracle/m66_lpeg_driver.lua CASES OUT [census|flush] [start=ID]
--
-- `re` and `lpeg-utility` come from this tree's nselib/. lpeg-utility requires
-- stdnse only for the default printer of its `debug` helper, so a stub stands
-- in for it; no case reaches the printer. The case runner is
-- oracle/m66_lpeg_core.lua, shared with the 7.94 probe (m66_lpeg_probe.nse).
local here = arg[0]:match("^(.*)/[^/]*$") or "."
local repo = here .. "/../../../../.."
package.path = repo .. "/nselib/?.lua;" .. package.path
package.preload["stdnse"] = function() return { debug1 = function() end } end

local fh = assert(io.open(here .. "/m66_lpeg_core.lua", "r"))
local core = assert(load(fh:read("a"), "=m66_lpeg_core.lua"))()
fh:close()

local cases, outp = assert(arg[1], "CASES"), assert(arg[2], "OUT")
local opts = {}
for i = 3, #arg do
  if arg[i] == "census" then opts.census = true
  elseif arg[i] == "flush" then opts.flush = true
  elseif arg[i]:match("^start=") then opts.start = arg[i]:sub(7)
  else error("unknown option " .. arg[i]) end
end
local out = assert(io.open(outp, opts.start and "a" or "w"))
local t0 = os.clock()
local n = core.run(cases, out, opts)
out:close()
io.stderr:write(string.format("m66 lpeg driver: %d cases, cpu %.2fs\n", n, os.clock() - t0))
