-- M6.6 step 0b: run the LPeg corpus inside nmap's own NSE state.
--
-- nmap --datadir REPO -sn -n --script oracle/m66_lpeg_probe.nse \
--   --script-args 'core=PATH,cases=PATH,out=PATH[,flush=1][,start=ID]' 127.0.0.1
--
-- A prerule, so nothing is sent. The cases run through the same runner as the
-- standalone driver (oracle/m66_lpeg_core.lua, loaded under the same chunk
-- name), with this tree's nselib/re.lua and lpeg-utility.lua from --datadir.
-- The last line of OUT is `done` when every case ran.
description = "M6.6: the LPeg corpus under nmap's LPeg"
categories = {"safe"}
author = "nmap-rs differential"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

prerule = function() return true end

action = function()
  local args = nmap.registry.args
  local fh = assert(io.open(args.core, "r"))
  local core = assert(load(fh:read("a"), "=m66_lpeg_core.lua"))()
  fh:close()
  local start = args.start
  if start == "" then start = nil end
  local out = assert(io.open(args.out, start and "a" or "w"))
  core.run(args.cases, out, { flush = args.flush == "1", start = start })
  out:write("done\n")
  out:close()
  return nil
end
