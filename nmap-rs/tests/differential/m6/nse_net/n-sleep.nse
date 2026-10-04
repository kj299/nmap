description = "nmap.socket.sleep through stdnse.sleep; its checks."
categories = {"net"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local t0 = nmap.clock_ms()
  out[#out+1] = "sleep " .. show(stdnse.sleep(0.2))
  out[#out+1] = "slept enough " .. tostring(nmap.clock_ms() - t0 >= 150)
  out[#out+1] = "negative " .. show(pcall(stdnse.sleep, -1))
  out[#out+1] = "stats " .. type(nmap.socket.get_stats().connect_waiting)
  return table.concat(out, "\n")
end
