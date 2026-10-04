description = "nmap.resolve."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = type(t[i]) == "table" and table.concat(t[i], " ") or tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  out[#out+1] = "ip " .. show(nmap.resolve("127.0.0.1"))
  out[#out+1] = "ip6 " .. show(nmap.resolve("::1", "inet6"))
  out[#out+1] = "localhost " .. show(nmap.resolve("localhost", "inet"))
  out[#out+1] = "mismatch " .. show(nmap.resolve("127.0.0.1", "inet6"))
  out[#out+1] = "invalid " .. show(nmap.resolve("no-such-host.invalid"))
  out[#out+1] = "badfam " .. show(pcall(nmap.resolve, "x", "inet4"))
  return table.concat(out, "\n")
end
