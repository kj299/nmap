description = "TCP: connect with a host table and a port table; get_info."
categories = {"net"}
local nmap = require "nmap"
portrule = function(host, port) return port.number == 46030 end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function(host, port)
  local out = {}
  local s = nmap.new_socket()
  out[#out+1] = "connect " .. show(s:connect(host, port))
  local st, lip, lport, rip, rport = s:get_info()
  out[#out+1] = "info " .. show(st, lip, type(lport), rip, rport)
  out[#out+1] = "send " .. show(s:send("x"))
  out[#out+1] = "receive " .. show(s:receive())
  s:close()
  return table.concat(out, "\n")
end
