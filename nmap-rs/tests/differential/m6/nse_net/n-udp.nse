description = "UDP: connect, send, receive, sendto, get_info."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket("udp")
  s:set_timeout(2000)
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46034))
  out[#out+1] = "send " .. show(s:send("dgram one"))
  out[#out+1] = "receive " .. show(s:receive())
  local st, lip, lport, rip, rport = s:get_info()
  out[#out+1] = "info " .. show(st, lip, type(lport), rip, rport)
  s:close()
  local u = nmap.new_socket("udp")
  u:set_timeout(2000)
  out[#out+1] = "sendto " .. show(u:sendto("127.0.0.1", 46034, "dgram two"))
  out[#out+1] = "receive " .. show(u:receive())
  u:close()
  local q = nmap.new_socket("udp")
  q:set_timeout(300)
  out[#out+1] = "connect silent " .. show(q:connect("127.0.0.1", 46036))
  out[#out+1] = "receive silent " .. show(q:receive())
  q:close()
  return table.concat(out, "\n")
end
