description = "TCP: a closed port; operations on a socket that never connected."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46033))
  local u = nmap.new_socket()
  out[#out+1] = "receive " .. show(pcall(u.receive, u))
  out[#out+1] = "send " .. show(pcall(u.send, u, "x"))
  out[#out+1] = "info " .. show(pcall(u.get_info, u))
  out[#out+1] = "close " .. show(u:close())
  out[#out+1] = "badproto " .. show(pcall(u.connect, u, "127.0.0.1", 46030, "sctp"))
  out[#out+1] = "badport " .. show(pcall(u.connect, u, "127.0.0.1", "x"))
  out[#out+1] = "newbad " .. show(pcall(nmap.new_socket, "icmp"))
  out[#out+1] = "type " .. type(s)
  return table.concat(out, "\n")
end
