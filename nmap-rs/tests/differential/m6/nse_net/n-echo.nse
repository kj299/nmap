description = "TCP: connect, send, receive, receive_lines, close twice."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46030))
  out[#out+1] = "send " .. show(s:send("ping\n"))
  out[#out+1] = "receive " .. show(s:receive())
  out[#out+1] = "send " .. show(s:send("a\nb\n"))
  out[#out+1] = "lines " .. show(s:receive_lines(2))
  out[#out+1] = "close " .. show(s:close())
  out[#out+1] = "close again " .. show(s:close())
  out[#out+1] = "send closed " .. show(pcall(s.send, s, "x"))
  return table.concat(out, "\n")
end
