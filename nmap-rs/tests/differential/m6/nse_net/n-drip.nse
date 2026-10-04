description = "TCP: receive_bytes and receive_lines over data that arrives in pieces."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  s:set_timeout(3000)
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46035))
  out[#out+1] = "bytes " .. show(s:receive_bytes(3))
  out[#out+1] = "lines " .. show(s:receive_lines(1))
  out[#out+1] = "bytes " .. show(s:receive_bytes(100))
  out[#out+1] = "after " .. show(s:receive())
  s:close()
  return table.concat(out, "\n")
end
